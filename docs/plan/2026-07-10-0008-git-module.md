# 0008 — git Module

## Anforderung

Implementiere das Modul `git` mit der Methode `git.clone`, das ein Git-Repository auf den Server klont oder auf einen bestimmten Branch, Tag oder Commit aktualisiert. Dient für Code-Deployments via Playbooks.

## API

```typescript
git.clone(repo: string, destination: string, options?: { ref?: string }): Module
```

- `repo` — Repository-URL (HTTPS oder SSH)
- `destination` — Zielverzeichnis auf dem Server
- `ref` — Optional: Branch, Tag oder Commit-SHA (Default: Default-Branch des Repos)

## Architekturentscheidungen

### Helper-Funktionen

Drei interne Helper extrahiert für Lesbarkeit und Testbarkeit:

- `cloneRepo()` — Klont ein neues Repository. Versucht erst `git clone --branch <ref>`, fällt bei Fehler (z.B. bare SHA) auf `git clone` + `git checkout` zurück.
- `updateRepo()` — Aktualisiert ein bestehendes Repository via `fetch` + `checkout` + `reset --hard`. Versucht erst `origin/<ref>` (Branch), fällt auf `<ref>` zurück (Tag/SHA).
- `resolveReference()` — Löst eine Referenz zu einem Commit-SHA auf. Versucht erst `origin/<ref>`, dann `<ref>^{commit}`.

### Fehlerbehandlung

Alle Helper geben `boolean` zurück um Erfolg/Misserfolg zu signalisieren. `apply` gibt `{ status: "failed" }` zurück wenn ein git-Befehl fehlschlägt — konsistent mit dem Pattern von `hostname.set` und `service`-Modulen.

### Check-Logik

1. Kein SSH → `NEEDS_APPLY`
2. `.git`-Verzeichnis existiert nicht → `NEEDS_APPLY`
3. Kein ref → `"ok"` (Repo existiert)
4. Mit ref → fetch, dann `rev-parse HEAD` vs. resolved ref vergleichen

### Apply-Logik

1. Kein SSH → `{ status: "failed" }`
2. Neues Verzeichnis → `cloneRepo()` (mit SHA-Fallback)
3. Bestehendes Verzeichnis → `updateRepo()` (fetch + checkout + reset)
4. Ohne ref bei bestehendem Verzeichnis → `git pull`

## Betroffene Dateien

| Datei                                       | Aktion                      |
| ------------------------------------------- | --------------------------- |
| `packages/paratix/src/modules/git.ts`       | Neu — Modul-Implementierung |
| `packages/paratix/src/modules/index.ts`     | Export hinzugefügt          |
| `packages/paratix/test/modules/git.test.ts` | Neu — 18 Unit-Tests         |

## Testergebnisse

- 18 Tests (10 check, 8 apply), alle bestanden
- Gesamte Test-Suite: 265 Tests bestanden
- Lint, TypeScript, Build: fehlerfrei

## Review-Findings und Behebung

### Finding 1: Fehlende Fehlerbehandlung in apply (Wichtig)

**Problem:** `apply` gab immer `{ status: "changed" }` zurück, auch bei fehlgeschlagenen git-Befehlen.
**Lösung:** Helper-Funktionen geben `boolean` zurück, `apply` gibt `{ status: "failed" }` bei Fehler zurück.

### Finding 2: Clone mit Commit-SHA schlägt lautlos fehl (Wichtig)

**Problem:** `git clone --branch` unterstützt keine bare Commit-SHAs. Der Fehler wurde verschluckt.
**Lösung:** Fallback implementiert: bei fehlgeschlagenem `--branch` wird erst ohne Branch geklont, dann `checkout` auf den SHA ausgeführt.

## Scope-Einschränkungen

- Authentifizierung für private Repositories (SSH-Agent-Forwarding, Deploy-Keys) ist nicht im Scope (laut Spezifikation in `docs/module.md`).
