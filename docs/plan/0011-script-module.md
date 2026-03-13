# 0011 — script Module

## Anforderung

Implementiere das Modul `script` mit der Methode `script.once`, das ein lokales Skript auf den Server kopiert und einmalig ausfuehrt. Idempotenz wird ueber State-Flags mit Skriptname und Version sichergestellt, sodass das Skript bei Versionsaenderung erneut laeuft.

## API

```typescript
script.once(name: string, localPath: string, options?: { args?: string[]; version?: string }): Module
```

- `name` — Eindeutiger Bezeichner (alphanumerisch, Punkte, Bindestriche, Unterstriche)
- `localPath` — Pfad zum Skript auf dem Controller (lokal)
- `args` — Optionale Argumente (jedes Element wird einzeln shell-gequotet)
- `version` — Versionstring fuer das State-Flag (Default: `"1"`)

## Architekturentscheidungen

### State-Flag-Pattern

Nutzt dasselbe Pattern wie `apt.upgrade`/`apt.distUpgrade`: Flag-Dateien in `/var/lib/paratix/flags/`. Flag-Name: `script-<name>-<version>`. Bei Versionsaenderung werden alte Flags mit Prefix `script-<name>-` entfernt und ein neues Flag gesetzt.

### Input-Validierung

Der `name`-Parameter wird mit `/^[\w.\-]+$/iv` validiert um Shell-Injection ueber den Flag-Pfad und temporaeren Dateipfad zu verhindern. Shell-Metazeichen und Leerzeichen sind nicht erlaubt.

### Shell-Quoting der Argumente

`args` wurde bewusst als `string[]` statt `string` typisiert. Jedes Argument wird einzeln durch `shellQuote()` geschuetzt. Das verhindert Shell-Injection, die bei einem einzelnen String moeglich waere (vgl. `command.shell`, das bewusst raw shell akzeptiert).

### Try/Finally fuer Cleanup

Die gesamte Ausfuehrungslogik nach dem Upload ist in einen try/finally Block gewrapped. Das stellt sicher, dass die temporaere Datei (`/tmp/paratix-script-<name>`) auch bei Fehlern aufgeraeumt wird.

### Check-Logik

1. Kein SSH → `NEEDS_APPLY`
2. Flag-Datei existiert → `"ok"`
3. Sonst → `NEEDS_APPLY`

### Apply-Logik

1. Kein SSH → `{ status: "failed" }`
2. Flags-Verzeichnis sicherstellen (`mkdir -p`)
3. Skript via `ssh.uploadFile()` hochladen
4. `chmod +x` auf das hochgeladene Skript
5. Skript ausfuehren (mit optionalen gequoteten Args)
6. Bei Exit-Code ≠ 0 → `{ status: "failed" }`
7. Alte Flags entfernen, neues Flag setzen
8. Finally: Temp-Datei aufraeuemen
9. Return `{ status: "changed" }`

## Betroffene Dateien

| Datei                                          | Aktion                      |
| ---------------------------------------------- | --------------------------- |
| `packages/paratix/src/modules/script.ts`       | Neu — Modul-Implementierung |
| `packages/paratix/src/modules/index.ts`        | Export hinzugefuegt         |
| `packages/paratix/test/modules/script.test.ts` | Neu — 20 Unit-Tests         |

## Testergebnisse

- 20 Tests (4 check, 11 apply, 3 name, 3 input validation), alle bestanden
- Gesamte Test-Suite: 348 Tests bestanden
- Lint, TypeScript, Build: fehlerfrei

## Review-Findings und Behebung

### Finding 1: Shell-Injection ueber args (Kritisch)

**Problem:** `args` war als `string` typisiert und wurde direkt in den Shell-Befehl interpoliert.
**Loesung:** `args` als `string[]` typisiert, jedes Argument einzeln durch `shellQuote()` geschuetzt.

### Finding 2: Fehlende Name-Validierung (Wichtig)

**Problem:** `name` wurde ohne Validierung in Flag-Pfade und temporaere Dateipfade eingesetzt.
**Loesung:** Regex-Validierung `/^[\w.\-]+$/iv` — nur alphanumerische Zeichen, Punkte, Bindestriche und Unterstriche erlaubt.

### Finding 3: Fehlendes Cleanup bei Exceptions (Wichtig)

**Problem:** Wenn `chmod` oder die Skript-Ausfuehrung eine Exception wirft, blieb die temporaere Datei auf dem Server.
**Loesung:** Try/finally Block um die gesamte Ausfuehrungslogik nach dem Upload.
