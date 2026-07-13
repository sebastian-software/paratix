# 0014 — sysctl Module

## Anforderung

Implementiere ein `sysctl`-Modul, das Linux-Kernel-Parameter idempotent setzen kann — sowohl live (sofort wirksam) als auch persistent (überlebt Reboots via `/etc/sysctl.d/`).

## API

```typescript
sysctl.set(key: string, value: string, options?: { state?: "absent" | "present" }): Module
```

- **`state: "present"` (default):** Setzt den Wert live via `sysctl -w key=value` und schreibt `/etc/sysctl.d/99-paratix-<sanitized-key>.conf`
- **`state: "absent"`:** Entfernt die Persistenz-Datei (Live-Wert wird nicht revertiert, Kernel-Default greift nach Reboot)

## Architekturentscheidungen

- **Einzelne Methode `set()`:** Deckt 95% der Anwendungsfälle ab. Kein `get()` oder `load()` nötig.
- **Persistenzpfad:** `/etc/sysctl.d/99-paratix-<sanitized-key>.conf` — Priorität 99 stellt sicher, dass paratix-Werte andere Konfigurationen überschreiben.
- **Key-Sanitisierung:** `.` → `-` für Dateinamen (z.B. `net.ipv4.ip_forward` → `net-ipv4-ip_forward`).
- **Dual-Check:** `check` prüft sowohl den Live-Wert (`sysctl -n`) als auch den Inhalt der Persistenz-Datei — nur wenn beides stimmt, ist der Zustand `"ok"`.
- **Pattern:** Folgt `hostname.ts` (einfaches Modul) und `net.ts` (Persistenz via Drop-in-Dateien).

## Betroffene Dateien

| Aktion | Datei                                          |
| ------ | ---------------------------------------------- |
| Neu    | `packages/paratix/src/modules/sysctl.ts`       |
| Neu    | `packages/paratix/test/modules/sysctl.test.ts` |
| Edit   | `packages/paratix/src/modules/index.ts`        |

## Implementierungsdetails

### sysctl.ts

- Hilfsfunktionen: `sanitizeKey()`, `buildSysctlConfig()`
- `shellQuote` für alle dynamischen Werte in Shell-Befehlen
- `EXEC_OPTS = { ignoreExitCode: true, silent: true }` für fehlertolerante Kommandos
- `apply (present)`: `sysctl -w` + `writeFile` für Persistenz
- `apply (absent)`: `rm -f` der Persistenz-Datei
- `check (present)`: Live-Wert vergleichen + Persistenz-Datei Existenz + Inhalt prüfen
- `check (absent)`: Persistenz-Datei Existenz prüfen

### Tests (13 Testfälle)

- 7 check-Tests (5 present, 2 absent)
- 4 apply-Tests (3 present inkl. Fehlerfall, 1 absent)
- 2 name-Tests

## Review-Findings

| #   | Schweregrad | Thema                                  | Entscheidung                                               |
| --- | ----------- | -------------------------------------- | ---------------------------------------------------------- |
| 1   | Wichtig     | writeFile-Fehler nach sysctl -w        | Codebase-weites Pattern (net.route identisch) — kein Fix   |
| 2   | Wichtig     | Key-Validierung (Path Traversal)       | Geringes Risiko (Developer-Input), codebase-weit identisch |
| 3   | Hinweis     | apply gibt immer "changed" zurück      | Konsistent mit hostname.set, service.\*                    |
| 4   | Hinweis     | environment-Parameter nicht deklariert | Codebase-weites Pattern                                    |

## Validierung

- 554 Tests grün (541 bestehende + 13 neue)
- 0 Lint-Errors
- TypeScript: 0 Fehler
- Formatting: OK (Prettier)
