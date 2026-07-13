# 0005 — systemd Module

## Anforderung

Neues Modul `systemd` für Paratix, das systemd-Funktionen abdeckt, die über das bestehende
`service`-Modul (start/stop/enable/disable/restart/reload) hinausgehen:

- Unit-Dateien deployen (`.service`, `.timer`, `.socket` etc.)
- `systemctl daemon-reload` als Signal-Modul
- Units maskieren/demaskieren (`mask`/`unmask`)

## Architekturentscheidungen

### Kein separater `timer()`-Wrapper

Timer-Units sind normale Unit-Dateien. Der User deployt sie mit
`systemd.unit("foo.timer", content)` und aktiviert sie mit
`service.enabled("foo.timer")` + `service.running("foo.timer")`.
Ein dedizierter Wrapper hätte keinen Mehrwert geliefert.

### `unit()` führt `daemon-reload` automatisch aus

Nach dem Schreiben einer Unit-Datei muss immer `systemctl daemon-reload` laufen.
Dies automatisch in `unit().apply()` einzubauen verhindert, dass es vergessen wird.
Zusätzlich gibt es `daemonReload()` als eigenständiges Signal-Modul für explizite Nutzung.

### Idempotenz via String-Vergleich mit Trimming

`unit().check()` vergleicht den Remote-Dateiinhalt (via `ssh.readFile()`) mit dem
gewünschten Content. Beide Seiten werden getrimmt, da `readFile()` intern `stdout.trim()`
anwendet. Dieses Pattern ist konsistent mit `apt.repository()`.

### `masked()`/`unmasked()` nutzen stdout-Parsing statt Exit-Code

Im Gegensatz zu `service.ts` (das `--quiet` und Exit-Codes nutzt) parsen `masked()`
und `unmasked()` den stdout von `systemctl is-enabled`, weil der "masked"-Status
nicht allein über den Exit-Code unterscheidbar ist.

## Betroffene Dateien

| Datei                                           | Aktion             |
| ----------------------------------------------- | ------------------ |
| `packages/paratix/src/modules/systemd.ts`       | Neu erstellt       |
| `packages/paratix/src/modules/index.ts`         | Export hinzugefügt |
| `packages/paratix/test/modules/systemd.test.ts` | Neu erstellt       |

## Methoden

| Methode               | Typ        | Beschreibung                                       |
| --------------------- | ---------- | -------------------------------------------------- |
| `daemonReload()`      | Signal     | `systemctl daemon-reload`, check immer needs-apply |
| `masked(name)`        | Idempotent | `systemctl mask`, check via is-enabled stdout      |
| `unit(name, content)` | Idempotent | Unit-Datei schreiben + daemon-reload               |
| `unmasked(name)`      | Idempotent | `systemctl unmask`, check via is-enabled stdout    |

## Testergebnisse

- 26 Unit-Tests in `test/modules/systemd.test.ts`
- Alle Tests bestanden
- Gesamtprojekt: 208 Tests bestanden, 0 Fehler

## Review-Findings

1. **Trimming-Bug (behoben):** `unit().check()` verglich `readFile()`-Output (getrimmt)
   mit `content` (ungetrimmt). Fix: beide Seiten trimmen.
2. **Path-Traversal (akzeptiert):** `name`-Parameter wird nicht validiert. Konsistent mit
   allen bestehenden Modulen — Framework-Level-Concern.
3. **writeFile-Exception (akzeptiert):** `writeFile()` nicht in try-catch. Konsistent mit
   bestehenden Modulen, Fehlerbehandlung auf Orchestrierungs-Layer.
