# 0018 — Fehlende Sub-Module: net.waitFor, net.request, system.facts, download.large

## Anforderung

4 Sub-Module aus der Spec (`docs/module.md`) fehlten in der Implementierung:

- `net.waitFor` — Wartet auf Bedingung (Port offen, Datei vorhanden, String in Datei)
- `net.request` — HTTP Health-Check vom Server aus
- `system.facts` — Sammelt System-Informationen als Meta-Keys
- `download.large` — Download grosser Dateien mit State-Flag-Idempotenz

## Architekturentscheidungen

### Datei-Struktur

Alle Module wurden in bestehende Dateien eingefuegt — kein neuer Export in `index.ts` noetig:

| Modul                        | Datei                                              |
| ---------------------------- | -------------------------------------------------- |
| `net.waitFor`, `net.request` | `packages/paratix/src/modules/net.ts`              |
| Hilfsfunktionen fuer net     | `packages/paratix/src/modules/netHelpers.ts` (neu) |
| `system.facts`               | `packages/paratix/src/modules/system.ts`           |
| `download.large`             | `packages/paratix/src/modules/download.ts`         |

### net.waitFor

- Polling-basiert mit konfigurierbarem `interval` (default: 2000ms) und `timeout` (default: 60000ms)
- Bedingungspruefung per `ssh.test()`: `nc -z` (Port), `test -f` (Datei), `grep -q` (Contains)
- Check prueft einmalig, Apply pollt bis Timeout

### net.request

- curl-basierter HTTP-Check auf dem Remote-Host
- Prueft Statuscode und optionalen Body-String
- try/catch um curl-Aufrufe fuer robustes Error-Handling
- Gibt `ok`/`failed` zurueck (nie `changed` — reines Check-Modul)

### system.facts

- 9 SSH-Befehle fuer 11 Meta-Keys
- OS-Info aus `/etc/os-release` (robuster als `lsb_release`)
- Fehler bei einem einzelnen Befehl → sofort `failed`
- `Partial<Record<string, string>>` fuer OS-Info um fehlende Keys abzufangen

### download.large

- URL-Hash mit Node.js `crypto.createHash("sha256")` statt serverseitigem Hash
- Flag-Pfad: `/var/lib/paratix/flags/download-<sha256(url)>`
- Nutzt bestehende `performDownload()` Funktion
- Flag wird nach erfolgreichem Download gesetzt

## Betroffene Dateien

### Implementierung

- `packages/paratix/src/modules/net.ts` — `waitFor` und `request` Methoden
- `packages/paratix/src/modules/netHelpers.ts` — Hilfsfunktionen (neu)
- `packages/paratix/src/modules/system.ts` — `facts` Methode + Parser
- `packages/paratix/src/modules/download.ts` — `large` Methode + Flag-Logik

### Tests

- `packages/paratix/test/modules/net.test.ts` — +34 Tests
- `packages/paratix/test/modules/system.test.ts` — +13 Tests
- `packages/paratix/test/modules/download.test.ts` — +15 Tests

## Review-Findings und Behebung

| Finding                                                                                       | Schweregrad | Behebung                                                                     |
| --------------------------------------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------- |
| `parseOsRelease` gibt `Record<string, string>` zurueck — fehlende Keys fuehren zu `undefined` | MAJOR       | Rueckgabetyp auf `Partial<Record<string, string>>` geaendert, `??` Fallbacks |
| `checkHttpCondition` ohne try/catch                                                           | MAJOR       | try/catch mit `return false` bei Fehler                                      |
| Spec sagt system.facts check = "ok", Impl gibt "needs-apply"                                  | MINOR       | Bewusste Abweichung — sonst wuerde apply nie laufen                          |

## Testergebnisse

- 682 Tests bestanden (62 neue)
- 0 Lint-Errors
- TypeCheck bestanden
