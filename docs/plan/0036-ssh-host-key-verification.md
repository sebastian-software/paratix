# 0036 — SSH Host-Key-Verifizierung

## Anforderung

SSH Host-Key-Verifizierung implementieren. Lokale `~/.ssh/known_hosts` auslesen
und gegen den Host-Key des Zielservers pruefen. `hostVerifier`-Callback an ssh2
`ConnectConfig` uebergeben. Option `strictHostKeyChecking` mit Werten
`accept-new`/`yes`/`no` unterstuetzen, Default: `accept-new`.

## Architekturentscheidungen

- **Neues Modul `knownHosts.ts`:** Separates Modul fuer Parsing/Lookup/Append
  von `~/.ssh/known_hosts`. Haelt `sshHelpers.ts` schlank und die Logik testbar.
- **Raw-Key-Vergleich ohne `hostHash`:** ssh2 `hostVerifier` bekommt ohne
  `hostHash` den rohen Public Key als `Buffer`. `known_hosts` speichert denselben
  Key base64-encoded. Direkter `Buffer.equals()`-Vergleich ohne Hashing.
- **`SyncHostVerifier`:** Synchroner Callback reicht, da `known_hosts` vorab mit
  `readFileSync` gelesen wird (einmal pro `buildHostVerifier`-Aufruf).
- **`accept-new` persistiert:** Bei unbekanntem Host wird der Key akzeptiert und
  automatisch an `~/.ssh/known_hosts` angehaengt (wie OpenSSH).
- **`yes` wirft direkt:** Kein interaktiver Prompt — sicher fuer CI/Automation.
- **Nur `~/.ssh/known_hosts`:** Kein konfigurierbarer Pfad, haelt die Config
  minimal.
- **Gehashte Hostnamen und `@`-Marker uebersprungen:** `|1|`-Eintraege und
  `@revoked`/`@cert-authority`-Zeilen werden ignoriert.
- **Bounds-Checks in `extractAlgoFromKey`:** Defensive Validierung des
  Key-Buffer-Formats verhindert `RangeError` bei korrupten Daten.

## Betroffene Dateien

| Datei                     | Aenderung                                                                                                  |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `src/knownHosts.ts`       | Neue Datei: `parseKnownHosts`, `lookupHostKey`, `appendHostKey`, `extractAlgoFromKey`, `buildHostVerifier` |
| `src/types.ts`            | `SshConfig.strictHostKeyChecking?: "accept-new" \| "no" \| "yes"` neu                                      |
| `src/sshHelpers.ts`       | `ConnectParameters.hostVerifier` neu, `buildConnectConfig()` extrahiert                                    |
| `src/ssh.ts`              | `tryConnectOnPorts` baut `hostVerifier` pro Port via `buildHostVerifier()`                                 |
| `src/server.ts`           | `validateSshConfig()` extrahiert, validiert `strictHostKeyChecking`                                        |
| `src/cli.ts`              | `collectSshErrors` validiert `strictHostKeyChecking`                                                       |
| `llm-guide.md`            | SSH-Beispiel um `strictHostKeyChecking` erweitert                                                          |
| `test/knownHosts.test.ts` | 37 neue Tests fuer alle Funktionen                                                                         |
| `test/server.test.ts`     | 14 neue Tests fuer Validierung                                                                             |
| `test/ssh.test.ts`        | 6 neue Tests fuer Host-Key-Propagation                                                                     |
| `test/cli.test.ts`        | 8 neue Tests fuer `collectSshErrors` Validierung                                                           |

## Testergebnisse

- 1088 Tests bestanden (vorher 1024), 0 fehlgeschlagen
- 0 TypeScript-Fehler, 0 Lint-Fehler
- Neue Tests: parseKnownHosts (6), lookupHostKey (4), extractAlgoFromKey (2+),
  appendHostKey (3), buildHostVerifier (15+), server validation (14),
  ssh propagation (6), cli validation (8)

## Review-Findings

| #     | Schweregrad | Status  | Beschreibung                                                 |
| ----- | ----------- | ------- | ------------------------------------------------------------ |
| R-001 | Wichtig     | Offen   | Race Condition: Multi-Port appendHostKey kann Key doppeln    |
| R-002 | Wichtig     | Behoben | appendHostKey .catch() gab keine Warnung aus                 |
| R-003 | Wichtig     | Behoben | Algorithmus fehlte in Key-Mismatch-Fehlermeldung             |
| R-004 | Kritisch    | Behoben | extractAlgoFromKey ohne Bounds-Checks                        |
| R-005 | Hinweis     | Behoben | @revoked/@cert-authority Marker nicht uebersprungen          |
| R-007 | Hinweis     | Offen   | Test-Coverage-Luecken (leerer Buffer, EACCES)                |
| R-008 | Hinweis     | Offen   | readFileSync blockiert Event Loop (akzeptabel fuer CLI-Tool) |
