# 0055: Initial-User-Auswahl für create-paratix

## Anforderung

`create-paratix` soll den technischen Schalter `--bootstrap-root` durch ein verständlicheres Initial-User-Konzept ersetzen. Nutzer sollen explizit wählen, ob der Zielserver initial per `root` oder per konkretem Admin-User erreichbar ist. Dieselbe Auswahl muss interaktiv und nicht-interaktiv verfügbar sein.

## Architekturentscheidungen

- Das interne Scaffold-Modell wird nicht mehr als Modus-Flag, sondern als Initial-User-Konfiguration modelliert:
  - `{ kind: "root" }`
  - `{ kind: "admin", user: string }`
- Die CLI verwendet dafür `--initial-user <root|name>` als nicht-interaktive API.
- Ohne CLI-Parameter fragt `create-paratix` interaktiv:
  - `root` oder `admin`
  - bei `admin` zusätzlich den konkreten Usernamen
- Der Root-Pfad bleibt fachlich erhalten:
  - initiale SSH-Verbindung als `root`
  - dedizierter Admin-User wird weiterhin provisioniert
  - Root-Login wird danach deaktiviert
- Der Admin-Pfad verwendet den konkret gewählten User direkt als Verbindungsnutzer und scaffoldet keinen Root-Bootstrap.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                              |
| -------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `packages/create-paratix/src/index.ts`       | Neues Initial-User-Modell, Prompt-Flow, `--initial-user`-Parsing und Template-Generierung |
| `packages/create-paratix/test/index.test.ts` | Regressionstests für Prompt-Flow, CLI-Flow und beide Template-Varianten                   |
| `packages/create-paratix/README.md`          | Dokumentation der neuen Initial-User-Auswahl und Entfernung von `--bootstrap-root`        |

## Implementierungsdetails

- `createServerTemplate(...)` leitet das generierte `server.ts` jetzt aus einer `InitialUserConfig` ab.
- Der gehärtete Admin-Pfad interpoliert den konkret gewählten Admin-User direkt in das Scaffold.
- Der Root-Pfad bleibt ein bewusst kommentierter Übergangsmodus, wird aber jetzt über `root` als Initial-User ausgewählt statt über einen separaten Spezial-Flag.
- Die CLI lehnt `--bootstrap-root` explizit mit Migrationshinweis auf `--initial-user root` ab.
- Der interaktive Prompt läuft nur im CLI-Einstieg, nicht in den internen Schreib- oder Scaffold-Helfern.

## Testergebnisse

- `pnpm --filter create-paratix exec vitest run test/index.test.ts`
- `pnpm --filter create-paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
