# 0056: FIRST_RUN-Bootstrap-Flag für create-paratix

## Anforderung

Das von `create-paratix` erzeugte Projekt soll einen expliziten Boolean-Flag erhalten, der den ersten Bootstrap-Lauf von späteren regulären Läufen unterscheidet. Darüber sollen SSH-Portwahl, Firewall-Freigaben und `strictHostKeyChecking` zwischen Erstlauf und Folgezustand umschalten.

## Architekturentscheidungen

- Das generierte `server.ts` erhält einen sichtbaren `const FIRST_RUN = true`.
- Aus `FIRST_RUN` werden drei Scaffold-Konstanten abgeleitet:
  - `sshPorts`
  - `firewallTcpPorts`
  - `strictHostKeyChecking`
- Die Umschaltlogik wird in beiden Scaffold-Varianten identisch verwendet:
  - direkter Admin-User
  - Root-Bootstrap
- `FIRST_RUN` wird zusätzlich im `env`-Block exponiert, damit der Bootstrap-Zustand im generierten Playbook klar sichtbar bleibt.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                                      |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `packages/create-paratix/src/templates.ts`   | Führt `FIRST_RUN` und die davon abgeleiteten Scaffold-Konstanten im generierten `server.ts` ein   |
| `packages/create-paratix/test/index.test.ts` | Aktualisiert und erweitert Regressionstests für SSH-Port-, Firewall- und Host-Key-Bootstrap-Logik |
| `packages/create-paratix/README.md`          | Dokumentiert die neue `FIRST_RUN`-Semantik und den empfohlenen Wechsel nach dem ersten Bootstrap  |

## Implementierungsdetails

- Der Scaffold-Default bleibt auf Erstlauf vorbereitet: `FIRST_RUN = true`.
- Der erste Lauf verwendet dadurch Port `22`, öffnet `22` zusätzlich in der Firewall und nutzt `strictHostKeyChecking = "accept-new"`.
- Nach dem manuellen Umschalten auf `FIRST_RUN = false` verwendet dasselbe Playbook Port `2222`, entfernt Port `22` aus der Firewall und kehrt zu `strictHostKeyChecking = "yes"` zurück.
- Im Root-Bootstrap-Pfad bleibt zusätzlich der bestehende Hinweis erhalten, dass `ssh.user` nach dem ersten Lauf auf den Admin-User umgestellt werden soll.

## Testergebnisse

- `pnpm --filter create-paratix exec vitest run test/index.test.ts`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
