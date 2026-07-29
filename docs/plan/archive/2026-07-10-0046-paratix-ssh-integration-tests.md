# 0046: echte SSH-Integrationstests fuer Paratix

## Anforderung

`packages/paratix` hatte bislang nur mock-basierte Tests fuer SSH, SFTP und Playbook-Ausfuehrung. Es fehlte eine reproduzierbare Integrationstest-Schicht gegen einen echten SSH-Server, inklusive Host-Key-Verifikation, `probeSudo()`, SFTP-Transfers, Reconnect nach Portwechsel und einem echten `runPlaybook()`-Happy-Path.

Zusatzanforderung: Der Testlauf soll zuerst `colima` pruefen, bei fehlendem Colima sauber abbrechen, bei vorhandenem Colima einen kleinen Docker-SSHD-Container starten und den Testcontainer nach dem Lauf wieder entfernen.

## Architekturentscheidungen

- **Separater Integrationstest-Entry-Point** — echte SSH-Tests laufen nicht im normalen `vitest`-Pfad, sondern ueber `vitest.integration.config.ts` und `pnpm --filter paratix test:integration`. So bleiben Unit-Tests schnell und lokal reproduzierbar.
- **TypeScript-Harness statt Shell-Skript** — Container-Lifecycle, Colima-Pruefung, Docker-Port-Ermittlung und Cleanup liegen zentral in `test/integration/harness.ts`. Das kapselt Fehlerbehandlung und verhindert Shell-Glued-Code in den Tests.
- **Repo-lokaler SSHD-Testendpoint** — Dockerfile, `sshd_config` und Startskript liegen unter `test/integration/docker/`, damit der Testserver voll reproduzierbar aus dem Repo gebaut wird.
- **Getrennte Root- und Non-Root-Szenarien** — `probeSudo()` wird explizit gegen den Non-Root-User `paratix` getestet; SFTP- und `runPlaybook()`-Happy-Paths laufen ueber Root-Login, um container-spezifische `sudo`/Tempfile-Eigenheiten nicht mit dem eigentlichen Integrationsziel zu vermischen.
- **Public API vervollstaendigt** — `src/index.ts` exportiert jetzt auch die Built-in-Module, passend zum bestehenden API-Kommentar im File und fuer realistische Playbook-Integrationstests ueber den Public Entry-Point.

## Betroffene Dateien

| Datei                                                           | Beschreibung                                                      |
| --------------------------------------------------------------- | ----------------------------------------------------------------- |
| `packages/paratix/package.json`                                 | Neuer Script-Entry `test:integration`                             |
| `packages/paratix/vitest.config.ts`                             | Integrationstests aus der normalen Unit-Suite ausgeschlossen      |
| `packages/paratix/vitest.integration.config.ts`                 | Separate Vitest-Konfiguration fuer echte SSH-Integrationstests    |
| `packages/paratix/test/integration/harness.ts`                  | Colima-/Docker-Harness, Image-Build, Port-Ermittlung, Cleanup     |
| `packages/paratix/test/integration/paratix.integration.test.ts` | Reale SSH-, SFTP-, Reconnect- und Playbook-Tests                  |
| `packages/paratix/test/integration/docker/Dockerfile`           | Reproduzierbarer SSHD-Testcontainer mit `paratix`- und Root-Login |
| `packages/paratix/test/integration/docker/sshd_config`          | SSHD-Konfiguration fuer Testports und Login-Regeln                |
| `packages/paratix/test/integration/docker/start-sshd.sh`        | Minimaler Container-Entrypoint                                    |
| `packages/paratix/test/integration/fixtures/client_ed25519*`    | Test-Keypair fuer Client-Authentifizierung                        |
| `packages/paratix/src/index.ts`                                 | Built-in-Module ueber den Public Entry-Point exportiert           |
| `packages/paratix/README.md`                                    | Doku fuer den neuen Integrationstest-Workflow                     |

## Implementierungsdetails

### Harness

- prueft `colima` zuerst ueber `which colima`
- versucht bei vorhandenem, aber gestopptem Colima automatisch `colima start`
- bricht mit klarer Fehlermeldung ab, wenn Colima fehlt oder Docker trotz Colima nicht erreichbar ist
- baut das SSHD-Testimage lokal per Docker
- startet einen temporaeren Container mit zwei publizierten SSH-Ports (`22` und `2222`)
- liest den echten Host-Key aus dem laufenden Container aus
- wartet aktiv auf TCP-Readiness beider Ports
- entfernt Container und temporaeres Home-Verzeichnis auch bei Fehlern best effort

### Testfaelle

- **Connect + Host-Key-Verification** — unbekannter Host-Key wird bei `strictHostKeyChecking: "yes"` abgelehnt
- **`probeSudo()`** — echter Login als `paratix`, anschliessend erfolgreiche Sudo-Pruefung
- **SFTP Upload/Download** — echte Dateiuebertragung gegen den laufenden SSHD-Container
- **Reconnect nach Portwechsel** — Verbindung wird nach Umkonfiguration von Port `22` auf `2222` neu aufgebaut
- **`runPlaybook()` Happy Path** — echtes Playbook mit `file.directory`, `file.copy`, `file.template` und `command.shell`

### Testserver

- Debian-basierter SSHD-Container
- User `paratix` mit `NOPASSWD`-sudo fuer `probeSudo()`
- Root-Login per Public Key fuer Dateipfade und Root-Happy-Path
- feste, im Repo abgelegte Client-Key-Fixture
- frisch generierte Host-Keys pro Image-Build

## Validierung

- `pnpm --filter paratix exec tsc --noEmit`: bestanden
- `pnpm --filter paratix test`: bestanden
- `pnpm --filter paratix exec vitest run --config vitest.integration.config.ts`: bestanden
- `pnpm agent:check`: ausstehend zum Plan-Zeitpunkt, danach separat ausgefuehrt

## Review-Findings

Keine Findings. Die neue Harness ist bewusst separat geschnitten, greift nicht in den schnellen Unit-Test-Pfad ein und deckt die im Review identifizierte Integrationsluecke gezielt ab.
