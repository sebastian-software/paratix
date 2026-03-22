# 0062: create-paratix ssh2 Host-Fingerprint-Bootstrap

## Anforderung

`create-paratix` soll beim interaktiven Scaffold anbieten, den aktuell auf SSH-Port `22` präsentierten Host-Key direkt per `ssh2` auszulesen, daraus einen OpenSSH-Fingerprint zu berechnen und diesen als `ssh.expectedHostFingerprint` in das generierte `server.ts` zu schreiben.

## Architekturentscheidungen

- Der Host-Key-Abruf läuft bewusst über `ssh2` statt über einen externen `ssh-keyscan`-Prozess.
- Der Fingerprint wird lokal in `create-paratix` im bestehenden OpenSSH-Format `SHA256:...` berechnet.
- Wenn der User den TOFU-Schritt ablehnt oder der Abruf fehlschlägt, bleibt der bisherige Placeholder-Fallback erhalten.
- Ist ein Fingerprint vorhanden, scaffoldet `server.ts` von Anfang an mit `strictHostKeyChecking: "yes"` statt mit dem `accept-new`-Fallback.

## Betroffene Dateien

| Datei                                                     | Beschreibung                                                                                        |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `packages/create-paratix/src/hostFingerprintBootstrap.ts` | Neuer ssh2-basierter Host-Key-Abruf und Fingerprint-Berechnung                                      |
| `packages/create-paratix/src/interactivePrompts.ts`       | Neuer interaktiver Prompt für den optionalen Host-Key-TOFU-Schritt                                  |
| `packages/create-paratix/src/index.ts`                    | Verkabelung des neuen Host-Key-Bootstrap-Flows in den Scaffold-Ablauf                               |
| `packages/create-paratix/src/templates.ts`                | Optionales Einbetten von `expectedHostFingerprint` und konsistenter `strictHostKeyChecking`-Vertrag |
| `packages/create-paratix/src/promptUi.ts`                 | Verallgemeinerter Hilfetext für Cursor-Auswahlen                                                    |
| `packages/create-paratix/package.json`                    | `ssh2`-Abhängigkeit für den lokalen Host-Key-Abruf                                                  |
| `packages/create-paratix/test/index.test.ts`              | Regressionen für Prompt, ssh2-Abruf, Fallback und Template-Ausgabe                                  |
| `packages/create-paratix/README.md`                       | Doku für den neuen TOFU-basierten Host-Key-Bootstrap                                                |

## Implementierungsdetails

- Der neue Helper baut per `ssh2.Client` eine Verbindung zu `host:22` auf und nutzt den `hostVerifier`-Pfad, um den präsentierten Host-Key ohne Authentisierung abzugreifen.
- Der Prompt bietet zwei explizite Modi:
  - Host-Key jetzt scannen und fingerprint pinnen
  - Placeholder im Template behalten
- Das generierte `server.ts` unterscheidet jetzt zwei Host-Key-Pfade:
  - mit gescanntem Fingerprint: `strictHostKeyChecking: "yes"` und gesetztes `expectedHostFingerprint`
  - ohne Scan/Fallback: bisheriger `FIRST_RUN ? "accept-new" : "yes"`-Pfad mit kommentiertem Placeholder

## Testergebnisse

- `pnpm --filter create-paratix test`
- `pnpm --filter create-paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine neuen offenen Findings aus diesem Feature-Umfang.
