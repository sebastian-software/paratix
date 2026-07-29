# 0047: verlaesslicher Integrationspfad fuer Paratix-Tests

## Anforderung

Die bestehende Integrationssuite in `packages/paratix` pruefte bereits echte SSH-, SFTP- und Reconnect-Pfade sowie einen einzelnen Playbook-Happy-Path. Es fehlte aber ein verlaesslicher Review-/CI-Check, der `test:integration` gezielt einbindet, und die reale Server-Abdeckung war fuer Kernmodule noch zu schmal. Ziel war daher:

- einen klaren Full-Check fuer Reviews und spaetere CI-Laeufe bereitzustellen
- den Harness fuer Linux/CI ohne Colima-Annahme nutzbar zu machen
- weitere echte Server-Szenarien mit verifizierbaren Remote-Zustaenden fuer zentrale Module zu ergaenzen

## Architekturentscheidungen

- **Schneller Default-Check bleibt erhalten**: `pnpm agent:check` bleibt bewusst frei von Docker-/Integrationsabhaengigkeiten. Der neue Full-Check liegt separat als `pnpm agent:check:integration`, damit lokale Standardlaeufe schnell bleiben und Reviews trotzdem einen verbindlichen Tiefenpfad haben.
- **CI-Template statt aktiver Workflow**: Da GitHub Actions vorerst noch nicht live gehen sollen, liegt der Workflow als deaktivierte Vorlage unter `.github/workflows/integration-check.yml.disabled`. So ist der gewuenschte CI-Pfad vorbereitet, aber noch nicht aktiv.
- **Docker-first in CI, Colima nur lokal auf macOS**: Der Integrations-Harness unterscheidet jetzt zwischen lokalen macOS-Laeufen und CI/Linux. Auf macOS bleibt Colima der lokale Standard, auf Linux/CI wird direkt ein erreichbarer Docker-Runtime erwartet.
- **Remote-State vor Exit-Code**: Neue Integrationsfaelle validieren nicht nur, dass Module erfolgreich laufen, sondern dass der Zielzustand auf dem echten Server wirklich erreicht wurde: Inhalte, `mode`, `owner`, `group`, Flag-Dateien und anschliessende `check()`-Konformitaet.
- **Breiterer Modulschnitt statt sofortiger Vollausbau**: Der Ausbau fokussiert sich auf `file.directory`, `file.copy`, `file.template`, `command.shell`, `download.url` und `download.large`. Das adressiert zentrale Betriebsrisiken, ohne die Integrationssuite sofort in eine fragilere Vollsystem-Matrix ausufern zu lassen.

## Betroffene Dateien

| Datei                                                           | Beschreibung                                                                         |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `package.json`                                                  | Neuer Root-Full-Check `agent:check:integration` und Root-Shortcut `test:integration` |
| `README.md`                                                     | Workspace-Hinweis auf den neuen Full-Check                                           |
| `.github/workflows/integration-check.yml.disabled`              | Deaktivierte GitHub-Actions-Vorlage fuer den spaeteren Integrationscheck             |
| `packages/paratix/test/integration/docker/Dockerfile`           | Testcontainer um `curl` und `python3` fuer echte Download-Szenarien erweitert        |
| `packages/paratix/test/integration/harness.ts`                  | Runtime-Erkennung fuer macOS/Colima vs. Linux/CI/Docker                              |
| `packages/paratix/test/integration/paratix.integration.test.ts` | Neue echte Server-Szenarien fuer `file`, `command` und `download`                    |
| `packages/paratix/README.md`                                    | Doku fuer lokalen Integrationslauf, Full-Check und deaktivierte CI-Vorlage           |
| `review-report-2026-03-19.md`                                   | Review-Finding zum Integrationspfad als umgesetzt markiert                           |

## Implementierungsdetails

### Check-Strategie

- Root-Script `test:integration` delegiert an `pnpm --filter paratix test:integration`
- Root-Script `agent:check:integration` fuehrt zuerst den bisherigen Workspace-Check und danach die echte Integrationssuite aus
- dadurch gibt es jetzt einen klaren Review-/Freigabe-Pfad, ohne den schnellen Developer-Default zu belasten

### Harness und Runtime

- auf macOS ausserhalb von CI wird wie bisher Colima geprueft und bei Bedarf gestartet
- auf Linux oder in `CI=true` wird stattdessen direkt eine funktionierende Docker-Runtime verlangt
- dadurch ist dieselbe Integrationssuite lokal und in spaeteren CI-Laeufen wiederverwendbar

### Neue Integrationsszenarien

- **Datei-/Command-Konvergenz**:
  - `file.directory` setzt echtes Verzeichnis mit `mode` und `owner`
  - `file.copy` laedt reale Datei hoch und verifiziert Inhalt plus Metadaten
  - `file.template` rendert mit echter Umgebung gegen den Live-Host
  - `command.shell` erzeugt Marker-Datei und wird anschliessend ueber `check()` als compliant bestaetigt
- **Download-Konvergenz**:
  - im Testcontainer laeuft ein lokaler `python3 -m http.server`
  - `download.url` und `download.large` laden echte Artefakte ueber den Live-SSHD-Host
  - danach werden Inhalt, `mode`, `owner`, `group`, das Large-Download-Flag und das nachgelagerte `check()` verifiziert

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/integration/paratix.integration.test.ts`
- `pnpm agent:check`
- `pnpm agent:check:integration`

## Review-Findings und deren Behebung

- **Behoben**: Das Review-Finding zum fehlenden verlaesslichen Integrationspfad ist umgesetzt. Es gibt jetzt einen dedizierten Full-Check und breitere echte Server-Abdeckung mit ueberpruefbarem Remote-Zielzustand.
- **Offen**: Keine weiteren Findings aus dieser Aenderung.
