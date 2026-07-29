# 0088: Publish-Integration-Gate

## Anforderung

Der Publish-Workflow muss vor dem npm-Publish den vollständigen Integrations-Check ausführen, damit Release-Artefakte nicht nur mit dem schnellen Standard-Agent-Check validiert werden.

## Architekturentscheidungen

- **Publish-Gate bleibt im bestehenden Validate-Job**: Der vorhandene `validate`-Job erzeugt und lädt das Publish-Artefakt hoch. Deshalb wird dort `pnpm agent:check` durch `pnpm agent:check:integration` ersetzt, statt einen zweiten Release-Pfad oder einen separaten Workflow zu aktivieren.
- **Standard-CI bleibt getrennt**: Die normale Pull-Request- und Main-CI bleibt bei `pnpm agent:check`; nur das Release-Publish-Gate führt die Integrationstests verpflichtend aus.
- **Bestehendes Script wird wiederverwendet**: `pnpm agent:check:integration` enthält bereits `pnpm agent:check` und anschließend `pnpm test:integration`, sodass keine Logik im Workflow dupliziert wird.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                 |
| -------------------------------------------- | ---------------------------------------------------------------------------- |
| `.github/workflows/publish.yml`              | Führt im Publish-Validate-Job den Full-Check inklusive Integrationstests aus |
| `docs/plan/0088-publish-integration-gate.md` | Dokumentiert Anforderung, Entscheidungen, Validierung und Review-Ergebnis    |

## Implementierungsdetails

Der Release-Please-Job bleibt unverändert. Wenn Release Please einen Release erzeugt, läuft weiterhin der `validate`-Job vor `publish`. Dieser installiert die Abhängigkeiten mit `pnpm install --frozen-lockfile` und führt nun `pnpm agent:check:integration` aus. Erst danach werden die Paket-Artefakte hochgeladen, die der nachgelagerte `publish`-Job per `needs: validate` verwendet.

## Testergebnisse

- `pnpm exec prettier --check .github/workflows/publish.yml docs/plan/0088-publish-integration-gate.md`
- `pnpm agent:check:integration` – nicht bestanden, weil lokal kein Colima-Runtime lief.
- `PARATIX_INTEGRATION_START_COLIMA=true pnpm agent:check:integration` – zunächst in der Sandbox wegen fehlender Schreibrechte auf `~/.colima/default/colima.yaml` blockiert; eskaliert gestartet und bis zur bestehenden Integration-Suite ausgeführt. Ergebnis: 6 bestanden, 9 fehlgeschlagen; die Fehlschläge betreffen SFTP-Uploads und erwartete `paratix`-Benutzer in `test/integration/paratix.integration.test.ts`.
- `pnpm agent:check`

## Review-Findings

Kein separater Reviewer gestartet, weil die Änderung ausschließlich GitHub-Actions-Konfiguration betrifft, eng begrenzt ist und durch fokussierte Formatprüfung, `pnpm agent:check:integration` sowie `pnpm agent:check` validiert wird.
