# 0087: Pull-Request-CI-Checks

## Anforderung

Pull Requests und normale Pushes nach `main` müssen einen aktiven Qualitätscheck ausführen. Der bestehende Publish-Workflow bleibt von Release Please und Veröffentlichung getrennt.

## Architekturentscheidungen

- **Separater Basis-CI-Workflow**: `.github/workflows/ci.yml` läuft auf `pull_request` und `push` nach `main`, damit Qualitätsprüfungen unabhängig von Release-Erzeugung stattfinden.
- **Konsistentes Tooling**: Der Workflow nutzt Node 24, `pnpm/action-setup@v6`, `actions/setup-node@v6` und pnpm-Cache analog zur bestehenden Publish-Pipeline.
- **Release/Publish bleibt getrennt**: `.github/workflows/publish.yml` wird nicht verändert, damit Release Please und npm-Publish unverändert bedingt bleiben.
- **Keine Integrationstests im Basis-CI**: Die deaktivierte Vorlage `integration-check.yml.disabled` bleibt der separate Pfad für `pnpm agent:check:integration`; der neue CI-Workflow führt nur den Standard-Agent-Check aus.

## Betroffene Dateien

| Datei                                      | Beschreibung                                                              |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| `.github/workflows/ci.yml`                 | Neuer aktiver GitHub-Actions-Workflow für Pull Requests und Main-Pushes   |
| `docs/plan/0087-pull-request-ci-checks.md` | Dokumentiert Anforderung, Entscheidungen, Validierung und Review-Ergebnis |

## Implementierungsdetails

Der neue Workflow hat einen einzelnen Job `check` auf `ubuntu-latest`. Er checkt das Repository aus, richtet pnpm und Node 24 ein, installiert Abhängigkeiten mit `pnpm install --frozen-lockfile` und führt anschließend `pnpm agent:check` aus. Damit laufen Linting, Formatprüfung, Typecheck, Build und Tests bereits vor Merge beziehungsweise bei normalen Pushes nach `main`.

## Testergebnisse

- `pnpm exec prettier --check .github/workflows/ci.yml docs/plan/0087-pull-request-ci-checks.md`
- `pnpm agent:check`

## Review-Findings

Kein separater Reviewer gestartet, weil die Änderung ausschließlich GitHub-Actions-Konfiguration betrifft, eng begrenzt ist und durch fokussierte Formatprüfung sowie `pnpm agent:check` validiert wird.
