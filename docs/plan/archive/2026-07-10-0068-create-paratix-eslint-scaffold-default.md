# 0068: ESLint als Default im create-paratix-Scaffold

## Anforderung

`create-paratix` soll neue Projekte mit einer vorkonfigurierten ESLint-Setupdatei scaffolden. Die Konfiguration soll `eslint-config-setup` verwenden und über `await getEslintConfig({ node: true })` erzeugt werden. Zusätzlich soll das Scaffold die nötigen Abhängigkeiten und ein `lint`-Script mitbringen.

## Architekturentscheidungen

- Das Scaffold erhält ein minimales, Node-orientiertes ESLint-Setup.
- Die Konfiguration bleibt klein und lehnt sich an das Workspace-Muster an, übernimmt aber keine repo-spezifischen Optionen wie `ai` oder `oxlint`.
- Es wird bewusst nur ein `lint`-Script scaffoldet, kein `lint:fix`.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                                    |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `packages/create-paratix/src/templates.ts`   | Enthält das neue `eslint.config.ts`-Template                                                    |
| `packages/create-paratix/src/index.ts`       | Schreibt `eslint.config.ts` und ergänzt `package.json` um ESLint-Dependencies und `lint`-Script |
| `packages/create-paratix/test/index.test.ts` | Regressionstests für ESLint-Dependency, Script und Config-Datei                                 |
| `packages/create-paratix/README.md`          | Dokumentiert das neue ESLint-Setup im Scaffold                                                  |

## Implementierungsdetails

- Neue Projekte enthalten jetzt `eslint.config.ts` mit:
  - `import { getEslintConfig } from "eslint-config-setup"`
  - `export default await getEslintConfig({ node: true })`
- `package.json` enthält:
  - `eslint`
  - `eslint-config-setup`
  - `lint: "eslint ."`

## Testergebnisse

- `pnpm --filter create-paratix test`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine neuen Findings.
