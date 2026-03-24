# 0067: Prettier als Default im create-paratix-Scaffold

## Anforderung

`create-paratix` soll neue Projekte mit einer vorkonfigurierten Prettier-Installation scaffolden. Die Konfiguration soll der bestehenden Vorlage aus dem Testprojekt entsprechen. Außerdem soll die generierte `package.json` Format-Scripts enthalten, und Lockfiles dürfen nicht von Prettier verarbeitet werden.

## Architekturentscheidungen

- Das Scaffold erhält Prettier als reine DX-Ergänzung ohne Build- oder Runtime-Änderungen.
- Die Prettier-Konfiguration wird als statische Scaffold-Vorlage mitgeschrieben, nicht dynamisch aus einem externen Pfad gelesen.
- Lockfiles werden zentral über `.prettierignore` ausgeschlossen.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                                       |
| -------------------------------------------- | ---------------------------------------------------------------------------------- |
| `packages/create-paratix/src/templates.ts`   | Enthält neue Templates für `.prettierrc` und `.prettierignore`                     |
| `packages/create-paratix/src/index.ts`       | Schreibt die Prettier-Dateien und ergänzt `package.json` um Dependency und Scripts |
| `packages/create-paratix/test/index.test.ts` | Regressionstests für Prettier-Dependency, Scripts und Scaffold-Dateien             |
| `packages/create-paratix/README.md`          | Dokumentiert die neuen Format-Scripts und Scaffold-Dateien                         |

## Implementierungsdetails

- Neue Projekte enthalten jetzt:
  - `.prettierrc`
  - `.prettierignore`
  - `prettier` als Dev-Dependency
  - `format:check` und `format:fix` in `package.json`
- `.prettierrc` übernimmt die gewünschte DX-orientierte Vorlage.
- `.prettierignore` schließt `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock` und `bun.lockb` aus.

## Testergebnisse

- `pnpm --filter create-paratix test`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine neuen Findings.
