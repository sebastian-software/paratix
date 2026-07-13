# 0066: DX-freundliche TypeScript-Konfiguration im create-paratix-Scaffold

## Anforderung

`create-paratix` soll standardmäßig eine TypeScript-Konfiguration für direkt mit `tsx` ausgeführte Projekte scaffolden, die extensionlose relative Imports in `.ts`-Quellen erlaubt. Die bisherige NodeNext-Konfiguration war dafür unnötig streng und zwang zu `.js`-Suffixen in relativen Imports.

## Architekturentscheidungen

- Das Scaffold bleibt buildfrei und `tsx`-orientiert.
- Die generierte `tsconfig.json` wird von NodeNext auf eine DX-orientierte Konfiguration umgestellt:
  - `module: "ESNext"`
  - `moduleResolution: "Bundler"`
- `include` wird auf `["**/*.ts"]` erweitert, damit auch Unterordner wie `server/**/*.ts` erfasst werden.
- Es wird bewusst keine Runtime- oder Bundler-Architektur geändert; nur der TS-Authoring-Vertrag im Scaffold.

## Betroffene Dateien

| Datei                                        | Beschreibung                                          |
| -------------------------------------------- | ----------------------------------------------------- |
| `packages/create-paratix/src/templates.ts`   | Erzeugt die scaffolded `tsconfig.json`                |
| `packages/create-paratix/test/index.test.ts` | Regressionstest für die generierte `tsconfig.json`    |
| `packages/create-paratix/README.md`          | Dokumentiert die neue DX-orientierte TS-Konfiguration |

## Implementierungsdetails

- `TSCONFIG_TEMPLATE` verwendet jetzt `ESNext` + `Bundler` statt `NodeNext`.
- Die generierte `include`-Konfiguration deckt alle `*.ts`-Dateien im Projektbaum ab.
- Die vorhandenen Templates benötigen keine `.js`-Suffixe in relativen Imports; es war daher keine weitere Template-Anpassung nötig.

## Testergebnisse

- `pnpm --filter create-paratix test`
- temporärer `tsc --noEmit`-Check mit extensionlosem Relativimport und der neuen Scaffold-`tsconfig`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine neuen Findings.
