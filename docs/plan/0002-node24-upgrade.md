# 0002: Node 24 Upgrade

## Anforderung

Upgrade der Node.js-Mindestversion von Node 16 auf Node 24. TypeScript-Modulstrategie auf `NodeNext` umstellen, Build-Targets aktualisieren, `engines`-Feld in allen `package.json`-Dateien ergänzen.

## Analyse

Die Codebase wurde auf modernisierbare Patterns untersucht:

- **Keine Polyfills** für Node-Built-ins gefunden (kein `node-fetch`, kein `structuredClone`, kein `AbortController`)
- **Keine veralteten APIs** die in Node 24 deprecated sind
- **Keine Dependencies** die durch Node 24 Built-ins ersetzbar wären
- Das Upgrade ist **rein konfigurativ**

## Architekturentscheidungen

### `NodeNext` statt `Node16`

TypeScript empfiehlt `NodeNext` als Nachfolger von `Node16`. Beide sind funktional identisch, aber `NodeNext` wird aktiver gepflegt und passt sich automatisch an zukünftige Node-Semantik an.

### `ES2024` als Target beibehalten

`target: "ES2024"` war bereits gesetzt und ist optimal für Node 24 (V8 13.6+).

### `engines: ">=24.0.0"`

Explizites `engines`-Feld in allen drei `package.json`-Dateien, damit pnpm/npm bei falscher Node-Version warnt.

## Betroffene Dateien

| Datei                                    | Änderung                                                      |
| ---------------------------------------- | ------------------------------------------------------------- |
| `tsconfig.json`                          | `module`/`moduleResolution`: `"Node16"` → `"NodeNext"`        |
| `packages/paratix/tsup.config.ts`        | `target`: `"node22"` → `"node24"`                             |
| `packages/create-paratix/tsup.config.ts` | `target`: `"node22"` → `"node24"`                             |
| `packages/create-paratix/src/index.ts`   | Scaffold-Template: `ES2022` → `ES2024`, `Node16` → `NodeNext` |
| `package.json` (Root)                    | `engines.node: ">=24.0.0"` hinzugefügt                        |
| `packages/paratix/package.json`          | `engines.node: ">=24.0.0"` hinzugefügt                        |
| `packages/create-paratix/package.json`   | `engines.node: ">=24.0.0"` hinzugefügt                        |
