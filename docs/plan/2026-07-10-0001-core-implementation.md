# 0001 — Paratix Core Implementation

## Anforderung

Implementierung des gesamten Paratix CLI-Tools basierend auf den Spezifikationen in
`docs/initialbeschreibung.md` und `docs/module.md`. Paratix ist ein idempotentes VPS-Setup-Tool in
TypeScript, das per SSH Module auf Zielservern ausführt.

## Scope

- Monorepo-Setup (pnpm workspace, tsup, vitest)
- Core-Infrastruktur: CLI, Runner, SSH-Connection, Env-System, Template-Engine, Output-Renderer
- 11 Modul-Namespaces: apt, file, service, sshd, ufw, user, group, hostname, command
- Built-in-Funktionen: assert, debug, fail, pause, when
- create-paratix Scaffolding-Package
- Unit-Tests (67 Tests)

## Architekturentscheidungen

| Entscheidung    | Wahl            | Begründung                                  |
| --------------- | --------------- | ------------------------------------------- |
| SSH-Library     | ssh2            | Volle Kontrolle über Connections, Streaming |
| CLI-Parser      | commander       | Stabil, etabliert                           |
| Build           | tsup (ESM)      | Schnell, esbuild-basiert                    |
| Test            | vitest          | TypeScript-nativ, schnell                   |
| Farben          | picocolors      | Winzig, keine Dependencies                  |
| Template-Engine | Custom {{key}}  | Minimalistisch per Spec                     |
| Monorepo        | pnpm workspaces | Per Spec                                    |
| Target          | ES2024          | Für RegExp v-flag Support                   |

## Betroffene Dateien

### Root

- `pnpm-workspace.yaml` — Workspace-Definition
- `package.json` — Root-Konfiguration mit agent:check Script
- `tsconfig.json` — ES2024 Target, Node16 Module
- `.gitignore` — node_modules, dist, .env
- `eslint.config.ts` — ESLint mit eslint-config-setup
- `oxlint.config.ts` — OxLint-Konfiguration
- `.prettierrc` — Prettier-Konfiguration

### packages/paratix/src/ — Core

| Datei          | Verantwortung                                            |
| -------------- | -------------------------------------------------------- |
| types.ts       | Alle TypeScript-Typen (Module, Environment, SSH, etc.)   |
| ssh.ts         | SshConnectionImpl + shellQuote Utility                   |
| runner.ts      | Sequenzieller Executor mit Signal-Handling               |
| recipe.ts      | recipe() Composite-Module                                |
| environment.ts | resolveEnvironment, loadDotEnvironment, mergeEnvironment |
| template.ts    | Template-Engine mit {{key}} Syntax                       |
| output.ts      | Terminal-Renderer mit picocolors                         |
| builtins.ts    | assert, debug, fail, pause, when                         |
| cli.ts         | Commander CLI Entry-Point                                |
| server.ts      | server() Identity-Funktion mit Validierung               |
| index.ts       | Public API Re-Exports                                    |

### packages/paratix/src/modules/

| Datei       | Module                                               |
| ----------- | ---------------------------------------------------- |
| apt.ts      | installed, absent, upgrade, distUpgrade              |
| file.ts     | copy, template, line, directory, absent              |
| service.ts  | running, stopped, enabled, disabled, restart, reload |
| sshd.ts     | port, config                                         |
| ufw.ts      | rule, enabled                                        |
| user.ts     | present, absent                                      |
| group.ts    | present, absent                                      |
| hostname.ts | set                                                  |
| command.ts  | shell                                                |

### packages/create-paratix/

| Datei        | Verantwortung                               |
| ------------ | ------------------------------------------- |
| src/index.ts | Scaffolding CLI mit eingebetteten Templates |

### Tests (packages/paratix/test/)

8 Test-Dateien mit 67 Tests, Mock-SSH-Helper für Module.

## Offene Punkte (für spätere Iterationen)

- Weitere Module: compose, sysctl, mount, rsync, op, system, net, download, etc.
- ~~user.present Check erkennt keine Attribut-Änderungen (#7)~~ — Erledigt
- ~~Klartext-Passwort in chpasswd (#8)~~ — Erledigt
- ~~reconnectTimeout CLI-Option wird nicht durchgereicht (#12)~~ — Erledigt
- ~~when() Environment-Propagation im Check (#13)~~ — Erledigt
