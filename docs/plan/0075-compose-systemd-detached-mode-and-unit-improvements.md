# 0075: Compose systemd detached mode and unit improvements

## Anforderung

`compose.systemd(...)` soll standardmäßig `compose up` ohne `-d` verwenden. Gleichzeitig soll ein expliziter Parameter zwischen attached und detached Start umschalten können. Außerdem sollen die generierten systemd-Units zusätzliche Verbesserungen wie `Wants=network-online.target`, `--remove-orphans`, Journal-Output und `TimeoutStartSec=0` erhalten.

## Architekturentscheidungen

- `compose.systemd(...)` erhält den neuen Parameter `detached?: boolean`.
- Default ist `false`, damit die generierte Unit standardmäßig `compose up --remove-orphans` verwendet.
- `detached: true` aktiviert explizit `compose up -d --remove-orphans`.
- Die zusätzlichen systemd-Verbesserungen gelten für beide Varianten und beide Runtimes.

## Betroffene Dateien

| Datei                                           | Beschreibung                                            |
| ----------------------------------------------- | ------------------------------------------------------- |
| `packages/paratix/src/modules/compose.ts`       | neue `detached`-Option und verbesserte Unit-Generierung |
| `packages/paratix/test/modules/compose.test.ts` | angepasste und neue Expectations für attached/detached  |
| `packages/paratix/llm-guide.md`                 | API-Referenz für `compose.systemd({ detached })`        |
| `packages/paratix/README.md`                    | Nutzerhinweis zum neuen Standardverhalten               |

## Implementierungsdetails

- `generateSystemdUnit(...)` erzeugt jetzt je nach `detached` entweder `compose up --remove-orphans` oder `compose up -d --remove-orphans`.
- Alle generierten Units enthalten zusätzlich:
  - `Wants=network-online.target`
  - `TimeoutStartSec=0`
  - `StandardOutput=journal`
  - `StandardError=journal`
- Die bestehende Docker-/Podman-Unterscheidung über `After=` und `Requires=` bleibt erhalten.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/compose.test.ts`
- `pnpm --filter paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und deren Behebung

- Keine zusätzlichen Findings im Rahmen dieses Features.
