# 0076: Podman Quadlet container module

## Anforderung

Paratix soll ein eigenes Podman-Quadlet-Modul bekommen. Für die erste Version soll der Scope bewusst klein bleiben und nur `.container`-Quadlets abdecken, damit Podman-native Services sauber neben `compose.systemd(...)` modelliert werden können.

## Architekturentscheidungen

- Neues Modul `quadlet` mit der ersten Methode `quadlet.container(...)`.
- V1 schreibt nur `.container`-Dateien unter `/etc/containers/systemd/`.
- Das Modul kümmert sich um `systemctl daemon-reload`, nicht um `enable` oder `start`.
- Aktivierung und Start bleiben bewusst bei den bestehenden `service.*(...)`-Modulen.

## Betroffene Dateien

| Datei                                           | Beschreibung                                         |
| ----------------------------------------------- | ---------------------------------------------------- |
| `packages/paratix/src/modules/quadlet.ts`       | neues Quadlet-Modul mit `quadlet.container(...)`     |
| `packages/paratix/src/modules/index.ts`         | Modul-Export für `quadlet`                           |
| `packages/paratix/src/index.ts`                 | Top-Level-Export für `quadlet`                       |
| `packages/paratix/test/modules/quadlet.test.ts` | Regressionen für Render-, Check- und Apply-Verhalten |
| `packages/paratix/llm-guide.md`                 | API-Referenz für `quadlet.container(...)`            |
| `packages/paratix/README.md`                    | Nutzerhinweis für Podman-native Services             |

## Implementierungsdetails

- `quadlet.container(...)` rendert eine deklarative `.container`-Datei mit den Abschnitten `[Unit]`, `[Container]` und `[Install]`.
- Der Zielpfad ist `/etc/containers/systemd/<name>.container`.
- Bei `apply()` wird das Quadlet-Verzeichnis bei Bedarf per `mkdir -p` angelegt, die Datei mit Modus `0644` geschrieben und danach `systemctl daemon-reload` ausgeführt.
- `check()` ist idempotent und vergleicht den Remote-Inhalt mit dem lokal gerenderten Zielinhalt.
- Unterstützt werden in V1 typische Container-Felder wie `Image`, `ContainerName`, `Environment`, `PublishPort`, `Volume`, `Network`, `PodmanArgs`, `Exec`, `AutoUpdate` und `WantedBy`.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/quadlet.test.ts`
- `pnpm agent:check`

## Review-Findings und deren Behebung

- Keine zusätzlichen Findings im Rahmen dieses Features.
