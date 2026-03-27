# 0081: Quadlet-targeted image updates

## Anforderung

Paratix soll einen First-Class-API-Pfad fuer gezielte Container-Image-Updates auf Quadlet-basierten Services erhalten. Der neue Pfad soll handgeschriebenes `command.shell("podman pull ...")` in Projekt-Code ersetzen, Registry-authentifizierte Images unterstuetzen und sich sauber mit `quadlet.container(...)` kombinieren lassen, damit Deploy- und Image-Update-Flows dieselbe Konfigurationsquelle verwenden.

## Architekturentscheidungen

- **Neues Modul `quadlet.updateImage(...)`:** Der Update-Pfad lebt direkt neben `quadlet.container(...)`, damit Quadlet-Deployments und spaetere Image-Refreshes im selben Modul-Namespace bleiben.
- **Strukturell kompatible Optionsform:** `quadlet.updateImage(...)` benoetigt nur `name` und `image` sowie optional `authFile` und `serviceName`. Dadurch koennen bestehende `quadlet.container(...)`-Optionsobjekte direkt wiederverwendet werden.
- **Signal-artige Check-Strategie:** Der Registry-Stand laesst sich ohne Pull nicht verlaesslich vorab pruefen. Deshalb liefert `check()` immer `needs-apply`, waehrend `apply()` anhand der Podman-Ausgabe zwischen `ok` und `changed` unterscheidet.
- **Restart nur bei geaendertem Image:** Ein erfolgreicher Pull ohne Downloadmarker startet den Quadlet-Service nicht neu. So bleibt der Modulpfad trotz signal-artigem Check im Effekt idempotent.
- **Registry-Auth ueber Host-Login oder `authFile`:** Das Modul greift standardmaessig auf vorhandene Podman-Registry-Authentifizierung des Hosts zurueck und unterstuetzt optional `--authfile` fuer explizite Auth-Dateien.

## Betroffene Dateien

| Datei                                            | Beschreibung                                                                              |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/quadlet.ts`        | Neues Modul `quadlet.updateImage(...)` inkl. Pull-, Change- und Restart-Logik             |
| `packages/paratix/src/modules/quadletHelpers.ts` | Gemeinsame Helper fuer Pull-Command, Service-Namensableitung und Change-Erkennung         |
| `packages/paratix/test/modules/quadlet.test.ts`  | Regressionstests fuer Changed/Unchanged-Pulls, `authFile`, `serviceName` und Fehlerfaelle |
| `packages/paratix/llm-guide.md`                  | API-Referenz fuer `quadlet.updateImage(...)`                                              |
| `packages/paratix/README.md`                     | Kurzbeschreibung des gezielten Quadlet-Image-Update-Flows                                 |
| `docs/module.md`                                 | Modul-Dokumentation mit Beispiel fuer geteilte Quadlet-Konfiguration                      |
| `cspell.json`                                    | Neue Woerter fuer die bearbeiteten Quadlet-Dateien                                        |

## Implementierungsdetails

- `quadlet.updateImage(...)` validiert denselben Quadlet-Namen wie `quadlet.container(...)` und akzeptiert optional einen abweichenden `serviceName`.
- Der Pull-Command wird als `podman pull [--authfile ...] <image> 2>&1` gebaut, damit sowohl Registry-Auth-Dateien als auch die textbasierte Change-Erkennung unterstuetzt werden.
- Als Download-Indikatoren gelten bekannte Podman-Marker wie `Copying blob`, `Copying config`, `Writing manifest`, `Storing signatures` und `Downloaded newer image`.
- Nur wenn einer dieser Marker auftritt, fuehrt das Modul `systemctl restart <service>` aus und meldet `changed`.
- Bei Ausgaben wie `Image is up to date` liefert das Modul `ok` und ueberspringt den Restart.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/quadlet.test.ts`
- `pnpm agent:check`

## Review-Findings und deren Behebung

- Keine zusaetzlichen Findings ueber die Validator-Hinweise des bestehenden Repos hinaus.
