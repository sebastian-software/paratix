# 0079: quadlet.container — vollständige Feldabdeckung

## Anforderung

Erweitere das `quadlet.container`-Modul um alle gängigen Podman-Quadlet-Felder, sodass generierte `.container`-Dateien die vollständige Quadlet-Spezifikation abbilden können. Verschiebe `Restart=` in die korrekte `[Service]`-Sektion.

## Architekturentscheidungen

- **Rendering-Logik in eigene Datei extrahiert:** `quadletHelpers.ts` enthält Typen und alle Builder-Funktionen. `quadlet.ts` bleibt schlank mit SSH-Logik und Modul-Export. Grund: oxlint max-lines (300) und complexity (10) Limits.
- **Builder-Funktionen nach logischen Gruppen:** Identity, Network, Security, Runtime, Storage, Metadata, Tuning, Healthcheck — jeweils unter dem Complexity-Limit.
- **Restart nach [Service] verschoben:** `Restart=` ist eine systemd-`[Service]`-Direktive, nicht `[Container]`. Breaking Change: generierte Dateien ändern sich.
- **Neue [Service]-Sektion:** Optional, nur wenn `restart`, `timeoutStartSec` oder `timeoutStopSec` gesetzt sind.
- **Neue Helpers:** `renderQuadletKeyValue` für Record-Felder (Label, Annotation, Sysctl), `maybeRenderQuadletBool` für Boolean-Felder, `maybeRenderQuadletNumber` für numerische Felder.
- **podmanArgs als Escape-Hatch:** Exotische Felder (Rootfs, EnvironmentHost) werden nicht typisiert — `podmanArgs` deckt diese ab.

## Betroffene Dateien

| Datei                                            | Beschreibung                                                            |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| `packages/paratix/src/modules/quadlet.ts`        | SSH-Logik, Quadlet-Generierung, Modul-Export — Rendering-Logik entfernt |
| `packages/paratix/src/modules/quadletHelpers.ts` | NEU: Typen, Rendering-Helpers, Builder-Funktionen                       |
| `packages/paratix/test/modules/quadlet.test.ts`  | Bestehende Tests angepasst (Restart-Verschiebung), 5 neue Tests         |
| `packages/paratix/llm-guide.md`                  | Signatur um alle neuen Felder aktualisiert                              |

## Implementierungsdetails

### Neue Felder in `QuadletContainerOptions` (34 Felder)

**Container-Sektion:**

| Feld                   | Typ                                           | Quadlet-Key            |
| ---------------------- | --------------------------------------------- | ---------------------- |
| `addCapability`        | `string[]`                                    | `AddCapability`        |
| `addDevice`            | `string[]`                                    | `AddDevice`            |
| `annotation`           | `Record<string, string>`                      | `Annotation`           |
| `dns`                  | `string[]`                                    | `DNS`                  |
| `dnsOption`            | `string[]`                                    | `DNSOption`            |
| `dnsSearch`            | `string[]`                                    | `DNSSearch`            |
| `dropCapability`       | `string[]`                                    | `DropCapability`       |
| `entrypoint`           | `string[]`                                    | `Entrypoint`           |
| `exposeHostPort`       | `string[]`                                    | `ExposeHostPort`       |
| `groupAdd`             | `string[]`                                    | `GroupAdd`             |
| `healthOnFailure`      | `string`                                      | `HealthOnFailure`      |
| `hostName`             | `string`                                      | `HostName`             |
| `ip`                   | `string`                                      | `IP`                   |
| `ip6`                  | `string`                                      | `IP6`                  |
| `label`                | `Record<string, string>`                      | `Label`                |
| `logDriver`            | `string`                                      | `LogDriver`            |
| `mask`                 | `string[]`                                    | `Mask`                 |
| `mount`                | `string[]`                                    | `Mount`                |
| `noNewPrivileges`      | `boolean`                                     | `NoNewPrivileges`      |
| `notify`               | `boolean`                                     | `Notify`               |
| `pull`                 | `"always" \| "missing" \| "never" \| "newer"` | `Pull`                 |
| `readOnly`             | `boolean`                                     | `ReadOnly`             |
| `runInit`              | `boolean`                                     | `RunInit`              |
| `seccompProfile`       | `string`                                      | `SeccompProfile`       |
| `secret`               | `string[]`                                    | `Secret`               |
| `securityLabelDisable` | `boolean`                                     | `SecurityLabelDisable` |
| `securityLabelType`    | `string`                                      | `SecurityLabelType`    |
| `stopTimeout`          | `number`                                      | `StopTimeout`          |
| `sysctl`               | `Record<string, string>`                      | `Sysctl`               |
| `timezone`             | `string`                                      | `Timezone`             |
| `tmpfs`                | `string[]`                                    | `Tmpfs`                |
| `ulimit`               | `string[]`                                    | `Ulimit`               |
| `unmask`               | `string[]`                                    | `Unmask`               |
| `user`                 | `string`                                      | `User`                 |
| `userNs`               | `string`                                      | `UserNS`               |
| `workingDir`           | `string`                                      | `WorkingDir`           |

**Service-Sektion (neu):**

| Feld              | Typ                    | Quadlet-Key                          |
| ----------------- | ---------------------- | ------------------------------------ |
| `restart`         | `QuadletRestartPolicy` | `Restart` (verschoben aus Container) |
| `timeoutStartSec` | `number`               | `TimeoutStartSec`                    |
| `timeoutStopSec`  | `number`               | `TimeoutStopSec`                     |

### Rendering-Reihenfolge im [Container]-Block

Identity → Network → Security → Runtime → PodmanArgs → Storage → Metadata → Tuning → Healthcheck

## Testergebnisse

- 1630 Tests bestanden (15 davon quadlet.test.ts, davon 5 neu)
- TypeScript-Checks bestanden
- Lint fehlerfrei (0 Errors)
