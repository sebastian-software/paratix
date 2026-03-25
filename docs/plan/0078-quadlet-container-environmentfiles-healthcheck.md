# 0078: quadlet.container — environmentFiles und Healthcheck-Support

## Anforderung

Erweitere das `quadlet.container`-Modul um optionale `environmentFiles`- und Healthcheck-Felder, sodass generierte `.container`-Dateien `EnvironmentFile=`- und `Health*`-Direktiven enthalten können.

## Architekturentscheidungen

- **environmentFiles als Array:** Quadlet unterstützt mehrere `EnvironmentFile=`-Zeilen, daher wird ein `string[]` verwendet und über `renderQuadletRepeated` gerendert.
- **Healthcheck-Block nur bei gesetztem healthCmd:** Die Felder `healthInterval`, `healthTimeout`, `healthRetries` und `healthStartPeriod` werden nur geschrieben, wenn `healthCmd` definiert ist. Eine eigene Helper-Funktion `buildQuadletHealthcheckLines` kapselt diese Logik.
- **healthRetries als number:** Wird intern mit `String()` konvertiert, da Quadlet-Dateien Textformat verwenden.

## Betroffene Dateien

| Datei                                           | Beschreibung                                                                                                                                                 |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/paratix/src/modules/quadlet.ts`       | Typ `QuadletContainerOptions` erweitert, `buildQuadletHealthcheckLines` hinzugefügt, `buildQuadletContainerLines` um EnvironmentFile und Healthcheck ergänzt |
| `packages/paratix/test/modules/quadlet.test.ts` | 3 neue Tests: EnvironmentFile + Healthcheck, mehrere EnvironmentFiles, Healthcheck-Auslassung ohne healthCmd                                                 |
| `packages/paratix/llm-guide.md`                 | Signatur um die neuen Felder aktualisiert                                                                                                                    |

## Implementierungsdetails

Neue Felder in `QuadletContainerOptions`:

- `environmentFiles?: string[]`
- `healthCmd?: string`
- `healthInterval?: string`
- `healthRetries?: number`
- `healthStartPeriod?: string`
- `healthTimeout?: string`

Rendering-Reihenfolge im `[Container]`-Block: Image, ContainerName, AutoUpdate, Exec, Restart, Network, PodmanArgs, PublishPort, Volume, Environment, EnvironmentFile, Health\*.

## Testergebnisse

- 1625 Tests bestanden (10 davon quadlet.test.ts, davon 3 neu)
- TypeScript-Checks bestanden
- Lint fehlerfrei (0 Errors)
