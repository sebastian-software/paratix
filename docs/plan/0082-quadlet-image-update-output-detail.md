# 0082: Quadlet image update output detail

## Anforderung

Bei Image-Updates wie `quadlet.updateImage(...)` soll hinter dem Status `changed` in Klammern die neue Image-ID ausgegeben werden, damit der CLI-Output direkt sichtbar macht, welches Image jetzt aktiv gepullt wurde.

## Architekturentscheidungen

- **Allgemeines `ModuleResult.detail`:** Statt eines Spezialfalls nur fuer Quadlet bekommt der Core ein allgemeines Detailfeld fuer normale Apply-Ergebnisse.
- **Dry-Run bleibt separat:** `_dryRunDetail` bleibt fuer Dry-Run-Ausgaben bestehen und hat dort weiter Vorrang.
- **Image-ID vor Restart ermitteln:** `quadlet.updateImage(...)` liest die neue Image-ID direkt nach einem geaenderten Pull und vor dem Service-Restart. So gibt es bei erfolgreichem `changed` immer auch die passende ID.
- **Fehlende Image-ID ist ein Fehler:** Wenn `podman image inspect` fehlschlaegt oder keine ID liefert, wird der Lauf als `failed` behandelt, statt einen unvollstaendigen Erfolg auszugeben.

## Betroffene Dateien

| Datei                                            | Beschreibung                                                                        |
| ------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `packages/paratix/src/types.ts`                  | Neues allgemeines `detail`-Feld fuer `ModuleResult`                                 |
| `packages/paratix/src/runner.ts`                 | Reicht `ModuleResult.detail` an die normale Modul-Ausgabe weiter                    |
| `packages/paratix/src/recipe.ts`                 | Reicht `ModuleResult.detail` auch fuer Module innerhalb von Recipes weiter          |
| `packages/paratix/src/modules/quadletHelpers.ts` | Helper fuer `podman image inspect`, Image-ID-Parsing und geklammertes Detail        |
| `packages/paratix/src/modules/quadlet.ts`        | `quadlet.updateImage(...)` liefert bei `changed` jetzt die neue Image-ID als Detail |
| `packages/paratix/test/modules/quadlet.test.ts`  | Regressionen fuer Image-ID-Detail und Inspect-Fehlerfaelle                          |
| `packages/paratix/test/output.test.ts`           | Output-Regression fuer normale Detailtexte                                          |
| `packages/paratix/test/runner.test.ts`           | End-to-end-Regression, dass `ModuleResult.detail` im Run-Output erscheint           |
| `packages/paratix/llm-guide.md`                  | API-Verhalten fuer `quadlet.updateImage(...)` dokumentiert                          |
| `packages/paratix/README.md`                     | Nutzerhinweis zum neuen Changed-Detail                                              |
| `docs/module.md`                                 | Modul-Dokumentation fuer Quadlet-Image-Updates erweitert                            |

## Implementierungsdetails

- `ModuleResult.detail` ist ein optionaler kurzer Zusatztext, der hinter dem Status in dimmed Text ausgegeben wird.
- `runner.ts` verwendet bei normalen Apply-Laeufen jetzt `result.detail`, waehrend Dry-Run-Ausgaben weiterhin `_dryRunDetail` nutzen.
- `recipe.ts` gibt dieses Detail auch fuer Kindmodule aus, damit `quadlet.updateImage(...)` in Recipes dieselbe Ausgabe erzeugt wie auf Top-Level.
- `quadlet.updateImage(...)` fuehrt nach einem geaenderten Pull `podman image inspect --format '{{.Id}}' <image>` aus, formatiert die ID als `(sha256:...)` und haengt sie an das Changed-Ergebnis an.
- Wenn `podman image inspect` fehlschlaegt oder leer zurueckkommt, liefert das Modul `failed`.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/quadlet.test.ts test/output.test.ts test/runner.test.ts`
- `pnpm agent:check`

## Review-Findings und deren Behebung

- Keine zusaetzlichen Findings im Rahmen dieses Features.
