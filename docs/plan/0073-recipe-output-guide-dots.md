# 0073: Recipe-Output mit Guide-Punkten

## Anforderung

Die CLI-Ausgabe von Paratix soll verschachtelte Recipes nicht nur über Einrückung, sondern auch über eine vertikale Punktführung visualisieren. Zwischen einem Recipe-Header wie `[mailcow]` und seiner abschließenden Ergebniszeile soll auf der Spalte des `[` eine dünne Punktführung (`·`) erscheinen.

## Architekturentscheidungen

- Die Guide-Punkte werden rein im Output-Layer umgesetzt.
- Die bestehende Orchestrierung von Runner und Recipes bleibt unverändert; nur für die abschließende Ergebniszeile eines verschachtelten Recipes wird ein kleiner Output-Hinweis durchgereicht.
- Die Punktführung wird als Overlay auf dem vorhandenen Einrückungsraum gerendert, damit sich die Statusspalte nicht verschiebt.

## Betroffene Dateien

| Datei                                  | Beschreibung                                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/output.ts`       | Verwaltet aktive Recipe-Guide-Spalten und rendert die Punktführung für Header, Kindmodule und Abschlusszeilen |
| `packages/paratix/src/recipe.ts`       | Markiert Abschlusszeilen verschachtelter Recipes für den speziellen Output-Pfad                               |
| `packages/paratix/test/recipe.test.ts` | Sichert die Guide-Punkte für verschachtelte Recipes per Regressionstest ab                                    |

## Implementierungsdetails

- `output.ts` hält aktive Recipe-Guide-Tiefen und eine kurzlebige Liste gerade geschlossener Recipe-Tiefen.
- Während ein Recipe aktiv ist, werden auf allen darunterliegenden Zeilen Guide-Punkte auf die entsprechenden Spalten des Header-`[` gelegt.
- Wenn ein verschachteltes Recipe endet, wird seine Ergebniszeile noch einmal mit derselben Guide-Spalte gerendert.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/output.test.ts test/recipe.test.ts`
- `pnpm agent:check`

## Review-Findings und deren Behebung

- Keine zusätzlichen Findings im Rahmen dieses Features.
