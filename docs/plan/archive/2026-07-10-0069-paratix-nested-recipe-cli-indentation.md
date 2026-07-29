# 0069: Eingerückte CLI-Ausgabe für verschachtelte Recipes

## Anforderung

Die CLI-Ausgabe von Paratix soll verschachtelte `recipe(...)`-Strukturen sichtbar machen. Bisher wurden auch Recipes innerhalb anderer Recipes optisch wie Top-Level-Blöcke gerendert. Das erschwert das Lesen der tatsächlichen Struktur des Playbooks.

## Architekturentscheidungen

- Die Lösung bleibt rein im Output-Layer und ändert keine Orchestrierungssemantik.
- Recipes verwalten einen kleinen Output-Scope über die aktuelle Verschachtelungstiefe.
- Top-Level-Ausgabe bleibt unverändert.
- Verschachtelte Recipe-Header, Kind-Module und Fehlermeldungsblöcke erhalten zusätzliche Einrückung.

## Betroffene Dateien

| Datei                                  | Beschreibung                                                                   |
| -------------------------------------- | ------------------------------------------------------------------------------ |
| `packages/paratix/src/output.ts`       | Depth-aware Rendering für Recipe-Header, Modulzeilen, Spinner und Fehlerblöcke |
| `packages/paratix/src/recipe.ts`       | Öffnet einen Output-Scope für verschachtelte normale Recipe-Ausführung         |
| `packages/paratix/src/dryRunRecipe.ts` | Öffnet denselben Output-Scope im Dry-Run-Pfad                                  |
| `packages/paratix/test/recipe.test.ts` | Regressionstest für die eingerückte verschachtelte Recipe-Ausgabe              |

## Implementierungsdetails

- `output.ts` verwaltet jetzt eine interne `recipeOutputDepth`.
- `withRecipeOutputScope(...)` erhöht die Tiefe für die Dauer einer Recipe-Ausführung und setzt sie anschließend zurück.
- Top-Level-Modulzeilen bleiben bei ihrer bisherigen Einrückung.
- Ein verschachteltes Recipe innerhalb eines Recipes wird zusätzlich eingerückt, ebenso seine Kind-Module.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/recipe.test.ts test/output.test.ts`
- `pnpm --filter paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine neuen Findings.
