# 0063: paratix Live-Modul-Spinner

## Anforderung

`paratix apply` soll während der Ausführung eines Moduls sofort sichtbar machen, welcher Schritt gerade läuft. Bisher erscheint die Ausgabe erst nach Abschluss von `check()` oder `apply()`. Künftig soll im interaktiven Terminal direkt eine laufende Zeile mit Spinner erscheinen und nach Abschluss in den finalen Status übergehen.

## Architekturentscheidungen

- Der Live-Spinner wird nur auf TTY-Ausgaben animiert. Nicht-interaktive Ausgaben bleiben stabil und logfreundlich.
- Es gibt bewusst nur genau eine aktive Spinner-Zeile gleichzeitig.
- Die Implementierung nutzt keine externe Spinner-Abhängigkeit.
- Der bestehende finale Status-Renderer bleibt die Wahrheit; der Spinner ist nur eine vorgeschaltete Live-Anzeige.
- Dry-Run-, Recipe- und Signal-Pfade werden in denselben Live-Ausgabevertrag integriert.

## Betroffene Dateien

| Datei                                         | Beschreibung                                                               |
| --------------------------------------------- | -------------------------------------------------------------------------- |
| `packages/paratix/src/output.ts`              | Spinner-State, TTY-Rendering und Umschreiben der laufenden Modulzeile      |
| `packages/paratix/src/runner.ts`              | Start der Live-Anzeige vor regulären Modul-`check()`- und `apply()`-Pfaden |
| `packages/paratix/src/recipe.ts`              | Start der Live-Anzeige für Recipe-Kindmodule                               |
| `packages/paratix/src/dryRunRecipe.ts`        | Live-Anzeige für Dry-Run-Module und Dry-Run-Recipe-Kindmodule              |
| `packages/paratix/src/signalOrchestration.ts` | Live-Anzeige für Signal-Ausführung                                         |
| `packages/paratix/test/output.test.ts`        | Regression für TTY-Spinner und finale Zeilenumschreibung                   |
| `oxlint.config.ts`                            | Ignoriert das lokal generierte Testprojekt im Repo-Root                    |
| `eslint.config.ts`                            | Ignoriert das lokal generierte Testprojekt im Repo-Root                    |

## Implementierungsdetails

- `output.ts` verwaltet einen kleinen In-Memory-Spinner-State mit ASCII-Frames und `setInterval`.
- Beim Start eines Moduls wird eine laufende Zeile mit Status `running` gerendert.
- Nach Abschluss stoppt dieselbe Infrastruktur den Spinner, löscht die aktive Zeile und schreibt den finalen Modulstatus (`ok`, `changed`, `failed`, `skipped`) an derselben Stelle.
- Nicht-TTY-Ausgaben verwenden keinen animierten Spinner und bleiben beim bisherigen finalen Zeilen-Output.
- Der Hook-Punkt liegt jeweils direkt vor dem ersten blockierenden Schritt des Moduls, damit der User auch bei längeren SSH-Operationen sofort Feedback sieht.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/output.test.ts`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine neuen offenen Findings aus diesem Feature-Umfang.
