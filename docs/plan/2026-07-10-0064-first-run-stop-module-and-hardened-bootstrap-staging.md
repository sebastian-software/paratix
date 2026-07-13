# 0064: First-Run-Stop-Modul und gehärtete Bootstrap-Staging-Grenze

## Anforderung

Paratix soll ein explizites First-Run-Stop-Modul erhalten, das einen Lauf kontrolliert beendet, wenn `paratix apply` mit `--first-run` gestartet wurde. Das von `create-paratix` erzeugte Scaffold soll diesen Stop nach `ssh-hardening`, `kernel-hardening` und `automatic-security-upgrades` einbauen, damit spätere Dienste erst auf einem gehärteten Grundsetup installiert werden.

## Architekturentscheidungen

- Das neue Feature wird als Builtin `firstRun.stop(...)` im Core-API-Pfad umgesetzt, nicht als zusätzlicher CLI-Sonderpfad.
- Ein First-Run-Stop ist ein erfolgreicher, kontrollierter Abbruch und daher kein `failed`-Status.
- Für die interne Runner-Steuerung wird `ModuleResult` um den internen Marker `_stopRun?: true` erweitert.
- Runner, Recipes und Dry-Run-Rezepte propagieren diesen Marker bis zum oberen Lauf und brechen danach ohne Fehlerstatus ab.
- Top-Level-Signale und Recipe-Signale werden nach einem First-Run-Stop nicht mehr ausgeführt.
- `create-paratix` erzeugt nun zusätzlich zwei Grundsetup-Rezepte:
  - `kernel-hardening`
  - `automatic-security-upgrades`
- Der Scaffold setzt den Stop explizit nach diesen Blöcken und markiert die Stelle als Grenze für spätere Anwendungs- und Benutzerdienste.

## Betroffene Dateien

| Datei                                        | Beschreibung                                                               |
| -------------------------------------------- | -------------------------------------------------------------------------- |
| `packages/paratix/src/builtins.ts`           | Neues Builtin `firstRun.stop(...)`                                         |
| `packages/paratix/src/index.ts`              | Exportiert `firstRun` im Public API Entry Point                            |
| `packages/paratix/src/types.ts`              | Interner `_stopRun`-Marker in `ModuleResult` und `OrchestrationStep`       |
| `packages/paratix/src/runner.ts`             | Stop-Propagation im Top-Level-Runner, Unterdrückung von Top-Level-Signalen |
| `packages/paratix/src/recipe.ts`             | Stop-Propagation in Recipes, Unterdrückung von Recipe-Signalen             |
| `packages/paratix/src/dryRunRecipe.ts`       | Stop-Verhalten im Dry-Run-Rezeptpfad                                       |
| `packages/paratix/test/builtins.test.ts`     | Tests für `firstRun.stop(...)`                                             |
| `packages/paratix/test/runner.test.ts`       | Regressionen für kontrollierten Run-Stop und Signal-Unterdrückung          |
| `packages/paratix/llm-guide.md`              | Dokumentiert `firstRun.stop(...)` in der API-Referenz                      |
| `packages/create-paratix/src/templates.ts`   | Neue Scaffold-Reihenfolge mit Hardening-Rezepten und First-Run-Stop        |
| `packages/create-paratix/src/index.ts`       | Schreibt zusätzliche Scaffold-Dateien für unattended-upgrades              |
| `packages/create-paratix/test/index.test.ts` | Prüft Reihenfolge, Stop-Einbau und Scaffold-Dateien                        |
| `packages/create-paratix/README.md`          | Erklärt die neue Bootstrap-Staging-Grenze                                  |

## Implementierungsdetails

- `firstRun.stop(...)` erkennt First-Run über `PARATIX_FIRST_RUN === "true"` und zusätzlich `FIRST_RUN === true` im Environment.
- Das Modul ist `local: true` und `_dryRunBlocker: true`, damit es im Dry-Run denselben Staging-Stop modelliert.
- Während eines First-Run liefert `apply()`:
  - `status: "ok"`
  - `_stopRun: true`
  - `_dryRunDetail: "(first-run stop)"`
- Der Runner zählt den Schritt damit nicht als Fehler, bricht aber die restlichen Module ab.
- Das Scaffold ergänzt:
  - `recipe("kernel-hardening", [...sysctl.set(...)])`
  - `recipe("automatic-security-upgrades", [...])`
  - `firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue.")`
  - einen Kommentar-Anker für spätere Dienste unterhalb des Stops
- Das Scaffold schreibt zusätzlich:
  - `files/20auto-upgrades`
  - `files/50unattended-upgrades`

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/builtins.test.ts test/runner.test.ts`
- `pnpm --filter create-paratix exec vitest run test/index.test.ts`
- `pnpm -r --filter './packages/*' exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
