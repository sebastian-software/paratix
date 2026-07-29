# 0093: CLI-Recipe-Filter

**Planungsstatus:** Umgesetzt
**Quelle:** /plan
**Empfohlener Workflow:** Feature (`/build`)

## Anforderung

Der `paratix apply`-Befehl soll einen neuen Filter-Parameter erhalten, mit dem sich
ein Lauf auf einzelne, namentlich benannte Knoten (Receips oder Module) beschränken
lässt. Alle nicht ausgewählten Knoten werden **übergangen**, aber weiterhin in der
Terminal-Ausgabe angezeigt – mit dem bereits vorhandenen `skipped`-Status (Symbol
`⊘`, dimmed).

Beispiel:

```
paratix apply server.ts --filter rybbit,palamedes-examples
```

führt ausschließlich die Receips `rybbit` und `palamedes-examples` aus. `base-setup`
und die übrigen Services innerhalb von `service-layer` werden als `skipped`
markiert dargestellt, aber nicht ausgeführt.

Die Empfehlung lautet **Feature (`/build`)**, weil neues, vom Nutzer sichtbares
CLI-Verhalten (ein neues Flag mit eigener Ausführungs- und Anzeige-Semantik)
hinzukommt.

### Geklärte Entscheidungen (aus der Rückfrage)

1. **Flag-Syntax:** `--filter <names>` mit kommaseparierter Liste, zusätzlich
   wiederholbar (`--filter a,b` **und** `--filter a --filter b`).
2. **Match-Ziel:** Namen matchen **jeden Knoten** (Receips wie einzelne Module).
   In ein nicht getroffenes Receip wird abgestiegen, wenn es ein getroffenes Kind
   (in beliebiger Tiefe) enthält.
3. **Skip-Anzeige:** **kompakt** – ein übergangener Knoten wird als genau eine
   `skipped`-Zeile gezeigt, ohne seine Kinder aufzuklappen.
4. **Kein Treffer:** Enthält der Filter einen Namen, der auf keinen Knoten passt,
   bricht der Lauf **vor** dem SSH-Connect mit klarer Fehlermeldung und Exit-Code
   `2` ab.

## Architekturentscheidungen

- **Umsetzung als Baum-Transformation vor dem Lauf, nicht als Filter-Threading
  durch die Ausführungs-Hot-Loops.** Der Filter wird in einem neuen Modul
  `moduleFilter.ts` als reine Transformation über `definition.run` umgesetzt:
  ausgewählte Teilbäume bleiben unverändert, übergangene Knoten werden durch ein
  synthetisches „Skip-Modul" ersetzt, teil-getroffene Receips werden mit
  gefilterten Kindern neu aufgebaut. Begründung: Der `skipped`-Status ist in
  `RunStats` (`runner.ts`) und im Output-Layer (`output.ts`: `STATUS_ICONS`,
  `getModuleStatusText`, `printSummary`) **bereits vollständig vorhanden**, wird
  aber bisher nie emittiert. Dadurch bleiben `runner.ts`, `recipe.ts`,
  `dryRunRecipe.ts` und `output.ts` unverändert; die gesamte Kern-Orchestrierung
  (SSH-Lifecycle, Signale, Shutdown, Meta-Propagation) wird nicht angefasst.
  Verworfene Alternative: Einen `filter`-Kontext plus „ancestorSelected"-Flag
  durch `runModuleLoop`, `recipe.executeModules` **und** die separate
  `dryRunRecipe`-Schleife zu fädeln – deutlich invasiver, dupliziert die
  Selektionslogik über zwei parallele Ausführungspfade und berührt die
  empfindliche Signal-/Shutdown-Maschinerie.

- **Skip-Modul-Verhalten.** Das synthetische Skip-Modul ist ein `local`-Modul,
  dessen `check()` immer `"needs-apply"` liefert und dessen `apply()` (sowie
  `_applyDryRun`) ohne Seiteneffekt `{ status: "skipped" }` zurückgibt. `check()`
  muss `"needs-apply"` liefern, damit ein neu aufgebautes „Descend"-Receip die
  Kurzschluss-Optimierung in `runRecipeModule` (bei `check() === "ok"` wird
  `apply()` übersprungen) **nicht** auslöst und seine Kinder – inklusive der
  Skip-Zeilen – tatsächlich rendert. Für den Dry-Run trägt das Skip-Modul den
  Marker `_dryRunBlocker: true` und ein `_applyDryRun`, damit
  `shouldExecuteApplyDuringDryRun` (`dryRunDispatch.ts`) es auch im Dry-Run als
  `skipped` statt als `changed (dry-run)` darstellt.

- **Neuaufbau nur für teil-getroffene Receips.** Vollständig ausgewählte
  Teilbäume werden per Referenz unverändert übernommen (kein Neuaufbau, kein
  Risiko). Nur ein Receip, das selbst nicht getroffen ist, aber ein getroffenes
  Kind enthält, wird via `recipe(name, gefilterteKinder, { signals: _signals })`
  neu erzeugt; die Dry-Run-Marker werden dabei durch `recipe()` korrekt aus den
  transformierten Kindern neu abgeleitet. Die ursprünglichen Signale des Receips
  (`_signals`) werden übernommen.

- **Nicht-Receip-Composite-Module** (Module mit `_supportsChildStepHook`, aber
  ohne `_isRecipe`/`_modules`) werden für den Filter als Blattknoten behandelt:
  über den Namen treffbar oder übersprungen, aber es wird nicht in sie
  abgestiegen. Nur `RecipeModule`-Knoten (`_isRecipe === true`) exponieren
  `_modules` und sind Abstiegspunkte.

- **Platzierung der Validierung im CLI, vor dem Connect.** Parsing, Namens-
  Validierung und Transformation laufen in `cli.ts` (`runApplyCommand`), nachdem
  die Server-Definition geladen wurde, aber bevor `runPlaybook` verbindet. So
  entsteht der „Kein Treffer"-Fehler ohne SSH-Verbindung. `runPlaybook` und die
  öffentliche Bibliotheks-API bleiben unverändert.

## Betroffene Dateien

| Datei                                         | Beschreibung                                                                                                                                                                                         |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/moduleFilter.ts`        | **Neu.** Filter-Kernlogik: Namen-Sammlung, Subtree-Match, Skip-Modul-Fabrik, Baum-Transformation.                                                                                                    |
| `packages/paratix/src/cli.ts`                 | `--filter`-Option (variadisch, kommasepariert, wiederholbar), Parser/Sammler, Verdrahtung in `ApplyCommandOptions`/`runApplyCommand`, Validierung + Transformation der `definition.run` vor `run()`. |
| `packages/paratix/src/recipe.ts`              | Keine Verhaltensänderung; nur Import von `recipe` durch `moduleFilter.ts` (bestehender Export wird wiederverwendet).                                                                                 |
| `packages/paratix/test/module-filter.test.ts` | **Neu.** Unit-Tests der Transformations- und Match-Logik.                                                                                                                                            |
| `packages/paratix/test/cli.test.ts`           | Ergänzung: Parsing/Validierung des `--filter`-Flags, Fehlerfall „kein Treffer".                                                                                                                      |
| `packages/paratix/README.md`                  | Dokumentation des neuen Flags im CLI-/Flags-Abschnitt (analog zu `--diff`, `--first-run`).                                                                                                           |

## Implementierungsdetails

### Vorgehen

1. **`moduleFilter.ts` anlegen** mit folgender Schnittstelle (englische Bezeichner):
   - `parseFilterNames(rawValues: string[]): string[]` – zerlegt die (bereits
     durch Commander gesammelten) Rohwerte an Kommas, trimmt, entfernt leere
     Einträge, dedupliziert unter Erhalt der Reihenfolge.
   - `collectModuleNames(modules: Module[]): Set<string>` – sammelt rekursiv alle
     Knotennamen (Receips **und** Blattmodule) über `_modules` der
     `RecipeModule`-Knoten. Dient der Validierung.
   - `subtreeHasFilterMatch(module: Module, filter: Set<string>): boolean` – `true`,
     wenn der Knoten selbst oder ein Nachfahre (rekursiv über `_modules`)
     namentlich im Filter liegt.
   - `createSkipModule(name: string): Module` – synthetisches Skip-Modul mit der
     oben beschriebenen Semantik.
   - `applyModuleFilter(modules: Module[], filter: Set<string>): Module[]` – bildet
     jeden Knoten über die Selektionsregel ab (siehe unten).
   - `validateFilterNames(names: string[], available: Set<string>): void` –
     wirft einen typisierten Fehler (`CliUsageError` aus `cli.ts` oder ein neuer,
     in `cli.ts` gefangener Fehlertyp) mit den unbekannten Namen; Exit-Code `2`.
2. **Selektionsregel** in `applyModuleFilter`, pro Knoten mit dem Kontext
   `ancestorSelected` (Start: `false`):
   - `selfSelected = ancestorSelected || filter.has(node.name)`.
   - `selfSelected` → Knoten unverändert übernehmen (ganzer Teilbaum läuft; für
     Receips laufen alle Kinder mit `ancestorSelected = true`).
   - sonst, wenn `isRecipe(node)` und `subtreeHasFilterMatch(node, filter)` →
     „Descend": Receip neu aufbauen mit
     `applyModuleFilter(node._modules, filter)` (weiterhin `ancestorSelected =
false`) und `{ signals: node._signals }`.
   - sonst → `createSkipModule(node.name)`.
3. **`cli.ts` erweitern:**
   - Neue Option `--filter <names...>` (Commander-variadisch) mit einem
     Sammler-Parser analog zu `collectEnvironment`, der Rohwerte akkumuliert.
   - `ApplyCommandOptions` um `filter?: string[]` ergänzen und im `.action`-Handler
     durchreichen.
   - In `runApplyCommand` **nach** `loadServerDefinitionFromFile` und **vor**
     `run(definition, runOptions)`: falls Filter gesetzt, `parseFilterNames`,
     dann `collectModuleNames(definition.run)`, `validateFilterNames(...)`, dann
     `const runModules = applyModuleFilter(definition.run, new Set(names))` und
     `run({ ...definition, run: runModules }, runOptions)`.
   - Der bestehende `try/catch` im `.action`-Handler routet `CliUsageError` bereits
     über `exitAfterApplyError` zu einer sauberen Meldung ohne Stacktrace; den
     „kein Treffer"-Fehler denselben Pfad nehmen lassen.
4. **Reihenfolge/No-Op-Fall:** Ist `--filter` nicht gesetzt, bleibt `definition.run`
   unverändert und es ändert sich nichts am bisherigen Verhalten.

### Komponenten-Struktur

Nicht relevant – reine CLI-/Backend-Logik ohne UI-Komponenten.

### State-Management

Nicht relevant – die Transformation ist zustandslos und rein funktional; sie
mutiert weder `definition` noch die Modulobjekte, sondern liefert ein neues
`run`-Array.

### API-Anbindung

- Wiederverwendete interne Signaturen: `Module`, `RecipeModule` (`_isRecipe`,
  `_modules`, `_signals`), `recipe()` aus `recipe.ts`, `isRecipe`-Prädikat
  (bereits in `runner.ts` vorhanden – bei Bedarf als Helfer nach `moduleFilter.ts`
  duplizieren oder aus einer gemeinsamen Stelle exportieren; kleiner, lokaler
  `_isRecipe`-Check bevorzugt, um Zyklen zu vermeiden).
- Der `skipped`-Status ist bereits Teil von `ModuleStatus`, `RunStats.update`,
  `STATUS_ICONS`, `getModuleStatusText` und `printSummary` – keine Änderung nötig.

### Styling-Ansatz

Nicht relevant.

### Barrierefreiheit

Nicht relevant (CLI). Die `skipped`-Ausgabe nutzt zusätzlich zum dimmed-Farbcode
das Symbol `⊘` und das Textlabel `skipped`, ist also nicht rein farbabhängig.

### Edge Cases

- **Filter nicht gesetzt:** unverändertes Verhalten (kein Skip, keine Validierung).
- **Kommasyntax + Wiederholung gemischt:** `--filter a,b --filter c` ergibt
  `[a, b, c]`; Duplikate werden dedupliziert.
- **Leere/whitespace-Einträge** (`--filter "a,,b"`, `--filter " "`): werden beim
  Parsen entfernt; ergibt der Filter nach dem Trimmen **keinen** Namen, wird das
  als „kein Treffer" behandelt (Fehler, Exit 2), damit kein stiller Nichts-Lauf
  entsteht.
- **Unbekannter Name:** Fehler mit Auflistung **aller** nicht getroffenen Namen,
  Exit 2, vor dem Connect.
- **Filter trifft nur tiefe Knoten:** Top-Level-`run`-Array behält seine Länge
  (Skip-Module ersetzen übersprungene Knoten), wird also nie leer – die
  `allowEmptyRun`-Validierung in `runPlaybook` bleibt unberührt.
- **Parent und Kind gleichzeitig im Filter** (`service-layer,rybbit`): Parent ist
  selektiert → ganzer Teilbaum läuft; das zusätzliche Kind ist redundant, aber
  gültig.
- **Doppelte Knotennamen im Baum:** ein Filtername trifft alle gleichnamigen
  Knoten (dokumentiertes Verhalten).
- **Dry-Run + Filter:** Skip-Module rendern dank `_dryRunBlocker` + `_applyDryRun`
  auch unter `--dry-run` als `skipped`.
- **Signale:** übersprungene Knoten liefern `skipped` (nicht `changed`) und lösen
  daher weder Receip- noch Top-Level-Signale aus – gewünschtes Verhalten, keine
  Sonderbehandlung nötig.
- **`_stopRun` / Exit-Code:** `skipped` setzt kein `shouldBreak` und beeinflusst
  `resolveExitCode` (nur `failed`-getrieben) nicht.
- **Nicht-Receip-Composite-Modul im Filterpfad:** wird als Blatt behandelt; ist
  es nicht direkt benannt, wird es (samt seiner internen Kinder) als eine
  `skipped`-Zeile dargestellt.

## Akzeptanzkriterien

- [ ] `paratix apply <file> --filter rybbit,palamedes-examples` führt ausschließlich
      die Knoten `rybbit` und `palamedes-examples` aus; alle übrigen Top-Level-
      und `service-layer`-Kinder erscheinen als je eine `skipped`-Zeile und werden
      nicht ausgeführt.
- [ ] `--filter` akzeptiert sowohl kommaseparierte Werte als auch mehrfaches
      Angeben und kombiniert beide zu einer deduplizierten Namensliste
      (verifiziert durch Unit-Test der Parser-Funktion).
- [ ] Ein Filtername, der auf keinen Knoten des geladenen Baums passt, führt zu
      Exit-Code `2` mit einer Fehlermeldung, die den/die unbekannten Namen nennt,
      **ohne** dass ein SSH-Connect versucht wird (verifiziert durch CLI-Test mit
      gemocktem `run`).
- [ ] Die Zusammenfassungszeile zählt übersprungene Knoten korrekt unter
      `N skipped` (verifiziert durch Transformations-/Stats-Test).
- [ ] In ein nicht benanntes Receip wird abgestiegen, wenn es ein benanntes Kind
      enthält; enthält es keins, wird es als einzelne `skipped`-Zeile dargestellt
      (verifiziert durch `applyModuleFilter`-Unit-Test auf einem verschachtelten
      Baum).
- [ ] Ohne `--filter` bleibt `definition.run` referenz-identisch bzw. verhaltens-
      gleich (keine Regression; verifiziert durch bestehende Runner-Tests).
- [ ] `pnpm agent:check` (Lint, Typecheck, Tests, Build) läuft grün.

## Validierungsplan

- **Unit-Tests `module-filter.test.ts`:**
  - `parseFilterNames` – Komma-Split, Trim, Dedup, Reihenfolge, leere Einträge.
  - `collectModuleNames` – rekursive Sammlung über verschachtelte Receips.
  - `subtreeHasFilterMatch` – Treffer in Tiefe > 1.
  - `applyModuleFilter` – erzeugt Skip-Module für nicht getroffene Knoten, baut
    Descend-Receips mit Teilmenge der Kinder neu, übernimmt selektierte Teilbäume
    per Referenz.
  - Skip-Modul – `check()` liefert `"needs-apply"`, `apply()`/`_applyDryRun`
    liefern `{ status: "skipped" }`, `local === true`.
- **CLI-Test-Ergänzung `cli.test.ts`:**
  - Flag-Parsing (kommasepariert + wiederholt).
  - „Kein Treffer" → Exit `2`, Fehlermeldung, `run` wird nicht aufgerufen
    (gemockte `RunPlaybookFunction`).
  - Gesetzter Filter → `run` erhält eine Definition, deren `run` die erwarteten
    Skip-/Selektions-Knoten enthält.
- **Manuelle Prüfung** (optional, gegen einen realen/gemockten Playbook-Baum):
  Ausgabe zeigt `⊘ ... skipped`-Zeilen kompakt, `[service-layer]`-Header bleibt
  sichtbar, ausgewählte Receips laufen normal, Summary-Zeile stimmt.
- **Regression:** `pnpm agent:check` inklusive der bestehenden Runner-, Recipe-
  und Dry-Run-Tests.

## Annahmen und offene Punkte

- **Annahme:** Der Filter wird nur für den `apply`-Befehl benötigt; es gibt aktuell
  keinen weiteren Unterbefehl, der ihn bräuchte.
- **Annahme:** „Kompakte" Skip-Anzeige bedeutet, dass ein übersprungenes Receip als
  **eine** Zeile ohne Kinder erscheint; ein teil-getroffenes Receip zeigt dagegen
  seinen Header und darunter die gemischten `skipped`/aktiven Kinder.
- **Annahme:** Für ein neu aufgebautes Descend-Receip sollen dessen Signale
  erhalten bleiben und feuern, wenn eines seiner ausgeführten Kinder `changed`
  liefert. (Bei Bedarf leicht umkehrbar, indem `_signals` beim Neuaufbau
  weggelassen wird.)
- **Offen (bewusst als Annahme dokumentiert):** Kein Alias `--only`; es bleibt bei
  `--filter`. Ein späterer Alias wäre additiv und nicht Teil dieses Plans.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       0 |       0 |
| Scope       |        0 |       0 |       0 |
| Wartbarkeit |        0 |       1 |       0 |

### Befunde

- **Architektur (Hinweis):** Das `isRecipe`/`_isRecipe`-Prädikat existiert bereits
  in `runner.ts` und `recipe.ts` (`isRecipeModuleLike`). In `moduleFilter.ts` wird
  ein schlanker lokaler `_isRecipe === true`-Check bevorzugt, um zusätzliche
  Modul-Kopplung/Importzyklen zu vermeiden; eine spätere Konsolidierung in einen
  gemeinsamen Helfer ist optional.
- **Fehlerfälle (Hinweis):** Der „kein Treffer nach Trimmen"-Fall (nur leere/
  whitespace-Werte) wird bewusst wie ein unbekannter Name behandelt (Fehler,
  Exit 2), um einen stillen Nichts-Lauf auszuschließen. In den Edge Cases und
  Akzeptanzkriterien abgedeckt.
- **Wartbarkeit (Wichtig):** Der Neuaufbau eines Descend-Receips über `recipe()`
  hängt an den internen Feldern `_modules` und `_signals` der `RecipeModule`-
  Struktur. Diese Kopplung an interne Marker wird in `moduleFilter.ts` an genau
  einer Stelle gebündelt und über den `applyModuleFilter`-Unit-Test abgesichert,
  sodass eine künftige Änderung der Recipe-Interna dort sofort auffällt. Bewusst
  eingegangen, weil die Alternative (Filter-Threading durch die Ausführungspfade)
  eine deutlich größere und riskantere Kopplung an die Runner-/Signal-Interna
  bedeutet.

## Testergebnisse

**Datum:** 2026-07-05
**Kommando:** `pnpm agent:check` (lint oxlint + eslint, format:check, typecheck, build, test)

- Ergebnis: **grün** (Exit-Code 0).
- paratix: 101 Test-Dateien, 3901 Tests bestanden (inkl. der neuen Filter-Tests); zusätzlicher Post-Build-Distributionslauf 9 Tests grün.
- create-paratix: 256 + 6 Tests grün (unverändert).
- Neue Tests:
  - `packages/paratix/test/module-filter.test.ts` — 19 Fälle: `parseFilterNames` (Split/Trim/Dedup/leer), `collectModuleNames` (rekursiv), `subtreeHasFilterMatch` (Tiefe), `createSkipModule` (apply/check/dry-run), `applyModuleFilter` (Skip/Descend/Referenz-Erhalt/Länge/Signale, mehrstufiger Descend auf tiefes Blatt) und zwei End-to-End-`runPlaybook`-Läufe (Apply zählt Top-Level-Skip in der Summary; Dry-Run rendert verschachtelten Skip mit „filtered out").
  - `packages/paratix/test/cli.test.ts` — `collectFilter`, `resolveFilteredRun` (No-Op, Transform, unbekannter Name → `CliUsageError`/Exit 2, nur-Whitespace → Fehler) sowie `runApplyCommand --filter` (Abbruch vor Connect bei unbekanntem Namen; gefilterte Definition an den Runner).

## Review-Findings

**Datum:** 2026-07-05
**Reviewer:** sf-nodejs-reviewer

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      3 |
| Offen / Nicht umgesetzt |      2 |

Behoben: F1 (Testlücke → zwei Tests ergänzt), F2 (Namenskollisions-Doku → README), F4 (Summary-Zählungs-Doku → README). Keine kritischen oder wichtigen Findings offen; die beiden verbleibenden Hinweise (F3 Performance-Mikrooptimierung, F5 Terminal-Sanitisierung der CliUsageError-Meldung) sind bewusst nicht umgesetzt und mit Begründung ausgelagert.

**Externer Review-Report:** `.sf-plugin/review/review-report-2026-07-05-plan-0093.md`
