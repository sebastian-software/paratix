# 0095: Live- und End-Laufzeit pro Task in der Paratix-Ausgabe

**Planungsstatus:** Umgesetzt
**Quelle:** /firmo plan
**Empfohlener Workflow:** Feature (`/firmo build`)

## Anforderung

Während `paratix apply` läuft, zeigt jede Modulzeile im interaktiven Terminal einen Spinner mit dem Status `running` (intern der Status `waiting`, gerendert als `running` in `output.ts`). Aktuell fehlt jede Zeitangabe.

Gewünscht:

- Während ein Task läuft, soll neben `running` die bisher vergangene Zeit dieses Tasks live hochgezählt angezeigt werden.
- Nach Abschluss des Tasks soll die verbrauchte Gesamtzeit als statischer Wert in der finalen Ergebniszeile stehen bleiben.

Geklärte Vorgaben (siehe Klärung):

- **Format:** adaptiv. Unter 60 s mit einer Nachkommastelle (z. B. `3.2s`), ab 60 s nur noch sekundengenau als Minuten und Sekunden (z. B. `1m 05s`).
- **Ausgabekanal:** Live-Counter nur im interaktiven TTY; der statische Endwert erscheint in der finalen Zeile in **allen** Ausgaben, also auch in Pipe-/Log-Ausgaben.
- **Schwelle:** Die Zeit wird erst ab einer Laufzeit von 1 s angezeigt. Sehr schnelle Checks (< 1 s, z. B. sofort `ok`) bleiben ohne Zeitangabe.

Es handelt sich um neues, sichtbares Nutzerverhalten in der CLI-Ausgabe – daher Feature.

## Architekturentscheidungen

- **Zeitmessung an den Spinner-Lebenszyklus koppeln.** Jeder Task durchläuft genau `startModuleSpinner(name)` → Arbeit → `printModuleResult`/`printRecipeModuleResult`. Es gibt bewusst nur genau einen aktiven Spinner-Slot gleichzeitig (bestehende Invariante in `output.ts`). Die Startzeit wird daher als einzelnes Feld im geteilten `liveOutputState`-Singleton gehalten (`activeModuleStartedAt: number | null`), passend zur bestehenden Ein-Slot-Semantik.
- **Startzeit unabhängig vom TTY erfassen.** Der Zeitstempel wird am Anfang von `startModuleSpinner` gesetzt, **vor** dem `supportsAnimatedModuleOutput()`-Early-Return. So steht der Endwert auch in nicht-interaktiver Ausgabe (Pipe/Log) zur Verfügung, obwohl dort kein Live-Spinner läuft.
- **Zeitquelle `Date.now()`**, konsistent mit der übrigen Codebase (z. B. `ssh.ts`, `net.ts`, `totp.ts`). Keine neue Abhängigkeit, keine injizierte Uhr; Tests steuern die Zeit über die bereits genutzten Vitest-Fake-Timer.
- **Reine Formatierung getrennt von Seiteneffekten.** Die adaptive Formatierung (`ms` → Anzeigetext oder „nichts“) lebt als pure Funktion in `outputFormatting.ts` neben den vorhandenen reinen Formatter-Helfern; `output.ts` liefert nur `Date.now()` und die Live-Verdrahtung. Das hält die Kernlogik unit-testbar ohne TTY-Setup.
- **Der finale Status-Renderer bleibt die Wahrheit.** Die Zeit ist ein zusätzliches, dimmendes Suffix an der bestehenden Modulzeile und ändert weder Status-Icon, Statuswort noch das bestehende `detail`-Verhalten. Die Zeit wird als eigenes Segment **am Zeilenende, nach dem `detail`** angehängt (im Plan-Review bestätigt).
- **Live-Takt der Nachkommastelle:** Unter 60 s läuft die Zehntelstelle live bei jedem Spinner-Frame (80 ms) mit; Live- und Endformat sind damit identisch (im Plan-Review bestätigt).

## Betroffene Dateien

| Datei                                      | Beschreibung                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/outputFormatting.ts` | Neue pure Funktion `formatModuleElapsed(elapsedMs)` mit adaptivem Format und 1-s-Schwelle (gibt `undefined` unterhalb der Schwelle zurück)                                                                                                                                                                                                                                   |
| `packages/paratix/src/output.ts`           | `activeModuleStartedAt` in `LiveOutputState`/Initialisierung; Zeitstempel-Erfassung am Anfang von `startModuleSpinner`; Helfer `getActiveModuleElapsed()`; optionaler `elapsed`-Parameter in `renderModuleLine`; Live-Einspeisung im Spinner-Intervall und im Erst-Render; Verbrauch der Startzeit in `printRenderedModuleResult`; Zurücksetzen in `resetLiveOutputForTests` |
| `packages/paratix/test/output.test.ts`     | Regressionstests für Live-Counter (ab 1 s), statischen Endwert in TTY und Nicht-TTY, ausgeblendete Zeit unter 1 s, adaptives Format ab 60 s und Reset-Verhalten; Unit-Tests für `formatModuleElapsed`                                                                                                                                                                        |

Kein weiterer Aufrufer musste geändert werden: `runner.ts`, `recipe.ts`, `dryRunRecipe.ts` und `signalOrchestration.ts` rufen bereits `startModuleSpinner` und `printModuleResult`/`printRecipeModuleResult` – sie erben das Verhalten automatisch.

## Implementierungsdetails

### Vorgehen

1. **Formatter (`outputFormatting.ts`).** Neue exportierte Funktion `formatModuleElapsed(elapsedMs: number): string | undefined`:
   - `elapsedMs < 1000` → `undefined` (unter der Schwelle, keine Anzeige).
   - `elapsedMs < 60000` → Sekunden mit einer Nachkommastelle, z. B. `3.2s` (Sekundenwert auf eine Nachkommastelle).
   - sonst → ganze Minuten und sekundengenau, Sekunden zweistellig mit führender Null, z. B. `1m 05s`.
   - Negative oder nicht-endliche Werte defensiv wie „unter Schwelle“ behandeln (`undefined`).
2. **Startzeit erfassen (`output.ts`).** In `startModuleSpinner` als allererste Anweisung `liveOutputState.activeModuleStartedAt = Date.now()` setzen, noch vor dem `supportsAnimatedModuleOutput()`-Guard, damit auch der Nicht-TTY-Pfad die Startzeit kennt.
3. **Live-Anzeige (`output.ts`).** `renderModuleLine` erhält einen optionalen Parameter für den bereits formatierten Elapsed-Text und hängt ihn – falls gesetzt – als dimmendes Suffix am Zeilenende an (nach dem bestehenden `detailSuffix`). Das Spinner-Intervall und der Erst-Render berechnen bei jedem Frame `Date.now() - activeModuleStartedAt` (gekapselt in `getActiveModuleElapsed()`), führen es durch `formatModuleElapsed` und übergeben das Ergebnis. Unterhalb von 1 s liefert der Formatter `undefined`, sodass der Counter erst ab 1 s erscheint und die Zeile davor unverändert nur `running` zeigt.
4. **Endwert (`output.ts`).** In `printRenderedModuleResult` (gemeinsame Basis von `printModuleResult` und `printRecipeModuleResult`) vor dem Zeilenbau `getActiveModuleElapsed()` berechnen, das Suffix an dieselbe Modul-Statuszeile anhängen und anschließend `activeModuleStartedAt = null` setzen, damit der Wert genau einmal verbraucht wird. Das Suffix landet am Ende der Hauptzeile, nicht in den Continuation-/Diff-Zeilen.
5. **Reset (`output.ts`).** `resetLiveOutputForTests` setzt `activeModuleStartedAt` auf `null`, damit Testisolierung keine stehengebliebene Startzeit erbt.

### Anzeigebeispiele

- Laufend (TTY, > 1 s): `⠹  service.restart: app                    running  4.2s`
- Endwert (überall, changed): `↺  service.restart: app                    changed  3.8s`
- Langläufer (≥ 60 s): `↺  download.file: big.iso                  changed  1m 05s`
- Schneller Check (< 1 s): `✓  hostname.set: my-server                  ok` (keine Zeit)

### Edge Cases

- **Ergebniszeile ohne vorausgegangenen `startModuleSpinner`:** Der Verbrauch ist nullsicher; ist `activeModuleStartedAt == null`, wird keine Zeit angezeigt. Alle heutigen Aufrufer von `printModuleResult`/`printRecipeModuleResult` haben zuvor `startModuleSpinner` durchlaufen (regulär, Recipe-Kind, Dry-Run-Kind, Signal, Recipe-Modul); die Invariante ist zusätzlich als Kommentar an `getActiveModuleElapsed` dokumentiert.
- **Verschachtelte Recipe-Module:** Kindmodule überschreiben den Ein-Slot-Startzeitpunkt und verbrauchen ihn bei ihrer eigenen Ergebniszeile. Eine eventuelle spätere Elternzeile findet `activeModuleStartedAt == null` vor und zeigt bewusst keine (sonst irreführende) Zeit. Die je Kindzeile gezeigte Zeit entspricht exakt der Laufzeit dieses Kindes – konsistent zur bestehenden Ein-Spinner-Semantik.
- **Schmales Terminal:** Das Elapsed-Suffix ist Teil der animierten Zeile und unterliegt derselben Breitenkürzung durch `fitAnimatedModuleLine` wie das bestehende `detail`. Bei sehr schmalen Terminals kann es abgeschnitten werden; das ist akzeptiert und verhält sich wie heute beim `detail`.
- **Abgebrochene Läufe (SIGINT vor Ergebniszeile):** Interrupt-Pfade drucken keine Ergebniszeile; die stehengebliebene Startzeit wird vom nächsten `startModuleSpinner` überschrieben und von `printSummary`/`stopLiveModuleOutput` nicht genutzt. Kein sichtbarer Effekt.
- **Live-Cadence der Nachkommastelle:** Unter 60 s aktualisiert sich die Zehntelstelle mit jedem Spinner-Frame (alle 80 ms). Das ist gewollt lebendig und im Plan-Review bestätigt; die Ruckelfreiheit entspricht dem bestehenden Spinner.

### Barrierefreiheit

Rein additive, dimmende Textangabe; keine ausschließlich farbcodierte Information. Der Live-Counter läuft nur im TTY, die statische Zeit steht auch in Log-Ausgaben und Screenreader-freundlichem Plaintext.

## Akzeptanzkriterien

- [x] Läuft ein Modul im TTY länger als 1 s, zeigt die `running`-Zeile eine live hochzählende Zeit, deren Format der adaptiven Regel entspricht (`< 60 s` einstellig-dezimal, `≥ 60 s` als `Xm YYs`).
- [x] Nach Abschluss enthält die finale Modulzeile denselben Zeitwert als statisches, dimmendes Suffix – sowohl im TTY als auch in nicht-interaktiver Ausgabe (Pipe/Log).
- [x] Module mit einer Laufzeit unter 1 s zeigen weder live noch final eine Zeitangabe; ihre Zeilen bleiben gegenüber heute unverändert.
- [x] `formatModuleElapsed` liefert `undefined` für `< 1000 ms`, `X.Xs` für `< 60000 ms` und `Xm YYs` (Sekunden zweistellig) für `≥ 60000 ms`.
- [x] Status-Icon, Statuswort und das bestehende `detail`-Verhalten bleiben unverändert; die Zeit erscheint als zusätzliches Endsuffix der Statuszeile.
- [x] `pnpm agent:check` und die Vitest-Suite für `output` laufen grün.

## Validierungsplan

- Unit-Tests für `formatModuleElapsed` an den Grenzen 999/1000 ms, knapp unter/über 60 s und bei glatten Minuten (zweistellige Sekunden mit führender Null).
- Erweiterung von `packages/paratix/test/output.test.ts`:
  - TTY: `startModuleSpinner`, Zeit per Fake-Timer über 1 s vorschieben, Frame auslösen, assert dass eine Live-Zeile den erwarteten Zeittext neben `running` enthält.
  - TTY: unter 1 s vorschieben, assert dass keine Zeit erscheint.
  - Endwert: nach Zeitvorschub `printModuleResult` aufrufen, assert dass die finale Zeile das Zeitsuffix enthält.
  - Nicht-TTY (`isTTY = false`): assert dass die finale Zeile den statischen Zeitwert dennoch enthält.
  - Adaptiv: Zeit über 60 s vorschieben, assert `Xm YYs`-Format in der finalen Zeile.
  - Reset: `resetLiveOutputForTests` löscht die Startzeit (kein Zeit-Leak in Folgetest).
- Ausführung: `pnpm --filter paratix exec vitest run test/output.test.ts` und `pnpm agent:check`.

## Testergebnisse

**Datum:** 2026-07-10

- `pnpm agent:check` grün (EXIT 0): oxlint + eslint, `prettier --check`, Typecheck (root + packages inkl. `tsconfig.typecheck.json`), Build und alle Tests.
- `packages/paratix/test/output.test.ts`: 58 Tests grün (40 bestehend + 18 neu).
  - 9 Unit-Tests für `formatModuleElapsed`: Schwelle 999/1000 ms, `3200`→`3.2s`, `59900`→`59.9s`, `60000`→`1m 00s`, `65300`→`1m 05s`, negativ/`NaN`/`Infinity`→`undefined`.
  - 9 Integrationstests: Live-Counter über/unter 1 s im TTY, statischer Endwert im TTY und im Nicht-TTY-Pfad, adaptives `Xm YYs`-Format ≥ 60 s, Einmal-Verbrauch der Startzeit bei aufeinanderfolgenden Ergebniszeilen ohne erneutes `startModuleSpinner`, Reset via `resetLiveOutputForTests`.

## Review-Findings

**Datum:** 2026-07-10
**Reviewer:** nodejs-reviewer

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      2 |
| Offen / Nicht umgesetzt |      4 |

Kritisch 0, Wichtig 0, Hinweis 6. Behoben im Workflow: Invarianten-Kommentar an `getActiveModuleElapsed` (jede Ergebniszeile hat einen vorausgehenden `startModuleSpinner`) und TSDoc-Hinweis zum frame-unabhängigen Endwert in `formatModuleElapsed`. Die vier verbleibenden Hinweise sind bewusst nicht umgesetzt (optionale Test-/Doku-Verbesserungen ohne Produktivbezug) und im externen Report festgehalten.

**Externer Review-Report:** `.firmo/review/review-report-2026-07-10-plan-paratix-live-task-elapsed-time.md`

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       2 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       0 |       0 |
| Scope       |        0 |       0 |       2 |
| Wartbarkeit |        0 |       0 |       0 |

### Befunde

- Hinweis (Architektur): Die Ein-Slot-Startzeit spiegelt die bestehende Ein-Spinner-Invariante wider. Sollte künftig echte Parallelität mehrerer Spinner eingeführt werden, müsste die Startzeit pro Spinner statt im Singleton gehalten werden. Für den heutigen Stand korrekt und bewusst minimal gehalten.
- Hinweis (Fehlerfälle): Der Verbrauch der Startzeit (`= null` nach der Ergebniszeile) verhindert doppelte oder irreführende Zeitanzeigen bei Recipe-Elternzeilen; die Nullsicherheit deckt Aufrufe ohne vorherigen Spinner ab.
- Hinweis (Scope, entschieden): Platzierung des Zeit-Suffix im vertieften Review geklärt – am Zeilenende nach dem `detail`. In Architekturentscheidungen und Anzeigebeispielen fixiert.
- Hinweis (Scope, entschieden): Live-Takt der Nachkommastelle im vertieften Review geklärt – Zehntel laufen pro Spinner-Frame (80 ms) mit. In Architekturentscheidungen und Edge Cases fixiert.
- Hinweis (Logik): Das adaptive Format ab 60 s trägt kein Stunden-Segment; sehr lange Laufzeiten erscheinen als wachsende Minutenzahl. Als bewusste Annahme dokumentiert, kein Umsetzungsblocker.

## Annahmen und offene Punkte

- **Entschieden (Plan-Review):** Die Zeit wird als Endsuffix nach dem `detail` platziert (z. B. `changed  (dry-run)  3.8s`).
- **Entschieden (Plan-Review):** Die Zehntelstelle unter 60 s läuft live pro Spinner-Frame (80 ms) mit; Live- und Endformat sind identisch.
- **Annahme:** `startModuleSpinner` ist für jeden Task der eindeutige Startpunkt der Messung; die Zeit misst die gesamte Task-Dauer (Check plus ggf. Apply) bis zur Ergebniszeile.
- **Annahme:** Läuft ein Modul länger als 60 Minuten, wächst die Minutenzahl unbegrenzt (z. B. `72m 03s`); ein Stunden-Segment ist bewusst nicht vorgesehen, da Task-Laufzeiten in diesem Bereich untypisch sind.

## Offene Punkte

- Keine offenen Punkte.
