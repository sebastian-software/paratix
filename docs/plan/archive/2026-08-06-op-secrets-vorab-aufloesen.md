# 1Password-Secrets zu Lauf-Beginn vorab auflösen

**Planungsstatus:** Umgesetzt
**Quelle:** /effective-flow plan
**Empfohlener Workflow:** Feature (`/effective-flow build`)

## Anforderung

Heute ruft `op.resolve(...)` die 1Password-CLI erst auf, wenn der Runner das Modul an seiner Position in `run` erreicht (`packages/paratix/src/modules/op.ts:431`). Der biometrische Unlock erscheint damit irgendwann mitten im Lauf — nach dem SSH-Connect, oft nach mehreren bereits ausgeführten Tasks, und im schlechtesten Fall erst dann, wenn der Nutzer das Terminal längst verlassen hat.

Ziel: **Alle `op read`-Aufrufe eines Laufs passieren gebündelt am Anfang**, vor dem SSH-Connect. Der Nutzer erlebt die Interaktion (Biometrie / `op signin`) sofort nach dem Kommando-Aufruf. Im weiteren Verlauf werden ausschließlich die bereits gelesenen Werte verwendet — kein weiterer CLI-Aufruf, kein weiterer Prompt.

Für OTP-Referenzen bleibt die Trennung erhalten, die es heute schon gibt: die `otpauth://`-URI (der Seed) wird **einmalig vorab** gelesen, die eigentliche TOTP-Code-Berechnung bleibt **lazy** pro Zugriff. Da der Seed dann bereits im Speicher liegt, braucht die Lazy-Hälfte weder Biometrie noch sonstige Nutzerinteraktion.

Begründung der Workflow-Empfehlung: Es entsteht neue Funktionalität — eine neue Vorab-Phase im Runner, ein neuer interner Hook im `Module`-Kontrakt und ein neuer lauf-gebundener Cache. Das beobachtbare Verhalten (Zeitpunkt des Prompts, Fail-Fast statt Modul-Fehler) ändert sich absichtlich. Das ist ein Feature, kein Bugfix und kein reines Refactoring.

## Architekturentscheidungen

- **Neuer interner Hook `_prewarmSecrets` im `Module`-Kontrakt.** Optionales Feld `_prewarmSecrets?: () => Promise<void>` in `packages/paratix/src/types.ts` (Module-Typ ab Zeile 189). Es folgt der etablierten Konvention der internen `_`-Marker (`_dryRunMetaProducer`, `_dryRunBlocker`, `_supportsChildStepHook`) und bleibt optional, damit bestehende eigene Module quellkompatibel bleiben. Der Hook ist bewusst generisch formuliert („Secrets vorwärmen"), nicht 1Password-spezifisch — ein späterer Secret-Provider (Vault, SOPS, …) kann ihn ohne Runner-Änderung nutzen.

- **Ein zentraler Walker in neuer Datei `packages/paratix/src/secretPrewarm.ts`.** Sie enthält drei Dinge: den ALS-gebundenen Referenz-Cache, den Baum-Walk und die von `op.ts` genutzte Memo-Funktion. Die Datei importiert nur `types.ts` und `recipeGuard.ts` — beide sind zyklusfrei erreichbar (`recipeGuard.ts` importiert `recipe.ts` nur als Typ, siehe die dortige Begründung in Zeile 14–18).

- **Rekursion über Recipes via `isRecipe` — über `_modules` und `_signals`.** `RecipeModule` hält beide Listen (`recipe.ts:39-41`, gesetzt in `recipe.ts:600-601`). Der Walk ist damit bewusst **weiter** als `collectModuleNames` (`moduleFilter.ts:46-55`) und `dryRunRecipe.ts:255`, die beide nur `_modules` betrachten: ein `op.resolve` in den Signal-Handlern eines Recipes würde sonst mitten im Lauf prompten — genau der Fall, für den `definition.signals` bereits eingeplant ist. `moduleFilter.ts:132-133` reicht `_signals` beim Filtern unverändert durch, die Liste überlebt also `--filter` und ist auf beiden Seiten des Trägervergleichs sichtbar.

- **Drei Orte halten Kindmodule, und nur drei.** Verifiziert: `recipe()` über `_modules`/`_signals`, `createConditionalModule` über eine Closure, und `ServerDefinition.signals`. `builtins.ts`, `conditionalExecution.ts`, `dryRunRecipe.ts`, `signalOrchestration.ts` und `signalBus.ts` halten keine eigenen Kinder, sondern bekommen Modullisten als Aufrufparameter. `_supportsChildStepHook` ist **kein** Kind-Marker: er sitzt sowohl auf Recipes (Kinder sichtbar) als auch auf Guard-Blöcken (Kinder unsichtbar) und taugt nicht zur Erkennung. Damit ist die Abdeckung des Walks vollständig belegt, nicht vermutet.

- **`when(...)` öffnet sich per Hook, nicht per öffentlichem Feld.** `createConditionalModule` (`packages/paratix/src/conditionalModules.ts:49`) implementiert `_prewarmSecrets` und delegiert an `parameters.modules`. Die Kinder bleiben damit in der Closure gekapselt; es entsteht keine neue öffentliche `_modules`-Fläche für Guard-Blöcke.

- **Vollständigkeit vor Sparsamkeit bei Guards.** Die Guard-Bedingung wird remote ausgewertet und ist vor dem SSH-Connect nicht bekannt. Ein `op.resolve` in einem `when(...)`-Zweig, dessen Bedingung später `false` ergibt, wird also aufgelöst, obwohl der Wert nicht gebraucht wird. Das ist der bewusste Preis dafür, dass kein Prompt mitten im Lauf auftauchen kann.

- **`--filter` wird ohne Zusatzarbeit respektiert.** `runApplyCommand` reicht bereits die gefilterte Definition an `runPlaybook` weiter (`packages/paratix/src/cli.ts:778-793`), und herausgefilterte Knoten sind `createSkipModule`-Platzhalter (`moduleFilter.ts:86`) ohne `_prewarmSecrets`. Ein ausgefiltertes `op.resolve` löst damit automatisch nichts auf. Neu ist lediglich eine Warnung im Filterpfad, die diesen Wegfall sichtbar macht (Vorgehen, Schritt 9); das Laufverhalten bleibt unverändert.

- **Lauf-gebundener Referenz-Cache über `AsyncLocalStorage`.** Key ist die vollständige `op://`-Referenz, Value ein `Promise<string>` mit dem **nachverarbeiteten** Wert — dem zeilenumbruch-bereinigten Secret bzw. der getrimmten `otpauth://`-URI. Genau dieser String wird auch im Secret-Sink registriert; ein roher Stdout im Cache würde die Maskierung ins Leere laufen lassen (siehe Vorgehen, Schritt 4). Gleiche Bauart wie `runScopedSecretCounts` (`packages/paratix/src/secretSink.ts:32`) und `runnerAbortSignalStorage` (`runnerAbortSignal.ts:24`), damit parallele `runPlaybook`-Aufrufe im selben Prozess sich nicht vermischen (Motivation identisch zu R-0000743). Ein abgelehntes Promise wird aus dem Cache entfernt, analog zu `createMemoizedEnvironmentResolver` (`meta.ts:278-318`).

- **`op.apply()` bleibt der einzige Meta-Produzent.** Die Vorab-Phase füllt nur den Cache; das Modul läuft weiterhin an seiner Position in `run`, ruft dieselbe Auflösungsfunktion auf, bekommt den gecachten Wert und gibt wie bisher `meta: environmentToMetaEntries(...)` zurück (`op.ts:449-452`). Der bestehende Meta-Merge-Pfad (`meta.ts:320`) bleibt damit vollständig unberührt — das ist die risikoärmste Variante.

- **Ohne aktiven Cache-Scope verhält sich `op.resolve` exakt wie heute.** Wer `op.resolve(...).apply(...)` direkt aufruft (Bibliotheksnutzung, bestehende Unit-Tests), löst weiterhin unmittelbar auf und bekommt bei Fehlern `failed(...)`. Der Cache ist eine Beschleunigung, keine Vorbedingung.

- **Platzierung im Runner: nach `printRunContext`, vor `connectAndRegister`.** Also zwischen `runner.ts:1310` und `runner.ts:1314`, innerhalb des `withRunnerAbortSignal`-Scopes (`runner.ts:1302`). Damit sieht der Pre-Spawn-Abort-Check in `op.ts:207` das Signal, und ein Strg-C während des Biometrie-Prompts beendet den `op`-Child sauber statt ihn hängen zu lassen.

- **`withRunScopedSecrets` wird hochgezogen.** Sie umschließt künftig Vorab-Phase, Connect und `executeRun` statt nur `executeRun` (heute `runner.ts:1325`). Ohne das wäre `registerRunScopedSecret` in der Vorab-Phase ohne Store und die Registrierung damit unbalanciert (`secretSink.ts:87-91`). Die Helper ist re-entrant (`secretSink.ts:181-183`), der bestehende innere Aufruf in `op.apply` (`op.ts:432`) bleibt deshalb korrekt und wird nicht angefasst.

- **Fail-Fast statt Modul-Fehler in der Vorab-Phase.** Ein Fehlschlag (op-CLI fehlt, nicht angemeldet, Timeout, abgebrochene Biometrie) wird als `Error` geworfen, nicht als `failed(...)` zurückgegeben. Er läuft durch `rethrowIfNotShutdown` (`runner.ts:1339`) und die CLI-Fehlerbehandlung (`cli.ts:796`) zu Exit-Code 2. Genau darin liegt der Nutzen der Vorverlagerung: Auth-Probleme zeigen sich, bevor eine SSH-Verbindung aufgebaut oder irgendein Task ausgeführt wurde.

- **Sequenzielle Auflösung bleibt.** Die Vorab-Phase löst Referenzen nacheinander auf, wie heute (`op.ts:300`, `op.ts:359`). Parallele `op read`-Aufrufe würden mehrere Biometrie-Prompts überlagern und den Nutzen zunichtemachen.

- **`definition.signals` wird mitgelaufen.** Signal-Handler sind ebenfalls `Module[]` (`types.ts:443`) und laufen im selben Lauf; ein `op.resolve` dort würde sonst wieder mitten im Lauf prompten.

- **Dry-Run bleibt eingeschlossen.** `_dryRunMetaProducer: true` (`op.ts:430`) bleibt unverändert; die Vorab-Phase läuft auch bei `--dry-run`, damit nachgelagerte Module im Dry-Run dieselbe Umgebung sehen wie im echten Lauf und der Dry-Run ein echter Vorab-Test inklusive 1Password-Auth bleibt.

- **Nicht-Ziel: `ssh.sudoPassword` aus `op.resolve` speisen.** Anti-Pattern 16 im LLM-Guide bleibt gültig. `SshConfig` wird zum `server()`-Konstruktionszeitpunkt eingefroren, die Vorab-Phase läuft erst innerhalb von `runPlaybook`. Die Vorverlagerung ändert daran nichts und darf nicht als Lösung dafür dokumentiert werden.

## Betroffene Dateien

| Datei                                                      | Beschreibung                                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `packages/paratix/src/secretPrewarm.ts`                    | Neu: ALS-Cache-Scope, Baum-Walk über `run` + `signals`, Memo-Funktion für Referenz-Auflösung                       |
| `packages/paratix/src/types.ts`                            | Neues optionales Feld `_prewarmSecrets` im `Module`-Typ (ab Zeile 189), mit `@internal`-Doku                       |
| `packages/paratix/src/runner.ts`                           | Vorab-Phase zwischen `printRunContext` und `connectAndRegister`; `withRunScopedSecrets` hochgezogen                |
| `packages/paratix/src/conditionalModules.ts`               | `createConditionalModule` implementiert `_prewarmSecrets` und delegiert an die gekapselten Kindmodule              |
| `packages/paratix/src/cli.ts`                              | `resolveFilteredRun` warnt, wenn `--filter` einen Knoten mit `_prewarmSecrets` entfernt                            |
| `packages/paratix/src/output.ts`                           | Zwei neue Exporte: eine Info- und eine Warnzeile, beide durch `maskRegisteredSecrets`                              |
| `packages/paratix/test/output.test.ts`                     | Ergänzung: beide neuen Helfer geben eine Zeile aus und maskieren registrierte Secrets                              |
| `packages/paratix/src/modules/op.ts`                       | `resolveRegularReferences` / `resolveOtpReferences` gehen über die Cache-Funktion; Modul erhält `_prewarmSecrets`  |
| `packages/paratix/test/secretPrewarm.test.ts`              | Neu: Walk über Recipes, `when(...)`, Skip-Module, Signals; Cache-Dedupe; Rejection-Invalidierung                   |
| `packages/paratix/test/modules/op.test.ts`                 | Ergänzungen: Prewarm-Pfad, Dedupe, OTP-Seed einmalig, Verhalten ohne Cache-Scope unverändert                       |
| `packages/paratix/test/conditionalModules.test.ts`         | Ergänzung: `when(...)` reicht `_prewarmSecrets` an seine Kinder durch, ohne die Guard-Bedingung auszuwerten        |
| `packages/paratix/test/runner-secrets-environment.test.ts` | Reihenfolge-Test (alle `op read` vor `ssh.connect`), Fail-Fast ohne Connect, Sink nach Lauf-Ende leer              |
| `packages/paratix/test/runner-dry-run.test.ts`             | Ergänzung: `--dry-run` löst die Vorab-Auflösung ebenfalls aus                                                      |
| `packages/paratix/test/cli.test.ts`                        | Ergänzung: `--filter`, das ein `op.resolve` ausschließt, erzeugt genau eine Warnung und ändert den Lauf nicht      |
| `docs/module.md`                                           | Deutscher `op`-Abschnitt: neuer Abschnitt zur Vorab-Auflösung, Umformulierung von „Lazy OTP-Auflösung"             |
| `packages/paratix/llm-guide.md`                            | `op.resolve`-Zeile in der Signatur-Tabelle, Hinweis auf die Vorab-Phase, Anti-Pattern 16 unmissverständlich halten |
| `cspell.json`                                              | Begriffe wie `prewarm` aufnehmen, falls die Rechtschreibprüfung anschlägt                                          |

`packages/paratix/src/recipe.ts` braucht **keine** Änderung: `_modules` und `_signals` sind bereits als Felder von `RecipeModule` vorhanden (`recipe.ts:39-41`), der Walk liest sie nur zusätzlich.

`test/publicApi.test.ts` braucht **keine** Änderung — verifiziert: die Datei prüft ausschließlich einen `resolveEnvironment`-Aufruf und die Export-Parität zwischen `paratix/modules` und dem Paket-Root; sie importiert `types.ts` nicht und hält keine Typfläche fest. Es gibt im Repo auch keinen `.d.ts`-Snapshot und keinen api-extractor-Report. Ein neues `@internal`-Feld am `Module`-Typ ist dort folglich unsichtbar.

Keine Änderungen an `ssh.ts`, `sftp.ts` oder `readFile`-Semantik — die in `AGENTS.md` geforderte lokale Docker-Integrationsprüfung ist für diesen Plan daher nicht einschlägig.

## Implementierungsdetails

### Vorgehen

1. **Kontrakt erweitern.** `_prewarmSecrets?: () => Promise<void>` im `Module`-Typ ergänzen, mit `@internal`-Markierung und dem Hinweis, dass der Hook vor dem SSH-Connect läuft, also keine `ssh`-Verbindung und keine `Environment` erhält. Der Hook ist bewusst parameterlos: alles, was er braucht, hat das Modul zur Konstruktionszeit bekommen.

2. **`secretPrewarm.ts` anlegen.** Drei Exporte:
   - ein `withSecretPrewarmScope(body)`, das den ALS-Cache öffnet und das Ergebnis von `body` durchreicht;
   - ein `prewarmSecrets(modules)`, das die Liste sequenziell durchläuft, pro Knoten `_prewarmSecrets?.()` awaited und bei `isRecipe(module)` zusätzlich rekursiv in `module._modules` **und** `module._signals` absteigt;
   - ein `resolveCachedSecret(reference, load)`, das bei aktivem Scope das gecachte Promise zurückgibt oder `load()` einträgt, und bei fehlendem Scope einfach `load()` durchreicht. Ein abgelehntes Promise wird aus der Map entfernt, damit ein späterer Versuch nicht dauerhaft auf dem Fehler festhängt.

3. **`when(...)` anschließen.** In `createConditionalModule` ein `_prewarmSecrets` ergänzen, das `prewarmSecrets(parameters.modules)` aufruft. Die Guard-Bedingung wird dabei **nicht** ausgewertet — sie ist remote und vor dem Connect nicht auswertbar.

4. **`op.ts` auf den Cache umstellen.** Die beiden `spawnWithInput("op", ["read", "--", reference], …)`-Stellen (`op.ts:304`, `op.ts:355`) wandern in die `load()`-Funktion von `resolveCachedSecret(reference, load)`. **Der Cache hält den fertig nachverarbeiteten Wert, nicht den rohen Stdout** — für reguläre Referenzen den zeilenumbruch-bereinigten Secret-Wert (`op.ts:305`), für OTP-Referenzen die getrimmte `otpauth://`-URI (`op.ts:357`). Das ist zwingend, weil der Secret-Sink genau den String maskiert, der später in der Ausgabe auftauchen kann: würde der rohe Stdout mit Zeilenumbruch registriert, träfe `maskSecrets` den getrimmten Wert nicht mehr. Eine Doppelbelegung ist ausgeschlossen, weil `splitReferences` (`op.ts:265`) jede Referenz allein anhand ihres Suffixes genau einem der beiden Zweige zuordnet.

5. **`_prewarmSecrets` am `op.resolve`-Modul ergänzen.** Es ruft für jede Referenz — reguläre wie OTP — `resolveCachedSecret` auf und verwirft das Ergebnis; der Wert bleibt im Cache. Fehler werden **geworfen**, nicht in `failed(...)` verpackt. `apply()` ruft anschließend dieselbe Funktion auf, erhält den gecachten Wert und baut für OTP-Referenzen erst dort die Lazy-Closure (`op.ts:371-389`) — die Closure gehört zum Modul, nicht in den Cache.

   Der Hook öffnet dafür **selbst** ein `withRunScopedSecrets` (`secretSink.ts:180`), genau wie `apply()` es heute schon tut (`op.ts:432`). Die Helper ist re-entrant, im Runner-Pfad ist das also ein No-Op — aber es macht den Hook selbsttragend. Ohne diese Klammer würde ein Direktaufruf ohne aktiven Scope die Werte prozessweit registrieren, ohne sie je wieder freizugeben: `registerRunScopedSecret` erhöht `secretCounts` bedingungslos und kehrt erst danach zurück, wenn kein Store existiert (`secretSink.ts:85-91`), und weder `teardownPlaybookResources` (`runner.ts:1236-1247`, R-0000518) noch irgendein anderer regulärer Pfad räumt das auf.

6. **Secret-Registrierung an die erste Beobachtung binden.** `registerRunScopedSecret` wandert in die `load()`-Funktion und registriert den nachverarbeiteten Wert, unmittelbar bevor er in den Cache geht. Ohne das läge zwischen Vorab-Auflösung und Modulausführung ein Fenster, in dem der Wert im Speicher liegt, ein Stacktrace ihn aber unmaskiert zeigen würde. Der bestehende Grundsatz aus `op.ts:441-447` — genau eine kanonische Registrierungsstelle — bleibt gewahrt; sie wandert nur eine Ebene nach unten. Die Leerwert-Regel bleibt: ein leerer Wert wird gecacht, aber nicht registriert (`op.ts:306`).

7. **Runner-Phase einhängen.** In `runPlaybook`: `withRunScopedSecrets` so hochziehen, dass sie den gesamten `try`-Block umschließt; darin zuerst `withSecretPrewarmScope(...)` öffnen, in dem `prewarmSecrets([...definition.run, ...(definition.signals ?? [])])` läuft, danach unverändert `connectAndRegister` und `executeRun`. Der bestehende innere `withRunScopedSecrets`-Aufruf um `executeRun` kann entfallen, weil die äußere Klammer ihn abdeckt.

8. **Zwei neue Ausgabe-Helfer in `output.ts`.** Verifiziert: `output.ts` hat für freie Meldungen **nichts** — alle 14 Exporte sind an feste Struktur-Slots gebunden (`printCliHeader`, `printRunContext`, `printModuleResult`, `printCommandError`, `printSummary` …), und einen Warn-Helfer gibt es überhaupt nicht; die einzigen Warnungen im Repo schreiben roh auf stderr (`knownHosts.ts:533-585`, `ssh.ts:1255`). Der Plan ergänzt deshalb zwei schlanke Exporte — einen für eine Info-Zeile, einen für eine Warnzeile — die beide durch `maskRegisteredSecrets` laufen und damit dieselbe Redaktionsgarantie tragen wie der Rest der Ausgabe.

   Die Vorab-Statuszeile nutzt den Info-Helfer: vor dem ersten `op read` genau eine feste Zeile, sinngemäß „Löse 1Password-Referenzen auf …", damit der Nutzer versteht, warum das Terminal auf einen Biometrie-Prompt wartet. Bewusst **ohne** Zähler, Fortschritt oder Referenznamen: Referenznamen sind selbst sensibel, und ein Fortschrittszähler wäre eine zusätzliche Ausgabefläche ohne Nutzen bei den üblichen ein bis fünf Referenzen. Ohne auflösbare Referenz im Lauf darf die Zeile nicht erscheinen. Ein Spinner-Konflikt besteht an beiden Ausgabestellen nicht, weil sowohl die Vorab-Phase als auch der Filterpfad vor der Modulschleife und damit vor jedem `startModuleSpinner` liegen.

9. **Warnen, wenn ein Filter eine Vorab-Auflösung ausschließt.** `--filter` kann ein `op.resolve` durch ein `createSkipModule` ersetzen (`moduleFilter.ts:136`), wodurch nachgelagerte Module ihren Env-Wert nicht finden — heutiges Verhalten, das aber unsichtbar ist. Dafür ein Helfer, der einen Modulbaum durchläuft und die Namen aller Knoten mit `_prewarmSecrets != null` sammelt (rekursiv über `isRecipe`/`_modules`; ein `when(...)`-Knoten zählt selbst als Träger, weil er den Hook trägt). `resolveFilteredRun` (`cli.ts:737`) vergleicht die Trägernamen des ursprünglichen mit denen des gefilterten Baums und gibt für jede weggefallene eine Warnung über den neuen Warn-Helfer aus Schritt 8 aus. Das Verhalten des Laufs ändert sich dadurch **nicht** — `moduleFilter.ts` bleibt eine reine Funktion mit unveränderter Signatur, die Prüfung sitzt danebengelagert in `cli.ts`.

10. **Fehlerpfad der Vorab-Phase vollständig selbst maskieren — Nachrichten, `cause` und Stack.** Der heutige Maskierungspfad hängt an der `leakedValues`-Liste, die `apply()` lokal aufbaut (`op.ts:436`, `op.ts:459-464`). Die Vorab-Phase braucht ihr eigenes Äquivalent: eine laufende Liste der bereits aufgelösten Werte, die zusammen mit den `op://`-Referenzen und `collectOpFailureOutputs(error)` (`opSpawnError.ts`) durch `maskSecrets` und `maskKnownSecretPrefixes` (`op.ts:464`) läuft, bevor der Fehler geworfen wird. Die bestehenden Hinweise (`OP_INSTALL_HINT`, `OP_SIGNIN_HINT`, `op.ts:31-34`) bleiben erhalten.

    **Auf den Secret-Sink als Auffangnetz kann sich dieser Pfad nicht verlassen** — verifiziert: `withRunScopedSecrets` awaited seinen Body innerhalb des `try`, sein `finally` entregistriert die Werte also, **bevor** die Ablehnung nach außen propagiert (`secretSink.ts:186-194`). Bis der Fehler bei `exitAfterApplyError` → `printExceptionError` (`cli.ts:796`, `cli.ts:302`) ankommt, ist `secretCounts` leer, und `maskRegisteredSecrets` (`secretSink.ts:384-387`) gibt den Text unverändert zurück. Anders als `withRegisteredSecrets` (`secretSink.ts:163-164`) maskiert `withRunScopedSecrets` den entweichenden Fehler auch nicht selbst. Der geworfene Fehler muss deshalb zum Wurfzeitpunkt fertig maskiert sein: `message`, `cause` und `stack`. `maskScopedError` liefert genau diese Klon-Semantik und ist als Vorbild zu verwenden.

11. **Dokumentation nachziehen.** `docs/module.md` und `packages/paratix/llm-guide.md` beschreiben die neue Reihenfolge, halten die bestehende OTP-Seed-Erläuterung inhaltlich aufrecht (der Seed rotiert nicht innerhalb eines Laufs) und lassen Anti-Pattern 16 unverändert gültig.

### Komponenten-Struktur

- `secretPrewarm.ts` — provider-neutral. Kennt weder 1Password noch `op://`; nur Modul-Walk, Scope und generische Memoisierung.
- `modules/op.ts` — bleibt der einzige Ort mit 1Password-Wissen. Neu ist nur, dass die beiden `op read`-Aufrufe durch die Memo-Funktion laufen und dass das Modul einen `_prewarmSecrets`-Hook trägt.
- `runner.ts` — kennt nur `prewarmSecrets` und `withSecretPrewarmScope`, keine Modultypen.

### Zustandsverwaltung

Der einzige neue Zustand ist der Referenz-Cache. Er ist lauf-gebunden (`AsyncLocalStorage`), nicht prozess-global, und endet mit dem Lauf. Es gibt bewusst **keine** Persistenz über Läufe hinweg: ein neuer `paratix apply`-Aufruf liest die Referenzen erneut, so wie es die bestehende Seed-Rotationszusage in `op.ts:334-341` beschreibt.

### API-Anbindung

Nicht relevant im Sinne einer HTTP-API. Die einzige externe Schnittstelle bleibt die 1Password-CLI über `op read -- <reference>`; Aufrufform, Timeout (`op.ts:29`) und Output-Begrenzung (`opOutputCapture.ts`) bleiben unverändert.

### Styling-Ansatz

Nicht relevant (CLI- und Backend-Code, keine UI).

### Barrierefreiheit

Nicht relevant im Web-Sinn. Der einzige nutzerseitige Aspekt ist die neue Ausgabezeile vor dem Prompt (Vorgehen, Schritt 8): sie erklärt eine Wartesituation, die sonst als „hängt" wahrgenommen wird.

### Randfälle

- **Playbook ohne `op.resolve`** → kein `op read`, keine Ausgabezeile, kein messbarer Mehraufwand. Der Walk läuft, findet keinen Hook, ist fertig.
- **Dieselbe Referenz in zwei `op.resolve`-Aufrufen** → genau ein `op read` pro Lauf, beide Module bekommen denselben Wert.
- **`op.resolve` in einem `when(...)`, dessen Bedingung später `false` ergibt** → Wert wird geholt und nie benutzt. Bewusst akzeptiert, in der Doku benannt.
- **`op.resolve` per `--filter` ausgeschlossen** → `createSkipModule` trägt keinen Hook, es wird nichts aufgelöst.
- **`op.resolve` in einem Recipe oder in `signals`** → wird über den Walk erreicht.
- **Strg-C während des Biometrie-Prompts** → `getRunnerAbortSignal()` ist gesetzt, der `op`-Child wird per SIGTERM/SIGKILL beendet (`opSpawnLifecycle.ts`), `rethrowIfNotShutdown` (`runner.ts:1339`) behandelt den Abbruch als Shutdown statt als Fehler.
- **`op`-CLI fehlt oder Session abgelaufen** → Vorab-Phase wirft, kein SSH-Connect, Exit-Code 2, Meldung mit Install- bzw. Signin-Hinweis.
- **Timeout (60 s, `op.ts:29`)** → greift unverändert, jetzt eben in der Vorab-Phase.
- **`op read` liefert leeren Stdout** → wie heute: nicht im Sink registriert, aber als leerer Wert gecacht und weitergereicht.
- **Stdout größer als `OP_OUTPUT_CAPTURE_LIMIT_BYTES`** → unverändertes Reject statt gekürztem Secret (`op.ts:130-138`), jetzt in der Vorab-Phase.
- **Parallele `runPlaybook`-Aufrufe im selben Prozess** → getrennte ALS-Scopes, keine Cache-Vermischung; gleiche Motivation wie R-0000743.
- **TOTP-Closure wird nach Lauf-Ende aufgerufen** → `hasActiveRunScopedSecretScope()` (`op.ts:380`) bleibt der Schutz dagegen und wird nicht angefasst.
- **Direkter Bibliotheksaufruf `op.resolve(...).apply(null, {})` ohne Runner** → kein Cache-Scope, unmittelbare Auflösung, `failed(...)` bei Fehler. Bestehende Tests bleiben damit unverändert gültig.
- **Lauf-Ausgabe des Moduls an seiner Position** → unverändert. `check()` liefert weiterhin `needs-apply` (`op.ts:475`), `apply()` läuft und liefert `status: "ok"` samt Meta; die Zeile im Run-Output sieht aus wie heute, nur ohne CLI-Aufruf dahinter. Es wird bewusst **kein** neuer Status wie `skipped` oder ein Zusatz „bereits vorab aufgelöst" eingeführt.
- **`--first-run` bzw. unbekannter Host-Key** → der Biometrie-Prompt kommt jetzt **vor** einem eventuellen Host-Key-Prompt. Zwei aufeinanderfolgende Interaktionen sind gewollt; die 1Password-Interaktion steht per Anforderung an erster Stelle.
- **Lazy `EnvironmentValue`-Thunks in `definition.env`** (`types.ts:5-13`) → bleiben unverändert lazy. Die Vorab-Phase kennt nur `_prewarmSecrets`-Knoten, nicht die Umgebung.
- **`--filter` schließt `op.resolve` aus, aber ein abhängiges Modul ein** → das abhängige Modul findet seinen Env-Wert nicht. Das ist bereits heute so und wird durch diesen Plan nicht verändert; neu ist ausschließlich eine Warnung, die den Zusammenhang sichtbar macht (Vorgehen, Schritt 9).
- **`--filter` schließt ein `op.resolve` aus, das im Lauf niemand braucht** → die Warnung erscheint trotzdem, weil der Filterpfad die Abhängigkeiten nicht kennt. Bewusst in Kauf genommen: eine Warnung ist billiger als eine falsch-negative Stille.

## Akzeptanzkriterien

- [ ] In einem Lauf mit `op.resolve` an beliebiger Position in `run` erfolgen **alle** `op read`-Aufrufe, bevor `ssh.connect` aufgerufen wird — nachgewiesen über die Aufrufreihenfolge bei gemocktem `spawn` und gemockter SSH-Verbindung.
- [ ] Nennen zwei `op.resolve`-Module dieselbe Referenz, wird `op read` für diese Referenz **genau einmal** pro Lauf ausgeführt.
- [ ] Ein `op.resolve` innerhalb von `recipe(...)` und ein `op.resolve` innerhalb von `when(...)` werden beide vorab aufgelöst.
- [ ] Ein `op.resolve` in `definition.signals` wird vorab aufgelöst.
- [ ] Ein per `--filter` ausgeschlossenes `op.resolve` löst **kein** `op read` aus und erzeugt genau eine Warnung, die den Modulnamen nennt; der Lauf selbst verhält sich unverändert.
- [ ] Ein Lauf mit `--filter`, der kein `op.resolve` ausschließt, erzeugt keine solche Warnung.
- [ ] Scheitert die Vorab-Auflösung (ENOENT bzw. „not signed in"), wirft `runPlaybook`, `ssh.connect` wurde nie aufgerufen, und die Meldung enthält den Install- bzw. Signin-Hinweis, aber keinen aufgelösten Wert und keine `op://`-Referenz im Klartext.
- [ ] `--dry-run` löst die Vorab-Auflösung ebenfalls aus; nachgelagerte Module sehen im Dry-Run dieselben Meta-Werte wie heute.
- [ ] Für eine OTP-Referenz erfolgt genau ein `op read` in der Vorab-Phase; zwei Zugriffe auf den Environment-Wert erzeugen zwei TOTP-Berechnungen ohne weiteren `spawn`-Aufruf.
- [ ] `op.resolve(...).apply(null, {})` ohne aktiven Cache-Scope verhält sich unverändert: unmittelbare Auflösung, `failed(...)` bei Fehler. Die bereits vorhandenen Testfälle in `test/modules/op.test.ts` bleiben grün, ohne dass ihre Erwartungen angepasst werden (neue Fälle dürfen ergänzt werden).
- [ ] Ein registrierter Secret-Wert wird in der Ausgabe auch dann maskiert, wenn er erst in der Vorab-Phase gelesen wurde — nachgewiesen über einen Fehler, der den aufgelösten Wert enthält, und `maskRegisteredSecrets` bzw. den Sink-Inhalt.
- [ ] Nach Lauf-Ende liefert `getRegisteredSecrets()` keine der aufgelösten Werte mehr zurück — die Vorab-Registrierung ist über den hochgezogenen `withRunScopedSecrets`-Scope balanciert.
- [ ] Ein Lauf mit mindestens einer auflösbaren Referenz gibt vor dem ersten `op read` genau eine Statuszeile aus, die weder Referenznamen noch Zähler enthält.
- [ ] Ein Playbook ohne `op.resolve` erzeugt keinen `spawn`-Aufruf und keine zusätzliche Ausgabezeile.
- [ ] Ein `op.resolve` in den Signal-Handlern eines Recipes (`recipe(name, modules, { signals })`) wird vorab aufgelöst.
- [ ] Ein in der Vorab-Phase geworfener Fehler enthält den aufgelösten Wert weder in `message` noch in `cause` noch im `stack` — geprüft am geworfenen Objekt selbst, ohne sich auf den Secret-Sink zu verlassen.
- [ ] `op.resolve(...)._prewarmSecrets()` ohne umgebenden Runner hinterlässt nach seinem Ende keine Einträge in `getRegisteredSecrets()`.
- [ ] `pnpm agent:check` läuft im Repo-Root fehlerfrei durch (Lint, Format, Typecheck, Build, Tests inklusive der bestehenden Coverage-Schwellen).

## Validierungsplan

**Planungsstand:** HEAD `080c1ae9`, 2026-08-06, Arbeitsverzeichnis sauber bis auf diese Plandatei. Vor der Umsetzung prüfen, ob `packages/paratix/src/runner.ts`, `modules/op.ts`, `secretSink.ts`, `conditionalModules.ts` oder `moduleFilter.ts` seither verändert wurden; die im Plan genannten Zeilennummern sind gegen diesen Stand verifiziert und dienen als Drift-Anker, nicht als Vertrag.

| Zweck                  | Kommando                     | Erwartung                                      |
| ---------------------- | ---------------------------- | ---------------------------------------------- |
| Fokussierte Unit-Tests | `pnpm --filter paratix test` | Exit 0, die unten benannten neuen Fälle laufen |
| Vollständige Prüfung   | `pnpm agent:check`           | Exit 0 (Lint, Format, Typecheck, Build, Tests) |
| Formatierung des Plans | `pnpm format:check`          | Exit 0                                         |

`pnpm --filter paratix test` ist `test:unit && test:dist`, und `test:unit` läuft als `vitest run --coverage`. Die Schwellen (`vitest.config.ts:44-49`: 82 Branches, 90 Functions/Lines/Statements) sind **global, nicht pro Datei**, mit gemessenem Vorlauf von rund drei bis vier Punkten. Eine schwach getestete neue Datei fällt dort also nicht zwingend auf. Zusätzlich schließt `vitest.config.ts:34` `src/cli.ts` von der Messung aus — die Filter-Warnung aus Vorgehen Schritt 9 ist damit coverage-unsichtbar und braucht ihren expliziten Testfall in `test/cli.test.ts` umso mehr.

- Neue Unit-Tests in `packages/paratix/test/secretPrewarm.test.ts` (vitest, Konventionen wie in `test/modules/op.test.ts`):
  - Walk erreicht Top-Level-Module, Recipe-`_modules`, Recipe-`_signals`, `when(...)`-Kinder und `definition.signals`.
  - Walk ruft an `createSkipModule`-Knoten nichts auf.
  - `resolveCachedSecret` löst pro Key genau einmal aus und gibt bei erneutem Aufruf dasselbe Promise zurück.
  - Ein abgelehntes Promise wird aus dem Cache entfernt; der Folgeaufruf startet einen neuen Ladevorgang.
  - Ohne aktiven Scope wird `load()` unverändert durchgereicht.
  - Der Trägersammler findet Knoten mit `_prewarmSecrets` auf Top-Level, in Recipes und als `when(...)`-Knoten, und ignoriert Skip-Module.
- Ergänzung in `packages/paratix/test/cli.test.ts`:
  - `--filter`, das ein `op.resolve` ausschließt, erzeugt genau eine Warnung mit dem Modulnamen.
  - `--filter`, das `op.resolve` einschließt, erzeugt keine Warnung.
  - Der zurückgegebene Modulbaum ist in beiden Fällen identisch zu dem ohne die neue Prüfung.
- Ergänzungen in `packages/paratix/test/modules/op.test.ts` — gleiche Mock-Bauart wie heute (`vi.mock("node:child_process")` plus handgebaute `EventEmitter`-Children, `spawnCalls`-Aufzeichnung):
  - Prewarm füllt den Cache; das anschließende `apply()` erzeugt keinen weiteren `spawn`.
  - OTP: ein `spawn` in der Vorab-Phase, danach mehrere Code-Berechnungen ohne `spawn`.
  - Fehlerpfad im Prewarm wirft statt `failed(...)` zurückzugeben; `message`, `cause` und `stack` des geworfenen Objekts sind maskiert, geprüft am Objekt selbst und nicht über den Sink.
  - `_prewarmSecrets()` ohne umgebenden Runner lässt den Sink nach seinem Ende leer.
- Runner-Tests in `test/runner-secrets-environment.test.ts` bzw. `test/runner-dry-run.test.ts`, aufgebaut auf `makeMockSshClass` aus `test/helpers/runnerMocks.ts:39` (dieselbe Mock-Klasse, die die bestehenden Runner-Suiten schon injizieren):
  - Reihenfolge `op read` → `ssh.connect` über eine gemeinsame Aufruf-Chronik, in die sowohl der `spawn`-Mock als auch der `connect`-Aufruf der Mock-SSH-Klasse schreiben.
  - Fail-Fast: `ssh.connect` wird bei Prewarm-Fehler nie erreicht.
  - `--dry-run` mit `op.resolve`: Vorab-Auflösung läuft, Meta erreicht nachgelagerte Module.
  - Secret-Sink ist nach Lauf-Ende leer.
- `pnpm agent:check` im Repo-Root.
- Manuelle Gegenprobe (nicht Teil der Akzeptanzkriterien): reales Playbook mit `op.resolve` gegen eine gesperrte 1Password-Session starten und beobachten, dass der Biometrie-Prompt vor dem SSH-Connect erscheint und danach kein weiterer Prompt kommt.
- Die Docker-gebundene Integrationssuite (`pnpm --filter paratix test:integration`, siehe `AGENTS.md`) ist nicht einschlägig, weil weder `ssh`- noch `readFile`-Semantik berührt wird.

## Annahmen und offene Punkte

- **Annahme:** `op.resolve` ist der einzige Ort im Code, an dem 1Password-Referenzen gelesen werden. Der Explore-Durchlauf hat außer den Re-Exports in `src/modules/index.ts:14` und `src/index.ts:45` keinen weiteren Nutzer von `modules/op.ts` gefunden.
- **Verifiziert, nicht angenommen:** Kindmodule liegen an genau drei Orten — Recipe-`_modules`/`_signals`, der `when(...)`-Closure und `definition.signals`. Der Walk deckt alle drei ab. Sollte später ein weiterer Container-Typ hinzukommen, der Kinder in einer Closure hält, bekommt er denselben `_prewarmSecrets`-Delegationshook.
- **Annahme:** Modulnamen sind innerhalb eines Playbooks eindeutig genug, dass der Namensvergleich zwischen ursprünglichem und gefiltertem Baum die Filter-Warnung korrekt auslöst. `collectModuleNames` (`moduleFilter.ts:46`) trifft dieselbe Annahme bereits für die Filter-Validierung selbst.
- **Bewusst akzeptiert:** Secrets in `when(...)`-Zweigen mit später `false`-Bedingung werden unnötig gelesen. Alternative wäre eine zweistufige Auflösung nach dem Connect, was den Kern der Anforderung (Interaktion ganz am Anfang) aufgeben würde.
- **Bewusst akzeptiert:** Der Fehlerpfad ändert sich von „Modul meldet `failed` an seiner Position" zu „Lauf bricht vor dem Connect ab". Ein Playbook, das sich bisher auf einen nachgelagerten Task nach einem gescheiterten `op.resolve` verlassen hat, verhält sich anders. Das ist gewollt und gehört in die Release-Notes.
- **Nicht-Anforderung:** Persistenter Secret-Cache über mehrere `paratix apply`-Läufe hinweg.
- **Nicht-Anforderung:** Parallelisierung der `op read`-Aufrufe.
- **Nicht-Anforderung:** `ssh.sudoPassword` aus `op.resolve` speisen (Anti-Pattern 16 bleibt gültig).
- **Nicht-Anforderung:** Ein öffentlicher Prewarm-Hook für eigene Nutzer-Module. Das Feld bleibt `@internal`; ob es später öffentlich wird, entscheidet ein eigener Plan.
- **Nicht-Anforderung:** `--filter` so ändern, dass `op.resolve` filter-fest wird. Das Laufverhalten bleibt unverändert; es kommt nur die Warnung aus Vorgehen Schritt 9 hinzu.
- **Nicht-Anforderung:** Fortschrittsanzeige oder Referenznamen in der Vorab-Statuszeile.
- **Nicht-Anforderung:** Das bestehende Verhalten in `op.ts:380` ändern, wo ein TOTP-Code außerhalb eines aktiven Run-Scopes gar nicht im Sink registriert wird. Das ist eine bewusste Abwägung gegen unbalancierte Registrierungen und älter als dieser Plan.
- **Nicht-Anforderung:** `collectModuleNames` (`moduleFilter.ts:46`) oder `dryRunRecipe.ts:255` ebenfalls auf `_signals` erweitern. Beide steigen heute nur in `_modules` ab; ob das dort ein Fehler ist, entscheidet ein eigener Vorgang.

### Abbruchbedingungen

- Die Umsetzung stoppt und der Plan wird überarbeitet, wenn sich zeigt, dass ein weiterer Container-Typ Kindmodule in einer Closure hält und der `_prewarmSecrets`-Delegationshook dort nicht ohne Vertragsänderung nachrüstbar ist.
- Stoppen, wenn das Hochziehen von `withRunScopedSecrets` bestehende Sink-Tests (`test/secretSink.test.ts`, `test/runner-secrets-environment.test.ts`) in einer Weise bricht, die eine Änderung der Sink-Semantik statt nur der Klammer verlangt.
- Stoppen, wenn die Vorab-Phase eine Änderung an `SshConfig` oder am `server()`-Konstruktionszeitpunkt nötig macht — das wäre der Anti-Pattern-16-Bereich und ist ausdrücklich nicht Teil dieses Plans.
- Stoppen, wenn `pnpm agent:check` schon vor der Änderung auf `main` rot ist, sodass sich Ergebnisse nicht zuordnen lassen.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       1 |       3 |
| Security    |        0 |       4 |       1 |
| Datenschutz |        0 |       0 |       1 |
| Fehlerfälle |        0 |       2 |       2 |
| Testbarkeit |        0 |       1 |       2 |
| Scope       |        0 |       2 |       4 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

Der zweite Durchgang (`/effective-flow review`) hat vier Annahmen des ersten adversarisch geprüft und widerlegt. Diese Befunde stehen zuerst.

- **Architektur (Wichtig, zweiter Durchgang):** Der Walk war als „Rekursion über `isRecipe`/`_modules`" beschrieben. `RecipeModule` hält aber **zwei** Kindlisten: `_modules` und `_signals` (`recipe.ts:39-41`, gesetzt in `recipe.ts:600-601`). Ein `op.resolve` in den Signal-Handlern eines Recipes wäre unerreichbar geblieben und hätte mitten im Lauf geprompted — genau der Fall, für den `definition.signals` schon eingeplant war, nur eine Ebene tiefer übersehen. Der Walk steigt jetzt in beide Listen ab. Nebenbei belegt: Kindmodule liegen an genau drei Orten, und `_supportsChildStepHook` taugt nicht als Kind-Marker, weil er auf Recipes wie auf Guard-Blöcken sitzt.
- **Security (Wichtig, zweiter Durchgang):** Der Plan nahm an, ein in der Vorab-Phase geworfener Fehler werde notfalls vom Secret-Sink aufgefangen. Verifiziert falsch: `withRunScopedSecrets` awaited seinen Body im `try`, das `finally` entregistriert also **vor** der Propagation (`secretSink.ts:186-194`), und `maskRegisteredSecrets` findet bei `printExceptionError` (`cli.ts:302`) eine leere `secretCounts`-Map vor. Anders als `withRegisteredSecrets` maskiert `withRunScopedSecrets` den entweichenden Fehler auch nicht selbst. Da Fail-Fast diesen Pfad zum Hauptfehlerweg macht, ist das scharf: Vorgehen Schritt 10 verlangt jetzt Maskierung von `message`, `cause` **und** `stack` zum Wurfzeitpunkt, mit `maskScopedError` als Vorbild.
- **Security (Wichtig, zweiter Durchgang):** `registerRunScopedSecret` erhöht `secretCounts` bedingungslos und kehrt erst danach zurück, wenn kein ALS-Store existiert (`secretSink.ts:85-91`); aufgeräumt wird das regulär nirgends (`runner.ts:1236-1247`, R-0000518). Solange die Registrierung in `apply()` sitzt, ist das ungefährlich, weil `apply()` sich selbst klammert (`op.ts:432`). Durch die Verlagerung in `load()` wäre `_prewarmSecrets` der erste Aufrufer ohne eigene Klammer geworden. Behoben: der Hook öffnet sein eigenes — re-entrantes und im Runner-Pfad kostenloses — `withRunScopedSecrets`.
- **Scope (Wichtig, zweiter Durchgang):** Die Annahme, Statuszeile und Warnung ließen sich ohne Erweiterung über `output.ts` ausgeben, ist widerlegt: alle 14 Exporte sind an feste Struktur-Slots gebunden, ein Warn-Helfer existiert nicht, und die einzigen Warnungen im Repo schreiben roh auf stderr (`knownHosts.ts:533-585`). Auf Entscheidung des Nutzers bekommt `output.ts` zwei schlanke Exporte, die durch `maskRegisteredSecrets` laufen — statt das Roh-stderr-Muster zu vervielfachen. Ein Spinner-Konflikt besteht nicht, weil beide Ausgabestellen vor der Modulschleife liegen.
- **Testbarkeit (Hinweis, zweiter Durchgang):** Die Coverage-Schwellen (`vitest.config.ts:44-49`) sind **global, nicht pro Datei**, mit drei bis vier Punkten Vorlauf, und `src/cli.ts` ist von der Messung ausgeschlossen (`vitest.config.ts:34`). Das Kriterium „`agent:check` grün inklusive Coverage" trägt für neuen Code also weniger, als es klingt; die Filter-Warnung braucht ihren expliziten `cli.test.ts`-Fall umso mehr. Im Validierungsplan festgehalten.
- **Scope (Hinweis, zweiter Durchgang):** Die Vermutung, `test/publicApi.test.ts` könnte die Typfläche festhalten, ist widerlegt — die Datei prüft nur einen `resolveEnvironment`-Aufruf und die Export-Parität, es gibt keinen `.d.ts`-Snapshot und keinen api-extractor-Report. Der spekulative Prüfpunkt ist durch die verifizierte Aussage ersetzt.

- **Security (Wichtig):** Der erste Entwurf ließ den Cache den **rohen** `op read`-Stdout halten und die Nachverarbeitung im Modul. Der Secret-Sink maskiert aber exakt den registrierten String: ein mit Zeilenumbruch registrierter Rohwert hätte den getrimmten Wert in der Ausgabe nicht mehr getroffen — der Wert wäre trotz Registrierung im Klartext sichtbar geblieben. Eingearbeitet in Vorgehen Schritt 4: der Cache hält den fertig nachverarbeiteten Wert. Eine Doppelbelegung derselben Referenz in beiden Zweigen ist ausgeschlossen, weil `splitReferences` (`op.ts:265`) allein nach Suffix zuordnet.
- **Security (Wichtig):** Der erste Entwurf hätte die Secret-Registrierung im Sink dort gelassen, wo sie heute steht — in `resolveRegularReferences`/`resolveOtpReferences`, also im `apply()`-Pfad. Damit läge zwischen Vorab-Auflösung und Modulausführung ein Zeitfenster, in dem der Wert im Speicher liegt, aber ein Stacktrace ihn unmaskiert zeigen würde. Eingearbeitet als Vorgehen Schritt 6: die Registrierung wandert in die `load()`-Funktion des Caches, also an die Stelle der ersten Beobachtung. Der Grundsatz „genau eine kanonische Registrierungsstelle" aus `op.ts:441-447` bleibt gewahrt.
- **Security (Wichtig):** Die neue Statuszeile darf keine Referenznamen ausgeben. Ein `op://vault/item/field` verrät Vault- und Item-Struktur; die Entscheidung für die schlichte Variante (Vorgehen Schritt 8) hält das fest, und die Nicht-Anforderung schließt eine spätere Aufweichung aus.
- **Security (Hinweis):** Das Hochziehen von `withRunScopedSecrets` ist keine Kosmetik, sondern Voraussetzung: ohne aktiven Store ist `registerRunScopedSecret` für die Aufräumseite ein No-Op (`secretSink.ts:87-91`), und die Registrierungen blieben bis zum Prozessende stehen. Als eigene Architekturentscheidung und eigenes Akzeptanzkriterium festgehalten.
- **Fehlerfälle (Wichtig):** Der Wechsel von `failed(...)` zu einem geworfenen Fehler ist eine beobachtbare Verhaltensänderung für bestehende Playbooks. Sie ist gewollt (so hat der Nutzer entschieden), aber sie darf nicht stillschweigend passieren — unter „Annahmen und offene Punkte" als Release-Notes-relevant markiert.
- **Fehlerfälle (Wichtig):** Der Maskierungspfad des Fehlerfalls hängt heute an der `leakedValues`-Liste, die `apply()` lokal aufbaut (`op.ts:436`, `op.ts:459-464`). Verlagert man die Auflösung, verliert der Fehlerpfad diese Liste ersatzlos. Eingearbeitet als eigener Vorgehen-Schritt 10: die Vorab-Phase führt ihr eigenes Äquivalent und speist es zusammen mit den Referenzen und `collectOpFailureOutputs` in dieselbe Maskierung.
- **Fehlerfälle (Hinweis):** Der Abbruch per Strg-C während des Biometrie-Prompts ist nur dann sauber, wenn die Vorab-Phase **innerhalb** des `withRunnerAbortSignal`-Scopes läuft — `op.ts:207` prüft das Signal vor dem Spawn. Deshalb ist die Platzierung im Plan auf die Zeilen zwischen `runner.ts:1310` und `runner.ts:1314` festgenagelt statt vage auf „am Anfang des Laufs".
- **Fehlerfälle (Hinweis):** Der Lauf-Output des Moduls an seiner Position war im ersten Entwurf gar nicht adressiert. Ergänzt als Randfall: die Zeile bleibt unverändert bei `status: "ok"`, weil `apply()` weiterhin läuft und dieselbe Meta erzeugt — kein neuer Status, kein Zusatztext.
- **Architektur (Hinweis):** `secretPrewarm.ts` bleibt provider-neutral und kennt kein `op://`. Das kostet nichts und hält die Tür für weitere Secret-Provider offen, ohne dafür heute etwas zu bauen.
- **Architektur (Hinweis):** Dass `op.apply()` weiterhin an seiner Position läuft und die Meta erzeugt, hält die Änderung klein. Der Meta-Merge-Pfad (`meta.ts:320`) und der Runner-Loop bleiben unberührt; die Änderung betrifft ausschließlich den Zeitpunkt des CLI-Aufrufs.
- **Datenschutz (Hinweis):** Der Cache hält die aufgelösten Werte bis zum Lauf-Ende. Das ist dieselbe Lebensdauer, die sie über die Umgebung ohnehin schon haben; es entsteht keine neue Aufbewahrung über den Lauf hinaus, und es gibt bewusst keine Persistenz auf Platte.
- **Testbarkeit (Wichtig):** Das Reihenfolge-Kriterium „alle `op read` vor `ssh.connect`" war zunächst nur als Absicht formuliert, ohne nachgewiesenen Prüfweg. Verifiziert: die bestehenden Runner-Suiten injizieren bereits eine Mock-SSH-Klasse über `makeMockSshClass` (`test/helpers/runnerMocks.ts:39`), in die sich eine gemeinsame Aufruf-Chronik mit dem `spawn`-Mock einhängen lässt. Im Validierungsplan konkret benannt, damit das Kriterium nicht unprüfbar bleibt.
- **Testbarkeit (Hinweis):** Die übrigen Akzeptanzkriterien sind mit der bestehenden Mock-Bauart aus `test/modules/op.test.ts` prüfbar (gemocktes `node:child_process`, aufgezeichnete `spawnCalls`).
- **Scope (Wichtig):** Der Plan enthielt zunächst weder einen Drift-Anker noch konkrete Prüfkommandos noch Abbruchbedingungen — bei einem Plan, dessen Argumentation an rund zwei Dutzend Zeilennummern hängt, ist das eine echte Lücke. Ergänzt: Planungsstand `080c1ae9`/2026-08-06 mit sauberem Arbeitsverzeichnis, eine Kommandotabelle mit erwarteten Ergebnissen und ein Abschnitt „Abbruchbedingungen".
- **Scope (Hinweis):** Der Hook bleibt `@internal`. Ihn sofort öffentlich zu machen wäre Over-Engineering, solange es genau einen Nutzer gibt.
- **Scope (Hinweis):** Das Nicht-Ziel `ssh.sudoPassword` ist explizit aufgeführt, weil die Vorverlagerung genau diese falsche Erwartung weckt. Ohne die Klarstellung würde eine Implementierung leicht versuchen, Anti-Pattern 16 mit zu „reparieren".
- **Scope (Hinweis):** Die `--filter`-Schwäche (ausgefiltertes `op.resolve` lässt abhängige Module ins Leere laufen) ist älter als dieser Plan. Auf Entscheidung des Nutzers wird sie nicht behoben, aber sichtbar gemacht: eine Warnung im Filterpfad, ohne Änderung am Laufverhalten und ohne Sonderregel in `moduleFilter.ts`.
- **Wartbarkeit (Hinweis):** `when(...)` bekommt einen Delegationshook statt eines öffentlichen `_modules`-Feldes. Damit bleibt die Kapselung erhalten, die `conditionalModules.ts:49-53` heute bewusst hat, und der Walk hat weiterhin genau zwei Abstiegswege: `isRecipe` und `_prewarmSecrets`.
- **Architektur (Hinweis, zweiter Durchgang):** Dass der Walk in `_signals` absteigt, `collectModuleNames` und `dryRunRecipe.ts` aber nicht, ist eine bewusste Asymmetrie. Ob die beiden anderen Stellen dort eine Lücke haben, ist eine eigene Frage und ausdrücklich nicht Teil dieses Plans.

## Umsetzungsergebnis

Umgesetzt am 2026-08-06 über `/effective-flow build` auf dem Branch `firmo/build/op-secrets-vorab-aufloesen`, Basis `080c1ae9`.

### Abweichungen vom Plan

- **Neue Datei `packages/paratix/src/modules/opFailureMasking.ts`.** Nicht im Plan vorgesehen. Der Zusatzcode kippte `op.ts` über den aktiven `max-lines`-Cap. Die Präzedenz im Paket ist eindeutig: `opSpawnError.ts`, `opOutputCapture.ts` und `opSpawnLifecycle.ts` wurden aus demselben Grund aus `op.ts` extrahiert. Enthält `buildOpFailureDetail`, `maskOpText` und die Klon-Maskierung.
- **Neue Datei `packages/paratix/src/output.ts`-Erweiterung um zwei Exporte** (`printInfoLine`, `printWarningLine`), beide durch `maskRegisteredSecrets` und `sanitizeTerminalText`. Das war die Konsequenz aus dem Plan-Review: `output.ts` hatte für freie Meldungen nichts Passendes.
- **Der ALS-Cache liegt als `Symbol.for`-Singleton auf `globalThis`.** Diese Entscheidung stand nicht im Plan und ist die wichtigste der Umsetzung. Der Build legt `secretPrewarm` in **zwei** Bundles ab (`dist/cli.js` und `dist/chunk-*.js`). Mit einer modul-lokalen `AsyncLocalStorage`-Instanz hätte der Runner den Scope in der CLI-Kopie geöffnet, während das `op`-Modul eines Nutzer-Playbooks aus der Library-Kopie liest — `apply()` hätte produktiv ein **zweites** `op read` samt zweitem Biometrie-Prompt ausgelöst, also genau das, was diese Änderung abschaffen soll. Alle Unit-Tests wären dabei grün geblieben, weil im Test nur eine Kopie existiert. Vorbild ist `LIVE_OUTPUT_STATE_KEY` in `output.ts:98`, das dasselbe Problem bereits so löst.
- **`prewarmSecrets(modules, { onBeforeFirstPrewarm })`** statt einer im Walker erzeugten Statuszeile. Hält `secretPrewarm.ts` provider-neutral: die Datei importiert weiterhin nur `types.ts` und `recipeGuard.ts`.
- **`withRunSecretScopes` in `runner.ts`**, weil die zwei verschachtelten Scopes sonst `max-nested-callbacks` verletzt hätten.
- **Der Trägersammler für die Filter-Warnung nutzt denselben Walk wie `prewarmSecrets`** und steigt damit auch in `_signals` ab. Plan-Schritt 9 nannte nur `_modules`. Eine Walk-Definition statt zwei.
- **`hasSecretPrewarmCarriers(modules)` als zusätzlicher Export** aus `secretPrewarm.ts`, aus dem Review-Befund F1 heraus entstanden (siehe unten).

### Bestätigte Plan-Zusagen

Der Reviewer hat die acht sicherheitskritischen Zusagen des Plans einzeln am Code verifiziert. Sieben trugen unverändert; die achte (Statuszeile nur bei tatsächlich vorhandener Referenz) war verletzt und wurde als F1 behoben.

## Testergebnisse

`pnpm agent:check` im Repo-Root: alle fünf Stufen grün (Lint, Format, Typecheck, Build, Test).

| Suite                     | Ergebnis                             |
| ------------------------- | ------------------------------------ |
| `packages/paratix`        | 4292 bestanden, 9 übersprungen       |
| `packages/create-paratix` | 268 bestanden                        |
| `website`, `scripts`      | 36 bestanden                         |
| **Gesamt**                | **4615 bestanden, 0 fehlgeschlagen** |

Coverage `packages/paratix` gegen die Schwellen 82/90/90/90: 86,39 % Branches, 98,18 % Functions, 95,73 % Lines, 93,71 % Statements — alle darüber.

Neu bzw. ergänzt: `test/secretPrewarm.test.ts` (neu) sowie Ergänzungen in `test/modules/op.test.ts`, `test/conditionalModules.test.ts`, `test/runner-secrets-environment.test.ts`, `test/runner-dry-run.test.ts`, `test/cli.test.ts` und `test/output.test.ts`. Die bestehenden Testfälle in `test/modules/op.test.ts` blieben ohne Anpassung ihrer Erwartungen grün — das entsprechende Akzeptanzkriterium ist erfüllt.

Die Docker-gebundene Integrationssuite war nicht einschlägig, weil weder `ssh`- noch `readFile`-Semantik berührt wurde.

## Review-Befunde

**Datum:** 2026-08-06
**Reviewer:** `effective-flow-nodejs-reviewer`

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      4 |
| Offen / Nicht umgesetzt |      1 |

Behoben wurden zwei wichtige Befunde — die Statuszeile feuerte bei jedem `when(...)`-Block, auch ohne jedes Secret (Verstoß gegen ein Akzeptanzkriterium dieses Plans), und ein Cache-Treffer registrierte den Wert nicht erneut im Secret-Sink, wodurch eine Redaktionsgarantie still verlorengehen konnte — sowie zwei Hinweise.

**Externer Review-Bericht:** `.effective-flow/review/review-report-2026-08-06-plan-op-secrets-vorab-aufloesen.md`

## Offene Punkte

- Keine offenen Punkte.
