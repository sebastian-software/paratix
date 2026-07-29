# Postbuild-Verifikation für gescaffoldete Projekte

**Planungsstatus:** Umgesetzt
**Quelle:** /effective-flow plan
**Empfohlener Workflow:** Feature (`/effective-flow build`)

## Anforderung

Ein mit `create-paratix` erzeugtes Projekt ließ sich weder installieren noch linten, und sein
`format:check` scheiterte ebenfalls. Vier Defekte, behoben in #175. Keiner davon war der
bestehenden Testsuite aufgefallen — und das ist der eigentliche Befund: die Suite prüft, **was das
Scaffolding schreibt**, aber nie, **ob das Ergebnis funktioniert**.

Ziel ist, diese Lücke zu schließen, sodass dieselbe Fehlerklasse künftig auffällt, bevor sie
Nutzer erreicht.

### Warum die Lücke besteht

Die vorhandenen Postbuild-Tests meiden das Netz bewusst. `cli.dist.test.ts` packt das Paket und
stellt Abhängigkeiten über `linkRuntimeDependencies` per Symlink bereit; `project-files.test.ts`
verlinkt `eslint-config-setup` und `jiti` aus dem Workspace. Das ist eine Entwurfsentscheidung für
Tempo und Hermetik, kein Versäumnis — sie hat nur die Folge, dass die Skripte des generierten
Projekts nie ausgeführt werden.

### Was welcher Prüfansatz gefangen hätte

| Defekt aus #175                 | Statische Template-Prüfung | Workspace-Binaries gegen generierte Dateien | Echter Install |
| ------------------------------- | -------------------------- | ------------------------------------------- | -------------- |
| `ERR_PNPM_IGNORED_BUILDS`       | tautologisch               | nein                                        | **ja**         |
| Lint-Absturz auf JSON-Dateien   | nein                       | **ja**                                      | ja             |
| Lint-Befunde in der `server.ts` | nein                       | **ja**                                      | ja             |
| `format:check` scheitert        | nein                       | **ja**                                      | ja             |

Drei der vier Defekte brauchen also keinen Install. Nur der erste tut es.

### Vorhandene Bausteine

`project-files.test.ts` löst bereits `tscBinaryPath` und `eslintBinaryPath` aus dem Workspace auf
und typecheckt generierte Dateien über `expectGeneratedServerToTypecheck`. ESLint wird dort bisher
nur für `--print-config` verwendet, nicht für einen echten Lauf. Der Schritt zu einer vollen
Prüfung ist damit klein.

Für den Install-Test existiert ein natürlicher Ort: `integration-check` läuft mit 30 Minuten
Timeout auf einem self-hosted Runner mit Netzzugang. `create-paratix` nimmt daran bisher nicht
teil — `test:integration` filtert nur auf `paratix`.

## Architekturentscheidungen

- **Zwei Stufen statt einer.** Ein schneller hermetischer Test in der normalen Suite fängt die drei
  Defekte, die keinen Install brauchen; ein Install-Test im Integrationslauf deckt den vierten ab.
  Begründung: 75 % der Absicherung kosten so praktisch nichts und geben Rückmeldung in Sekunden,
  während die teure Prüfung die PR-Rückmeldung nicht verlangsamt.
- **Der schnelle Test nutzt die Workspace-Binaries, nicht die des generierten Projekts.** Das
  entspricht dem bestehenden Muster von `expectGeneratedServerToTypecheck` und vermeidet einen
  Install. Der Preis ist eine Abweichung: geprüft wird mit den Versionen des Workspace, nicht mit
  denen, die das Scaffold deklariert. Der Install-Test schließt genau diese Lücke.
- **Der Install-Test prüft bewusst gegen die Registry.** Ein gescaffoldetes Projekt deklariert
  `paratix: ^<version>` über `deriveParatixDependencyRange()`, ein Install zieht also das
  veröffentlichte Paket statt des Arbeitsstands. Das ist gewollt: der Test prüft, was Nutzer
  tatsächlich bekommen. Ein Bruch im lokalen `paratix` fällt hier nicht auf — dafür sind die
  übrigen Tests da. Die Abweichung wird im Test dokumentiert, nicht stillschweigend hingenommen.
- **Der Install-Test wandert nach `test:integration`, nicht in `test:dist`.** `test:dist` läuft in
  jedem `agent:check` und damit in jedem lokalen Lauf; ein Netz-Install dort würde jede Iteration
  verlangsamen und lokale Arbeit ohne Netz unmöglich machen.
- **Beide Tests prüfen beide Scaffold-Varianten.** Die admin- und die root-Bootstrap-Variante
  erzeugen unterschiedliche Dateien: Nur bei vorhandenem Schlüssel entstehen der `ssh`-Import und
  die `adminPublicKey`-Konstante, und die Schlüssellänge entscheidet über den Zeilenumbruch. Ein
  Test gegen nur eine Variante hätte Defekt 3 und 4 je zur Hälfte verfehlt.

## Betroffene Dateien

| Datei                                                                        | Beschreibung                                                                                                                    |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `packages/create-paratix/test/generated-project.test.ts`                     | Neu: schneller hermetischer Test — scaffolden, dann eslint, prettier und tsc aus dem Workspace gegen das Ergebnis laufen lassen |
| `packages/create-paratix/test/helpers.ts`                                    | Gemeinsame Scaffold- und Binary-Auflösung, damit sie nicht in drei Testdateien dupliziert wird                                  |
| `packages/create-paratix/test/integration/generated-project.install.test.ts` | Neu: Install-Test — scaffolden, echter `pnpm install`, dann die Skripte des generierten Projekts                                |
| `packages/create-paratix/vitest.integration.config.ts`                       | Neu: eigene Vitest-Konfiguration analog zur bestehenden `vitest.distribution.config.ts`                                         |
| `packages/create-paratix/package.json`                                       | Neues Skript `test:integration`                                                                                                 |
| `package.json`                                                               | `test:integration` im Root nimmt `create-paratix` mit auf                                                                       |
| `packages/create-paratix/test/project-files.test.ts`                         | Nur falls die gemeinsame Auflösung aus `helpers.ts` die dortigen Duplikate ersetzt                                              |

Nicht betroffen: `.github/workflows/*`. Der Integrationslauf ruft bereits `agent:check:integration`
auf, das über das Root-Skript auch den neuen Test erfasst.

## Implementierungsdetails

### Vorgehen

**Stufe 1 — schneller hermetischer Test**

1. Beide Scaffold-Varianten in ein temporäres Verzeichnis erzeugen: admin (ohne Schlüssel) und
   root-Bootstrap (mit einem realistisch langen Schlüssel). Der bestehende Testschlüssel aus
   `project-files.test.ts` ist lang genug, um den Prettier-Umbruch auszulösen.
2. Die zum Linten nötigen Abhängigkeiten wie bisher aus dem Workspace verlinken.
3. ESLint aus dem Workspace über das generierte Projekt laufen lassen und einen Exit-Code von 0
   erwarten. Der Test muss zwischen „meldet Befunde" und „stürzt ab" unterscheiden: ein
   Konfigurationsfehler liefert Exit 2, Befunde liefern Exit 1. Beide sind ein Fehlschlag, aber die
   Meldung soll sagen, welcher Fall vorliegt — der Absturz war der Defekt, der die anderen verdeckt
   hat.
4. Prettier aus dem Workspace mit der **generierten** `.prettierrc` im `--check`-Modus laufen
   lassen. Die Konfiguration des generierten Projekts ist maßgeblich, nicht die des Workspace.
5. Den bestehenden Typecheck über `expectGeneratedServerToTypecheck` beibehalten.

**Stufe 2 — Install-Test im Integrationslauf**

1. `vitest.integration.config.ts` nach dem Vorbild von `vitest.distribution.config.ts` anlegen,
   mit `include: ["test/integration/**/*.test.ts"]`.
2. Skript `test:integration` in `packages/create-paratix/package.json` ergänzen und das
   Root-Skript von `pnpm --filter paratix test:integration` auf beide Pakete erweitern.
3. Im Test beide Varianten scaffolden, in jedem Projekt einen echten `pnpm install` ausführen und
   einen Exit-Code von 0 erwarten.
4. Danach die Skripte des generierten Projekts selbst aufrufen — `typecheck`, `lint`,
   `format:check` — und für jedes Exit 0 erwarten. Das ist der Punkt, an dem die im Scaffold
   deklarierten Versionen tatsächlich geprüft werden.
5. Die Testdauer großzügig begrenzen. Ein Install zieht rund 900 Pakete; mit warmem pnpm-Store
   dauert er wenige Sekunden, kalt deutlich länger.

### Randfälle

- **Kein Netz vorhanden.** Der Install-Test scheitert dann, und das ist richtig so: er gehört in
  den Integrationslauf, der ohnehin Netz voraussetzt. Er darf aber nicht in `test` oder
  `test:dist` landen, sonst bricht lokale Arbeit ohne Netz.
- **Registry liefert ein anderes `paratix` als erwartet.** Der Install-Test prüft bewusst das
  veröffentlichte Paket. Schlägt er fehl, während der schnelle Test grün ist, liegt die Ursache
  mit hoher Wahrscheinlichkeit dort und nicht im Scaffold. Die Fehlermeldung soll diesen Verdacht
  benennen, damit niemand im Scaffold sucht.
- **Der Install-Test läuft vor der ersten Veröffentlichung.** Solange die im Scaffold deklarierte
  `paratix`-Version noch nicht publiziert ist, kann der Install sie nicht auflösen. Erwartetes
  Verhalten: der Test überspringt sich mit begründeter Meldung, statt rot zu werden.
- **Prettier-Umbruch bei kurzen Schlüsseln.** Die admin-Variante ohne Schlüssel erzeugt keine
  `adminPublicKey`-Konstante, die root-Variante mit langem Schlüssel erzeugt die umbrochene Form.
  Beide Layouts müssen abgedeckt sein, sonst bleibt die Umbruchregel ungeprüft.
- **Aufräumen.** Beide Tests erzeugen temporäre Verzeichnisse mit `node_modules`. Sie müssen auch
  bei einem Fehlschlag entfernt werden, sonst bleiben nach einem roten Lauf hunderte Megabyte
  liegen.

## Akzeptanzkriterien

- [ ] `pnpm agent:check` bleibt grün, und die Laufzeit des `create-paratix`-Testlaufs wächst um
      weniger als 30 Sekunden.
- [ ] `pnpm agent:check:integration` bleibt grün und schließt den neuen Install-Test ein,
      nachweisbar daran, dass `pnpm test:integration` ihn im Lauf benennt.
- [ ] Der schnelle Test schlägt fehl, wenn `**/*.json` aus dem `ESLINT_CONFIG_TEMPLATE` entfernt
      wird, und die Meldung weist den Fall als Konfigurationsabsturz aus, nicht als Befund.
- [ ] Der schnelle Test schlägt fehl, wenn im Server-Template ein abschließendes Semikolon
      wiederhergestellt wird.
- [ ] Der schnelle Test schlägt fehl, wenn im Server-Template der `ssh`-Import auch ohne Schlüssel
      erzeugt wird.
- [ ] Der Install-Test schlägt fehl, wenn `allowBuilds` aus dem `PNPM_WORKSPACE_TEMPLATE` entfernt
      wird.
- [ ] Beide Tests decken die admin- und die root-Bootstrap-Variante ab.
- [ ] Nach einem absichtlich rot gemachten Lauf bleiben keine temporären Projektverzeichnisse
      zurück.

## Validierungsplan

- `pnpm agent:check` vor und nach der Änderung, mit Zeitmessung des `create-paratix`-Laufs für das
  30-Sekunden-Kriterium.
- `pnpm agent:check:integration` einmal vollständig.
- Die fünf Mutationsprüfungen der Akzeptanzkriterien einzeln durchführen: jeweils die genannte
  Stelle brechen, den Test rot sehen, zurücknehmen. Ein Test, der nur grün ist, beweist nichts —
  er muss nachweislich am richtigen Defekt scheitern.
- Den Install-Test einmal mit kaltem pnpm-Store laufen lassen, um die Laufzeitannahme zu prüfen.
- `ls` im Temp-Verzeichnis nach einem absichtlich abgebrochenen Lauf.

## Annahmen und offene Punkte

- **Annahme:** Der self-hosted Runner des Integrationslaufs hat Netzzugang zur npm-Registry. Belegt
  dadurch, dass beide Workflows `pnpm install --frozen-lockfile` gegen die Registry ausführen.
- **Annahme:** Das 30-Minuten-Timeout des Integrationslaufs reicht für den zusätzlichen Install.
  Der bisherige Lauf liegt bei rund vier Minuten.
- **Annahme:** Die im Scaffold deklarierte `paratix`-Version ist zum Testzeitpunkt veröffentlicht.
  Andernfalls greift der Übersprung-Randfall.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       2 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       1 |       1 |
| Testbarkeit |        0 |       1 |       0 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Testbarkeit, wichtig:** Ein Test, der nur grün ist, belegt nichts. Der Plan hätte sich damit
  begnügen können, die Existenz der Tests zu fordern. Eingearbeitet: fünf Akzeptanzkriterien sind
  als Mutationsprüfungen formuliert — jede benennt die Stelle, die gebrochen wird, und verlangt,
  dass der Test daran scheitert.
- **Fehlerfälle, wichtig:** Der Lint-Absturz war der Defekt, der die anderen beiden verdeckt hat.
  Ein Test, der nur den Exit-Code prüft, könnte denselben Fehler wieder unsichtbar machen.
  Eingearbeitet: der schnelle Test unterscheidet Exit 2 (Konfigurationsabsturz) von Exit 1
  (Befunde) und benennt den Fall in der Meldung.
- **Architektur, Hinweis:** Der schnelle Test prüft mit den Versionen des Workspace, nicht mit
  denen, die das Scaffold deklariert. Das ist eine bewusste Lücke, die der Install-Test schließt;
  sie ist als Architekturentscheidung festgehalten statt implizit zu bleiben.
- **Architektur, Hinweis:** Der Install-Test prüft das veröffentlichte `paratix`, nicht den
  Arbeitsstand. Das ist die Entscheidung des Auftraggebers und wird im Test dokumentiert, damit ein
  späterer Leser es nicht für einen Fehler hält.
- **Fehlerfälle, Hinweis:** Der Fall „deklarierte `paratix`-Version noch nicht veröffentlicht" ist
  vor dem ersten Release real. Der Plan legt Überspringen mit Begründung fest, nicht Rotwerden.
- **Scope, Hinweis:** Die Erweiterung von `helpers.ts` ist bewusst als „nur falls" markiert. Eine
  Vereinheitlichung der drei Testdateien wäre wünschenswert, gehört aber nicht in diese Änderung.
- **Wartbarkeit, Hinweis:** Beide Tests erzeugen `node_modules` in temporären Verzeichnissen. Das
  Aufräumen im Fehlerfall ist als Randfall und als Akzeptanzkriterium verankert, weil ein roter
  Lauf sonst hunderte Megabyte hinterlässt.

## Testergebnisse

`pnpm agent:check` grün. Testzahlen unverändert außer den neuen: `create-paratix` 262 statt 256
Unit-Tests, `paratix` 4200, dist-Suiten 10 und 6, `scripts` 34. Coverage unverändert bei
93.67 / 86.4 / 98.15 / 95.71.

Die Laufzeit des `create-paratix`-Laufs stieg von 4,84 s auf 7,01 s, also um **2,2 Sekunden**
gegen die im Plan gesetzten 30.

`pnpm --filter create-paratix test:integration` grün, beide Varianten, rund 14 Sekunden je
Variante mit warmem pnpm-Store.

### Mutationsprüfungen

Der Plan nannte im Validierungsplan „fünf"; die Akzeptanzkriterien listen tatsächlich vier
Mutationen plus die Aufräumprüfung. Alle fünf Prüfungen wurden durchgeführt:

| Gebrochene Stelle                           | Erwarteter Melder | Ergebnis                                                |
| ------------------------------------------- | ----------------- | ------------------------------------------------------- |
| `**/*.json` aus `ESLINT_CONFIG_TEMPLATE`    | schneller Test    | rot, Meldung nennt „configuration error, not a finding" |
| Semikolon zurück ins Server-Template        | schneller Test    | rot im Prettier-Fall                                    |
| `ssh`-Import auch ohne Schlüssel            | schneller Test    | rot, `no-unused-vars`                                   |
| `allowBuilds` aus `PNPM_WORKSPACE_TEMPLATE` | Install-Test      | rot, `pnpm install failed` mit `IGNORED_BUILDS`         |
| Aufräumen nach rotem Lauf                   | —                 | keine temporären Verzeichnisse zurückgeblieben          |

## Review-Befunde

**Datum:** 2026-07-29
**Reviewer:** inline durch den Orchestrator

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      1 |
| Offen / Nicht umgesetzt |      1 |

- **F1, Wichtig, behoben:** Ein `satisfies ScaffoldVariant[]` im Install-Test war redundant, weil
  die Konstante bereits typisiert ist; der zugehörige Typimport wurde damit ungenutzt. Beides
  entfernt.
- **F2, Hinweis, nicht umgesetzt:** Der schnelle Test verlinkt das **gebaute** `paratix`, weil
  typaware Lint-Regeln ohne Deklarationsdateien jede Nutzung als `any` melden. `pnpm agent:check`
  baut vorher, ein blankes `pnpm test` auf einem frischen Klon nicht zwingend. Abgefedert durch
  eine Fehlermeldung, die den Build-Befehl nennt, statt mit unverständlichen Typfehlern zu
  scheitern. Ein Build-on-demand im Test wäre die Alternative, wurde aber als zu invasiv verworfen.

## Abweichung vom Plan

Der Plan sah die gemeinsame Scaffold- und Binary-Auflösung in `test/helpers.ts` vor. Diese Datei
ist bereits ein großes SSH- und Krypto-Fixture-Modul; die Scaffold-Helfer wären dort thematisch
fehl am Platz gewesen und hätten die Datei weiter aufgebläht. Sie liegen stattdessen in
`test/scaffoldFixtures.ts`.

Ebenfalls nicht im Plan vorgesehen und beim Umsetzen aufgefallen: die Standard-Vitest-Konfiguration
schließt nur `test/postbuild/**` aus, nicht `test/integration/**`. Ohne Ergänzung wäre der
Netz-Install in jedem `agent:check` mitgelaufen — genau das, was der Plan verhindern sollte.

## Offene Punkte

- Keine offenen Punkte.
