# Agent-Discovery und öffentliche Nutzung von create-paratix

**Planungsstatus:** Umgesetzt
**Quelle:** `effective-flow plan`
**Empfohlener Workflow:** Feature (`effective-flow build`)

## Anforderung

Ein mit `create-paratix` erzeugtes Projekt soll von Codex und Claude Code direkt als
Paratix-Projekt erkannt werden. Die generierten Agent-Anweisungen sollen auf die zur
installierten Paratix-Version gehörende Autorenanleitung verweisen und keine internen
Anweisungen des Paratix-Repositories übernehmen. Die Paketdokumentation soll außerdem den
CLI-Hilfetext und die bereits veröffentlichte programmatische API verständlich erklären.

Das ist ein Feature, weil neue Projekte zusätzliche Dateien erhalten und `create-paratix`
einen erfolgreichen `--help`-/`-h`-Pfad bekommt. Eine API-Bereinigung oder Änderung der
Scaffold-Bootstrap-Logik gehört nicht dazu.

Planungsbasis: GitHub-`main` `00271a0` vom 23. September 2026, geprüft in einem sauberen
Checkout. Der lokale Arbeitsbaum steht auf `404d3d4`, ist zehn Commits hinter
`origin/main` und enthält sachfremde Änderungen an `CLAUDE.md`,
`docs/adr/effective-flow-project-setup.md` sowie unversionierte Dateien. Vor der Umsetzung
sind die betroffenen Dateien auf dem Ausführungsbranch erneut mit `main` abzugleichen;
fremde Änderungen bleiben unangetastet.

## Architekturentscheidungen

- `AGENTS.md` ist die einzige inhaltliche Agent-Anweisung im generierten Projekt.
  `CLAUDE.md` enthält nur `@AGENTS.md`, entsprechend der bereits verwendeten Konvention
  im Repository-Root. Beide Dateien werden standardmäßig für Root- und Admin-Bootstrap
  erzeugt; es gibt keinen zusätzlichen Scaffold-Schalter. Diese Kombination folgt
  der [Codex-Dokumentation zur automatischen `AGENTS.md`-Suche](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
  und der [Claude-Code-Dokumentation zu `@AGENTS.md`-Imports](https://code.claude.com/docs/en/memory#share-one-file-with-other-coding-tools).
- Die Agent-Anweisung bleibt kurz und projektspezifisch: Bei Änderungen an
  `server.ts`, Playbooks oder eigenen Modulen soll zuerst
  die Autorenanleitung unter `node_modules/paratix/llm-guide.md#agent-authoring-guidance`
  gelesen werden. Der generierte Text verwendet dafür einen relativen Markdown-Link.
  Er nennt den Importvertrag `paratix`/`paratix/modules` und verweist für die
  tatsächliche API auf den Guide, statt ihn zu duplizieren. Ist `node_modules`
  noch nicht vorhanden, muss zunächst die Projektinstallation abgeschlossen
  werden. Hostnamen, Schlüssel und andere Scaffold-Eingaben werden nicht in
  Agent-Dateien übernommen.
- Die neuen Dateien laufen durch den bestehenden `writeManagedScaffoldFile()`-Pfad.
  Sein atomarer `wx`-Schreibmodus und die Prüfung auf vorhandene Dateien oder Symlinks
  gelten auch für `AGENTS.md` und `CLAUDE.md`. `writeProjectFiles()` bleibt beim
  bisherigen nicht-atomaren Direktaufruf; `scaffoldProject()` behält sein Staging.
- `--help` und `-h` sind reine CLI-Ausgaben auf `stdout` mit Exit-Code 0, ohne
  Projektname, Prompts, Installation oder Dateischreibzugriff. Die Erkennung behandelt
  die Flags nur als eigenständige Optionen, nicht als Werte anderer Optionen.
  Die Hilfe beginnt mit dem bestehenden `getCliUsage()`-Text und ergänzt kurze
  Beschreibungen aller fünf Wertoptionen sowie beider Hilfeflags. Der bisherige
  Usage-Text in Fehlerpfaden und die öffentliche Rückgabeform von
  `parseCliArguments()` bleiben erhalten. Eine `--version`-Option wird nicht ergänzt.
- Die `create-paratix`-README beschreibt sowohl die CLI-Optionen als auch alle aktuell
  aus `src/index.ts` exportierten Funktionen und Typen, gruppiert nach
  Projektgenerierung, Validierung und CLI-/Prompt-Helfern. Die Hauptbeispiele nutzen
  `scaffoldProject()`, `writeProjectFiles()`, `ScaffoldOptions` und
  `InitialUserConfig`. Sie erklären Installation, Rückgabewerte und den Unterschied
  zwischen gestagtem und direktem Schreiben, ohne bestehende Exports umzubenennen oder
  als privat auszugeben. Der für `scaffoldProject()` erforderliche
  Paketmanager-Parameter wird mit seiner tatsächlichen Objektform gezeigt;
  ein derzeit nicht aus dem Root exportierter `PackageManager`-Typ wird nicht
  als importierbar dargestellt. Die Dokumentation benennt auch, dass
  `scaffoldProject()` bei einem vom Installer gemeldeten Fehlschlag `false`
  liefert, die Dateien behält und `process.exitCode` auf 1 setzt.
  `writeProjectFiles()` gibt `void` zurück und verwendet ohne Optionen
  `host: "1.2.3.4"` sowie den Admin-Benutzer `paratix`; der Host ist ein
  Platzhalter, der vor einem echten Apply ersetzt werden muss.

## Betroffene Dateien

| Datei                                                     | Beschreibung                                                                                 |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `packages/create-paratix/src/templates.ts`                | Statische Vorlagen für die beiden Agent-Dateien                                              |
| `packages/create-paratix/src/scaffoldFiles.ts`            | Agent-Dateien über den bestehenden Managed-Writer in jedem Scaffold erzeugen                 |
| `packages/create-paratix/src/index.ts`                    | Nebenwirkungsfreien CLI-Hilfepfad vor Prompts und Scaffolding behandeln                      |
| `packages/create-paratix/src/scaffoldConfig.ts`           | Vorhandenen Usage-Text für eine vollständige, gemeinsame Hilfe nutzen oder behutsam ergänzen |
| `packages/create-paratix/README.md`                       | Agent-Dateien, CLI-Optionen und sämtliche Root-Exports dokumentieren                         |
| `packages/create-paratix/test/project-files.test.ts`      | Inhalt und Überschreibschutz der Agent-Dateien prüfen                                        |
| `packages/create-paratix/test/scaffold-project.test.ts`   | Beide Agent-Dateien im gestagten Erfolgsweg und bei Installationsfehler prüfen               |
| `packages/create-paratix/test/postbuild/cli.dist.test.ts` | Gepackte CLI-Hilfe und programmatische README-Beispiele aus Consumer-Sicht prüfen            |

## Implementierungsdetails

### Vorgehen

1. Agent-Vorlagen mit abschließendem Zeilenumbruch anlegen. Die Anweisung
   verweist auf den mit dem Projekt installierten `paratix`-Guide und enthält
   nur Regeln für das generierte Projekt. `CLAUDE.md` verweist auf `AGENTS.md`.
2. Beide Vorlagen in `writeSharedScaffoldFiles()` über
   `writeManagedScaffoldFile()` schreiben. Die vorhandenen Varianten für
   `writeProjectFiles()` und `scaffoldProject()` bleiben am selben zentralen Pfad.
3. Eine frühe CLI-Hilfeerkennung für `--help` und `-h` einführen. Sie muss auch
   bei einem nachgestellten Flag funktionieren, aber Optionswerte korrekt
   überspringen. Den vorhandenen `getCliUsage()`-Text als erste Hilfezeile
   wiederverwenden und die fünf Wertoptionen sowie die beiden Hilfeflags
   jeweils kurz erklären. Bestehende Fehlermeldungen bleiben unverändert;
   `parseCliArguments()` darf für Bibliotheksnutzer nicht inkompatibel
   geändert werden.
4. Die README-Dateitabelle um `AGENTS.md` und `CLAUDE.md` erweitern. Eine
   kompakte CLI-Referenz soll Pflichtargument, sämtliche vorhandenen Optionen,
   interaktive Defaults und den neuen Hilfepfad erklären. Eine getrennte
   programmatische Referenz soll die aktuelle Exportmenge in `src/index.ts`
   vollständig abdecken und kopierbare Beispiele mit realen Typen zeigen.
5. Die bestehende Unit- und Distributionsteststruktur ergänzen. Neue Tests
   sollen die Agent-Dateien für Root- und Admin-Projekte, Kollisionen mit
   regulären Dateien und Symlinks, erhaltene Dateien nach einem bloß
   fehlgeschlagenen Installationslauf sowie Hilfeausgaben aus dem gepackten
   CLI prüfen. Beide dokumentierten Hauptbeispiele für `scaffoldProject()`
   und `writeProjectFiles()` werden gegen das gepackte Paket typgeprüft.

### Umsetzung

- `AGENTS.md` und `CLAUDE.md` werden über den vorhandenen zentralen Managed-Writer
  für beide Bootstrap-Varianten erzeugt. Die Agent-Anweisung verweist auf den
  installierten Paratix-Guide und die beiden Paket-Entry-Points.
- Der CLI-Einstieg erkennt `--help` und `-h` vor Parser, Prompts und Scaffolding.
  Bekannte Optionswerte werden bei der Hilfeflag-Suche übersprungen;
  `parseCliArguments()` und die bisherigen Fehlerpfade bleiben unverändert.
- Die Paket-README dokumentiert die generierten Dateien, die CLI-Optionen,
  alle Root-Exports und beide programmatischen Hauptaufrufe. Der
  Distributionstest extrahiert die beiden TypeScript-Beispiele aus der
  gepackten README und prüft sie gegen die gepackten Typdefinitionen.

### Randfälle

- Ein vorhandenes `AGENTS.md` oder `CLAUDE.md` darf nicht überschrieben
  werden. Beim direkten `writeProjectFiles()`-Aufruf können wie bisher zuvor
  geschriebene Dateien bestehen bleiben; dies ist in der programmatischen
  Dokumentation klar zu benennen. Beim gestagten `scaffoldProject()` darf eine
  Kollision kein fremdes Zielverzeichnis beschädigen.
- Scheitert nur die Dependency-Installation und liefert der Installer `false`,
  bleibt das erzeugte Projekt einschließlich Agent-Dateien bestehen. Der Guide
  unter `node_modules` ist erst nach erfolgreicher Installation verfügbar.
- `writeProjectFiles()` erstellt den Zielordner über den vorhandenen
  nicht-rekursiven Schreibpfad; dessen Elternverzeichnis muss bereits
  existieren. Die README darf keinen darüber hinausgehenden automatischen
  Verzeichnisaufbau versprechen.
- Die Hilfe darf `--help` oder `-h` als Wert von etwa `--host` nicht als
  Hilfewunsch deuten. Ohne Hilfeflag bleiben fehlende Projektargumente und
  unbekannte Optionen Fehler.
- Die generierten Agent-Dateien dürfen keine lokalen Repository-Pfade,
  Contributor-Checks, konkreten Serverdaten oder Geheimnisse enthalten.
- Claude Code liest `AGENTS.md` je nach Version und Einstellung auch direkt.
  Der explizite `CLAUDE.md`-Import bleibt trotzdem sinnvoll und lädt den
  Inhalt laut aktueller Claude-Code-Dokumentation nicht doppelt.
- `context7.json`, der Release-Refresh und das Root-`CLAUDE.md` existieren
  bereits. Sie werden für diese Änderung nicht erneut angelegt oder
  umgestaltet. Die separat festgestellten kaputten relativen NPM-Links sind
  ebenfalls nicht Teil dieses Arbeitspakets.

## Akzeptanzkriterien

- [x] CLI sowie `writeProjectFiles()` und `scaffoldProject()` erzeugen bei
      Root- und Admin-Bootstrap jeweils `AGENTS.md` und `CLAUDE.md` mit
      identischem, formatiertem Inhalt; `CLAUDE.md` enthält `@AGENTS.md`.
- [x] `AGENTS.md` verweist auf die installierte Paratix-Autorenanleitung und
      nennt die korrekten Paket-Entry-Points. Es enthält keine generierten
      Host-, Schlüssel- oder Credential-Werte und keine internen Repo-Regeln.
- [x] Vorhandene Dateien und Symlinks an beiden neuen Zielpfaden werden nicht
      überschrieben; die vorhandenen Staging- und Partial-Success-Verträge
      bleiben erhalten.
- [x] `create-paratix --help` und `create-paratix -h` liefern aus dem
      gepackten CLI Exit-Code 0 und Hilfe auf `stdout`, die alle fünf
      Wertoptionen sowie `-h` und `--help` mit kurzer Erklärung nennt, ohne
      Projektdateien zu erzeugen oder einen Prompt zu starten. Ein Hilfeflag
      nach dem Projektnamen funktioniert; Optionswert- und Fehlerfälle
      bleiben korrekt.
- [x] Die Paket-README listet beide Agent-Dateien, sämtliche CLI-Optionen
      und jeden Export aus `src/index.ts` auf. Ihre Hauptbeispiele sind mit
      den Typen des gepackten Pakets typprüfbar; Staging, Direktaufruf,
      Standardwerte und Installationsfehler sind zutreffend beschrieben.
- [x] `pnpm --filter create-paratix test` und `pnpm agent:check` bestehen auf
      dem Ausführungsbranch. Der bestehende Installationsintegrationstest
      besteht für Root- und Admin-Variante, sofern die dafür benötigte
      Registry erreichbar ist.

## Validierungsplan

- Im Paket `pnpm --filter create-paratix test` ausführen; die gezielten
  Unit- und Distributionstests prüfen Dateiinhalte, Konflikte, CLI-Hilfe
  einschließlich aller sieben Optionsbeschreibungen sowie beide README-
  Hauptbeispiele mit Consumer-Typen aus dem gepackten Paket.
- Die dokumentierte Exportliste direkt mit den benannten Exports aus
  `packages/create-paratix/src/index.ts` abgleichen; den Paketmanager-Parameter
  und beide Hauptbeispiele mit den erzeugten `.d.ts`-Dateien vergleichen.
- `pnpm --filter create-paratix test:integration` ausführen, um in beiden
  Scaffold-Varianten die Installation und deren eigene Skripte einschließlich
  `format:check` zu prüfen. Diese Suite benötigt Registry-Zugriff; falls
  der Zugriff fehlt, das Ergebnis als nicht geprüft ausweisen und den
  gezielten Offline-Formatcheck der Agent-Dateien separat durchführen.
- Abschließend `pnpm agent:check` im Repository-Root ausführen. Die
  Docker-gebundene Paratix-Integration ist hier nicht erforderlich, da
  weder `ssh`- noch `readFile`-Semantik geändert wird.
- Vor der Umsetzung die betroffenen Dateien mit Planungsbasis `00271a0`
  vergleichen. Bei geänderten CLI-Exports, Scaffold-Dateipfaden oder
  Testskripten den Plan an den neuen Vertrag anpassen; bloße
  Zeilenverschiebungen sind kein Hindernis.

## Annahmen und offene Punkte

- Verifiziert: `writeScaffoldFiles()` ist der gemeinsame Dateipfad für
  CLI und programmatische Generierung; `writeManagedScaffoldFile()` schützt
  bestehende Dateien und Symlinks mit `wx`.
- Verifiziert: `paratix` liefert `llm-guide.md` im NPM-Paket aus; die
  Autorenanleitung beginnt dort unter `#agent-authoring-guidance`.
- Verifiziert: Die gegenwärtige Paket-README beschreibt weder alle
  `src/index.ts`-Exports noch `--help`; die CLI hat noch keinen
  erfolgreichen Hilfepfad.
- Verifiziert: Die offiziellen Dokumentationen von Codex und Claude Code
  beschreiben die automatische Suche nach Projektanweisungen und den
  `@AGENTS.md`-Import in `CLAUDE.md`; die Verweise stehen bei der
  Architekturentscheidung.
- Annahme: Agent-Discovery ist ein Standardbestandteil jedes neuen
  Projekts. Ein konfigurierbares Opt-out wäre zusätzliche Produktfläche
  ohne erkennbaren Bedarf und ist nicht vorgesehen.
- Annahme: Die generierten Agent-Dateien und die Paketdokumentation sind
  auf Englisch, wie die bestehenden Scaffold-Texte und Paket-READMEs.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       1 |       0 |
| Umfang      |        0 |       1 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

### Befunde

- Wichtig, Umfang: Eine reine Usage-Zeile wäre keine vollständige CLI-Hilfe.
  Der Plan verlangt jetzt kurze Beschreibungen der fünf Wertoptionen und
  beider Hilfeflags, während bestehende Fehlertexte erhalten bleiben.
- Wichtig, Testbarkeit: Ein einziges typgeprüftes Beispiel würde die beiden
  dokumentierten Hauptaufrufe nicht absichern. Der Plan verlangt nun einen
  Consumer-Typcheck für `scaffoldProject()` und `writeProjectFiles()`.
- Hinweis, Fehlerfälle: Der Direktaufruf, der Platzhalter-Host und die
  `process.exitCode`-Nebenwirkung bei einem Installationsfehler sind als
  API-Verträge ausdrücklich in der Dokumentation vorgesehen. Der
  Installationsfehler und die Verfügbarkeit des Guides danach bleiben
  gezielte Randfälle.
- Keine offenen Befunde. Die offiziellen Codex- und Claude-Code-Anleitungen
  bestätigen das gewählte `AGENTS.md`-/`CLAUDE.md`-Muster.

## Offene Punkte

- Keine offenen Punkte.

## Testergebnisse

**Datum:** 23. September 2026

| Prüfung                                         | Ergebnis                                                                                                                               |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm agent:check`                              | Bestanden: Lint, Format, Typprüfung, Builds und Repository-Tests; darin 273 `create-paratix`-Unit- und 11 gepackte Distributionstests. |
| `pnpm --filter create-paratix test`             | Über `pnpm agent:check` vollständig ausgeführt; ein separater identischer Lauf wurde vermieden.                                        |
| `pnpm --filter create-paratix test:integration` | Bestanden: Root- und Admin-Projekt installieren und bestehen jeweils Typprüfung, Lint und Formatprüfung.                               |
| `git diff --check origin/main`                  | Bestanden.                                                                                                                             |

Ein erster Integrationslauf scheiterte, weil `paratix/dist` vor dem
Repository-Build noch nicht vorhanden war. Zwei Zwischenläufe des
Repository-Gates zeigten Lint-Befunde in den neuen Änderungen; beide wurden
behoben. Der abschließende Gate- und Integrationslauf bestand in dieser
Reihenfolge ohne Fehler. Die Docker-gebundene Paratix-Integration war nicht
erforderlich, da weder `ssh`- noch `readFile`-Semantik geändert wurde.

## Review-Befunde

**Datum:** 23. September 2026
**Reviewer:** Effective Flow Node.js-/CLI-Reviewer

Keine Befunde.
