# Paketsichere Dokumentationslinks in beiden NPM-Paketen

**Planungsstatus:** Umgesetzt
**Quelle:** `effective-flow plan`
**Empfohlener Workflow:** Documentation (`effective-flow docs`)
**Ziel-Pfad:** packages/paratix/README.md

## Anforderung

Die mit `paratix` und `create-paratix` veröffentlichten Markdown-Dateien sollen aus einem installierten NPM-Paket heraus auf alle verlinkten Dokumente führen. Derzeit verlassen fünf relative Links das jeweilige Paket: zwei im `paratix`-README, einer im `llm-guide.md` und zwei im `create-paratix`-README. Ihre Ziele liegen ausschließlich im Repository unter `docs/` und fehlen in den Tarballs. Die Links auf Troubleshooting, Migration und ADR-0006 sollen für Paketnutzer erreichbar sein; ein Distributionstest soll dieselbe Fehlerklasse künftig erkennen.

Der empfohlene Workflow ist `Documentation`, weil die sichtbare Änderung Dokumentationslinks und ihre Prüfung betrifft. Laufzeitverhalten, öffentliche API und Dateiliste der Pakete bleiben unverändert. Der Zielpfad bezeichnet das bestehende `paratix`-README als primären Einstiegspunkt; alle weiteren betroffenen Dateien sind unten ausdrücklich genannt. Eine Doku-Kategorie entfällt, da der Zielpfad eine bestehende Paketdatei außerhalb der vier `docs/`-Kategorien ist.

Planungsbasis: lokaler Checkout `404d3d43` und geprüfter GitHub-Stand `00271a0`, jeweils vom 23. September 2026. In beiden Ständen sind dieselben fünf Ziele betroffen. Der lokale Arbeitsbaum enthält sachfremde Änderungen an `CLAUDE.md` und `docs/adr/effective-flow-project-setup.md` sowie unversionierte Dateien; keine der betroffenen Paketdateien ist lokal verändert. Vor der Umsetzung sind die betroffenen Dateien gegen den dann aktuellen Branch erneut abzugleichen.

## Architekturentscheidungen

- Links zu Dokumenten, die nicht im Paket liegen, werden auf die kanonischen öffentlichen GitHub-Dateien unter `https://github.com/sebastian-software/paratix/blob/main/` umgestellt. Die drei konkreten Ziele für Migration, Troubleshooting und ADR-0006 lieferten bei einem anonymen Abruf am Planungstag HTTP 200. `main` führt bewusst zur aktuellen Online-Dokumentation; die Paket-READMEs behaupten damit keine unveränderliche, versionsgebundene Kopie.
- Der gültige paketinterne Link `packages/paratix/README.md` → `./llm-guide.md` bleibt relativ. `llm-guide.md` ist in `packages/paratix/package.json#files` enthalten und soll nach Installation lokal erreichbar bleiben.
- Die beiden bestehenden Distributionstests sind der Prüfpunkt. Sie erzeugen und entpacken bereits echte Tarballs. Der neue Check liest die tatsächlich mitgelieferten Markdown-Dateien und löst ihre relativen Dateilinks gegen den entpackten Paketinhalt auf. Ein bloßer Pfad-Check gegen den vollständigen Repository-Baum würde den Fehler nicht erkennen.
- Die Prüfung benötigt keinen Netzwerkzugriff in CI und keine neue Abhängigkeit. Externe URLs werden beim Umsetzen einmalig ohne Anmeldung geprüft; der dauerhafte Test kontrolliert die lokalen Paketgrenzen und die Existenz der drei GitHub-Zielpfade im Repository.

## Betroffene Dateien

| Datei                                                     | Beschreibung                                                                                               |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `packages/paratix/README.md`                              | Troubleshooting- und Migrationslink paketunabhängig machen; gültigen Link auf `./llm-guide.md` beibehalten |
| `packages/paratix/llm-guide.md`                           | Link auf ADR-0006 paketunabhängig machen                                                                   |
| `packages/create-paratix/README.md`                       | Migrations- und Troubleshooting-Link paketunabhängig machen                                                |
| `packages/paratix/test/postbuild/cli.dist.test.ts`        | Relative Markdown-Dateilinks im entpackten `paratix`-Tarball prüfen                                        |
| `packages/create-paratix/test/postbuild/cli.dist.test.ts` | Relative Markdown-Dateilinks im entpackten `create-paratix`-Tarball prüfen                                 |

## Implementierungsdetails

### Vorgehen

1. Die fünf `../../docs/...`-Links in den drei Paketdokumenten auf die passenden absoluten GitHub-Dateilinks umstellen. Linktext und umgebende technische Aussagen bleiben erhalten.
2. In beiden vorhandenen Postbuild-Tests die mitgelieferten Markdown-Dateien aus dem bereits entpackten Tarball prüfen. Anker ohne Dateipfad und externe HTTP(S)-Links sind keine Paketdateipfade. Jeder andere relative Dateipfad muss innerhalb der Paketwurzel bleiben und dort eine vorhandene Datei treffen; ein Escape per `..` oder ein fehlendes Ziel lässt den Test scheitern. Der Check soll mindestens `README.md` beider Pakete und das mitgelieferte `paratix/llm-guide.md` erfassen.
3. Die drei neuen GitHub-Zielpfade ohne Netzwerkabhängigkeit in CI gegen die entsprechenden Repository-Dateien absichern. Die öffentlichen URLs vor dem Abschluss noch einmal anonym auf Erreichbarkeit prüfen.
4. Beide Distributionstests und anschließend `pnpm agent:check` ausführen. Beim Review den Inhalt beider Tarballs und die Linkziele nachvollziehen.

### Randfälle

- Reine Abschnittsanker wie `#dos-and-donts` benötigen keine Paketdatei. Ein relativer Link mit Dateipfad und Anker prüft die Datei; die Ankerprüfung selbst gehört nicht zur Paketgrenzen-Regel.
- Der vorhandene Link `./llm-guide.md` muss den neuen Check bestehen. Ein Test, der alle relativen Links pauschal verbietet, wäre falsch.
- Eine Umstellung auf versionsgebundene GitHub-Tags würde bei jedem Release eine Link-Aktualisierung verlangen. Diese zusätzliche Release-Pflicht ist nicht Teil dieses Plans; falls die Dokumentation später versioniert wird, ist die Linkstrategie erneut zu entscheiden.
- Die frühere Homepage-Domain ist weiterhin nicht auflösbar und ist kein Ersatz für diese Ziele. Hosting, Website-Inhalte und NPM-Veröffentlichung gehören nicht zu diesem Arbeitspaket.

## Akzeptanzkriterien

- [x] Keiner der fünf zuvor paketfremden Links verwendet mehr `../../docs/...`; alle führen auf die jeweils richtige öffentliche GitHub-Datei für Troubleshooting, Migration oder ADR-0006.
- [x] `./llm-guide.md` bleibt im `paratix`-README erhalten und löst innerhalb des gepackten `paratix`-Tarballs auf.
- [x] Die Distributionstests prüfen alle mitgelieferten Markdown-Dateien der beiden Pakete gegen den jeweiligen entpackten Tarball. Ein absichtlich fehlendes oder aus dem Paket führendes relatives Dateiziel wird als Fehler erkannt.
- [x] Die drei GitHub-Zielpfade existieren im Repository; ihre öffentlichen URLs sind ohne Anmeldung erreichbar. CI benötigt für den Linktest keinen Netzwerkzugriff.
- [x] `pnpm --filter paratix test:dist`, `pnpm --filter create-paratix test:dist` und `pnpm agent:check` bestehen nach der Änderung.

## Validierungsplan

- Die vorhandenen Postbuild-Suiten erzeugen mit `pnpm pack` beziehungsweise `npm pack` je einen Tarball und entpacken ihn in ein temporäres Verzeichnis. Der neue Link-Check nutzt genau diese Artefakte; er darf keine Quellbaum-Datei als scheinbar gepacktes Linkziel akzeptieren.
- Ein kontrolliert fehlerhafter relativer Link demonstriert, dass die Prüfung auf fehlende Ziele und Paket-Escapes reagiert. Der gültige paketinterne Guide-Link dient als positiver Fall.
- Die drei GitHub-Ziele mit anonymem HTTP-Abruf prüfen. Netzwerkfehler werden als nicht verifiziert gemeldet und nicht durch einen erfolgreichen lokalen Pfadtest ersetzt.
- Nach den fokussierten Distributionstests den im Projekt vorgeschriebenen Check `pnpm agent:check` ausführen. Dieser umfasst Lint, Format, Typprüfung, Build und Tests.

## Annahmen und offene Punkte

- **Verifiziert:** Die drei Repository-Zieldateien existieren in lokalem Checkout und geprüftem `main`; die anonymen GitHub-Datei-URLs antworteten am Planungstag mit HTTP 200.
- **Verifiziert:** `paratix` packt `llm-guide.md`; beide bestehenden Distributionstests arbeiten mit echten Tarballs. Die Paket-READMEs sind im jeweiligen Tarball enthalten.
- **Annahme:** Leser sollen über diese Links die jeweils aktuelle Online-Dokumentation auf `main` erreichen. Bei einer späteren Anforderung an versionsgenaue Dokumentation muss die Zielstrategie angepasst werden.
- **Drift-Bedingung:** Falls sich Paket-`files`, die GitHub-Sichtbarkeit, die Dokumentationspfade oder die Distributionstests vor der Umsetzung ändern, ist dieser Plan vor dem Editieren abzugleichen. Sachfremde lokale Änderungen bleiben unangetastet.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       0 |       1 |
| Scope       |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Architektur (Hinweis):** Die kanonischen Repository-Dokumente werden verlinkt und nicht in beide Pakete kopiert. Dadurch bleibt je Dokument ein Inhaltseigentümer erhalten.
- **Fehlerfälle (Hinweis):** Anonyme Erreichbarkeit ist eine externe Eigenschaft. Sie wurde für alle drei Ziele geprüft und ist vor Veröffentlichung erneut zu prüfen; CI bleibt unabhängig vom Netzwerk.
- **Testbarkeit (Hinweis):** Der Test muss den entpackten Tarball als Wurzel verwenden. Diese Bedingung steht ausdrücklich in Vorgehen und Akzeptanzkriterien.
- **Wartbarkeit (Hinweis):** `main`-Links können auf neuere Dokumentation als die installierte Paketversion zeigen. Das ist eine bewusste aktuelle-Online-Doku-Entscheidung und in den Randfällen dokumentiert.

## Offene Punkte

- Keine offenen Punkte.

## Testergebnisse

- `pnpm --filter paratix test:dist`: bestanden, 14 von 14 Tests.
- `pnpm --filter create-paratix test:dist`: bestanden, 8 von 8 Tests.
- `pnpm agent:check`: bestanden; Lint, Format, Typprüfung, Build und vollständige Testsuite.
- `git diff --check`: bestanden; keine vom Testlauf erzeugten Projektänderungen.
- Drei öffentliche GitHub-Ziele am 23. September 2026 anonym geprüft: jeweils HTTP 200.

## Review-Befunde

- Ein unabhängiger Review fand und behob einen macOS-Pfadfehler (`/var` gegenüber `/private/var`) in beiden Linkprüfungen.
- Referenzlinks in Markdown werden nach einem weiteren Review-Befund ebenfalls erfasst und durch Negativbeispiele geprüft.
- Der abschließende Review fand keine offenen P1/P2-Befunde; die Laufzeitvalidierung ist bestanden.
