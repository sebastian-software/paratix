# Public API, Typdeklarationen und Guide synchronisieren

**Planungsstatus:** Umgesetzt
**Quelle:** effective-flow plan
**Empfohlener Workflow:** Bugfix (`effective-flow fix`)

## Anforderung

Die veröffentlichte API des npm-Pakets `paratix`, die daraus erzeugten Typdeklarationen und die als
vollständige Referenz ausgelieferte `packages/paratix/llm-guide.md` sollen wieder denselben
Consumer-Vertrag beschreiben. Der Fix ist abgeschlossen, wenn die beiden erlaubten Package-
Entry-Points, ihre Runtime- und Typ-Exporte sowie alle öffentlichen Beispiele und Tabellen
übereinstimmen und dieser Zustand am gepackten npm-Artefakt geprüft wird.

Die Abweichungen sind konkret reproduzierbar:

- Die erzeugte und veröffentlichte Root-Deklaration exportiert die in
  `packages/paratix/src/index.ts` kuratierten Typen korrekt, einschließlich `EnvironmentValue`,
  `ExecOptions` und `SshConfig`. Der Guide führt jedoch nicht die vollständige öffentliche
  Typoberfläche beider Entry-Points als importierbaren Vertrag auf.
- Zu Planungsbeginn empfahl der Guide `failedCommandWithDiagnostic`, `restartSystemdUnit`,
  `buildUnifiedDiff` und `buildKeyValueDiff`, obwohl diese Helper damals nicht öffentlich
  importierbar waren. Während der Umsetzung veröffentlichte `origin/main` diese Helper bewusst;
  der Abgleich übernimmt daher diese neue Basis, ohne interne Diff-Hooks als stabile
  Erweiterungsoberfläche zu bewerben.
- Die `SshConnection`-Tabelle dokumentiert für `addPort` den Rückgabewert `void` statt `boolean`,
  lässt `reconnect` und `removePort` aus und beschreibt `getConnectionInfo()` unvollständig.
- `isFirstRun()` und Teile der öffentlichen Meta-API fehlen in der vollständigen Referenz. README,
  CLI-Hilfe und JSDoc behaupten zugleich teilweise noch, `--first-run` mutiere
  `process.env.PARATIX_FIRST_RUN`, obwohl die Implementierung bewusst einen async-lokalen Kontext
  verwendet.
- Die Root-Reexports aller Built-in-Module sind laut Historie und bestehenden Unit- und
  Distributionstests unterstützte Kompatibilitäts-API. Der Guide bezeichnet dieselben Imports
  jedoch als verboten, während das JSDoc-Beispiel in `src/index.ts` sie empfiehlt.

Das Vorhaben erweitert oder verengt gegenüber der bei Delivery aktuellen Basis `1b3efd70` weder
Runtime- noch Typ-API. Es bleibt auf ausdrückliche
Entscheidung als Bugfix eingeordnet, weil widersprüchliche veröffentlichte Dokumentation im Projekt
als Produktdefekt behandelt wird; der Workflow `effective-flow fix` übernimmt daher auch die
zugehörigen Vertragstests. Änderungen an `create-paratix`, Website, Migrationsdokumentation,
Scaffold-Agent-Dateien und relativen Links im npm-Tarball bleiben außerhalb dieses Plans.

## Architekturentscheidungen

- `packages/paratix/package.json#exports` definiert weiterhin genau zwei öffentliche Library-
  Entry-Points: `paratix` und `paratix/modules`. Deep Imports werden weder dokumentiert noch neu
  freigegeben.
- Die kuratierten Barrels `packages/paratix/src/index.ts` und
  `packages/paratix/src/modules/index.ts` definieren die beabsichtigte öffentliche Oberfläche. Das
  gepackte Artefakt ist die maßgebliche Consumer-Grenze: Runtime-Imports und erzeugte `.d.ts` müssen
  diese Barrels vollständig abbilden.
- Die 28 Built-in-Module bleiben am Root und unter `paratix/modules` verfügbar und referenzidentisch.
  `paratix/modules` wird als übersichtlicher Standard für neue Playbooks empfohlen; Root-Reexports
  werden als unterstützte Kompatibilitäts-API beschrieben, nicht als Fehler oder verbotener Import.
- Die Delivery-Basis exportiert 65 Root-Werte und 31 Werte unter `paratix/modules`. Dazu gehören
  `failedCommandWithDiagnostic` am Root sowie `restartSystemdUnit`, `buildUnifiedDiff` und
  `buildKeyValueDiff` an beiden Runtime-Entry-Points. Diese Upstream-Exporte bleiben unverändert und
  werden vollständig dokumentiert und getestet. `_dryRunDiffProducer` und `_applyDryRun` bleiben
  interne Hooks und werden nicht als stabile Extension-API empfohlen.
- `meta` bleibt die bevorzugte Authoring-Oberfläche. Bereits öffentliche Standalone-Konstruktoren,
  Guards, Validierungs- und Konvertierungshelper werden als fortgeschrittene API vollständig
  inventarisiert. Diese Exportmatrix umfasst `meta`, `environmentMeta`, `sshdPortMeta`,
  `systemHostMeta`, `systemRebootMeta`, die acht Guards `isBooleanEnvironmentMetaEntry`,
  `isEnvironmentMetaEntry`, `isLazyEnvironmentMetaEntry`, `isNumberEnvironmentMetaEntry`,
  `isSshdPortMetaEntry`, `isStringEnvironmentMetaEntry`, `isSystemHostMetaEntry` und
  `isSystemRebootMetaEntry`, die beiden `assertValidModuleMeta*`-Funktionen sowie
  `diffEnvironmentToMetaEntries`, `environmentToMetaEntries` und `mergeEnvironmentFromMeta`. Weitere
  Meta-Typen oder interne Implementierungsdetails werden nicht exportiert.
- Die kanonische öffentliche Typmatrix besteht am Root aus `Environment`,
  `EnvironmentMetaEntry`, `EnvironmentValue`, `ExecOptions`, `ExecResult`,
  `MetaEnvironmentValue`, `Module`, `ModuleMetaEntry`, `ModuleResult`, `ServerDefinition`,
  `ShutdownSignal`, `SshConfig`, `SshConnection`, `SshdPortMetaEntry`, `SystemHostMetaEntry` und
  `SystemRebootMetaEntry` und `UnifiedDiffOptions` sowie unter `paratix/modules` aus `PackageSpec`,
  `UnifiedDiffOptions` und `UpgradeOptions`.
- `SshConnection` in `packages/paratix/src/types.ts` bleibt die Quelle für Methodennamen,
  Signaturen und den Rückgabewert von `getConnectionInfo()`. Implementierungsmethoden außerhalb
  dieses exportierten Typs werden nicht in den Guide übernommen.
- `isFirstRun()` ist die einzige öffentliche Abfrage des First-Run-Kontexts. Der Kontext gilt in
  der bestehenden Implementierung ausschließlich während Playbook-Import und
  Definitionserzeugung; `check` und `apply` laufen danach, ein öffentliches `init` existiert nicht.
  Öffentliche Texte beschreiben genau dieses Verhalten und nennen keine internen Context-Wrapper.
  Eine spätere Ausweitung auf die Modulausführung wird in GitHub-Issue
  [#201](https://github.com/sebastian-software/paratix/issues/201) verfolgt und gehört nicht zu
  diesem Dokumentationsabgleich.
- `packages/paratix/dist/**` bleibt generiert und unversioniert. Deklarationen werden nie direkt
  editiert. Der aktuelle Typvertrag wird als korrekte Referenz geprüft und nur dann neu geplant,
  wenn der Drift-Abgleich unmittelbar vor der Umsetzung eine neue Abweichung nachweist.
- Drift-Schutz wird an der gepackten Distribution verankert. Ein grüner Source-Typecheck allein
  reicht nicht, weil Guide-Imports und deklarierte Type-Exports aus Consumer-Sicht auflösbar bleiben
  müssen.
- Der automatische Drift-Schutz konzentriert sich auf den markierten Importblock, die kanonischen
  Runtime- und Typmatrizen, das Root-JSDoc sowie die konkret korrigierten API-Flächen
  `SshConnection`, `isFirstRun()` und Meta-API. Alle übrigen öffentlichen Codeblöcke und Tabellen
  werden bei der Umsetzung vollständig manuell gegen Source-Barrels, exportierte Typen und das
  gepackte Artefakt abgeglichen. Eine generische Parser-/Marker-Infrastruktur für jede Tabelle und
  jedes Beispiel ist bewusst nicht Teil dieses Scopes.

## Betroffene Dateien

| Datei                                              | Beschreibung                                                                                                                                                 |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/paratix/src/index.ts`                    | Consumer-JSDoc auf empfohlene Zweipfad-Imports ausrichten                                                                                                    |
| `packages/paratix/src/firstRunContext.ts`          | Öffentliche `isFirstRun()`-Dokumentation ohne internen Helper-Namen und mit korrekter async-lokaler Semantik formulieren                                     |
| `packages/paratix/src/cli.ts`                      | Veraltete JSDoc- und Help-Aussagen zur globalen First-Run-Umgebungsvariable korrigieren                                                                      |
| `packages/paratix/README.md`                       | CLI-Referenz für `--first-run` an das tatsächliche Verhalten anpassen                                                                                        |
| `packages/paratix/llm-guide.md`                    | Imports, öffentliche Helper und Typen, Root-Kompatibilität, `isFirstRun()`, Meta-API, Custom-Module-Hinweise und `SshConnection` vollständig synchronisieren |
| `packages/paratix/test/publicApi.test.ts`          | Beabsichtigte Runtime-Oberflächen und die Referenzidentität der Modul-Reexports explizit absichern                                                           |
| `packages/paratix/test/jsdoc-examples.test.ts`     | JSDoc-Beispiele über die kuratierten öffentlichen Barrels prüfen und den empfohlenen Importvertrag spiegeln                                                  |
| `packages/paratix/test/postbuild/cli.dist.test.ts` | Gepackte Runtime- und Typ-Imports einschließlich des markierten Guide-Importblocks und der kanonischen Typmatrix in einem isolierten Consumer prüfen         |

## Implementierungsdetails

### Vorgehen

1. Vor Änderungen den geplanten Scope gegen den dann aktuellen `main` und die neueste npm-Version
   prüfen. Sind die betroffenen Barrels, Typen oder Guides inzwischen verändert, wird die Export-
   Matrix aus `package.json`, beiden Source-Barrels und dem gepackten Artefakt neu abgeleitet.
2. Den bestehenden isolierten NodeNext-Consumer in
   `packages/paratix/test/postbuild/cli.dist.test.ts` um sämtliche im kanonischen Guide-
   Importabschnitt aufgeführten Runtime- und Type-Imports erweitern. Dazu gehören ausdrücklich
   alle Namen der kanonischen Typmatrix. Der Guide erhält um genau einen allein kompilierbaren
   TypeScript-Importblock die stabilen HTML-Marker `public-api-imports:start` und
   `public-api-imports:end`. Der Distributionstest extrahiert diesen Block aus der mitgepackten
   `llm-guide.md` und kompiliert ihn als NodeNext-Consumer; fehlende, doppelte, vertauschte oder
   mehrdeutige Marker lassen den Test scheitern.
3. Die Public-API-Tests um explizite erwartete Runtime-Exportmengen für `paratix` und
   `paratix/modules` ergänzen. Den bestehenden Test beibehalten, der alle Modul-Exports am Root und
   ihre Referenzidentität absichert; Type-Exporte werden am gepackten TypeScript-Consumer geprüft.
4. Den Importabschnitt des Guides als vollständiges Inventar der zwei Entry-Points überarbeiten:
   häufige Core- und Authoring-Imports, fortgeschrittene Meta-Helper und öffentliche Root-Typen
   getrennt aufführen; `PackageSpec` und `UpgradeOptions` als Type-Imports aus
   `paratix/modules` ergänzen. Root-Modulimporte als unterstützt, aber nicht als empfohlene
   Standardform kennzeichnen.
5. Nicht öffentliche Deep Imports und `@internal`-Hooks aus der Consumer-Anleitung entfernen. Die
   inzwischen öffentlich exportierten Diagnose-, Restart- und Diff-Helper vollständig über die zwei
   Package-Entry-Points dokumentieren. Den Custom-Diff-Abschnitt so formulieren, dass die
   Formatierungshelper nicht mit einer stabilen Runner-Hook-API verwechselt werden.
6. Die `SshConnection`-Tabelle vollständig aus dem exportierten Typ ableiten: `addPort(): boolean`,
   `reconnect(options?): Promise<void>`, `removePort(): void` und sämtliche Felder von
   `getConnectionInfo()` aufnehmen. Methoden, die nur die Implementierungsklasse besitzt, bleiben
   draußen.
7. `isFirstRun()` im Importinventar und in einer kurzen API-Erklärung ergänzen. Guide, README,
   CLI-Hilfe und JSDoc einheitlich darauf ausrichten, dass `--first-run` während Import und
   Definitionserzeugung des Playbooks beobachtbar ist und `process.env` nicht global mutiert.
   Empfehlungen für `init`, `check` oder `apply` entfernen, weil diese Flächen nicht innerhalb des
   aktuellen First-Run-Kontexts liegen.
8. Das Root-JSDoc-Beispiel auf Core-Imports aus `paratix` und Module aus `paratix/modules`
   umstellen. Dieses Beispiel wird im JSDoc-Test als eigene, dem Kommentar eindeutig zugeordnete
   Fixture oder per eindeutiger Extraktion geprüft; ein bloßer Wechsel der Testimports genügt nicht,
   weil die manuell kopierten Beispiele den Kommentartext sonst nicht gegen Drift schützen. Die
   Testausführung verwendet die kuratierten Barrels statt tiefer Source-Imports.
9. Den gepackten Consumer-Test um die kanonischen Guide-Imports, die Root-Typen, die zwei
   Modultypen, `isFirstRun`, die dokumentierten Meta-Helper und relevante
   `SshConnection`-Signaturen erweitern. Runtime-Assertions bleiben getrennt von TypeScript-
   Kompilationsassertions, damit ein fehlender Wert-Export und ein fehlender Typ-Export eindeutig
   diagnostiziert werden.
10. Abschließend sämtliche übrigen öffentlichen Codeblöcke und Tabellen des Guides manuell gegen
    die beiden Source-Barrels, die exportierten Typen und das frisch gepackte Artefakt abgleichen.
    Abweichungen werden in demselben Dokumentationsdurchlauf korrigiert; zusätzliche Parser oder
    Marker werden nur für die in den Architekturentscheidungen benannten automatisierten Flächen
    eingeführt.

### Randfälle

- Falls der Drift-Abgleich unmittelbar vor der Umsetzung einen neuen Unterschied zwischen
  Source-Barrel und gepackter Deklaration zeigt, wird nicht spekulativ an `src/index.ts` oder
  `tsup.config.ts` gearbeitet. Die Umsetzung hält an und der Plan wird mit dem konkreten neuen
  Deklarationsbefund revidiert.
- Der gemeinsam erzeugte `dist/index-*.d.ts`-Chunk kann interne oder transitive Deklarationen
  enthalten. Öffentlich ist ein Name erst, wenn der jeweilige Entry-Point ihn exportiert; der Guide
  darf Chunk-Inhalte nicht als API inventarisieren.
- `connect()` und `forceDestroy()` der SSH-Implementierung werden nicht ergänzt, weil sie nicht zum
  exportierten `SshConnection`-Typ gehören.
- Die vier spezialisierten Meta-Entry-Aliase aus `src/meta.ts` werden nicht neu am Root exportiert.
  Die bestehenden Guard-Rückgabetypen bleiben trotzdem nutzbar.
- Die Korrektur der First-Run-Texte darf keine Änderung an CLI-Option, Environment-Weitergabe oder
  async-lokalem Laufzeitverhalten auslösen.
- Die gewünschte spätere Verfügbarkeit von `isFirstRun()` während `check` und `apply` wird nicht in
  diesen Scope gezogen. Issue [#201](https://github.com/sebastian-software/paratix/issues/201) muss
  Runtime-Semantik, Verschachtelung/Reentrancy und Tests eigenständig planen.
- Vorhandene sachfremde Arbeitsbaumänderungen, insbesondere `.DS_Store`-Dateien und andere offene
  Pläne, bleiben unangetastet.

## Akzeptanzkriterien

Die Umsetzung gilt genau dann als abgeschlossen, wenn alle folgenden Kriterien gemeinsam erfüllt
sind:

- [x] `package.json` veröffentlicht weiterhin ausschließlich `paratix` und `paratix/modules`; es
      gibt keine neuen Deep Imports und der Fix fügt gegenüber der Delivery-Basis keinen
      Runtime-Export hinzu, entfernt oder benennt keinen um.
- [x] Das gepackte Root-`dist/index.d.ts` exportiert weiterhin jeden Typ der kanonischen Typmatrix,
      und ein isolierter NodeNext-Consumer kann diese Namen direkt aus `paratix` beziehungsweise
      `paratix/modules` importieren.
- [x] Alle 28 Built-in-Module sind weiterhin sowohl am Root als auch unter `paratix/modules`
      verfügbar und an beiden Entry-Points referenzidentisch.
- [x] Die festen Runtime-Matrizen umfassen 65 Root-Werte und 31 Modul-Werte einschließlich der auf
      `origin/main` neu veröffentlichten Helper; alle 31 Modul-Werte sind am Root referenzidentisch.
- [x] Jeder Import im kanonischen Guide-Importabschnitt kompiliert gegen das gepackte Artefakt; der
      Distributionstest extrahiert genau diesen markierten Block aus der mitgepackten Datei, und
      `PackageSpec` sowie `UpgradeOptions` kommen aus `paratix/modules`.
- [x] Der Guide enthält keine Empfehlung für einen Deep Import, einen nicht exportierten Helper
      oder einen als `@internal` markierten Custom-Module-Hook.
- [x] Die `SshConnection`-Tabelle stimmt bei Namen, Parametern, Rückgabewerten und
      `getConnectionInfo()`-Feldern mit dem exportierten Typ überein.
- [x] `isFirstRun()` und die bestehende öffentliche Meta-API sind auffindbar dokumentiert; Guide,
      README, CLI-Hilfe und öffentliche JSDoc behaupten nirgends mehr, dass `--first-run`
      `process.env.PARATIX_FIRST_RUN` global mutiert oder während `check`, `apply` beziehungsweise
      eines nicht vorhandenen `init` verfügbar ist.
- [x] Die fokussierten Public-API- und JSDoc-Tests, der vollständige Distributionstest und
      `pnpm agent:check` enden jeweils mit Exit-Code 0.
- [x] Ein dokumentierter manueller Abschlussabgleich bestätigt, dass die übrigen öffentlichen
      Codeblöcke und Tabellen keine weiteren Abweichungen zu Barrels, Typen oder gepacktem Artefakt
      enthalten.

## Validierungsplan

- `pnpm --filter paratix exec vitest run test/publicApi.test.ts test/jsdoc-examples.test.ts`
  prüft die Source-Barrels, die Modul-Referenzidentität und die ausführbaren JSDoc-Beispiele.
- `pnpm --filter paratix test:dist` baut das Paket, packt es und prüft Runtime- sowie TypeScript-
  Imports aus der Sicht eines isolierten Consumers. Dabei muss der Test ausdrücklich gegen das
  entpackte Paket und nicht gegen Workspace-Source-Dateien auflösen.
- Im erzeugten, nicht versionierten `packages/paratix/dist/index.d.ts` wird zusätzlich kontrolliert,
  dass die drei exemplarisch geprüften Root-Typen weiterhin in der finalen Exportliste stehen. Das
  Artefakt wird nicht manuell editiert oder eingecheckt.
- Mit `rg` wird in `packages/paratix/llm-guide.md`, `packages/paratix/README.md` und den öffentlichen
  JSDoc-Flächen geprüft, dass Deep-Import- und interne Hook-Empfehlungen sowie die falsche
  `PARATIX_FIRST_RUN`-Aussage nicht mehr vorkommen. Interne Implementierungsdokumentation darf ihre
  tatsächlichen Symbolnamen weiterhin verwenden.
- Die nicht automatisierten Codeblöcke und Tabellen werden anhand einer beim Umsetzen geführten
  Abschnittsliste vollständig durchgesehen; im Abschlussbericht werden geprüfte Abschnitte und
  gefundene beziehungsweise korrigierte Abweichungen genannt. Dieser manuelle Nachweis ersetzt
  keine der fokussierten automatischen Prüfungen.
- Abschließend läuft `pnpm agent:check` im Repository-Root. Die Docker-Integrationstests sind für
  diesen Fix nicht erforderlich, weil weder `ssh`- noch `readFile`-Semantik verändert wird.

## Annahmen und offene Punkte

- Verifiziert: npm veröffentlicht aktuell `paratix@0.19.0`; dessen ausgeliefertes
  `dist/index.d.ts` exportiert `EnvironmentValue`, `ExecOptions` und `SshConfig` bereits korrekt in
  der zweiten Zeile. Die erste Prüfung hatte nur die abschließende Exportliste betrachtet und war
  deshalb falsch.
- Verifiziert: Der Guide im npm-Tarball war zu Planungsbeginn inhaltlich identisch mit der damals
  geprüften Repository-Version und enthielt die beschriebenen nicht öffentlichen Imports und
  Typabweichungen.
- Delivery-Fortschreibung: Während der Umsetzung wurde `1b3efd70` nach `origin/main` gemergt und
  veröffentlichte die vier zuvor internen Helper sowie `UnifiedDiffOptions`. Der Delivery-Commit ist
  auf dieser Basis rebasiert; die festen Exportmatrizen, der Guide, der gepackte Consumer und dieser
  Plan beschreiben deshalb den neuen Vertrag mit 65 Root- und 31 Modul-Werten.
- Verifiziert: Commit `a5e0e383` und die Tests in `test/publicApi.test.ts` sowie
  `test/postbuild/cli.dist.test.ts` machen die Root-Reexports der Built-in-Module zu einer
  beabsichtigten Kompatibilitätsoberfläche.
- Verifiziert: `packages/paratix/dist/**` ist nicht versioniert. Der lokale Inhalt kann veraltet
  sein; für Annahme und Abnahme zählt deshalb der frische Build und das daraus gepackte Artefakt.
- Verifiziert: Die bewusst ausgegliederte Runtime-Erweiterung für `isFirstRun()` während
  `check`/`apply` ist als GitHub-Issue
  [#201](https://github.com/sebastian-software/paratix/issues/201) erfasst.
- Annahme: Der kanonische Importabschnitt des Guides lässt sich ohne neue Abhängigkeit so in den
  vorhandenen Distributionstest einbeziehen, dass der Test tatsächlich den ausgelieferten Guide
  und nicht nur eine manuell duplizierte Importliste prüft.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       1 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       0 |

### Befunde

- **Testbarkeit (direkt eingearbeitet):** Die frühere Behauptung fehlender Type-Exports beruhte auf
  einer unvollständigen Sicht auf `dist/index.d.ts`. Tatsachenbasis, Vorgehen, Randfälle und
  Abnahmekriterien sind korrigiert; der Plan verlangt keine unnötige Änderung der
  Deklarationserzeugung mehr.
- **Wartbarkeit (direkt eingearbeitet):** Ein manuell kopierter Guide-Importblock würde den
  behaupteten Drift-Schutz nicht liefern. Der Plan verlangt nun genau einen markierten,
  allein kompilierbaren Importblock und dessen Extraktion aus dem tatsächlich mitgepackten Guide.
- **Testbarkeit (direkt eingearbeitet):** Typ- und Meta-API waren für einen vollständigen Abgleich
  zu unbestimmt formuliert. Der Plan enthält nun die kanonischen Symbolmatrizen und verlangt für
  das Root-JSDoc eine eigene Fixture oder eindeutige Extraktion.
- **Architektur (Hinweis, eingearbeitet):** `isFirstRun()` wird ausschließlich für Playbook-Import
  und Definitionserzeugung dokumentiert. Die vom Nutzer gewünschte spätere Ausweitung auf
  `check`/`apply` bleibt eine eigenständige Runtime-Änderung und wird in GitHub-Issue
  [#201](https://github.com/sebastian-software/paratix/issues/201) verfolgt.
- **Testbarkeit (Hinweis, eingearbeitet):** Der maschinelle Schutz ist auf Importvertrag,
  Exportmatrizen, Root-JSDoc und die konkret korrigierten API-Flächen begrenzt. Alle übrigen
  öffentlichen Codeblöcke und Tabellen erhalten einen dokumentierten manuellen Abschlussabgleich;
  eine generische Dokumentations-Parser-Infrastruktur bleibt bewusst außerhalb des Scopes.
- **Scope (Hinweis, eingearbeitet):** Obwohl keine Runtime- oder Typ-API geändert wird, bleibt der
  Plan auf Nutzerentscheidung als `Bugfix` (`effective-flow fix`) klassifiziert, weil die
  widersprüchliche veröffentlichte Dokumentation als Produktdefekt behandelt wird.

## Offene Punkte

- Keine offenen Punkte.
