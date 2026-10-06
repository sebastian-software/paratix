# Archive-Modul und Containment-Flag aufteilen

**Planungsstatus:** Umgesetzt
**Quelle:** `effective-flow plan`
**Empfohlener Workflow:** Refactoring (`effective-flow refactor`)

## Anforderung

Der Befund R-0000016 aus `.effective-flow/review/review-report-2026-09-29.md` bemängelt, dass
`packages/paratix/src/modules/archive.ts` und die Containment-Logik aus PR #223 (Issue #219) zu groß
geworden sind. Der Reviewer empfahl zweierlei: den PR neu zu schneiden und `archive.ts` in Module für
Staging-Merge, Marker/Check und Apply-Orchestrierung aufzuteilen, statt die Datei weiter zu
verdichten.

PR #223 ist am 1. Oktober 2026 gemergt worden (`abec54d9`). Der Neuschnitt des PR ist damit
gegenstandslos. Dieser Plan setzt nur den zweiten Teil der Empfehlung um, und zwar als reinen
Refactor ohne Verhaltensänderung. Er betrifft die beiden Dateien, die die Lint-Grenze nur über ein
`eslint-disable max-lines` einhalten:

- `packages/paratix/src/modules/archive.ts`: 1.800 Zeilen, 1.001 Code-Zeilen.
- `packages/paratix/src/modules/archiveContainmentFlag.ts`: 892 Zeilen, 430 Code-Zeilen.

Das Lint-Limit liegt bei 300 Code-Zeilen pro Datei (oxlint `max-lines` mit `skipBlankLines` und
`skipComments`). Ziel: Beide Disables entfallen, und jede neue Datei hat eine klar benannte
Verantwortung.

Einordnung als Refactoring: Struktur und Prüfbarkeit werden besser. Emittierte Shell-Skripte,
Remote-Pfade, Fehlermeldungen und öffentliche API bleiben byte-gleich.

Planungsbasis ist `origin/main` `c62991d9`, nach #223 und #228. Alle Zeilenangaben beziehen sich auf
diesen Stand. Der lokale Branch `main` wurde während der Planung auf denselben Stand
vorgespult. Weicht `origin/main` bei der Umsetzung davon ab, müssen die Zeilenangaben vorher
abgeglichen werden.

## Architekturentscheidungen

- **Schnitt nach Verantwortung und Lint-Grenze.** Die drei Module aus der Review-Empfehlung reichen
  nicht aus. Marker und Check ergeben zusammen etwa 370 Code-Zeilen, Containment-Phase und
  Apply-Einstieg ebenfalls rund 370. Beide Paare werden deshalb geteilt. Zusätzlich wandern die
  Shell-Text-Bausteine des Staging-Merge in eine eigene Datei. Zwingend ist das nicht: Zusammen mit
  der Ausführung wären es etwa 275 Code-Zeilen. Der Schnitt greift aber den Review-Hinweis auf, dass
  Shell-Logik in TS-Arrays schwer prüfbar ist. Reiner Skript-Text steht dann getrennt vom
  Ausführungscode und behält Puffer.
- **Namenskonvention der Familie.** Neue Dateien heißen `archive<Concern>.ts` und liegen flach in
  `packages/paratix/src/modules/`, wie die bestehenden `archive*`-Dateien und wie die op-Aufteilung
  aus #192.
- **Keine Re-Exporte aus `archive.ts`** (Entscheidung des Nutzers, Vorbild #192). `archive.ts`
  exportiert danach nur noch `archive`. Tests, die interne Symbole brauchen, importieren direkt aus
  dem neuen Modul. Bestehende Re-Exporte in `archiveContainmentEnforcement.ts` und
  `archiveLinkValidation.ts` bleiben unberührt.
- **Abhängigkeitsrichtung strikt abwärts, auch bei reinen Typ-Importen.** Die Schichten von oben
  nach unten:

  1. Registrierung
  2. Apply und Check
  3. eingeschlossene Extraktion
  4. Staging-Merge
  5. Skript-Bausteine
  6. Marker und gemeinsame Validierung
  7. bestehende Containment-Dateien

  Erlaubt sind genau die Kanten unter „Komponentenstruktur“. oxlint prüft zwar `import/no-cycle`
  (`maxDepth: 3`), wertet Typ-Importe aber offenbar nicht aus. Die Richtung sichert deshalb Prüfung C
  ab, die auch Zwischenstände betrifft.

- **Typen und Helfer folgen ihren Nutzern.**
  - `ContainmentPhase`, `ContainmentProgress` und `containmentProgress` gehören zum Staging-Merge,
    weil `StagedExtractionParameters.progress` sie braucht (`archive.ts:960`, `archive.ts:1001`).
  - `MISSING_OWNER_PATHS_MARKER_PATTERN` und `isStringArray` gehören zum Marker, weil nur
    `readOwnerPathsMarker` sie nutzt (`archive.ts:1662`, `archive.ts:1674`).
  - Der Parametertyp von `archive.extract`, heute `ApplyParameters`, wandert in den Marker, neben
    `markerPath` und `containmentPathsFor`, aus denen er befüllt wird. So nutzen Apply und Check
    denselben Typ, ohne dass Check von Apply abhängt.
- **`ApplyParameters` heißt künftig `ArchiveExtractParameters`** (Entscheidung des Nutzers). Der alte
  Name wäre irreführend, sobald auch der Check den Typ nutzt. Umbenannt wird im selben Commit, der
  den Typ verschiebt, an allen Verwendungsstellen. Die Felder bleiben unverändert.
- **`newContainmentEntryName` bleibt in `archiveContainmentFlag.ts`.** `test/modules/archive.test.ts:162`
  ersetzt die Funktion per `vi.mock("../../src/modules/archiveContainmentFlag.js", …)`. Das wirkt nur,
  solange der Aufrufer in der Apply-Orchestrierung sie aus genau diesem Modul importiert.
- **`localSha256` wird weiterhin aus `./fileHelpers.js` importiert.** `archive.test.ts:1842` und
  `archive.test.ts:1880` hängen sich per `vi.spyOn` an diesen Namespace.
- **Lokale Kleinst-Konstanten werden dupliziert, und zwar wortgleich.** `EXEC_OPTS` und `SILENT`
  bekommt jedes Modul, das sie braucht, als eigene lokale Konstante. Das entspricht der Praxis in
  `archiveDestinationValidation.ts`. Erwartet werden:
  - `EXEC_OPTS` in Marker, Staging-Merge, Check und Apply;
  - `SILENT` in Staging-Merge und Apply.

  Kritisch ist die Kopie im Marker. `ARCHIVE_CAPTURE_EXEC_OPTS` (`archive.ts:59–62`) spreizt
  `EXEC_OPTS`. Fehlte dort `ignoreExitCode`, würfen die R-0000276-Lesepfade (`archive.ts:1652`,
  `archive.ts:1685`) eine Ausnahme, statt Drift zu melden.

- **Verschieben statt Umschreiben.** Funktionskörper, Kommentare und Skript-Fragmente wandern
  unverändert. Erlaubt sind nur diese Abweichungen:
  - neue `export`-Schlüsselwörter und angepasste Import-Blöcke;
  - Kommentare, die eine verschobene Datei beim Namen nennen;
  - die Umbenennung `ApplyParameters` → `ArchiveExtractParameters`;
  - die Hülle `checkExtract` samt Delegation aus `check()`;
  - ein kurzer Dateikopf, ein JSDoc-Absatz, pro neuem Modul, der seine Verantwortung benennt
    (Entscheidung des Nutzers);
  - drei JSDoc-Verweise, die nach dem Schnitt nicht mehr auflösen und sonst
    `jsdoc/no-undefined-types` verletzen:
    - `{@link clearContainmentEntries}` bei `archiveContainmentFlag.ts:29`
    - `{@link establishContainmentEntry}` bei `archiveContainmentFlag.ts:26`
    - `{@link newContainmentEntryName}` bei `archiveContainmentFlag.ts:665`

    Sie werden zu Code-Spannen mit Modulnamen, etwa „`establishContainmentEntry` in
    `archiveContainmentEstablish.ts`“. Importe nur für die Verweise würden Zyklen erzeugen.

  Auch offensichtliche Unschönheiten bleiben erhalten, etwa dass `runContainmentBackstop`
  `containmentPathsFor` neu berechnet, statt `parameters.containment` zu nutzen. Sie gehören nicht in
  diesen Refactor.

- **Ein PR mit einem Commit je neuem Modul, gemergt per Squash** (Entscheidung des Nutzers, wie bei
  #192, #223, #226 und #228). Die Modul-Commits dienen dem Review, auf `main` landet ein Commit.
  Korrekturen aus dem Review werden in den passenden Modul-Commit gefaltet.
- **Docker-Integrationslauf ist Pflicht auf dem PR-Kopf** (Entscheidung des Nutzers). Die CI hat
  keine Docker-Umgebung. Containment ist sicherheitskritisch, deshalb wird der Apply- und Check-Pfad
  vor dem Merge einmal Ende-zu-Ende geprüft.

## Betroffene Dateien

| Datei                                                                                                                    | Beschreibung                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/archive.ts`                                                                                | Schrumpft auf die Registrierung `archive.extract`: Ziel synchron validieren, `ArchiveExtractParameters` aus `markerPath` und `containmentPathsFor` befüllen, `apply` und `check` delegieren. Das `max-lines`-Disable entfällt. Etwa 50 Code-Zeilen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `packages/paratix/src/modules/archiveStagingMergeScript.ts` (neu)                                                        | Reiner Shell-Text: `TAR_HARDEN_FLAGS`, `extractCommand`, `buildStagingMergeScript`, `STAGING_MERGE_GUARD_FILE_SCRIPT`, die Typen `StagingMergeParameters`, `StagingMergeExec` und `StagingMergeTimeLimits`, `buildStagingMergeExec`, `STAGING_MERGE_TIME_LIMITS`, `boundedStagingMergeCommand`. Heute Zeilen 141–169, 257–468 und 477–520. Etwa 106 Code-Zeilen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `packages/paratix/src/modules/archiveStagingMerge.ts` (neu)                                                              | Ausführung des Staging-Merge: `ARCHIVE_STAGE_PREFIX`, `allocateExtractStagingDirectory`, `TIMEOUT_EXIT_CODE`, `TIMEOUT_KILLED_EXIT_CODE`, `moveExtractedContentsIntoDestination`, `cleanupStagingDirectory`, `validateTargetsForStagingMerge`, `StagedExtraction`, `runStagingMerge`, `mergeNotStarted`, `ContainmentPhase`, `ContainmentProgress`, `containmentProgress`, `StagedExtractionParameters`, `extractAndMergeStaging`, `extractViaStagingDirectory`. Heute Zeilen 178–186, 225–255, 469–475, 522–607 und 872–1044. Etwa 185 Code-Zeilen.                                                                                                                                                                                                                                                                                     |
| `packages/paratix/src/modules/archiveMarker.ts` (neu)                                                                    | Idempotenz-Marker, Schreib- und Leseseite. Enthält:<br>• Konstanten: `FLAGS_DIR`, `ARCHIVE_MARKER_MODE`, `ARCHIVE_CAPTURE_EXEC_OPTS`, `MISSING_OWNER_PATHS_MARKER_PATTERN`<br>• Pfade: `markerPath`, `containmentPathsFor`, `ownerPathsMarkerPath`, `membersMarkerPath`<br>• Typen: die Payload-Typen und `ArchiveExtractParameters` (bisher `ApplyParameters`)<br>• Schreiben: `writeMarker`, `writeOwnerPathsMarker`, `extractedArchiveMembers`, `serializeArchiveMarkerPayloads`, `writeMembersMarker`<br>• Lesen: `isStringArray`, `isExtractedArchiveMember`, `readMembersMarker`, `readOwnerPathsMarker`<br><br>Heute Zeilen 59–62, 64–65, 68–101, 117–139, 628–678, 744–831, 1494–1496, 1538–1573 und 1648–1678. Etwa 213 Code-Zeilen.                                                                                            |
| `packages/paratix/src/modules/archiveListingValidation.ts` (neu)                                                         | `validatedArchiveMembers` (heute 680–715): Listing holen, Mitglieder einzeln und Links als Ganzes prüfen. Apply und der Legacy-Fallback des Checks nutzen die Funktion gemeinsam. Ein eigenes Modul verhindert, dass Check von Apply abhängt. In `archiveMemberValidation.ts` würde ein Zyklus über `archiveLinkValidation.ts` entstehen. Etwa 25 Code-Zeilen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `packages/paratix/src/modules/archiveCheck.ts` (neu)                                                                     | Check-Modus: `ARCHIVE_STAT_OWNERSHIP_FIELDS`, `markerWithoutContainmentFailureCommand`, `ownerMatchesStat`, `archiveOwnerMatches`, `memberTypeProbeCode`, `extractedMembersMatch`, `ownerMatchesPaths`, `archiveMarkerMatches`. Heute Zeilen 66–67, 102–116, 1474–1492, 1498–1536, 1575–1646 und 1680–1702.<br><br>Dazu kommt `checkExtract(conn, parameters: ArchiveExtractParameters)`. Die Funktion beginnt damit, `containment`, `destination` (als `normalizedDestination`), `marker`, `owner`, `source` und `upload` aus `parameters` zu destrukturieren. Der Rest der heutigen Inline-Sequenz aus `archive.extract().check` (1759–1795) bleibt zeichengleich. Etwa 160 Code-Zeilen.                                                                                                                                               |
| `packages/paratix/src/modules/archiveContainedExtraction.ts` (neu)                                                       | Containment-Phase der Apply-Orchestrierung: `combineMergeFailures`, `runContainmentBackstop`, `recordAfterMerge`, `ContainedExtraction`, `NOTHING_PUBLISHED`, `extractAndValidateSymlinkContainment`, `recordAfterThrow`. Heute Zeilen 1089–1293. Etwa 105 Code-Zeilen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `packages/paratix/src/modules/archiveApply.ts` (neu)                                                                     | Einstieg und Ablauf des Apply: `ARCHIVE_UPLOAD_PREFIX`, `ARCHIVE_UPLOAD_DIRECTORY`, `allocateRemoteUploadPath`, `resolveRemoteSource`, `applyExtractedMemberOwner`, `preflightExtractDestination`, `createAndValidateExtractDestination`, `validateMembersForExtraction`, `finalizeExtraction`, `EntryExtractionParameters`, `extractUnderContainmentEntry`, `runExtraction`, `applyExtract`. Heute Zeilen 171–176, 188–223, 609–626, 717–742, 833–870, 1046–1087 und 1295–1472.<br><br>Importiert `newContainmentEntryName` weiter aus `./archiveContainmentFlag.js`. Etwa 257 Code-Zeilen; das ist das knappste Modul.                                                                                                                                                                                                                 |
| `packages/paratix/src/modules/archiveContainmentFlag.ts`                                                                 | Behält Eintragsformat und Vokabular:<br>• Konstanten: `CONTAINMENT_FLAG_LINK_LIMIT`, `CONTAINMENT_FLAG_BODY_LIMIT_BYTES`, `CONTAINMENT_FLAG_VERSION`<br>• Record-Meldungen: `TOO_MANY_OFFENDING_LINKS`, `UNIDENTIFIED_OFFENDING_LINKS`, `STOPPED_AFTER_MERGE_STARTED`<br>• Typen: `ContainmentFlagRecord`, `ContainmentFlagBody`, `ParsedContainmentFlag`, `ContainmentPaths`<br>• Rendern: `containmentFlagBody`<br>• Parser `parseContainmentFlag` und `parseContainmentEntryBytes` mit ihren privaten Helfern `NO_USABLE_LIST`, `IN_PROGRESS`, `FLAG_OBJECT_KEY_COUNT`, `NO_USABLE_LIST_STATE`, `validRecordedLinks` und `interpretFlagObject`<br>• Eintragsnamen: `ENTRY_ID_BYTES`, `newContainmentEntryName`<br><br>Das `max-lines`-Disable entfällt. Etwa 117 Code-Zeilen.                                                         |
| `packages/paratix/src/modules/archiveContainmentEstablish.ts` (neu)                                                      | Establish-Pfad. Enthält:<br>• Konstanten, die nur er nutzt: `CONTAINMENT_ENTRY_READ_LIMIT`, `ENTRY_READ_BYTES`, `ENTRY_NAME_MAX_BYTES`, `SHA256_HEX_LENGTH`, `ESTABLISH_LINE_MAX_BYTES`, `ESTABLISH_HEADROOM_BYTES`, `CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES`, `CONTAINMENT_ESTABLISH_EXIT`, `IN_PROGRESS_BODY`, `ENTRY_NAME_PATTERN`, `SHA256_PATTERN`, `HEX_DIGITS_PATTERN`<br>• Skript: `READ_LINE_FUNCTION`, `buildContainmentEstablishScript`, `buildContainmentEstablishCommand`<br>• Typen: `RemovableContainmentEntry`, `ContainmentLedger`, `ReadContainmentEntry`, `EstablishLine`<br>• Auswertung: `readEntryLine`, `parseEstablishLine`, `establishLines`, `parseContainmentEstablishOutput`, `offendingEntryPath`, `containmentEstablishFailure`<br>• Einstieg: `establishContainmentEntry`<br><br>Etwa 225 Code-Zeilen. |
| `packages/paratix/src/modules/archiveContainmentEntries.ts` (neu)                                                        | Operationen auf bestehenden Einträgen: `CONTAINMENT_ENTRY_MODE`, `CONTAINMENT_CLEAR_EXIT`, `buildContainmentClearScript`, `buildContainmentClearCommand`, `clearContainmentEntries`, `buildContainmentCheckScript`, `noContainmentEntriesCommand`, `writeOwnEntry`, `recordContainmentFailure`, `recordContainmentFailureAfterThrow`. Etwa 116 Code-Zeilen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `packages/paratix/test/modules/archive.test.ts`                                                                          | Nur Importpfade (Zeilen 8–14 und 26–37) auf die neuen Module umstellen. `vi.mock` auf `archiveContainmentFlag.js` und alle Erwartungen bleiben unverändert.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `packages/paratix/test/modules/archive.shell.smoke.test.ts`                                                              | Nur Importpfade (Zeilen 43–48 und 55–65) umstellen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `packages/paratix/test/modules/archiveContainmentFlag.test.ts`                                                           | Nur den Import-Block (Zeilen 7–27) für alle verschobenen Symbole umstellen: Establish, Clear/Check und Record. Die Testdatei bleibt eine Datei, wie `op.test.ts` nach #192.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `packages/paratix/src/modules/archiveMemberValidation.ts:20`, `packages/paratix/src/modules/download.ts:1056`            | Diese Kommentare nennen `archive.ts` als Fundort eines verschobenen Symbols. Sie zeigen künftig auf das neue Modul.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `src/ssh.ts:240`, `src/modules/flagLock.ts:137,378`, `src/modules/download.ts:291`, `test/modules/download.test.ts:1285` | Diese Kommentare verweisen auf eine Konvention „in archive.ts“. Jeden einzeln prüfen und nur umstellen, wenn das genannte Verhalten danach in einem anderen Modul steht.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

Reine Symbolnamen ohne Dateiangabe bleiben stehen, etwa in `archiveMemberValidation.ts:153,159` und
`archiveDestinationValidation.ts:20,27`.

Die Code-Zeilen sind ohne Leer- und Kommentarzeilen gezählt, die Import-Blöcke geschätzt.
Verbindlich ist allein, dass oxlint ohne `max-lines`-Disable besteht.

## Implementierungsdetails

### Vorgehen

1. **Branch anlegen:** von `origin/main` (`c62991d9` oder neuer). Mit `pnpm agent:check` prüfen,
   dass der Ausgangsstand grün ist.
2. **Commit 1, `archiveStagingMergeScript.ts`:** Die reinen Skript-Bausteine verschieben. Das Modul
   hängt nur von `../ssh.js` und `archiveProbe.ts` (`encodeNulPayload`) ab. Die Test-Imports der
   vier Staging-Merge-Exporte und des Typs `StagingMergeTimeLimits` zeigen danach auf das neue
   Modul.
3. **Commit 2, `archiveMarker.ts`:**
   - Verschoben werden Marker-Pfade, Typen sowie Schreib- und Lesefunktionen,
     `containmentPathsFor`, `MISSING_OWNER_PATHS_MARKER_PATTERN` und `isStringArray`.
   - Zusätzlich wandert `ApplyParameters` und heißt danach überall `ArchiveExtractParameters`.
4. **Commit 3, `archiveListingValidation.ts`:** `validatedArchiveMembers` verschieben.
5. **Commit 4, `archiveStagingMerge.ts`:** Die Ausführung des Staging-Merge verschieben, samt
   `ContainmentPhase`, `ContainmentProgress` und `containmentProgress`.
6. **Commit 5, `archiveCheck.ts`:**
   - Die Check-Helfer verschieben.
   - Die Inline-Sequenz aus `check()` als `checkExtract` herauslösen. Reihenfolge und Kurzschlüsse
     der vier Prüfungen bleiben unverändert.
   - `check()` in `archive.ts` behält nur die `conn`-Null-Prüfung und delegiert dann.
   - `noContainmentEntriesCommand` kommt vorerst aus `archiveContainmentFlag.ts`.
7. **Commit 6, `archiveContainedExtraction.ts`:** Die Containment-Phase verschieben. Den Typ
   `ContainmentLedger` vorerst aus `archiveContainmentFlag.ts` importieren.
8. **Commit 7, `archiveApply.ts`:** Den Apply-Einstieg verschieben.
9. **Commit 8, `archiveContainmentEntries.ts`:**
   - Die Clear-, Check- und Record-Operationen aus `archiveContainmentFlag.ts` herauslösen.
   - `ContainmentLedger` bleibt in diesem Zwischenstand in `archiveContainmentFlag.ts` und wird von
     dort importiert. Das ist eine Abwärtskante.
   - Den `{@link}`-Verweis bei `archiveContainmentFlag.ts:29` anpassen.
   - Die Importe von Check und Apply auf das neue Modul umstellen.
10. **Commit 9, `archiveContainmentEstablish.ts`:**
    - Den Establish-Pfad samt `ContainmentLedger` und `RemovableContainmentEntry` herauslösen.
    - Die Typ-Importe von Entries und der eingeschlossenen Extraktion auf das neue Modul umstellen.
    - Die `{@link}`-Verweise bei `:26` und `:665` anpassen.

    Die umgekehrte Reihenfolge würde vorübergehend einen Typ-Zyklus zwischen Format- und
    Establish-Modul erzeugen, weil der Clear-Code `ContainmentLedger` braucht
    (`archiveContainmentFlag.ts:746`, `archiveContainmentFlag.ts:770`).

11. **Wann die Disables fallen:** Jedes `eslint-disable max-lines` fällt in dem Commit, in dem die
    Datei erstmals 300 Code-Zeilen oder weniger hat. ESLint läuft mit `--max-warnings=0` und meldet
    eine ungenutzte Direktive als Warnung, der Commit wäre sonst rot.
    - `archive.ts`: erwartet in Commit 6 (danach etwa 292), spätestens in Commit 7.
    - `archiveContainmentFlag.ts`: erwartet in Commit 9 (nach Commit 8 noch etwa 326).

    Maßgeblich ist das Ergebnis von `pnpm lint`.

12. **Dateikopf:** Jedes neue Modul bekommt im Commit seiner Entstehung einen kurzen Dateikopf. Er
    besteht aus einem JSDoc-Absatz, der die Verantwortung des Moduls benennt.
13. **Prüfung je Commit:**
    - Lauf: `pnpm lint && pnpm typecheck && pnpm --filter paratix exec vitest run test/modules/archive`.
    - Commit-Nachrichten folgen dem Muster von #192, zum Beispiel
      `refactor(paratix): move archive staging-merge scripts into their own module`.
    - Jede Nachricht nennt die nicht byte-gleichen verschobenen Zeilen und den Grund dafür.
    - Ein PR-Titel mit `refactor(paratix):` erzeugt bei den Standard-Sektionen von release-please
      weder ein Release noch einen Changelog-Eintrag. Für einen reinen Refactor ist das richtig.
14. **Auf dem PR-Kopf:** den vollen `pnpm agent:check`, die Prüfungen A bis F und
    `pnpm --filter paratix test:integration` gegen einen lokalen Docker-Daemon ausführen.
15. **Vor dem PR:** die Verschiebungen mit `git diff --color-moved=dimmed-zebra origin/main`
    gegenlesen.

### Komponentenstruktur

Erlaubte Abhängigkeiten zu anderen `archive*`-Modulen im Endzustand, jeweils als vollständige Liste
pro Modul:

| Modul                         | Abhängigkeiten                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `archive.ts`                  | `archiveApply`, `archiveCheck`, `archiveMarker`, `archiveDestinationValidation`                                                                                                                                                                                                                                                          |
| `archiveApply`                | `archiveContainedExtraction`, `archiveStagingMerge`, `archiveMarker`, `archiveListingValidation`, `archiveContainmentFlag` (`newContainmentEntryName`, `ContainmentFlagRecord`), `archiveContainmentEstablish`, `archiveContainmentEntries`, `archiveDestinationValidation`, `archiveMemberValidation` (`ArchiveMember`), `archiveProbe` |
| `archiveCheck`                | `archiveMarker`, `archiveListingValidation`, `archiveContainmentEntries` (`noContainmentEntriesCommand`), `archiveContainmentFlag` (`ContainmentPaths`), `archiveDestinationValidation`, `archiveProbe`                                                                                                                                  |
| `archiveContainedExtraction`  | `archiveStagingMerge`, `archiveMarker` (`containmentPathsFor`), `archiveContainmentBackstop`, `archiveContainmentEnforcement`, `archiveContainmentFlag` (Typen und Meldungen), `archiveContainmentEstablish` (`ContainmentLedger`), `archiveMemberValidation` (`ArchiveMember`)                                                          |
| `archiveStagingMerge`         | `archiveStagingMergeScript`, `archiveDestinationValidation`, `archiveMemberValidation`                                                                                                                                                                                                                                                   |
| `archiveStagingMergeScript`   | `archiveProbe`                                                                                                                                                                                                                                                                                                                           |
| `archiveMarker`               | `archiveContainmentFlag` (`ContainmentPaths`), `archiveMemberValidation`, `archiveDestinationValidation` (`archiveMemberDestinationPaths`)                                                                                                                                                                                               |
| `archiveListingValidation`    | `archiveMemberValidation`, `archiveLinkValidation`                                                                                                                                                                                                                                                                                       |
| `archiveContainmentEntries`   | `archiveContainmentEstablish` (Typ), `archiveContainmentFlag`                                                                                                                                                                                                                                                                            |
| `archiveContainmentEstablish` | `archiveContainmentFlag`                                                                                                                                                                                                                                                                                                                 |
| `archiveContainmentFlag`      | wie bisher nur `archiveSymlinkListing`                                                                                                                                                                                                                                                                                                   |

Nicht-`archive*`-Abhängigkeiten wie `../ssh.js`, `../sshHelpers.js`, `fileHelpers` und
`fileMetadataHelpers` folgen den verschobenen Funktionen und werden hier nicht begrenzt.

Weicht eine Kante bei der Umsetzung ab, entscheidet die Abwärtsrichtung. Das Symbol wird dann anders
zugeordnet und die Tabelle angepasst, statt Code umzuschreiben.

### Zustandsverwaltung

Nicht relevant: Die Module sind zustandslos. `containmentProgress` bleibt ein lokales Objekt pro
Apply.

### API-Integration

Nicht relevant: Die öffentliche API ändert sich nicht. Unverändert bleiben:

- `src/modules/index.ts` und `src/index.ts`
- die Exports in `package.json`
- `test/publicApi.test.ts`
- `llm-guide.md`

### Styling-Ansatz

Nicht relevant.

### Barrierefreiheit

Nicht relevant.

### Randfälle

- **Mock-Bindung:** Importiert `archiveApply.ts` `newContainmentEntryName` versehentlich aus einem
  anderen Modul, schlagen viele Tests in `archive.test.ts` an den Eintragsnamen `run-000…1` fehl.
  Das zeigt einen falschen Importpfad an. Die Lösung ist der richtige Import, keine Änderung am
  Mock. Verschobene Symbole exportiert `archiveContainmentFlag.js` nicht mehr. Tests importieren sie
  aus dem neuen, nicht gemockten Modul.
- **Spy-Bindung:** Dasselbe gilt für `localSha256` in `archiveCheck.ts` und den `vi.spyOn` in
  `archive.test.ts:1842` und `archive.test.ts:1880`.
- **Literale Skripttexte in Tests:** Diese Regexe und Literale in `archive.test.ts` sind direkte
  Kopien der Skripte. Sie müssen ohne Anpassung grün bleiben:
  - Zeilen 183–188: Kopie von `containmentPathsFor`
  - Zeilen 372–395: Staging-Move-Muster und Kopie des Guarded-mkdir
  - Zeilen 7965–7990: Bounded-Command und Merge-Skript

  Schlägt einer davon fehl, hat sich Skripttext geändert. Das ist dann ein Fehler im Refactor.

- **Smoke-Tests unter macOS:** `archive.shell.smoke.test.ts` überspringt die Merge-Teile ohne GNU
  `cp` und `find` (`archive.shell.smoke.test.ts:145–154`, `:328`). Lokal unter macOS ohne GNU
  coreutils sichern deshalb die Literal-Kopien oben jeden Commit ab. Die vollständige
  Shell-Ausführung prüft erst die Linux-CI auf dem PR-Kopf.
- **Dynamischer Import:** `archiveProbe.test.ts:205` lädt `archive` per `await import` aus
  `archive.js`. Das bleibt gültig, weil `archive` dort bleibt.
- **Typ-Zyklen:** Der bestehende Typ-Zyklus `archiveMemberValidation` ⇄ `archiveTarListingParser`
  bleibt unberührt. Neue Zyklen schließt Prüfung C aus, auch reine Typ-Zyklen, die oxlint nicht
  meldet.
- **Coverage-Schwellen:** Die Schwellen von Vitest gelten global, nicht pro Datei. Verschobener Code
  bleibt von denselben Tests abgedeckt.
- **Knappes Apply-Modul:** `archiveApply.ts` hat bei etwa 257 Code-Zeilen nur rund 40 Zeilen Puffer.
  Reicht das nicht, wandern `allocateRemoteUploadPath`, `resolveRemoteSource` und die
  Upload-Konstanten in ein eigenes `archiveUpload.ts`. Dafür bekommt die Tabelle unter
  „Komponentenstruktur“ eine Zeile `archiveUpload` ohne `archive*`-Abhängigkeiten, und `archiveApply`
  erhält die Kante dorthin. Verdichtet wird nichts.

## Akzeptanzkriterien

- [ ] **A – Lint-Ausnahmen:** `grep -n "max-lines" packages/paratix/src/modules/archive.ts packages/paratix/src/modules/archiveContainmentFlag.ts`
      findet nichts. `git diff origin/main -- packages/paratix/src` fügt keine Zeile mit
      `eslint-disable` oder `oxlint-disable` hinzu.
- [ ] **B – Öffentliche API:** `archive.ts` hat genau einen Export, `archive`.
      `git diff origin/main --stat` listet weder `src/modules/index.ts` noch `src/index.ts`.
- [ ] **C – Abhängigkeitsrichtung:** - `grep -ln 'from "./archive.js"' packages/paratix/src/modules/archive*.ts` findet nichts. - Für jede Datei `packages/paratix/src/modules/archive*.ts` ist die Menge ihrer
      `archive*`-Importquellen (`grep -o 'from "\./archive[A-Za-z]*\.js"'`, Typ-Importe
      eingeschlossen) eine Teilmenge ihrer Zeile unter „Komponentenstruktur“. - Dateien, die dort nicht aufgeführt sind, behalten ihre `archive*`-Importquellen
      unverändert.
- [ ] **D – Tests:** `git diff origin/main -- packages/paratix/test` ändert ausschließlich
      Import-Anweisungen, auch deren Reihenfolge. Höchstens kommt eine Kommentarzeile in
      `download.test.ts` dazu. Keine Erwartung, kein Mock und kein Test wird hinzugefügt, entfernt
      oder geändert.
- [ ] **E – Konstanten-Kopien:** `grep -n "const EXEC_OPTS\|const SILENT" packages/paratix/src/modules/archive*.ts`
      zeigt `EXEC_OPTS` in Marker, Staging-Merge, Check und Apply sowie `SILENT` in Staging-Merge
      und Apply. Die bestehende Kopie in `archiveDestinationValidation.ts` erscheint ebenfalls.
      Jede neue Definition stimmt wortgleich mit
      `origin/main:packages/paratix/src/modules/archive.ts:58` beziehungsweise `:63` überein.
- [ ] **F – Commit-Schnitt:** Vor dem Squash-Merge besteht der PR aus einem Commit je neuem Modul.
      Review-Korrekturen sind in den passenden Modul-Commit gefaltet.
- [ ] **Abschlussbedingung:** Auf dem PR-Kopf enden `pnpm agent:check` und
      `pnpm --filter paratix test:integration` jeweils mit Exit-Code 0, und die Prüfungen A bis F
      sind erfüllt.

## Validierungsplan

- **`pnpm agent:check` am Ausgangsstand und auf dem PR-Kopf.** Der Lauf umfasst:
  - Lint mit oxlint und ESLint, mit `--max-warnings=0` und `import/no-cycle`
  - Format und Typecheck
  - Build
  - Unit- und Distributionstests, einschließlich der Shell-Smoke-Tests
- **Nach jedem Commit:**
  `pnpm lint && pnpm typecheck && pnpm --filter paratix exec vitest run test/modules/archive`. Damit
  sind alle `archive*`-Testdateien abgedeckt.
- **`pnpm --filter paratix test:integration` auf dem PR-Kopf, Pflicht.** Läuft gegen einen lokalen
  Docker-Daemon. `paratix.integration.test.ts:1133` und `:1208` prüfen Apply und Check von
  `archive.extract` Ende-zu-Ende.
- **Prüfungen A bis F** aus den Akzeptanzkriterien als Kommandos ausführen.
- **Verschiebungen gegenlesen** mit `git diff --color-moved=dimmed-zebra origin/main`. Das ist eine
  Review-Hilfe, kein Abnahmekriterium.

## Annahmen und offene Punkte

- **Annahme:** Die Code-Zeilen pro Modul sind gezählt, die Import-Blöcke geschätzt (etwa ±10
  Zeilen). Liegt ein Modul trotzdem über 300, wird es entlang der genannten Grenzen weiter geteilt,
  nicht verdichtet. Für `archiveApply.ts` gibt es dafür eine Ausweichlösung (siehe Randfälle).
- **Annahme:** oxlint ignoriert reine Typ-Importe bei `import/no-cycle`. Dafür spricht, dass der
  bestehende Typ-Zyklus den Lint besteht. Prüfung C sichert die Richtung deshalb unabhängig von
  oxlint ab.
- **Annahme:** Ein `vi.spyOn` auf den `fileHelpers`-Namespace wirkt nach dem Umzug in
  `archiveCheck.ts` genauso wie heute in `archive.ts`, weil sich der Mechanismus nicht ändert.
- **Bewusst außerhalb des Umfangs:**
  - `archiveLinkValidation.ts` liegt bei etwa 300 Code-Zeilen und hat keinen Puffer mehr. Eine
    Trennung in archivinterne Linkregeln und das Merge-Modell mit Host-Zustand wäre naheliegend.
    Sie gehört aber nicht zum vom Nutzer gewählten Umfang.
  - Die übrigen Containment-Dateien liegen unter dem Limit.
  - Funktionale Folgefragen aus R-0000016 gehören nicht in einen reinen Refactor. Das betrifft ein
    eigenes Design-Review für die Absicherung nach dem Merge, die Kernel-Gegenprüfung, die
    Quarantäne-Entfernung und das Containment-Flag.
- **Annahme zum Befund:** Nach der Umsetzung ist R-0000016 nur teilweise erledigt. Die
  Modulaufteilung ist umgesetzt, der PR-Neuschnitt durch den Merge von #223 überholt. Das sollte
  beim Abschluss des Befunds so vermerkt werden.

## Plan-Review

### Durchgang vom 1. Oktober 2026 (Planerstellung)

**Ergebnis:** Freigegeben

Geprüft gegen `origin/main` `c62991d9`. Die Code-Zeilen wurden ohne Leer- und Kommentarzeilen
nachgezählt. Das Lint-Verhalten wurde stichprobenartig über ESLint mit `--stdin` geprüft, ohne
Dateien zu schreiben. Alle Befunde sind eingearbeitet.

#### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       3 |       1 |
| Sicherheit  |        0 |       0 |       1 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        1 |       1 |       1 |
| Umfang      |        0 |       0 |       0 |
| Wartbarkeit |        0 |       1 |       3 |

#### Befunde

- **Testbarkeit, kritisch, eingearbeitet:** Das Disable in `archiveContainmentFlag.ts` wäre nach dem
  vorletzten Commit ungenutzt gewesen. ESLint mit `--max-warnings=0` hätte den Commit dann rot
  gemacht. Jetzt gilt: Das Disable fällt im ersten Commit unter dem Limit.
- **Architektur, wichtig, eingearbeitet:** Drei Zuordnungen hätten Zyklen oder Aufwärtskanten
  erzeugt. Neu zugeordnet sind:
  - `ContainmentProgress` und Verwandte zum Staging-Merge;
  - `MISSING_OWNER_PATHS_MARKER_PATTERN` und `isStringArray` zum Marker;
  - der Parametertyp zum Marker.
- **Wartbarkeit, wichtig, eingearbeitet:** Drei `{@link}`-Verweise verletzen nach dem Schnitt
  `jsdoc/no-undefined-types`. Sie sind jetzt als erlaubte Kommentaränderung benannt.
- **Testbarkeit, wichtig, eingearbeitet:** Die Akzeptanzkriterien ergaben keine eindeutige
  Abschlussbedingung. Jetzt gibt es die Prüfungen A bis F und eine einzige Abschlussbedingung.
- **Hinweise, eingearbeitet:**
  - Der Prüfaufwand je Commit ist gesenkt.
  - Größenschätzungen, Konstanten-Zuordnung, Kanten und Zeilenangaben sind korrigiert.
  - Prüfung E sichert die Kopien von `EXEC_OPTS` ab.

### Durchgang vom 1. Oktober 2026 (tiefes interaktives Review)

**Ergebnis:** Freigegeben

Es wurde jedes Top-Level-Symbol beider Quelldateien auf genau eine Zuordnung geprüft. Außerdem
wurde nachgewiesen, dass jeder Commit für sich kompiliert. Vier Entscheidungen hat der Nutzer
getroffen, alle übrigen Befunde sind direkt eingearbeitet.

#### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       2 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       1 |       4 |
| Umfang      |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       5 |

#### Befunde

- **Testbarkeit, wichtig, eingearbeitet:** Die erste Suche in Prüfung C fand immer
  `src/modules/index.ts`, das `archive` bewusst re-exportiert. Die Abschlussbedingung war damit
  unerfüllbar. Die Suche ist jetzt auf `archive*.ts` beschränkt.
- **Architektur, wichtig, eingearbeitet:** In der alten Reihenfolge hätte der Establish-Commit
  vorübergehend einen Typ-Zyklus zwischen Format- und Establish-Modul erzeugt. Die beiden letzten
  Commits sind deshalb getauscht: erst Entries, dann Establish.
- **Architektur, wichtig, eingearbeitet:** Die Abhängigkeitsliste widersprach den Zuordnungen. Es
  fehlten Kanten, und Marker sowie Listing fehlten ganz. Die Liste ist jetzt eine vollständige
  Tabelle je Modul und über Prüfung C verbindlich.
- **Testbarkeit, Hinweis, eingearbeitet:** Prüfung C prüfte nur Stichproben. Sie gilt jetzt für alle
  `archive*`-Dateien.
- **Testbarkeit, Hinweis, eingearbeitet:** Die Begründung zum Mock war falsch und ist korrigiert.
- **Testbarkeit, Hinweis, eingearbeitet:** Prüfung E verwies auf Zeilen, die es nach dem Refactor
  nicht mehr gibt. Sie verweist jetzt auf `origin/main` und nennt die erwarteten Kopien.
- **Testbarkeit, Hinweis, eingearbeitet:** Die Smoke-Tests überspringen unter macOS ohne GNU
  coreutils die Merge-Teile. Das ist jetzt als Randfall dokumentiert.
- **Wartbarkeit, Hinweis, eingearbeitet:**
  - Überlappende und fehlende Zeilenbereiche sind korrigiert.
  - Bisher ungenannte private Helfer in `archiveContainmentFlag.ts` sind jetzt zugeordnet.
  - Die Formulierung zu `checkExtract` ist präzisiert.
  - Für jeden `{@link}`-Verweis ist festgelegt, in welchem Commit er angepasst wird.
  - Die Größenschätzungen sind aktualisiert.
- **Umfang, Hinweis, eingearbeitet:** Der Plan wollte einen Dateikopf von `archive.ts` anpassen, den
  es nicht gibt. Die Anweisung ist ersetzt durch einen kurzen Kopf für jedes neue Modul.
- **Entscheidungen des Nutzers:**
  - Squash-Merge; Prüfung F bezieht sich auf den Stand vor dem Merge.
  - Der Docker-Integrationslauf ist Pflicht auf dem PR-Kopf.
  - `ApplyParameters` wird schon in diesem PR zu `ArchiveExtractParameters`.
  - Jedes neue Modul bekommt einen kurzen Dateikopf.

## Offene Punkte

- Keine offenen Punkte.
