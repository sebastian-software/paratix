# Breaking Change 0.18.0 in die Migration aufnehmen

**Planungsstatus:** Umgesetzt
**Quelle:** `effective-flow plan`
**Empfohlener Workflow:** Documentation (`effective-flow docs`)
**Doku-Kategorie:** user-guide
**Ziel-Pfad:** docs/user-guide/migration.md

## Anforderung

Die bestehenden englischen Migration Notes sollen den Breaking Change aus `paratix` 0.18.0
aufnehmen: Seit dieser Version beendet ein fehlgeschlagenes Signal die noch nicht ausgeführten
Signale derselben Liste. Betroffen sind Playbooks, die sich darauf verlassen, dass spätere,
unabhängige Signale trotz eines vorherigen Fehlers noch versucht werden.

Der neue Eintrag muss den Wechsel von Versionen vor 0.18.0 auf 0.18.0 oder neuer im etablierten
Format `Before` / `Now` / `Upgrade` beschreiben. Er muss sowohl einen zurückgegebenen Status
`"failed"` als auch eine geworfene Exception abdecken, den Abbruch auf die aktuelle Signal-Liste
begrenzen und zugleich klarstellen, dass der umgebende Fail-fast-Kontrollfluss nicht garantiert,
dass eine später angeordnete Liste im selben Playbook-Lauf noch erreicht wird.

Die Änderung ist reine Dokumentation. Changelog, ADR, Agent-Guide, Implementierung und Tests sind
bereits konsistent und dienen nur als Quellen. Der vorhandene Auditvermerk wird um einen gezielten
Nachtrag zu 0.18.0 ergänzt; er darf keinen vollständigen Re-Audit aller Releases nach 0.13.0
behaupten.

Planungsbasis ist der Repository-Stand `404d3d43` vom 23. September 2026. Die Zieldatei ist im
Arbeitsbaum unverändert; alle übrigen vorhandenen Arbeitsbaumänderungen sind sachfremd und bleiben
unangetastet.

## Architekturentscheidungen

- `docs/user-guide/migration.md` bleibt die einzige kanonische, nutzerorientierte Oberfläche für
  bestätigte Änderungen, die eine Anpassung bestehender Projekte erfordern.
- Der neue Abschnitt steht im Teil `paratix` nach den vorhandenen 0.11.0-Einträgen und vor
  `create-paratix`. Er folgt damit der bestehenden aufsteigenden Versionsfolge.
- `Before` beschreibt das belegte Verhalten bis 0.17.x: `runSignalModules` merkte einen Fehler vor,
  führte aber die restlichen Signale derselben Liste weiter aus.
- `Now` beschreibt das Verhalten ab 0.18.0: Der erste Status `"failed"` oder die erste geworfene
  Exception beendet die aktuelle Liste mit Status `"failed"`. Es gibt keinen
  `continueOnError`-Schalter.
- `Upgrade` unterscheidet abhängige und unabhängige Arbeit. Abhängige Signale bleiben für bewusstes
  Fail-fast-Verhalten zusammen. Arbeit, die trotz eines anderen Fehlers garantiert versucht werden
  soll, wird in einen separaten Playbook-Lauf verlegt. Eine separate Signal-Liste allein wird nicht
  als Garantie empfohlen.
- Der Migrationseintrag verspricht nicht pauschal, dass jede separate Liste nach einem Fehler noch
  ausgeführt wird. Der Recipe- oder Run-Kontrollfluss kann den umgebenden Lauf bereits beendet
  haben.
- Nach einem Signalfehler wird zuerst die Ursache behoben. Ein normaler erneuter Playbook-Lauf
  versucht die übersprungenen Signale nur, wenn mindestens ein Modul im selben Recipe- oder
  Top-Level-Scope erneut `changed` meldet. Meldet der ganze Scope `ok`, steht keine Signal-Liste
  aus; auch `signals.flush()` kann sie dann nicht erzwingen. Zur Wiederherstellung wird deshalb
  entweder eine echte, beabsichtigte Zustandsänderung ausgelöst, die in diesem Scope zu `changed`
  führt, oder die übersprungene Operation wird direkt ausgeführt. Für einen bereits unter einer
  älteren Version entstandenen geteilten Quadlet-Stack verweist der Eintrag auf den vorhandenen
  sicheren Wiederherstellungsweg in `troubleshooting.md`; ein Downgrade auf das frühere Verhalten
  wird nicht empfohlen.
- Der Auditvermerk behält die ursprüngliche Prüfung bis 0.13.0 bei und ergänzt eine datierte,
  gezielte 0.18.0-Prüfung gegen `paratix-v0.17.0`, `paratix-v0.18.0`, Changelog, ADR,
  Implementierung, Tests und Agent-Guide.
- Es wird kein Codebeispiel ergänzt. Für diesen kompakten Eintrag ist die handlungsorientierte
  Umbauanweisung eindeutiger als ein künstliches Beispiel, das eine bestimmte Playbook-Struktur
  voraussetzen würde.

## Betroffene Dateien

| Datei                          | Beschreibung                                                       |
| ------------------------------ | ------------------------------------------------------------------ |
| `docs/user-guide/migration.md` | Versionierten 0.18.0-Eintrag und gezielten Auditnachtrag ergänzen. |

`packages/paratix/CHANGELOG.md`,
`docs/adr/0006-signal-lists-stop-at-the-first-failed-signal.md`,
`packages/paratix/llm-guide.md`, `packages/paratix/src/signalOrchestration.ts`,
`packages/paratix/src/recipe.ts`, `packages/paratix/src/runner.ts` sowie die Signal-Tests sind
ausschließlich Analyse- und Validierungsquellen und werden nicht geändert.

## Implementierungsdetails

### Vorgehen

1. Vor dem Schreiben die aktuelle Zieldatei sowie den 0.18.0-Abschnitt des Paratix-Changelogs, den
   akzeptierten ADR-0006 und den Signal-Abschnitt des Agent-Guides erneut lesen. Zusätzlich die Tags
   `paratix-v0.17.0` und `paratix-v0.18.0` mit `git rev-parse --verify` auflösen und den Diff von
   `packages/paratix/src/signalOrchestration.ts` zwischen beiden Tags prüfen. Erwartet wird, dass
   0.17 Fehler sammelt und die Liste fortsetzt, während 0.18 bei Fehlerstatus und Exception sofort
   `"failed"` zurückgibt. Falls Tags fehlen oder die Quellen nicht übereinstimmen, die Umsetzung
   stoppen und den Plan revidieren.
2. Im Abschnitt `paratix` einen englischen Eintrag mit der Überschrift
   `### 0.18.0: signal lists stop at the first failure` ergänzen.
3. In `Before` festhalten, dass vor 0.18.0 spätere Signale derselben Liste auch nach einem
   zurückgegebenen Fehlerstatus oder einer Exception weiter ausgeführt wurden und der umgebende
   Recipe- oder Run-Status den Fehler erst nach der Liste behandelte.
4. In `Now` festhalten, dass ab 0.18.0 der erste Fehler die restlichen Signale dieser Liste
   überspringt, die Liste als fehlgeschlagen gilt und es keinen Opt-out über `continueOnError` gibt.
5. In `Upgrade` abhängige Schritte zusammenlassen und unabhängig auszuführende Arbeit in separate
   Playbook-Läufe verlegen. Ausdrücklich davor warnen, eine separate oder später angeordnete
   Signal-Liste im bereits fehlgeschlagenen Lauf als garantiert anzunehmen. Als Recovery nach einem
   tatsächlichen Fehler die Ursache beheben und das Playbook erneut ausführen; für einen bereits
   geteilten Quadlet-Stack auf den Abschnitt `A Quadlet container cannot be replaced` in
   `troubleshooting.md` verweisen.
6. Den bestehenden Auditvermerk um einen separaten Satz zur gezielten 0.18.0-Prüfung am 23. September 2026 ergänzen. Die ursprüngliche Reichweite bis 0.13.0 bleibt unverändert sichtbar.
7. Format, Patchsauberkeit, bestehendes Rücklinkziel und den vollständigen Repository-Check gemäß
   Validierungsplan prüfen.

### Randfälle

- Ein Signal kann entweder mit Status `"failed"` enden oder eine Exception werfen. Beide Pfade
  brechen die aktuelle Liste ab und müssen durch die Formulierung abgedeckt sein.
- Eine separat aufgerufene Signal-Liste hat keinen globalen Sperrzustand aus der zuvor
  fehlgeschlagenen Liste. Daraus folgt jedoch keine Zusage, dass ein öffentlicher Playbook-Lauf
  diese spätere Liste tatsächlich erreicht.
- `create-paratix` 0.18.0 enthält laut eigenem Changelog keinen entsprechenden Breaking Change und
  erhält keinen Migrationseintrag.
- Der Eintrag gehört nicht unter `Unreleased`, da er mit `paratix-v0.18.0` veröffentlicht wurde.
- Falls vor der Umsetzung eine neue Paratix-Version oder ein weiterer bestätigter Breaking Change
  erscheint, wird nur die Versions- und Vollständigkeitsannahme erneut geprüft; zusätzliche
  Migrationseinträge erweitern diesen Plan nicht automatisch.
- Falls `docs/user-guide/migration.md` seit `404d3d43` inhaltlich geändert wurde, die Einfügestelle,
  Auditreichweite und Akzeptanzkriterien vor der Umsetzung erneut prüfen. Falls dafür oder für einen
  weiteren Migrationseintrag zusätzlicher Scope nötig wird, den Plan revidieren.
- Falls die Validierungsbasis bereits fehlschlägt und sich ein Ergebnis nicht eindeutig diesem
  Dokumentationspatch zuordnen lässt, nicht mit einem unbelegten Erfolg fortfahren.
- Die bestehenden README-Links auf die Migration Notes bleiben gültig. Navigation, ADR,
  Changelog, Agent-Guide, Produktcode und Tests sind nicht Teil des Schreibumfangs.
- Der Dokumentationspatch selbst kann vollständig zurückgenommen werden und enthält keine Daten-,
  Schema- oder Laufzeitmigration. Ein Downgrade auf Paratix 0.17.x ist kein empfohlener Rollback des
  sicheren Fail-fast-Verhaltens.

## Akzeptanzkriterien

- [ ] `docs/user-guide/migration.md` enthält unter `paratix` genau einen versionierten
      0.18.0-Eintrag im bestehenden englischen `Before` / `Now` / `Upgrade`-Format.
- [ ] Der Eintrag nennt als betroffene Nutzer Playbook-Autoren, deren spätere Signale derselben
      Liste trotz eines vorherigen Fehlers weiterlaufen sollten.
- [ ] `Before` beschreibt korrekt das Verhalten bis 0.17.x; `Now` beschreibt korrekt den Abbruch
      bei zurückgegebenem `"failed"` und geworfener Exception ab 0.18.0.
- [ ] Der Text begrenzt den direkten Abbruch auf die aktuelle Signal-Liste, behauptet aber nicht,
      eine später angeordnete Liste im selben Recipe oder Run werde garantiert ausgeführt.
- [ ] `Upgrade` empfiehlt für Arbeit, die trotz eines anderen Fehlers garantiert versucht werden
      soll, separate Playbook-Läufe. Der Text stellt klar, dass eine separate Signal-Liste allein
      diese Garantie nicht bietet, erwähnt den fehlenden `continueOnError`-Schalter und nennt als
      Recovery das Beheben der ersten Fehlerursache mit anschließendem erneuten Playbook-Lauf.
- [ ] Ein vorhandener geteilter Quadlet-Stack wird nicht als automatisch repariert dargestellt;
      der Eintrag verweist dafür auf den bestehenden Wiederherstellungsweg in
      `docs/user-guide/troubleshooting.md`.
- [ ] Der Auditvermerk dokumentiert die gezielte Prüfung von 0.18.0, ohne eine vollständige Prüfung
      aller Releases von 0.14.0 bis 0.19.0 zu behaupten.
- [ ] `Unreleased`, der Abschnitt `create-paratix` und alle Produkt- und Dokumentationsdateien
      außerhalb `docs/user-guide/migration.md` bleiben unverändert. Planstatus und Archivierung im
      späteren Effective-Flow-Lifecycle sind von dieser Produktpatch-Allowlist ausgenommen.
- [ ] Die fokussierte Prettier-Prüfung, `git diff --check` und `pnpm agent:check` enden mit
      Exit-Code 0; Docker-/SSH-Integrationstests sind für diese reine Markdown-Änderung nicht nötig.

## Validierungsplan

- `pnpm exec prettier --check docs/user-guide/migration.md` im Repository-Root ausführen;
  erwartetes Ergebnis ist Exit-Code 0 ohne Formatabweichung.
- Mit
  `test "$(rg -c '^### 0\\.18\\.0: signal lists stop at the first failure$' docs/user-guide/migration.md)" -eq 1`
  prüfen, dass die neue Überschrift genau einmal vorkommt; erwartetes Ergebnis ist Exit-Code 0.
- `git diff --check -- docs/user-guide/migration.md` ausführen; erwartetes Ergebnis ist keine
  Ausgabe und Exit-Code 0.
- Mit `test -f docs/user-guide/README.md` prüfen, dass das vorhandene relative Rücklinkziel weiter
  existiert; erwartetes Ergebnis ist Exit-Code 0.
- Den fertigen Eintrag manuell gegen `packages/paratix/CHANGELOG.md`, ADR-0006,
  `packages/paratix/llm-guide.md`, die aktuelle Implementierung und die Tests für fehlgeschlagene,
  werfende und getrennt aufgerufene Signal-Listen abgleichen.
- `pnpm --filter paratix exec vitest run test/runner-signals.test.ts test/recipe.test.ts` ausführen;
  erwartetes Ergebnis ist Exit-Code 0 für die fokussierten Signal- und Recipe-Regressionstests.
- Abschließend `pnpm agent:check` ausführen; erwartetes Ergebnis ist Exit-Code 0. Der Check umfasst
  Lint, den repository-weiten Prettier-Check, Typecheck, Build und Tests. Integrationstests sind für
  den reinen Dokumentationspatch nicht erforderlich.

## Annahmen und offene Punkte

- Verifiziert: `packages/paratix/CHANGELOG.md` weist die Änderung in 0.18.0 ausdrücklich als
  Breaking Change aus.
- Verifiziert: `paratix-v0.17.0` führte nach einem fehlgeschlagenen Signal weitere Signale derselben
  Liste aus; aktuelle Implementierung und Regressionstests brechen bei Fehlerstatus und Exception
  sofort ab.
- Verifiziert: ADR-0006 und `packages/paratix/llm-guide.md` dokumentieren das aktuelle Verhalten,
  den fehlenden `continueOnError`-Schalter und die Trennung unabhängiger Arbeit.
- Verifiziert: Der öffentliche Recipe- und Run-Kontrollfluss kann nach dem Listenfehler abbrechen;
  eine spätere Liste im selben Lauf darf daher nicht als garantiert dargestellt werden.
- Verifiziert: Es gibt keinen eigenen Docs-Build oder Markdown-Linkchecker. Prettier und der
  Repository-Gesamtcheck sind die etablierten automatisierten Prüfpfade.
- Annahme: Ein kurzer Migrationseintrag ohne Codebeispiel genügt dem etablierten Umfang der Seite.
  Falls bei der Umsetzung eine verständliche Formulierung ohne Beispiel nicht möglich ist, wird
  nicht improvisiert, sondern der Plan vor einer Scope-Erweiterung revidiert.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       2 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       2 |
| Testbarkeit |        0 |       0 |       2 |
| Scope       |        0 |       0 |       2 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Architektur (Hinweis):** Die bestehende Migration-Seite ist bereits die richtige kanonische
  Oberfläche. Ein neues Dokument oder Änderungen an Changelog, ADR und Agent-Guide würden dieselbe
  Aussage nur duplizieren.
- **Architektur (Hinweis, entschieden):** Der interne Listen-Runner begrenzt den Abbruch auf eine
  Liste, der öffentliche Recipe- und Run-Kontrollfluss kann danach aber vollständig abbrechen. Für
  garantiert unabhängige Versuche empfiehlt der Plan deshalb separate Playbook-Läufe; eine separate
  Signal-Liste allein wird ausdrücklich nicht als Garantie dargestellt.
- **Fehlerfälle (Hinweis):** Die Formulierung muss Statusfehler und Exceptions abdecken und die
  Listen-Grenze von der Wirkung des umgebenden Recipe- oder Run-Abbruchs unterscheiden.
- **Fehlerfälle (Hinweis, eingearbeitet):** Der Plan nennt nun das Beheben der Fehlerursache mit
  anschließendem erneutem Lauf und verweist für einen bereits geteilten Quadlet-Stack auf den
  vorhandenen sicheren Wiederherstellungsweg. Ein Downgrade wird nicht empfohlen.
- **Testbarkeit (Hinweis):** Es existiert kein eigener Markdown-Test. Format- und Patchprüfung,
  Quellenabgleich sowie `pnpm agent:check` bilden den belastbaren repository-nativen Prüfpfad.
- **Testbarkeit (Hinweis, eingearbeitet):** Tag-Auflösung, historischer Implementierungsdiff,
  exakte Überschriftenzählung und fokussierte Regressionstests machen die historischen und
  strukturellen Aussagen reproduzierbar.
- **Scope (Hinweis):** Der gezielte Auditnachtrag verhindert eine unbelegte Aussage, alle Releases
  von 0.14.0 bis 0.19.0 seien erneut vollständig geprüft worden.
- **Scope (Hinweis, eingearbeitet):** Die Ein-Datei-Allowlist gilt für den Produktpatch; spätere
  Planstatus- und Archivierungsänderungen des Effective-Flow-Lifecycles sind ausdrücklich davon
  getrennt.
- **Wartbarkeit (Hinweis):** Der Eintrag verweist inhaltlich auf den stabilen Fehlervertrag und
  vermeidet Details einer konkreten Playbook-Struktur, die schneller veralten könnten.

## Testergebnisse

- `git rev-parse --verify paratix-v0.17.0` und `paratix-v0.18.0`: bestanden; beide historischen
  Tags sind vorhanden.
- Historischer Diff von `packages/paratix/src/signalOrchestration.ts`: bestätigt das Fortsetzen
  innerhalb der Liste in 0.17.0 und das sofortige `"failed"` bei Fehlerstatus oder Exception in
  0.18.0.
- `./node_modules/.bin/prettier --check docs/user-guide/migration.md`: bestanden.
- Exakte Überschriftenzählung für den 0.18.0-Eintrag: bestanden; die Überschrift kommt genau einmal
  vor.
- `git diff --check -- docs/user-guide/migration.md`: bestanden.
- Existenzprüfung für `docs/user-guide/README.md`: bestanden.
- `pnpm --filter paratix exec vitest run test/runner-signals.test.ts test/recipe.test.ts`:
  bestanden; 89 Tests in zwei Testdateien erfolgreich.
- `pnpm agent:check`: bestanden; Lint, repository-weites Prettier, Typecheck, Build, Workspace- und
  Script-Tests erfolgreich. Im Gesamtlauf bestanden 4.292 Tests, 9 wurden übersprungen.
- Docker-/SSH-Integrationstests: nicht ausgeführt, da ausschließlich Markdown geändert wurde und
  weder `ssh`- noch `readFile`-Semantik betroffen ist.

## Review-Befunde

- Keine Befunde. Der unabhängige Inhaltsabgleich bestätigt die Fehlersemantik, die konservative
  Empfehlung separater Playbook-Läufe, Recovery, Linkziel und begrenzte Auditreichweite.
- Es existiert kein eigener Docs-Build oder Markdown-Linkchecker. Das relative Linkziel und der
  konkrete Anker wurden deshalb direkt geprüft.

## Offene Punkte

- Keine offenen Punkte.
