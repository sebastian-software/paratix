# Automatische Drift-Prüfungen

**Planungsstatus:** Umgesetzt
**Quelle:** effective-flow plan
**Empfohlener Workflow:** Feature (`effective-flow build`)

## Anforderung

Ein automatisch erzeugter Changelog-Eintrag unter „⚠ BREAKING CHANGES“ soll vor einem Release eine strukturell vollständige Migrationsanleitung ohne offenkundige Platzhalter erzwingen. Derzeit gibt es diesen Abgleich nicht. Der einzige seit 0.14.0 ausdrücklich markierte Fall auf GitHub `main` ist `paratix` 0.18.0; der nachträglich ergänzte Eintrag in `docs/user-guide/migration.md` ist ein positiver Ausgangsfall.

Die bereits implementierten Prüfungen für öffentliche Exports, JSDoc-Importe und den markierten Importblock des gepackten `llm-guide.md` bleiben bestehen. Die fünf defekten Links und ihre Tarball-Prüfung sind im gleichzeitig angelegten, offenen Plan `docs/plan/2026-09-23-paketsichere-dokumentationslinks.md` vollständig beschrieben. Dieser Plan dupliziert weder dessen Dateiänderungen noch dessen Tests. Zusammen decken die beiden Pläne die im Dokumentationsreview benannten verbleibenden automatischen Drift-Prüfungen ab.

Planungsbasis ist der lesend geprüfte GitHub-Stand `00271a0` vom 23. September 2026. Der lokale Checkout steht bei `404d3d43` und enthält sachfremde Änderungen an `CLAUDE.md`, `docs/adr/effective-flow-project-setup.md` sowie unversionierte Plan-Dateien. Vor der Umsetzung ist der aktuelle `main`-Stand erneut zu prüfen; die vorhandene 0.18.0-Migrationsnotiz und die jüngeren Distributionstests dürfen nicht durch Arbeit auf dem älteren Checkout verloren gehen.

## Architekturentscheidungen

- Die Prüfung betrachtet die beiden von Release Please gepflegten Dateien `packages/paratix/CHANGELOG.md` und `packages/create-paratix/CHANGELOG.md` getrennt. Ein Breaking-Abschnitt wird dem umschließenden `## [Version]`-Abschnitt seines Pakets zugeordnet.
- Ein ausdrücklich markierter Breaking-Abschnitt erfordert im passenden Paketabschnitt von `docs/user-guide/migration.md` mindestens einen Eintrag für dieselbe Version. Der Eintrag muss nicht leere „Before“-, „Now“- und „Upgrade“-Teile ohne offenkundige Platzhalter enthalten. Eine Notiz für das andere Paket oder eine andere Version zählt nicht.
- Für das kontrollierte Format der Release-Please-Changelogs und des vorhandenen Migration Guides genügt eine kleine, getestete Auswertung von Markdown-Überschriften und Abschnittstext. Es wird keine neue Parser-Abhängigkeit eingeführt. Fehlende Paketabschnitte und fehlende Versionseinträge für erkannte Breaking-Abschnitte führen zu einem klaren Fehler statt zu einem leeren Erfolg. Eine Version ohne Breaking-Abschnitt benötigt keinen Migrationseintrag.
- Die Prüfung liegt zusammen mit ihren Gegenbeispielen in `scripts/migrationDocumentation.test.mjs`; eine nur von diesem Test genutzte Hilfsdatei wäre unnötig. Der bestehende Root-Befehl `pnpm test:scripts` nimmt `scripts/*.test.mjs` automatisch auf. Damit läuft der Check über `pnpm agent:check` sowohl in PR-CI als auch im `validate`-Job vor der Veröffentlichung.
- Es wird nur deklarierte Breaking-Change-Drift geprüft. Der Migration Guide vermerkt selbst, dass 0.14.0–0.19.0 nicht vollständig semantisch auditiert wurden. Ein solcher Voll-Audit ist ein separates Arbeitspaket; ein Test kann nicht aus beliebigen Codeänderungen zuverlässig eine nicht deklarierte Verhaltensänderung ableiten.

## Betroffene Dateien

| Datei                                     | Beschreibung                                                               |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| `scripts/migrationDocumentation.test.mjs` | Paket- und versionsgenauer Check mit Gegenbeispielen und echten Dokumenten |

Der parallel entstandene Link-Plan berührt die Paket-READMEs, den `llm-guide.md` und beide Distributionstests. Diese Dateien werden in diesem Vorhaben nur als bestehende beziehungsweise geplante Nachbar-Gates berücksichtigt.

## Implementierungsdetails

### Vorgehen

1. Den aktuellen `main`-Stand, die Release-Please-Konfiguration, beide Changelogs, den Migration Guide und die Skripttest-Verkabelung erneut lesen. Falls der Link-Plan inzwischen umgesetzt wurde, dessen Tarball-Check als vorhandenes Gate bestätigen; andernfalls die Arbeitspakete getrennt lassen.
2. Changelog-Abschnitte anhand ihrer Versionsüberschriften begrenzen und innerhalb jedes Abschnitts die Breaking-Überschrift erkennen. Für jedes gefundene Paar aus Paket und Version den passenden Abschnitt im Migration Guide suchen. Fehlende oder mehrdeutige Struktur mit Paket, Version und Quelldatei melden. Eine sichtbare, aber nicht als Überschrift erkannte „BREAKING CHANGES“-Kennzeichnung darf nicht stillschweigend übergangen werden.
3. Den passenden Migrationseintrag auf nicht leere „Before“-, „Now“- und „Upgrade“-Inhalte prüfen. Offenkundige Platzhalter wie `TODO`, `TBD`, `coming soon` sowie reine Leerzeichen oder nur eine Überschrift dürfen nicht genügen. Mehrere Migrationseinträge für dieselbe Version sind zulässig; mindestens einer muss diese Strukturprüfung bestehen.
4. Mit synthetischen Dokumenten nachweisen, dass fehlende Einträge, falsche Pakete, falsche Versionen, leere Upgrade-Teile, die benannten Platzhalter und fehlerhafte Überschriften scheitern. Eine Version ohne Breaking-Abschnitt und ein korrekt dokumentierter Breaking Change müssen bestehen.
5. Die echten Repository-Dateien als Regressionstest einlesen. Der Test muss den vorhandenen Breaking-Abschnitt von `paratix` 0.18.0 tatsächlich finden und seinen Migrationseintrag bestätigen; dadurch bleibt eine versehentlich inaktive Erkennung sichtbar.
6. `pnpm test:scripts` und `pnpm agent:check` ausführen. CI- oder Publish-Workflow nur anpassen, wenn der aktuelle Branch diese Befehle nicht mehr im PR- beziehungsweise Publish-Validate-Pfad ausführt.

### Randfälle

- Die zwei Pakete haben gekoppelte Versionsnummern. Trotzdem darf eine `paratix`-Notiz keinen Breaking Change in `create-paratix` abdecken.
- Ein Changelog-Release ohne ausdrückliche Breaking-Überschrift benötigt keinen Migrationseintrag. Additive Features und interne Fixes sollen keinen Fehlalarm erzeugen.
- Mehrere Breaking-Punkte in einer Version können einen gemeinsamen Migrationseintrag haben. Der Test erzwingt die Version und die Bestandteile einer Anleitung, nicht die semantische Vollständigkeit jedes einzelnen Punkts.
- Auch ein vollständig formulierter, aber sachlich falscher Upgrade-Schritt kann die Strukturprüfung bestehen. Seine Richtigkeit bleibt Gegenstand des fachlichen Reviews.
- Ändert Release Please die Überschriftenform, muss der Erkennungstest mit dem bekannten 0.18.0-Fall weiterhin nachweisbar greifen oder der Parser mit überprüfbarer Anpassung geändert werden.
- Die Prüfung benötigt weder Git-Historie noch Netzzugriff oder einen Registry-Zugang und ist in einem normalen PR-Checkout reproduzierbar.

## Akzeptanzkriterien

- [x] Der neue Skripttest findet in den echten Changelogs mindestens den Breaking-Abschnitt von `paratix` 0.18.0 und akzeptiert dessen konkrete Migrationsnotiz.
- [x] Ein ausdrücklich markierter Breaking-Abschnitt ohne strukturell vollständige Anleitung für genau dasselbe Paket und dieselbe Version lässt den Test mit einer aussagekräftigen Fehlermeldung scheitern. Leere Felder und die benannten Platzhalter zählen nicht als Anleitung; ein Eintrag unter dem anderen Paket oder einer anderen Version kann den Test nicht grün machen.
- [x] Ein Release ohne Breaking-Abschnitt bleibt ohne neue Migrationsnotiz zulässig; fehlerhafte oder leere Dokumentstruktur wird nicht stillschweigend als „keine Breaking Changes“ behandelt.
- [x] `pnpm test:scripts` und `pnpm agent:check` bestehen. Der neue Check wird damit in PR-CI und vor der Veröffentlichung ausgeführt, ohne eine zusätzliche CI-Pipeline einzuführen.
- [x] Die bestehenden API- und Guide-Drift-Tests bleiben erhalten; die Tarball-Linkprüfung verbleibt eindeutig beim offenen Plan `2026-09-23-paketsichere-dokumentationslinks.md`.

## Validierungsplan

| Zweck                        | Befehl im Repository-Root                             | Erwartetes Ergebnis                                                            |
| ---------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| Einzelner Drift-Test         | `node --test scripts/migrationDocumentation.test.mjs` | Reale Dokumente bestehen; alle Gegenbeispiele unterscheiden Fehlerfälle        |
| Fokussierter Migrationscheck | `pnpm test:scripts`                                   | Synthetische Gegenbeispiele werden abgewiesen; echte 0.18.0-Zuordnung besteht  |
| Gesamtes Repository-Gate     | `pnpm agent:check`                                    | Lint, Format, Typprüfung, Build und alle Tests bestehen                        |
| Scope und Format             | `git diff --check` und `git status --short`           | Keine Whitespace-Fehler; nur geplante und bereits vorhandene fremde Änderungen |

Vor der Umsetzung `00271a0` und die genannten Dateiformate mit dem aktuellen `main`-Stand vergleichen. Falls Release Please, die Migrationsüberschriften oder die Skripttest-Verkabelung abweichen, den Plan vor dem Schreiben entsprechend anpassen. Die synthetischen Negativfälle beweisen, dass der Test beim Entfernen einer nötigen Migrationseintragung tatsächlich rot wird.

## Annahmen und offene Punkte

- Verifiziert auf GitHub `main` `00271a0`: `release-please-config.json` verwaltet beide Pakete mit gekoppelten Versionen; die beiden Paket-Changelogs nutzen `## [Version]` und für `paratix` 0.18.0 die Überschrift „⚠ BREAKING CHANGES“.
- Verifiziert auf GitHub `main` `00271a0`: `docs/user-guide/migration.md` enthält unter `paratix` 0.18.0 eine Notiz mit „Before“, „Now“ und „Upgrade“. Die Datei bezeichnet den fehlenden Voll-Audit für 0.14.0–0.19.0 ausdrücklich.
- Verifiziert auf GitHub `main` `00271a0`: `package.json` bindet `scripts/*.test.mjs` über `pnpm test:scripts` in `pnpm agent:check` ein; PR-CI und Publish-Validate führen das Gate aus.
- Annahme: Neue Breaking Changes werden weiterhin in den Release-Please-Changelogs ausdrücklich markiert. Eine nicht markierte semantische Änderung erfordert weiterhin Review und gegebenenfalls den separaten Voll-Audit.
- Der offene Plan für paketsichere Links ist organisatorisch benachbart, aber keine technische Voraussetzung für diesen Migrationscheck. Beide Pläne können getrennt umgesetzt werden.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       1 |       1 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Architektur (Hinweis):** Das vorhandene Skripttest-Gate bindet die Prüfung ohne zusätzlichen Workflow in CI und Publish-Validate ein.
- **Fehlerfälle (Hinweis):** Die Prüfung verlangt erkennbare Paket- und Versionsabschnitte; ein Strukturfehler wird nicht als leere Trefferliste gewertet.
- **Testbarkeit (Hinweis):** Der reale 0.18.0-Fall und synthetische Gegenbeispiele beweisen sowohl Erkennung als auch Ablehnung.
- **Scope (Hinweis):** Der separate Link-Plan verhindert doppelte Änderungen an Dokumenten und Distributionstests. Nicht deklarierte Breaking Changes bleiben eine Review-Aufgabe.
- **Wartbarkeit (Hinweis):** Die Überschriftenauswertung bleibt auf das vom Projekt erzeugte Format begrenzt und benötigt keine neue Abhängigkeit.

### Tiefenreview vom 23. September 2026

- **Testbarkeit (Wichtig, eingearbeitet):** Nicht leere „Before“-, „Now“- und „Upgrade“-Teile allein hätten `TBD` akzeptiert. Der Plan nennt jetzt konkrete Platzhalter als Negativfälle und begrenzt den automatischen Nachweis ausdrücklich auf Struktur und offenkundige Platzhalter; die sachliche Richtigkeit bleibt im Review.
- **Fehlerfälle (Hinweis, eingearbeitet):** Ein fehlender Versionsabschnitt ist nur dann ein Fehler, wenn für dieses Paket und diese Version ein Breaking-Abschnitt erkannt wurde. Diese Bedingung steht nun ausdrücklich in der Architekturentscheidung.

## Offene Punkte

- Keine offenen Punkte.

## Testergebnisse

**Datum:** 23.09.2026

- `node --test scripts/migrationDocumentation.test.mjs`: 9 von 9 Tests bestanden, einschließlich des echten Breaking Changes von `paratix` 0.18.0, eines Vorabversionsfalls und synthetischer Gegenbeispiele.
- `pnpm test:scripts`: bestanden; der neue Test wird durch das bestehende Skripttest-Muster erfasst.
- `pnpm agent:check`: vollständig bestanden – Lint, Formatprüfung, Typprüfung, Build und Tests. Die Ausgabe enthielt erwartete Warnungen aus simulierten Fehlerfällen der bestehenden Tests.
- `git diff --check`: bestanden. Im isolierten Checkout entstand außer `scripts/migrationDocumentation.test.mjs` keine fachliche Änderung.

## Review-Befunde

**Datum:** 23.09.2026
**Reviewer:** Effective-Flow-Validierung und eigener Strukturreview

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      1 |
| Offen / Nicht umgesetzt |      0 |

Die Überschrift `##[Version]` nach einem gültigen Release hätte einen folgenden Breaking-Abschnitt zunächst der vorherigen Version zugeordnet. Die Erkennung wurde korrigiert und mit einem Negativtest abgesichert. Für den Tooling-Bereich ergab die abschließende technische Validierung keine offenen Befunde.

### Dokumentationsabgleich

- **Öffentliche API und In-Code-Dokumentation: keine Auswirkung.** Die Änderung ergänzt nur einen Repository-Skripttest und ändert keine öffentliche Schnittstelle.
- **Nutzeranleitung und README: keine Auswirkung.** Der Test prüft bestehende Migrationsnotizen; er ändert weder Paketverhalten noch Nutzungsschritte.
- **Technische Dokumentation und Agent-Konventionen: keine Auswirkung.** `pnpm test:scripts`, `pnpm agent:check` und die CI-Verkabelung bleiben unverändert; der neue Dateiglob-Treffer benötigt keine neue Anweisung.
