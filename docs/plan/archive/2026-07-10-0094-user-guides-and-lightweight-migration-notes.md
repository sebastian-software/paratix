# 0094: User guides and lightweight migration notes

**Planungsstatus:** Umgesetzt
**Quelle:** GitHub-Issue #91, `$firmo plan #91`
**Empfohlener Workflow:** Dokumentation (`$firmo docs`)
**Doku-Kategorie:** user-guide
**Ziel-Pfad:** docs/user-guide/README.md

## Anforderung

Paratix erhält einen englischsprachigen User-Guide mit drei kompakten, eigenständig nutzbaren Dokumenten:

1. Troubleshooting/FAQ für die von der Anwendung bereits differenziert diagnostizierten Fehlerfälle,
2. einen ehrlichen Vergleich mit Ansible und pyinfra als Entscheidungshilfe,
3. kurze, fortlaufend pflegbare Migrationshinweise für bestätigte Breaking Changes ab der festgelegten 0.1-Baseline bis zur zukünftigen Paratix-Paketversion 1.0.0.

Die Änderung ist reine Dokumentation. Sie verändert weder öffentliche APIs noch Laufzeitverhalten und wird deshalb über `$firmo docs` umgesetzt. Die neuen Dokumente gehören zur Kategorie `user-guide`; `docs/user-guide/README.md` wird der kuratierte Einstiegspunkt.

## Verifizierter Kontext

- Commit `ee125596` ist gemäß User-Entscheidung die verbindliche 0.1-Baseline für beide Pakete.
- Paketbezogene Tags und Changelogs reichen derzeit von `paratix-v0.2.0` beziehungsweise `create-paratix-v0.2.0` bis `0.13.0`; paketbezogene `0.1.0`-Tags existieren nicht.
- Die unpräfixierten Root-Tags `v1.0.0` und `v1.0.1` gehören nicht zum Versionsverlauf der Pakete `paratix` und `create-paratix` und werden nicht als deren 1.0-Migration behandelt.
- Fehlendes `tsx` wird in `packages/paratix/src/cli.ts` mit Exit-Code 2 und Installationshinweis diagnostiziert.
- Host-Key-Fehler und die Modi `yes` beziehungsweise `accept-new` sind in `packages/paratix/src/knownHosts.ts` sowie den zugehörigen Tests differenziert abgebildet.
- Reconnect-Fehler nach Portwechseln und Reboots werden in `packages/paratix/src/runner.ts` unterschieden; vorhandene Tests decken Timeout-, Unreachable- und Connection-refused-Fälle ab.
- `docs/module.md` enthält noch einen toten Link auf `./ansible.md`; `docs/initialbeschreibung.md` enthält eine historische, nur auf Ansible bezogene Vergleichstabelle.

## Architekturentscheidungen

- Alle neuen Inhalte werden auf Englisch geschrieben, passend zu den öffentlichen READMEs und zur geplanten einheitlichen Sprache der aktuellen öffentlichen Dokumentation.
- `docs/user-guide/README.md` ist der einzige Navigationseinstieg; Troubleshooting, Vergleich und Migration bleiben getrennte, kurze Themendokumente.
- `docs/user-guide/migration.md` behandelt `paratix` und `create-paratix` gemeinsam, aber in klar getrennten Abschnitten. Das vermeidet doppelte Versionsnavigation und macht gekoppelte Änderungen sichtbar.
- Die Migrationshistorie nennt nur bestätigte, für Nutzer handlungsrelevante Inkompatibilitäten. Interne Refactorings, reine Fehlerkorrekturen und additive Änderungen werden nicht aufgenommen.
- Vollständigkeit wird nicht aus Conventional-Commit-Bezeichnungen abgeleitet. Die Umsetzung vergleicht ab `ee125596` für jede Paketversion die öffentlichen Exporte und Typen, CLI-Optionen, Defaults sowie die generierte Scaffold-Struktur und gleicht Kandidaten mit Changelogs, Tests und Implementierung ab.
- `migration.md` enthält einen kurzen Prüfvermerk mit Baseline, Prüfdatum, geprüften Paket-Tags und untersuchten öffentlichen Oberflächen. Ausführliche Kandidatenlisten und interne Diffs werden nicht in die User-Dokumentation übernommen.
- Der aktuelle Stand wird bis zum neuesten paketbezogenen 0.x-Tag plus gesondertem Abschnitt für bestätigte unveröffentlichte Brüche dokumentiert. Die spätere Paketversion 1.0.0 erhält erst bei ihrer tatsächlichen Vorbereitung einen knappen Übergangsabschnitt; unbekannte zukünftige Änderungen werden nicht vorweggenommen.
- Aussagen über Ansible und pyinfra werden bei der Umsetzung gegen aktuelle offizielle Dokumentation geprüft. Marketingzahlen oder historische Behauptungen aus `docs/initialbeschreibung.md` werden nicht ungeprüft übernommen.
- Produktseite, Hosting und Domains sind nicht Teil dieses Plans.

## Betroffene Dateien

| Datei                                | Beschreibung                                                                                                |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `docs/user-guide/README.md`          | Neuer kuratierter Einstieg mit kurzer Lese-Reihenfolge und Links auf die drei Guides.                       |
| `docs/user-guide/troubleshooting.md` | Symptome, Ursachen, sichere Behebung und Verifikation für konkrete Laufzeit- und Verbindungsfehler.         |
| `docs/user-guide/comparison.md`      | Sachlicher Vergleich Paratix, Ansible und pyinfra mit geeigneten und ungeeigneten Einsatzfällen.            |
| `docs/user-guide/migration.md`       | Leichtgewichtige, fortlaufende Migrationshinweise ab `ee125596` bis zur zukünftigen Paketversion 1.0.0.     |
| `README.md`                          | Sichtbarer Link auf den User-Guide und direkte Einstiege in Troubleshooting, Vergleich und Migration.       |
| `packages/paratix/README.md`         | Paketnaher Link auf Troubleshooting und Migration.                                                          |
| `packages/create-paratix/README.md`  | Paketnaher Link auf relevante Scaffold- und CLI-Migrationshinweise.                                         |
| `docs/module.md`                     | Toten `ansible.md`-Link durch den neuen Vergleich ersetzen, ohne weitere historische Inhalte umzuschreiben. |

Die beiden Paket-Changelogs, öffentlichen Exporte, CLI- und Scaffold-Dateien sowie zugehörige Tests sind ausschließlich Analysequellen und werden in diesem Dokumentationsworkflow nicht geändert. Weicht eine bestehende Aussage vom verifizierten Verhalten ab, wird die neue Dokumentation am tatsächlichen Verhalten ausgerichtet; ein möglicher Produktfehler wird separat verfolgt.

## Implementierungsdetails

### Vorgehen

1. `docs/user-guide/` anlegen und `README.md` als knappen Einstieg mit der Reihenfolge Troubleshooting, Vergleich, Migration erstellen.
2. Für `troubleshooting.md` die vorhandenen Fehlermeldungen und Tests als Primärquellen erfassen. Mindestens fehlendes `tsx`, unbekannte oder geänderte Host Keys sowie Reconnect-Probleme nach Portwechsel oder Reboot dokumentieren.
3. Jeden Troubleshooting-Eintrag einheitlich mit Symptom beziehungsweise erkennbarer Meldung, wahrscheinlicher Ursache, sicherem Diagnoseweg, konkreter Behebung und Verifikationsschritt strukturieren.
4. Bei Host-Key-Problemen keine blinde Vertrauensübernahme empfehlen: Fingerprints müssen über einen unabhängigen Kanal geprüft werden; `accept-new` ist gegenüber geändertem Schlüssel klar abzugrenzen.
5. `comparison.md` nach stabilen Entscheidungskriterien strukturieren: Programmiersprache und Typisierung, Idempotenzmodell, Inventar und Fleet-Orchestrierung, Transport und Zielsysteme, Ökosystem, Einstieg sowie Erweiterbarkeit.
6. Für jedes Werkzeug geeignete und ungeeignete Szenarien nennen. Paratix ausdrücklich nicht für große Fleet-Orchestrierung oder Nicht-SSH-Ziele empfehlen; Ansible beziehungsweise pyinfra nicht künstlich abwerten.
7. Für `migration.md` zunächst eine interne Kandidatenliste durch tagweise beziehungsweise releaseweise Diffs ab `ee125596` erstellen. Untersucht werden öffentliche Exporte und Signaturen, CLI-Flags und Defaults, Konfigurationsformen sowie generierte Scaffold-Dateien beider Pakete.
8. Jeden Kandidaten anhand von Quellcode, Tests und Changelog bestätigen. Nur Änderungen aufnehmen, die bestehende Nutzer ohne Anpassung brechen oder sicherheitsrelevante Default-Änderungen mit erforderlicher Handlung darstellen.
9. Bestätigte Einträge knapp nach Paket und Zielversion anordnen. Jeder Eintrag nennt Ausgangszustand, neuen Zustand und genau den erforderlichen Upgrade-Schritt. Unsichere Versionszuordnungen werden nicht als Fakt veröffentlicht.
10. Direkt in `migration.md` einen knappen Prüfvermerk ergänzen. Er nennt `ee125596`, das Prüfdatum, die tatsächlich geprüften Paket-Tags und die geprüften Oberflächen API, CLI, Defaults und Scaffold; er enthält keine ausführliche Audit-Historie.
11. Einen kurzen Abschnitt „Toward 1.0“ als Pflegekonvention vorsehen: bestätigte unveröffentlichte Brüche werden dort gesammelt und beim tatsächlichen 1.0-Release in einen versionierten Übergangsabschnitt überführt. Root-`v1.0.x` wird ausdrücklich ausgeschlossen.
12. Links in Root-README, beiden Paket-READMEs und `docs/module.md` aktualisieren. Änderungen außerhalb der in der Tabelle genannten Dateien vermeiden.

### Edge Cases

- Fehlt für eine Änderung ein eindeutiger Release-Tag, wird die Git-Position relativ zu den benachbarten Paket-Tags ermittelt. Bleibt die Zielversion unklar, erscheint der Punkt höchstens als bestätigte unveröffentlichte Änderung, nicht unter einer geratenen Version.
- Änderungen, die bereits innerhalb der als Baseline gewählten Version `0.1.0` stattfanden, werden nur dann als Migrationseintrag aufgenommen, wenn ein Nutzerzustand am Baseline-Commit und ein späterer inkompatibler Zustand eindeutig vergleichbar sind.
- Die Paketversionen und Root-Versionen dürfen nicht vermischt werden.
- Neue 0.x-Releases nach Planerstellung werden über dieselbe Prüfmethode ergänzt; der Plan fixiert keine veraltete Endversion.
- Vergleichsaussagen ohne belastbare offizielle Quelle werden neutral formuliert oder weggelassen.
- Troubleshooting darf Sicherheitsgrenzen wie Strict Host Key Checking nicht zugunsten einer schnellen Problemumgehung abschwächen.

## Akzeptanzkriterien

- [ ] `docs/user-guide/README.md`, `troubleshooting.md`, `comparison.md` und `migration.md` existieren auf Englisch und sind untereinander über funktionierende relative Links erreichbar.
- [ ] Root-README und beide Paket-READMEs verlinken die jeweils relevanten User-Guide-Inhalte; `docs/module.md` enthält keinen Link mehr auf die nicht vorhandene Datei `ansible.md`.
- [ ] Troubleshooting behandelt mindestens fehlendes `tsx`, unbekannte und geänderte Host Keys sowie Reconnect-Probleme nach Portwechsel und Reboot jeweils mit Symptom, Ursache, Diagnose, sicherer Behebung und Verifikation.
- [ ] Host-Key-Hinweise empfehlen keine ungeprüfte Vertrauensübernahme und unterscheiden erstmaliges Vertrauen von einem geänderten Schlüssel.
- [ ] Der Vergleich deckt die festgelegten Entscheidungskriterien für Paratix, Ansible und pyinfra ab und nennt Fleet-Orchestrierung sowie Nicht-SSH-Ziele ausdrücklich als Fälle, in denen Paratix nicht die passende Wahl ist.
- [ ] `migration.md` nennt `ee125596` als 0.1-Baseline, trennt `paratix` und `create-paratix`, schließt Root-`v1.0.x` aus und dokumentiert nur bestätigte handlungsrelevante Breaking Changes.
- [ ] Jeder Migrationseintrag nennt betroffene Zielversion oder den Status „unreleased“, vorheriges Verhalten, neues Verhalten und einen konkreten Upgrade-Schritt.
- [ ] `migration.md` enthält einen kurzen Prüfvermerk mit Baseline `ee125596`, Prüfdatum, allen tatsächlich geprüften paketbezogenen Tags und den geprüften Oberflächen API, CLI, Defaults und Scaffold.
- [ ] Eine nachvollziehbare Prüfung der öffentlichen API, CLI, Defaults und Scaffold-Ausgabe zwischen Baseline, allen paketbezogenen 0.x-Tags und aktuellem Stand ergibt keine bestätigte handlungsrelevante Änderung, die in `migration.md` fehlt.
- [ ] Der vorbereitete 1.0-Abschnitt bleibt kurz, enthält keine spekulativen Änderungen und beschreibt, wie bestätigte unveröffentlichte Einträge beim zukünftigen Paket-Release 1.0.0 übernommen werden.
- [ ] Alle relativen Markdown-Links der geänderten Dateien sind auflösbar und `pnpm agent:check` ist erfolgreich.

## Validierungsplan

- Repository-Suche nach `ansible.md` und Prüfung sämtlicher neu hinzugefügter relativer Markdown-Links gegen existierende Ziele.
- Abgleich der Troubleshooting-Begriffe und Empfehlungen mit den tatsächlichen Meldungen, Optionen und Tests in CLI, Known-Hosts- und Reconnect-Pfaden.
- Abgleich der Vergleichsaussagen mit zum Umsetzungszeitpunkt aktuellen offiziellen Dokumentationen von Ansible und pyinfra.
- Reproduzierbare Inventur der öffentlichen Oberflächen beider Pakete zwischen `ee125596`, allen paketbezogenen 0.x-Tags und aktuellem Stand; Abgleich jedes bestätigten Breaking-Change-Kandidaten mit `migration.md`.
- Prüfung, dass keine Root-Release-Tags als Paketversionen dargestellt werden und keine unbekannte zukünftige 1.0-Änderung behauptet wird.
- Projektweiter Abschlusscheck mit `pnpm agent:check`.

## Annahmen und offene Punkte

- Annahme: Ein gemeinsames Migrationsdokument mit getrennten Paketabschnitten ist leichter auffindbar und wartbarer als zwei nahezu parallel versionierte Dateien.
- Annahme: „Leichtgewichtig“ bedeutet, nur erforderliche Nutzeraktionen aufzunehmen und auf ausführliche Release Notes, interne Änderungen oder vollständige Changelog-Duplikation zu verzichten.
- Annahme: Der spätere Paratix-Paket-Release 1.0.0 ist nicht mit den vorhandenen Root-Tags `v1.0.0` und `v1.0.1` identisch.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       1 |       0 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       0 |

### Befunde

- **Hinweis – Scope (eingearbeitet):** Code, Tests und Changelogs waren als Analysequellen benannt, aber nicht eindeutig als Änderungsziele ausgeschlossen. Der Plan stellt nun klar, dass der Dokumentationsworkflow ausschließlich die aufgeführten Dokumentationsdateien ändert und mögliche Produktfehler separat verfolgt.
- **Wichtig – Testbarkeit (eingearbeitet):** Die Vollständigkeitsprüfung hatte keinen dauerhaft auffindbaren Evidenzort. Auf User-Entscheidung dokumentiert ein kurzer Prüfvermerk direkt in `migration.md` Baseline, Prüfdatum, Paket-Tags und untersuchte Oberflächen, ohne die User-Dokumentation mit einem Audit-Anhang zu belasten.
- Keine offenen Befunde. Die zuvor unklare 0.1-Baseline ist auf `ee125596` festgelegt; Root- und Paketversionen sind getrennt; die Vollständigkeitsprüfung und der leichte Umfang sind messbar beschrieben.

## Offene Punkte

- Keine offenen Punkte.

## Testergebnisse

- `pnpm agent:check` erfolgreich: Lint, Formatprüfung, TypeScript-Prüfung, Build sowie Unit-, Distribution- und Script-Tests.
- Prettier-Prüfung aller acht geänderten Dokumentationsdateien erfolgreich.
- Relative Linkziele in Root-README, beiden Paket-READMEs, `docs/module.md` und allen User-Guide-Dateien erfolgreich geprüft.
- `git diff --check` ohne Befund.

## Review-Findings

- Drei Review-Runden korrigierten unvollständige beziehungsweise falsch zugeordnete historische Migrationseinträge. Das finale unabhängige Review und die technische Validierung melden keine offenen kritischen oder wichtigen Findings.
