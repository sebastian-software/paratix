# Open-Source-Lizenzstrategie für Paratix

**Planungsstatus:** Nicht umgesetzt
**Quelle:** `$firmo plan`
**Empfohlener Workflow:** Dokumentation (`$firmo docs`)
**Doku-Kategorie:** developer-guide
**Ziel-Pfad:** docs/developer-guide/open-source-licensing-strategy.md

## Anforderung

Vor einer noch nicht getroffenen Open-Source-Entscheidung soll eine belastbare, englischsprachige Entscheidungsgrundlage für die Lizenzierung von Paratix entstehen. Sie vergleicht gängige permissive, schwach reziproke und stark reziproke Open-Source-Lizenzen einschließlich europäischer Varianten, bewertet sie anhand der tatsächlichen Paratix-Architektur und spricht eine priorisierte Empfehlung aus.

Das Dokument ändert weder die bestehende MIT-Lizenz noch Paketmetadaten. Es bereitet ausschließlich eine spätere Geschäfts- und Rechtsentscheidung vor. Diese Trennung ist wesentlich: Bereits veröffentlichte MIT-Versionen bleiben unter MIT nutzbar; eine künftige Relizenzierung kann nur zukünftige Veröffentlichungen und Code erfassen, für den die erforderlichen Rechte vorliegen.

Die Umsetzung ist reine Dokumentation. Sie erzeugt deshalb ein Dokument im Developer-Guide und wird über `$firmo docs` ausgeführt.

## Verifizierter Kontext

- Workspace, `paratix` und `create-paratix` deklarieren derzeit MIT; identische MIT-Texte liegen im Repository-Root und in beiden Paketen.
- Der bestehende historische Plan `2026-07-10-0029-mit-license-files.md` nennt Sebastian Software GmbH als Copyright-Inhaberin und das Jahr 2026.
- Paratix ist gleichzeitig CLI und TypeScript-API. Nutzer-Playbooks sind eigenständige TypeScript-Dateien, importieren aber `server`, `recipe` und Module aus `paratix` beziehungsweise `paratix/modules`.
- `create-paratix` erzeugt umfangreiche Ausgangsdateien aus Repository-Templates. Eigener Nutzer-Code bleibt urheberrechtlich beim Nutzer; an unverändert oder substanziell übernommenem Template-Text entsteht dadurch jedoch kein exklusives Nutzerurheberrecht. Für beliebig lizenzierbare generierte Projekte braucht es daher eine ausdrücklich dokumentierte Template-/Output-Regel oder eine permissive Teil-Lizenzierung.
- Die Git-Historie enthält neben dem Hauptautor weitere menschliche Autoren. Vor einer tatsächlichen Relizenzierung muss geklärt werden, ob deren Beiträge der Sebastian Software GmbH zugeordnet sind oder individuelle Zustimmung benötigen.
- Das aktuelle `CONTRIBUTING.md` enthält weder CLA noch DCO-Regel. Eine zukünftige Contribution-Policy ist eine eigene Governance-Entscheidung.
- Die direkten Laufzeitabhängigkeiten sind permissiv lizenziert; eine spätere Umsetzung muss dennoch einen vollständigen Abhängigkeits- und Distributionsaudit durchführen.

## Architekturentscheidungen

- **MPL 2.0 ist die primäre Empfehlung für den Paratix-Ausführungscode.** Ihr Copyleft gilt auf Dateiebene: Änderungen an MPL-Dateien müssen bei Verteilung wieder als Quelltext verfügbar sein, während neue getrennte Dateien in einem „Larger Work“ unter einer anderen, auch proprietären Lizenz stehen dürfen. Das bildet die gewünschte Grenze zwischen Paratix-Kern und Nutzer-Playbooks verständlicher ab als LGPL oder GPL.
- **Apache 2.0 ist die permissive Ausweichoption.** Sie ist vorzuziehen, wenn maximale Verbreitung, geringe Compliance-Hürden und eine ausdrückliche Patentlizenz wichtiger sind als die Pflicht, Verbesserungen am Paratix-Kern zurückzugeben.
- **EUPL 1.2 ist die europäische reziproke Alternative.** Sie ist mehrsprachig, OSI-anerkannt, auf EU-Recht ausgerichtet, erlaubt Interoperabilität mit unabhängigen Komponenten und erfasst auch bestimmte Netzwerkbereitstellungen. Sie kommt in Betracht, wenn europäische Rechtsverankerung und Netzwerkreziprozität den höheren Erklärungs- und Prüfaufwand im Node.js-Ökosystem rechtfertigen.
- **LGPL 3.0 wird nicht als erste Wahl empfohlen.** Ihr bibliotheksbezogenes Copyleft und die Vorgaben für kombinierte Werke beziehungsweise Relinking passen schlechter zu einem npm-Paket, das zugleich Bibliothek und CLI ist. Die gewünschte Trennung lässt sich mit MPL 2.0 klarer dokumentieren.
- **GPL 3.0 und AGPL 3.0 werden für den aktuellen Zielkonflikt nicht empfohlen.** Ihr starkes Copyleft erhöht das Risiko, dass verteilte Playbooks oder eng kombinierte Erweiterungen als Teil eines abgeleiteten Gesamtwerks behandelt werden. AGPL ergänzt zusätzlich eine Netzwerkpflicht. Beide Varianten stehen damit quer zum Ziel, proprietäre Playbooks ohne Sonderausnahme sicher zu ermöglichen.
- **Keine individuelle „Paratix Public License“ entwerfen.** Nutzungsbeschränkungen gegen bestimmte Branchen, kommerzielle Angebote oder Wettbewerber wären nicht Open Source im Sinne der OSI. Eine eigene Ausnahme zur GPL wäre möglich, erhöht aber Rechts-, Kompatibilitäts- und Akzeptanzaufwand und soll nur nach spezialisierter Rechtsberatung erwogen werden.
- **`create-paratix` und generierter Code werden getrennt betrachtet.** Das Strategiedokument empfiehlt, Generator und Templates auch bei einer MPL-Lizenzierung des Runtime-Pakets permissiv zu halten oder eine juristisch geprüfte Output-Ausnahme zu verwenden. Es verspricht nicht fälschlich exklusives Eigentum an kopiertem Template-Text, sondern garantiert als Ziel eine beliebige Lizenzierbarkeit des Nutzerprojekts.
- **Die konkrete Lizenzumstellung bleibt außerhalb dieses Plans.** Nach der strategischen Entscheidung folgt ein eigener, juristisch geprüfter Umsetzungsplan für Lizenztexte, SPDX-Metadaten, Notices, Paketgrenzen, Contribution-Policy und Kommunikation des Stichtags.

## Lizenzvergleich

Das Zieldokument enthält mindestens folgende Gegenüberstellung. Die Bewertungen werden in der Umsetzung anhand der verlinkten Originallizenzen und offiziellen FAQs erneut verifiziert.

| Lizenz                | Modell                                                             | Vorteile für Paratix                                                                                                  | Nachteile und Risiken                                                                                                          | Eignung für proprietäre Playbooks                                     |
| --------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| MIT                   | permissiv                                                          | sehr kurz, bekannt, minimale Pflichten, heutiger Zustand                                                              | keine ausdrückliche Patentklausel, keine Rückgabepflicht für Kernänderungen                                                    | sehr hoch                                                             |
| BSD 3-Clause          | permissiv                                                          | ähnlich einfach wie MIT, zusätzliche Nicht-Endorsement-Klausel                                                        | keine Reziprozität, weniger naheliegend als bestehende MIT-Lizenz                                                              | sehr hoch                                                             |
| Apache 2.0            | permissiv                                                          | ausdrückliche Patentlizenz und Patentbeendigung, hohe Unternehmensakzeptanz                                           | NOTICE-/Kennzeichnungspflichten, keine Rückgabepflicht                                                                         | sehr hoch                                                             |
| MPL 2.0               | schwaches Copyleft auf Dateiebene                                  | Kernänderungen bleiben offen, klare Grenze zu neuen separaten Dateien, Patentklauseln                                 | Dateigrenzen und Source-Angebot müssen sauber verwaltet werden; reine Netzwerkverwendung löst regelmäßig keine Offenlegung aus | hoch; primäre Empfehlung                                              |
| LGPL 3.0              | schwaches Bibliotheks-Copyleft                                     | proprietäre Anwendungen können die Bibliothek grundsätzlich nutzen; Änderungen an der Bibliothek bleiben offen        | komplexere Kombinations-, Austausch- und Relinking-Pflichten; für TypeScript-CLI und npm-Bundling schwerer erklärbar           | mittel bis hoch, aber mit höherer Rechtsunsicherheit                  |
| EPL 2.0               | schwaches Copyleft                                                 | für JavaScript geeignet, Patentlizenz, kommerzielle Einbindung möglich, optionale GPL-Kompatibilität                  | geringere Bekanntheit, Secondary-License-Entscheidung, andere Begriffs- und Compliance-Welt als npm-Standardlizenzen           | hoch bei sauber getrennten Dateien                                    |
| GPL 3.0               | starkes Copyleft                                                   | starke Rückgabe von verteilten Ableitungen, etablierte Community-Lizenz                                               | potenziell zu weit für importierende Playbooks und Erweiterungen; höhere Unternehmenshürde                                     | niedrig ohne zusätzliche Ausnahme                                     |
| AGPL 3.0              | starkes Copyleft plus Netzwerkpflicht                              | schließt die klassische SaaS-Lücke für modifizierte Netzwerksoftware                                                  | stärkste Akzeptanz- und Compliance-Hürde; Paratix ist primär lokal ausgeführtes Werkzeug, Netzwerkbezug nicht immer passend    | niedrig ohne zusätzliche Ausnahme                                     |
| EUPL 1.2              | europäisches Copyleft mit Kompatibilitätsklausel und Netzwerkbezug | 23 gleichwertige Sprachfassungen, EU-Rechtsrahmen, breite ausgehende Copyleft-Kompatibilität, Interoperabilitätsfokus | im Node.js-Ökosystem weniger vertraut; Netzwerk- und Derivatbegriffe müssen für Paratix anwaltlich eingeordnet werden          | voraussichtlich hoch für unabhängige Playbooks; juristisch bestätigen |
| CeCILL 2.1 / CeCILL-C | französische Copyleft-Familie                                      | auf französisches Recht zugeschnitten; CeCILL-C ist für Komponenten und proprietäre Gesamtanwendungen konzipiert      | außerhalb Frankreichs und wissenschaftlicher Ökosysteme wenig bekannt; geringerer praktischer Vorteil gegenüber MPL oder EUPL  | hoch bei CeCILL-C, aber für Paratix nur Spezialoption                 |

## Offizielle Quellenbasis

- [Open Source Definition und Verbot von Einschränkungen nach Einsatzgebiet](https://opensource.org/osd)
- [MIT-Lizenz bei der OSI](https://opensource.org/license/mit)
- [BSD-3-Clause-Lizenz bei der OSI](https://opensource.org/license/BSD-3-clause)
- [Apache License 2.0 – Anwendung und Patentbedingungen](https://www.apache.org/legal/apply-license)
- [MPL 2.0 FAQ – Dateiebene, Larger Works und proprietäre neue Dateien](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
- [GNU-Lizenz-FAQ – LGPL-Linking, GPL-Kombinationen und Programmausgaben](https://www.gnu.org/licenses/gpl-faq.en.html)
- [GNU LGPL 3.0](https://www.gnu.org/licenses/lgpl)
- [EPL 2.0 FAQ – schwaches Copyleft, JavaScript und Secondary Licenses](https://www.eclipse.org/legal/epl-2.0/faq/)
- [EUPL 1.2 – offizieller Lizenzüberblick der Europäischen Kommission](https://interoperable-europe.ec.europa.eu/licence/european-union-public-licence-version-12-eupl)
- [EUPL 1.2 – offizielle Sprachfassungen](https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12)
- [CeCILL-Lizenzfamilie von CEA, CNRS und Inria](https://www.cecill.info/licences.en.html)

## Betroffene Dateien

| Datei                                                    | Beschreibung                                                                                                                              |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/developer-guide/open-source-licensing-strategy.md` | Neue englischsprachige Entscheidungsgrundlage mit Vergleich, Empfehlung, Paketgrenzen, Migrationsvoraussetzungen und offiziellen Quellen. |

Lizenzdateien, `package.json`, READMEs, Source-Code, Templates und Contribution-Dateien sind in diesem Dokumentationsplan ausschließlich Analysegegenstand und werden nicht geändert.

## Implementierungsdetails

### Vorgehen

1. Das Zieldokument mit einer klaren Nicht-Rechtsberatungs- und Statusnotiz eröffnen: Paratix ist heute MIT-lizenziert; Open Source und eine Relizenzierung sind noch nicht beschlossen.
2. Die Ziele in überprüfbare Entscheidungskriterien übersetzen: beliebig lizenzierbare proprietäre Playbooks, gewünschte Reziprozität am Runtime-Kern, Patentklarheit, Netzwerkverwendung, Ökosystemakzeptanz, Compliance-Aufwand, europäischer Rechtsbezug und spätere Governance.
3. Copyright-Eigentum, Lizenzrecht und Copyleft sauber trennen. Klarstellen, dass die Verwendung eines Open-Source-Werkzeugs das Eigentum an eigenen Eingaben oder gewöhnlichen Ausgaben nicht überträgt, kopierter Template-Code aber gesondert zu behandeln ist.
4. Die zehn Lizenzen beziehungsweise Lizenzfamilien aus der Vergleichstabelle konsistent nach denselben Kriterien bewerten. Marketingbegriffe wie „viral“ vermeiden und stattdessen den jeweiligen Copyleft-Trigger nennen.
5. Die Paratix-spezifische Grenze anhand dreier Fälle erklären: eigenständiges handgeschriebenes Playbook, Custom Module mit Paratix-API-Importen und von `create-paratix` erzeugtes Projekt mit kopiertem Template-Code.
6. MPL 2.0 als Hauptempfehlung begründen und Apache 2.0 sowie EUPL 1.2 als konditionale Alternativen darstellen. LGPL 3.0 ausdrücklich gegen MPL 2.0 abgrenzen.
7. Eine Paketstrategie skizzieren: Runtime unter der gewählten Kernlizenz; Generator/Templates permissiv oder mit geprüfter Output-Ausnahme; keine Lizenzpflicht für eigenständigen Nutzer-Code allein aufgrund der Ausführung durch Paratix.
8. Die Voraussetzungen einer späteren Relizenzierung dokumentieren: Rechtekette aller Beiträge, Stichtag und Versionsgrenze, Abhängigkeitsaudit, SPDX-/NOTICE-Konzept, Contribution-Policy, Kommunikation bestehender MIT-Versionen und spezialisierte Rechtsprüfung.
9. Alle Rechtsbehauptungen auf den Wortlaut der Originallizenzen und offizielle Steward-FAQs zurückführen. Sekundärquellen nur zur Orientierung nutzen und nicht als alleinige Grundlage zitieren.
10. Mit einer kompakten Entscheidungsmatrix abschließen:

- Kernverbesserungen sollen ohne Netzwerkpflicht zurückfließen → MPL 2.0.
- Maximale Adoption und Patentklarheit → Apache 2.0.
- Netzwerkreziprozität und EU-Rechtsrahmen → EUPL 1.2 nach Rechtsprüfung.
- Stärkstes Copyleft trotz Playbook-Reibung → GPL/AGPL nur mit bewusstem Strategiewechsel oder geprüfter Ausnahme.

### Edge Cases

- **Bereits veröffentlichte MIT-Versionen:** Die Dokumentation behauptet keine rückwirkende Entziehung bestehender Rechte und trennt Altversionen von zukünftigen Releases.
- **Externe Beiträge:** Autorennamen in der Git-Historie werden nicht mit einer geklärten Rechteübertragung gleichgesetzt. Eine Relizenzierung wird bis zur Rechteprüfung nicht als rein technische Änderung dargestellt.
- **Handgeschriebene Playbooks:** Eigenständiger Nutzer-Code wird nicht allein deshalb als Paratix-Code bezeichnet, weil er öffentliche APIs importiert. Bei starkem Copyleft bleibt die rechtliche Einordnung kombinierter Werke dennoch ein Prüfpunkt.
- **Custom Modules:** Module, die Paratix-Typen importieren und intern eng mit dem Runtime-Modell gekoppelt sind, werden separat von reinen Playbooks bewertet; das Dokument gibt hier keine ungesicherte Garantie.
- **Generierte Projekte:** Kopierter Template-Code und eigene Ergänzungen werden urheberrechtlich getrennt. Die Empfehlung zielt auf freie Lizenzwahl für das Gesamtprojekt, nicht auf die unzutreffende Behauptung, der Nutzer erhalte exklusives Urheberrecht an fremdem Ausgangstext.
- **Interne Nutzung:** MPL, LGPL, EPL und GPL knüpfen Offenlegung im Regelfall an Verteilung; rein interne Modifikationen müssen häufig nicht veröffentlicht werden. EUPL und AGPL haben zusätzliche Netzwerkdimensionen, deren konkrete Wirkung auf ein lokal ausgeführtes Infrastrukturwerkzeug geprüft werden muss.
- **Source-available statt Open Source:** Soll später etwa Konkurrenzbetrieb, Hosting oder bestimmte kommerzielle Nutzung untersagt werden, ist das ein anderes Lizenzmodell und muss klar als nicht OSI-konformes Source-available bezeichnet werden.
- **Markenrecht:** Softwarelizenz und Recht zur Nutzung des Namens „Paratix“ bleiben getrennte Themen. Eine Trademark-Policy ist nicht Teil dieses Plans.

## Akzeptanzkriterien

- [ ] `docs/developer-guide/open-source-licensing-strategy.md` existiert auf Englisch und nennt klar den unverbindlichen Entscheidungsstatus sowie den Hinweis, dass das Dokument keine Rechtsberatung ersetzt.
- [ ] Das Dokument vergleicht mindestens MIT, BSD 3-Clause, Apache 2.0, MPL 2.0, LGPL 3.0, EPL 2.0, GPL 3.0, AGPL 3.0, EUPL 1.2 und CeCILL/CeCILL-C nach identischen Kriterien.
- [ ] Für jede Lizenz sind Copyleft-Umfang, Auslöser durch Verteilung beziehungsweise Netzwerkbereitstellung, Patentregelung, Compliance-Aufwand, Ökosystemakzeptanz und Wirkung auf proprietäre Playbooks beschrieben oder ausdrücklich als juristisch zu prüfen markiert.
- [ ] MPL 2.0 wird nachvollziehbar als Hauptempfehlung, Apache 2.0 als permissive Alternative und EUPL 1.2 als europäische Netzwerk-/Copyleft-Alternative eingeordnet; LGPL 3.0 wird konkret gegen MPL 2.0 abgegrenzt.
- [ ] Handgeschriebene Playbooks, Custom Modules und generierter Template-Code werden als drei unterschiedliche Rechts- und Architekturflächen behandelt.
- [ ] Das Dokument verspricht keine rückwirkende Relizenzierung bestehender MIT-Versionen und keine ungeprüfte Rechtekette für externe Beiträge.
- [ ] Die empfohlene Paketstrategie ermöglicht beliebig lizenzierbaren eigenständigen Nutzer-Code und behandelt kopierte `create-paratix`-Templates über eine permissive Teil-Lizenz oder juristisch geprüfte Output-Ausnahme.
- [ ] Ein eigener Abschnitt listet die Voraussetzungen einer tatsächlichen Umstellung auf, ohne in diesem Plan `LICENSE`, Paketmetadaten, Source-Code, Templates oder Contribution-Dateien zu ändern.
- [ ] Jede wesentliche Lizenzbehauptung verweist auf den Originallizenztext oder eine offizielle FAQ des jeweiligen License Stewards; sämtliche Links sind erreichbar.
- [ ] Markdown-Formatprüfung, relative Linkprüfung und `pnpm agent:check` sind erfolgreich.

## Validierungsplan

- Jede Zeile der Lizenzmatrix gegen den aktuellen Originallizenztext und die verlinkte offizielle Steward-FAQ prüfen; Unterschiede zwischen Verteilung, interner Nutzung und Netzwerkbereitstellung explizit verifizieren.
- Die Aussagen zu Playbooks, Custom Modules und Generator-Templates gegen `packages/paratix/README.md`, `packages/paratix/llm-guide.md`, `packages/create-paratix/src/templates.ts` und `packages/create-paratix/README.md` abgleichen.
- Die aktuelle Lizenzierung über Root- und Paket-`LICENSE`-Dateien sowie alle `license`-Felder der `package.json`-Dateien verifizieren.
- Git-Historie und Contribution-Dokumentation nur zur Feststellung verwenden, dass eine Rechteprüfung erforderlich ist; keine ungeklärte Rechteübertragung behaupten.
- Alle Links automatisiert oder manuell auf Erreichbarkeit und korrekte Zielseite prüfen.
- Die neue Markdown-Datei mit dem projektkonfigurierten Formatter prüfen und den projektweiten Abschlusscheck `pnpm agent:check` ausführen.
- Vor jeder tatsächlichen Relizenzierung einen auf deutsches und internationales Open-Source-Recht spezialisierten Rechtsanwalt die Paketgrenzen, Beitragerechte, Template-Regel und finale Lizenzwahl prüfen lassen.

## Annahmen und offene Punkte

- Annahme: Ziel dieses Plans ist eine belastbare Entscheidungsgrundlage und Empfehlung, nicht die sofortige Änderung der bestehenden MIT-Lizenz.
- Annahme: „Voll im Besitz des Erstellers“ bedeutet für eigenständige Nutzerdateien, dass Paratix keine Rechteübertragung oder Copyleft-Pflicht daran auslösen soll. Bei kopiertem Generator-Template wird stattdessen beliebige Lizenzierbarkeit angestrebt, weil exklusives Urheberrecht an fremdem Ausgangstext nicht versprochen werden kann.
- Annahme: Rückfluss von Änderungen am Paratix-Kern ist erwünscht; Offenlegung sämtlicher Nutzer-Playbooks oder ein generelles Verbot proprietärer Nutzung ist nicht erwünscht.
- Annahme: Eine Einschränkung von Konkurrenten oder kommerziellen Hosting-Angeboten ist derzeit kein zwingendes Ziel. Falls sich dieses Ziel ändert, muss die Entscheidung ausdrücklich zwischen Open Source und Source-available neu getroffen werden.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Security    |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       0 |
| Scope       |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

### Befunde

- Keine offenen Befunde. Der Plan trennt Strategiepapier und spätere Relizenzierung, behandelt Nutzer-Playbooks und Generator-Templates getrennt, kennzeichnet juristisch unsichere Grenzfälle und bindet die tatsächliche Lizenzänderung an eine spezialisierte Rechtsprüfung.

## Offene Punkte

- Keine offenen Punkte.
