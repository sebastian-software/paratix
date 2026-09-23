# Context7-Konfiguration für Paratix

**Planungsstatus:** Nicht umgesetzt
**Quelle:** `effective-flow plan`
**Empfohlener Workflow:** Feature (`effective-flow build`)

## Anforderung

Paratix soll im Repository-Root eine `context7.json` erhalten, damit Context7 beim Indexieren des
öffentlichen GitHub-Repositories gezielt die aktuelle, für Anwender relevante Dokumentation nutzt
und historische oder interne Unterlagen nicht als Produktreferenz behandelt.

Zusätzlich soll die Root-`.gitignore` den plattformtypischen Dateinamen `.DS_Store` in jeder
Verzeichnistiefe ignorieren. Bereits vorhandene unversionierte `.DS_Store`-Dateien werden dadurch
nicht gelöscht oder verändert, erscheinen nach der Umsetzung aber nicht mehr als unversionierte
Arbeitsbaumänderungen.

Die Änderung ist als Feature eingeordnet, weil sie eine neue externe Dokumentationsintegration
konfiguriert. Sie ändert weder die Paratix-Laufzeit noch die öffentliche TypeScript-API. Zum
End-to-End-Scope gehören die einmalige Einreichung beziehungsweise Aktualisierung des öffentlichen
Repositories bei Context7 und die Prüfung des veröffentlichten Indexes. Das Claiming der
Bibliothek, ein dauerhafter automatischer Refresh-Workflow und Änderungen an bestehender
Dokumentation sind nicht Bestandteil dieses Plans.

Planungsbasis ist der Repository-Stand `404d3d43` vom 23. September 2026. Der lokale Branch `main`
liegt zwei Commits hinter `origin/main`; die Abweichung betrifft nach der read-only Prüfung weder
die vorgesehenen Dokumentationspfade noch eine vorhandene `context7.json` oder `.DS_Store`-Regel.
Im Arbeitsbaum liegen nur die sachfremden, unversionierten Dateien `.DS_Store` und
`website/.DS_Store`; ihr Dateiinhalt bleibt unangetastet. Seit Beginn dieses Planlaufs ist außerdem
die Plan-Datei `docs/plan/2026-09-23-context7-konfiguration.md` selbst unversioniert vorhanden.
Während des Reviews kam zusätzlich die fremde, unversionierte Plan-Datei
`docs/plan/2026-09-23-public-api-typdeklarationen-und-guide-synchronisieren.md` hinzu; sie liegt
außerhalb dieses Scopes und bleibt unverändert.

## Architekturentscheidungen

- Die Konfiguration liegt ausschließlich als `context7.json` im Repository-Root, wie es die
  offizielle Context7-Dokumentation vorsieht.
- `$schema` verweist auf `https://context7.com/schema/context7.json` und steht als erstes Feld in
  der Datei. Damit bleiben Editorunterstützung und eine externe Draft-07-Schemavalidierung möglich.
- `folders` arbeitet als Allowlist mit `docs/user-guide`, `packages/paratix` und
  `packages/create-paratix`. Context7 nimmt Root-Markdown unabhängig von dieser Allowlist auf, sodass
  `README.md` weiterhin Teil des Indexes ist.
- `excludeFolders` enthält exakt `coverage`, `dist`, `node_modules`, `src` und `test`. Das hält die
  Absicht auch dann eindeutig, wenn Context7 seinen
  Quellcode-Fallback oder die unterstützten Dateitypen später erweitert.
- `excludeFiles` enthält exakt `AGENTS.md`, `CHANGELOG.md`, `CHANGELOG.mdx`, `CLAUDE.md`,
  `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `LICENSE`, `LICENSE.md`, `SECURITY.md`, `changelog.md`,
  `changelog.mdx`, `code_of_conduct.md` und `license.md`. Damit bleiben die aktuellen
  Context7-Defaultvarianten trotz eigener Ausschlüsse erhalten und die repository-spezifischen
  internen Dateien kommen hinzu. Die Ausschlüsse gelten nach Context7-Vertrag über den reinen
  Dateinamen in allen erlaubten Ordnern.
- `projectTitle` lautet exakt `Paratix`. `description` lautet exakt `Idempotent VPS automation over
SSH with TypeScript playbooks, a CLI, and project scaffolding.`
- `rules` enthält exakt diese fünf langlebigen Consumer-Regeln:
  1. `Treat packages/paratix/llm-guide.md as the normative API and module reference.`
  2. `Import the core API from paratix and built-in modules from paratix/modules.`
  3. `For idempotency with command.shell(), always provide a check command.`
  4. `Use shellQuote() whenever dynamic values are interpolated into shell commands.`
  5. `In strict file.template() templates, every placeholder must use an explicit modifier; use shell for shell output.`
- `branch`, `previousVersions`, `branchVersions`, Claiming-/Ownership-Felder und Redirects bleiben
  zunächst aus der Datei. Der Default-Branch reicht für diesen Scope aus; historische Versionen und
  Ownership benötigen eine separate, bewusst getroffene Entscheidung.
- Die bestehende Root-`.gitignore` erhält genau eine basename-basierte Zeile `.DS_Store` ohne
  führenden Slash. Damit greift die Regel im Repository-Root und in Unterordnern. Vorhandene
  Ignore-Regeln werden weder umsortiert noch anderweitig bereinigt.
- Der veröffentlichte Context7-Eintrag verwendet die stabile Library-ID
  `/sebastian-software/paratix` und die Repository-URL
  `https://github.com/sebastian-software/paratix`.
- Der End-to-End-Schritt nutzt ausschließlich einen zur Laufzeit bereitgestellten
  `CONTEXT7_API_KEY`. Der Schlüssel wird weder in Dateien geschrieben noch in Ausgaben oder
  Fehlermeldungen wiederholt. Fehlt er, endet die Umsetzung vor jeder externen Mutation als
  blockiert.
- Ist die Library noch nicht vorhanden, wird das öffentliche Repository über `POST
/api/v2/add/repo/github` mit ausschließlich `docsRepoUrl` eingereicht. Antwort `200` muss die
  erwartete Library-ID liefern. Antwort `409` bedeutet, dass der Eintrag bereits existiert, und
  führt in den Refresh-Pfad statt zu einer zweiten Einreichung.
- Für einen bestehenden oder neu angelegten Eintrag stößt `POST /api/v1/refresh` mit
  `libraryName: /sebastian-software/paratix` die Aktualisierung an. Verarbeitung wird höchstens zehn
  Minuten lang in Abständen von mindestens 20 Sekunden geprüft; `202` bleibt „noch nicht fertig“,
  `429` respektiert `Retry-After`, und dauerhafte `4xx`-/`5xx`-Fehler blockieren den Abschluss.
- Der veröffentlichte Index wird über die Library-Suche und mehrere konkrete Context-Abfragen
  geprüft. Da Context7 keinen dokumentierten Endpunkt für ein vollständiges Datei-Inventar bietet,
  bleibt die exakte Acht-Dateien-Menge eine lokale Strukturprüfung; der Remote-Nachweis prüft die
  tatsächlich nutzbare Auffindbarkeit repräsentativer Inhalte und, soweit die Antwort
  Quellenmetadaten liefert, dass keine ausgeschlossenen Pfade erscheinen.

## Betroffene Dateien

| Datei           | Beschreibung                                                                  |
| --------------- | ----------------------------------------------------------------------------- |
| `.gitignore`    | `.DS_Store` im gesamten Repository ignorieren                                 |
| `context7.json` | Neue Root-Konfiguration für Auswahl, Darstellung und Agent-Regeln in Context7 |

## Implementierungsdetails

### Vorgehen

1. In der bestehenden Root-`.gitignore` genau eine Zeile `.DS_Store` ergänzen. Die vorhandenen
   Dateien `.DS_Store` und `website/.DS_Store` weder löschen noch anderweitig anfassen.
2. `context7.json` im Repository-Root mit der bestehenden JSON-Konvention anlegen: zwei Leerzeichen,
   doppelte Anführungszeichen, abschließender Zeilenumbruch und `$schema` als erstes Feld.
3. Projekttitel und Beschreibung aus `README.md` sowie den Paketmetadaten übernehmen, ohne neue
   Marketingaussagen oder nicht belegte Fähigkeiten einzuführen.
4. Die drei aktuellen Dokumentationsflächen über `folders` erlauben und Quellcode-, Test-, Build-,
   Coverage- sowie Abhängigkeitsordner explizit ausschließen.
5. Repository-interne und historische Markdown-Dateien über `excludeFiles` ausschließen. Dabei nur
   Dateinamen verwenden, weil Context7 in diesem Feld keine Pfade akzeptiert.
6. Die wenigen Agent-Regeln gegen `packages/paratix/llm-guide.md` prüfen. Regeln müssen den dortigen
   Vertrag verkürzen, dürfen ihn aber weder erweitern noch widersprüchlich paraphrasieren.
7. Ignore-Wirkung, JSON-Syntax, Format, offizielles Context7-Schema und den vollständigen
   Repository-Check gemäß
   Validierungsplan ausführen. Temporäre Schema-Dateien werden außerhalb des Repositories angelegt
   und nach der Prüfung entfernt.
8. Mit einem vorhandenen `CONTEXT7_API_KEY` den bestehenden Context7-Eintrag suchen. Bei fehlendem
   Eintrag das öffentliche GitHub-Repository einreichen, andernfalls direkt den Refresh auslösen.
9. Die Verarbeitung begrenzt abwarten und den veröffentlichten Index mit den festgelegten
   Suchabfragen prüfen. Ohne erfolgreichen Remote-Nachweis bleibt die Umsetzung unvollständig.

### API-Integration

Die Datei ist die deklarative Integrationsoberfläche zu Context7. Einreichung, Refresh und Abfragen
laufen über die offizielle Context7-API mit Bearer-Authentifizierung. Es werden keine Context7-
API-Keys, öffentlichen Schlüssel oder anderen Credentials eingecheckt. Das Claiming der Bibliothek
und ein dauerhafter GitHub-Actions-Refresh bleiben außerhalb dieses Arbeitspakets.

### Randfälle

- Root-Markdown wird von Context7 trotz nicht leerer `folders`-Allowlist berücksichtigt. Deshalb
  müssen irrelevante Root-Dateien über `excludeFiles` ausgeschlossen werden, während `README.md`
  bewusst indexierbar bleibt.
- `excludeFiles` akzeptiert nur Dateinamen. Pfadangaben in diesem Feld wären schemakonformitäts- oder
  wirkungslos und müssen bei der Implementierung vermieden werden.
- Falls das offizielle Schema während der Implementierung nicht erreichbar ist, darf die Änderung
  nicht als schemavalidiert gemeldet werden. Die Prüfung wird später wiederholt oder die Umsetzung
  bis zur belastbaren Validierung angehalten.
- Falls sich die Dokumentationsstruktur seit der Planungsbasis geändert hat, wird die Allowlist vor
  dem Schreiben neu mit `README.md`, den Paket-READMEs, `packages/paratix/llm-guide.md` und
  `docs/user-guide/**` abgeglichen. Neue normative Dokumentation wird nicht stillschweigend
  ausgeschlossen.
- Die vorhandenen `.DS_Store`-Dateien bleiben auf dem Dateisystem bestehen. Die Umsetzung ändert
  ausschließlich ihre Git-Sichtbarkeit über die neue Ignore-Regel.
- Die während des Reviews hinzugekommene fremde Plan-Datei unter `docs/plan/` ist eine
  Arbeitsbaumänderung einer anderen Session. Sie wird bei Scope-Prüfungen als vorbestehend behandelt
  und weder verändert noch in die Umsetzung aufgenommen.
- Antwort `409` bei der Einreichung ist kein Fehler, sondern der idempotente Übergang zum Refresh
  der vorhandenen Library. Antwort `301` bei Such- oder Context-Abfragen wird nur akzeptiert, wenn
  `redirectUrl` eindeutig auf den kanonischen Paratix-Eintrag verweist; andernfalls wird nicht
  geraten.
- Erreicht die Verarbeitung nach zehn Minuten keinen abfragbaren Zustand, fehlen API-Zugriff oder
  Rate-Limit-Kapazität, oder liefert Context7 eine dauerhafte Fehlerantwort, endet die Umsetzung als
  blockiert. Lokale Checks allein erfüllen den gewählten End-to-End-Scope nicht.

## Akzeptanzkriterien

- [ ] Der vollständige Scope besteht aus der neuen Root-Datei `context7.json` und genau einer
      ergänzten `.DS_Store`-Regel in der vorhandenen Root-`.gitignore`; andere Projektdateien und die
      beiden `.DS_Store`-Dateien bleiben unverändert.
- [ ] `git check-ignore -v .DS_Store website/.DS_Store` weist für beide Dateien dieselbe neue
      Root-Regel `.DS_Store` nach.
- [ ] Die Datei ist valides JSON und enthält ausschließlich `$schema`, `projectTitle`, `description`,
      `folders`, `excludeFolders`, `excludeFiles` und `rules` mit den im Plan vollständig
      festgelegten Werten.
- [ ] Die Instanz validiert ohne Fehler gegen das aktuelle Draft-07-Schema unter
      `https://context7.com/schema/context7.json`.
- [ ] Die lokal aus Allowlist, unterstützten Dateitypen und Ausschlüssen abgeleitete
      Kandidatenmenge umfasst `README.md` sowie genau die sieben aktuellen Dokumente
      `packages/paratix/README.md`, `packages/paratix/llm-guide.md`,
      `packages/create-paratix/README.md`, `docs/user-guide/README.md`,
      `docs/user-guide/troubleshooting.md`, `docs/user-guide/comparison.md` und
      `docs/user-guide/migration.md`.
- [ ] Pläne, Reviews, ADRs, historische Designdokumente, interne Agent-Anweisungen, Changelogs,
      Contribution-/Security-Dokumente sowie Website-Quellen werden durch Allowlist und Ausschlüsse
      nicht als aktuelle Context7-Produktreferenz indexiert.
- [ ] Jede Regel in `rules` ist direkt durch `packages/paratix/llm-guide.md` belegt und bleibt kurz
      genug, um als langlebige Agent-Anweisung zu funktionieren.
- [ ] `pnpm exec prettier --check context7.json` und `pnpm agent:check` enden jeweils mit Exit-Code 0.
- [ ] Die Context7-API bestätigt den Eintrag `/sebastian-software/paratix`; eine Neueinreichung
      liefert `200` mit dieser Library-ID oder ein bestehender Eintrag wird nach `409` ohne Duplikat
      aktualisiert.
- [ ] Nach dem Refresh liefern konkrete Context-Abfragen verwertbare Paratix-Dokumentation für
      Playbook/API-Importe, Projekt-Scaffolding, Troubleshooting, Migration und den Vergleich mit
      Ansible beziehungsweise pyinfra. Soweit Context7 Quellenpfade ausgibt, stammt kein Treffer aus
      einem ausgeschlossenen Pfad oder Dateinamen.

## Validierungsplan

- JSON-Syntax mit
  `node -e 'JSON.parse(require("node:fs").readFileSync("context7.json", "utf8"))'` prüfen;
  erwartetes Ergebnis ist Exit-Code 0 ohne Parse-Fehler.
- `git check-ignore -v .DS_Store website/.DS_Store` ausführen; erwartetes Ergebnis sind zwei Treffer
  auf die neue `.gitignore`-Zeile. Danach mit `git diff --check` sicherstellen, dass die zwei
  geplanten Änderungen keine Whitespace-Fehler enthalten.
- Mit `mktemp -d` ein temporäres Verzeichnis anlegen, das Schema per `curl -fsSL
https://context7.com/schema/context7.json` dorthin laden und anschließend `pnpm dlx
ajv-cli@5.0.0 validate --spec=draft7` mit der temporären Schema-Datei und `context7.json`
  ausführen; erwartetes Ergebnis ist „valid“ ohne unbekannte Felder oder Typfehler. Das temporäre
  Verzeichnis wird danach entfernt und es wird keine Projektabhängigkeit aufgenommen.
- `pnpm exec prettier --check context7.json` im Repository-Root ausführen; erwartetes Ergebnis ist
  Exit-Code 0 und keine Formatabweichung.
- Die lokale Kandidatenmenge mit `find docs/user-guide packages/paratix packages/create-paratix`
  auf die Context7-Dateitypen `.md`, `.mdx`, `.markdown`, `.rst`, `.txt` und `.ipynb` begrenzen,
  Pfade unter den fünf `excludeFolders` und Basenames aus `excludeFiles` herausfiltern, `README.md`
  ergänzen und lexikografisch sortieren. Die Ausgabe muss exakt der in den Akzeptanzkriterien
  genannten Acht-Dateien-Menge entsprechen.
- `git status --short --untracked-files=all` gegen den dokumentierten Ausgangszustand prüfen. Als
  Umsetzungsänderungen sind nur `.gitignore` und `context7.json` zulässig; die Plan-Datei gehört zum
  Workflow-Artefakt. `git diff --check -- .gitignore` prüft ausschließlich die versionierte
  Ignore-Änderung, während Prettier die unversionierte JSON-Datei abdeckt.
- Abschließend `pnpm agent:check` im Repository-Root ausführen; erwartetes Ergebnis ist Exit-Code 0.
  Integrationstests gegen Docker sind für diese reine Repository-Metadatenänderung nicht nötig.
- Vor externen Aufrufen nur die Existenz von `CONTEXT7_API_KEY` prüfen, nie seinen Wert ausgeben.
  Mit `GET /api/v2/libs/search` nach `Paratix` suchen und die exakte ID
  `/sebastian-software/paratix` bestimmen. Fehlt sie, `POST /api/v2/add/repo/github` mit
  `docsRepoUrl: https://github.com/sebastian-software/paratix` ausführen; bei `409` ohne erneute
  Einreichung fortfahren.
- `POST /api/v1/refresh` mit `libraryName: /sebastian-software/paratix` ausführen und den
  Verarbeitungszustand innerhalb des festgelegten Zehn-Minuten-Fensters abfragen. `202` wird erneut
  geprüft, `429` nach `Retry-After`; andere nicht erfolgreiche Antworten blockieren den Abschluss.
- Über `GET /api/v2/context` mindestens fünf spezifische Abfragen ausführen: Playbook mit
  `paratix`-/`paratix/modules`-Importen, neues Projekt mit `create-paratix`, SSH-/Reconnect-
  Troubleshooting, Migration eines bestehenden Projekts und Vergleich mit Ansible/pyinfra.
  Erwartet werden jeweils inhaltlich passende Paratix-Snippets; vorhandene Quellenmetadaten werden
  zusätzlich gegen Allowlist und Ausschlüsse geprüft.

## Annahmen und offene Punkte

- Verifiziert: Es existiert auf `HEAD` und `origin/main` keine `context7.json`.
- Verifiziert: `packages/paratix/llm-guide.md` ist laut Root-README die aktuelle normative Referenz;
  `docs/plan/**`, `docs/review/**`, `docs/module.md` und `docs/initialbeschreibung.md` sind dagegen
  historische oder zeitgebundene Unterlagen.
- Verifiziert: Das Repository formatiert JSON mit Prettier und prüft Änderungen in CI über
  `pnpm agent:check`; ein eigener Context7- oder allgemeiner JSON-Schema-Validator existiert nicht.
- Verifiziert: Die Root-`.gitignore` enthält bislang keine `.DS_Store`-Regel; `.DS_Store` und
  `website/.DS_Store` sind aktuell unversioniert und werden nicht ignoriert.
- Verifiziert aus offizieller Context7-Dokumentation und Schema: `context7.json` gehört in den
  Repository-Root, `folders` ist eine Allowlist, Root-Markdown bleibt eingeschlossen,
  `excludeFiles` akzeptiert Dateinamen und unbekannte Schemafelder sind nicht erlaubt.
- Annahme: Die acht benannten Dokumente bleiben bis zur Umsetzung die vollständige normative
  Consumer-Dokumentation. Der Validierungsplan enthält deshalb einen Drift-Abgleich.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       0 |       1 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       1 |
| Testbarkeit |        0 |       0 |       2 |
| Scope       |        0 |       0 |       2 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Architektur (Hinweis):** Eine enge Allowlist ist robuster als das nachträgliche Ausschließen
  sämtlicher historischer Ordner. Die Entscheidung ist im Plan verankert.
- **Security (Hinweis):** Claiming-Schlüssel oder API-Keys gehören nicht in dieses Arbeitspaket.
  Die geplante Datei enthält ausschließlich öffentliche Parsing-Metadaten und Regeln.
- **Fehlerfälle (Hinweis):** Die Schemavalidierung hängt von einer extern erreichbaren Quelle ab.
  Der Plan definiert dafür eine Stop-Bedingung statt eines stillen Erfolgs.
- **Testbarkeit (Hinweis):** Das Repository besitzt keinen Schema-Validator. Die einmalige
  Draft-07-Prüfung ohne neue Projektabhängigkeit ergänzt Syntax-, Format- und Gesamtchecks.
- **Scope (Hinweis):** Context7-Einreichung, Claiming und Refresh-Automation sind bewusst getrennte
  Folgeschritte. Die zusätzlich gewünschte `.gitignore`-Änderung ist auf eine einzelne
  basename-basierte Regel begrenzt; vorhandene `.DS_Store`-Dateien werden nicht gelöscht.
- **Wartbarkeit (Hinweis):** Versions- und Branchkonfiguration bleibt draußen, bis Paratix dafür
  einen stabilen Release-Vertrag festlegt. Das verhindert vorzeitige, schnell veraltende Metadaten.

### Tiefenreview vom 23. September 2026

- **Scope (Wichtig):** Der Plan schloss Einreichung und Refresh aus, formulierte die Acht-Dateien-
  Menge aber zunächst als tatsächlich veröffentlichten Context7-Index. Die lokale Kandidatenmenge
  und der veröffentlichte Index sind nicht dasselbe. Der Benutzer hat End-to-End gewählt:
  Einreichung beziehungsweise Refresh und Remote-Abfragen sind nun Teil des Scopes; die lokale
  Acht-Dateien-Prüfung bleibt der präzise Strukturvertrag.
- **Testbarkeit (Hinweis):** Syntax-, Schema-, Kandidatenmengen- und Scope-Prüfung waren zunächst
  nur als Methoden beschrieben. Sie wurden auf konkrete Werkzeuge, eine feste Validator-Version,
  erwartete Ergebnisse und die Grenzen von `git diff --check` präzisiert.
- **Wartbarkeit (Hinweis):** Die JSON-Werte waren durch Formulierungen wie „mindestens“ und „kurz
  genug“ nicht deterministisch. Beschreibung, Arrays und Regeltexte sind nun vollständig festgelegt;
  die `command.shell()`-Regel beschreibt korrekt die idempotente Nutzung statt eine syntaktische
  Pflicht für jeden Aufruf zu behaupten.
- **Scope (Hinweis):** Context7 bietet keinen dokumentierten vollständigen Datei-Inventar-Endpunkt.
  Der Plan trennt deshalb die lokal exakt beweisbare Acht-Dateien-Kandidatenmenge vom Remote-
  Verhaltenstest mit repräsentativen Abfragen, statt dem API-Nachweis mehr Aussagekraft
  zuzuschreiben, als er besitzt.

## Lokaler Umsetzungsnachweis

**Datum:** 23. September 2026

### Umsetzung

- Die Root-`.gitignore` enthält genau eine neue basename-basierte Regel `.DS_Store`.
- Die Root-`context7.json` enthält ausschließlich die sieben im Plan festgelegten Felder und Werte.
- Die vorhandenen Dateien `.DS_Store` und `website/.DS_Store` sowie sachfremde Arbeitsbaumänderungen
  blieben unangetastet.

### Dokumentationsabgleich

- In-Code-Dokumentation und CLI-Hilfe: `no impact`, weil keine öffentliche Codefläche geändert
  wurde.
- Root-README und User Guide: `no impact`, weil weder Verhalten noch Befehle oder
  Anwenderkonfiguration geändert wurden.
- Technische Dokumentation: `no impact`, weil Architektur, Schnittstellen, Build-/Testbefehle,
  Runtime und Abhängigkeiten unverändert sind.
- `AGENTS.md`: `no impact`, weil der Repository-Workflow unverändert ist.

### Testergebnisse

- JSON-Syntax und exakter Wertevergleich: bestanden.
- Draft-07-Schemavalidierung mit `ajv-cli@5.0.0` und dem temporär geladenen
  `ajv-formats@2.1.1`: bestanden (`context7.json valid`).
- Ignore-Wirkung für `.DS_Store` und `website/.DS_Store`: bestanden.
- Lokale Kandidatenmenge: exakt die acht im Plan festgelegten Dokumente.
- Alle fünf `rules` sind durch `packages/paratix/llm-guide.md` belegt.
- Prettier und `git diff --check -- .gitignore`: bestanden.
- `pnpm agent:check` mit dem projektgepinnten pnpm 11.17.0: bestanden. Darin enthalten sind
  OXLint, ESLint, Prettier, TypeScript-Typechecks, alle Builds, 4.302 bestandene Paratix-Tests bei
  9 regulär übersprungenen Tests, 268 bestandene `create-paratix`-Tests, 2 bestandene Website-Tests
  und 36 bestandene Skripttests.

### Verbleibender End-to-End-Nachweis

`CONTEXT7_API_KEY` war im Umsetzungslauf nicht gesetzt. Außerdem liegt `context7.json` vor dem
Merge noch nicht auf dem öffentlichen Default-Branch, von dem Context7 indexiert. Deshalb wurden
weder Einreichung noch Refresh ausgelöst und die fünf Remote-Abfragen noch nicht ausgeführt. Der
Plan bleibt bis zu diesem Nachweis im Status „Nicht umgesetzt“ und wird noch nicht archiviert.

## Review-Befunde

**Datum:** 23. September 2026
**Reviewer:** `effective-flow-code-validator` (technische Validierung; kein Produktreviewer für den
reinen Tooling-Scope erforderlich)

Keine Befunde.

## Offene Punkte

- Keine offenen Punkte.
