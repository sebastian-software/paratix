# Code-Review-Bericht

**Datum:** 2026-03-15
**Scope:** Gesamter Code (~45 Source-Dateien + ~30 Test-Dateien)
**Projekt-Typ:** CLI / Library (Node.js Monorepo)

## Zusammenfassung

| Schweregrad | Anzahl |
| ----------- | ------ |
| Kritisch    | 1      |
| Wichtig     | 6      |
| Hinweis     | 4      |

| Komplexitaet | Anzahl |
| ------------ | ------ |
| Leicht       | 9      |
| Mittel       | 2      |
| Schwer       | 0      |

| Aktion         | Anzahl |
| -------------- | ------ |
| /fix           | 7      |
| /refactor      | 3      |
| /build-feature | 1      |

### Technische Validierung

| Check                     | Status        |
| ------------------------- | ------------- |
| TypeScript                | 0 Fehler      |
| Linting (oxlint + eslint) | 0 Fehler      |
| Build                     | Erfolgreich   |
| Tests                     | 850 bestanden |

## Findings

### [R-001] Command Injection via unsanitized `flagPrefix`

- **Schweregrad**: Kritisch
- **Komplexitaet**: Leicht
- **Bereich**: Security
- **Datei**: packages/paratix/src/modules/moduleHelpers.ts:22
- **Problem**: `setVersionedFlag` verwendet `flagPrefix` direkt in einem Shell-Glob-Pattern (`rm -f ${FLAGS_DIRECTORY}/${flagPrefix}*`), ohne es zu quoten oder zu sanitizen. Der `flagName` wird korrekt mit `shellQuote` behandelt, aber der `flagPrefix` nicht. Bei boeswilligem Input koennte dies zu Command Injection fuehren.
- **Empfehlung**: `flagPrefix` ebenfalls durch `shellQuote` schuetzen oder gegen `/^[\w.-]+$/` validieren.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "Command Injection in `setVersionedFlag`: `flagPrefix` wird ohne Shell-Quoting in ein `rm -f`-Glob eingesetzt. Erwartet: `flagPrefix` wird mit `shellQuote` geschuetzt oder validiert. Betroffen: packages/paratix/src/modules/moduleHelpers.ts:22."

---

### [R-002] Vorhersagbarer temporaerer Dateiname in `writeFile`

- **Schweregrad**: Wichtig
- **Komplexitaet**: Leicht
- **Bereich**: Security
- **Datei**: packages/paratix/src/ssh.ts:230
- **Problem**: `join(tmpdir(), \`paratix-write-${Date.now()}\`)` erzeugt einen vorhersagbaren Dateinamen. Dies ist anfaellig fuer TOCTOU/Symlink-Angriffe auf dem lokalen System.
- **Empfehlung**: `crypto.randomUUID()` statt `Date.now()` verwenden.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "Vorhersagbarer temp-Dateiname in `writeFile`. Erwartet: kryptographisch zufaelliger Name via `crypto.randomUUID()`. Betroffen: packages/paratix/src/ssh.ts:230."

---

### [R-003] Synchrones `readFileSync` in async `connect()`

- **Schweregrad**: Wichtig
- **Komplexitaet**: Leicht
- **Bereich**: Performance
- **Datei**: packages/paratix/src/ssh.ts:50
- **Problem**: `readFileSync` blockiert den Event Loop in einer `async`-Methode. Bei grossen Keys oder langsamen Dateisystemen kann dies zu Verzoegerungen fuehren.
- **Empfehlung**: `readFile` aus `node:fs/promises` verwenden.
- **Aktion**: `/refactor`
- **Prompt-Vorschlag**: "`readFileSync` in async `connect()` durch `await readFile()` ersetzen in packages/paratix/src/ssh.ts:50. Ziel: konsistent asynchroner I/O."

---

### [R-004] Keine Validierung des `--reconnect-timeout` CLI-Parameters

- **Schweregrad**: Wichtig
- **Komplexitaet**: Leicht
- **Bereich**: Error Handling
- **Datei**: packages/paratix/src/cli.ts:167
- **Problem**: `Number(options.reconnectTimeout)` wird nicht validiert. Bei Eingaben wie `"abc"` entsteht `NaN`, was zu undefiniertem Verhalten fuehrt. Negative Werte werden ebenfalls nicht abgefangen.
- **Empfehlung**: Validierung hinzufuegen: `if (Number.isNaN(timeout) || timeout <= 0)` mit Fehlermeldung und `process.exit(2)`.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "Fehlende Validierung von `--reconnect-timeout`. Erwartet: NaN und negative Werte abfangen mit Fehlermeldung. Betroffen: packages/paratix/src/cli.ts:167."

---

### [R-005] SFTP-Streams werden bei Fehler nicht vollstaendig aufgeraeumt

- **Schweregrad**: Wichtig
- **Komplexitaet**: Mittel
- **Bereich**: Error Handling
- **Datei**: packages/paratix/src/sftp.ts:24-42
- **Problem**: Bei einem Fehler des `readStream` bleibt der `writeStream` offen (und umgekehrt). Zudem fehlt ein Guard gegen doppeltes `reject` -- wenn beide Streams Fehler melden, wird das Promise zweimal rejected.
- **Empfehlung**: Einen `settled`-Flag einfuehren und beide Streams bei Fehler mit `.destroy()` aufraumen.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "SFTP-Stream-Cleanup: Bei Fehler in `sftpDownload`/`sftpUpload` werden Streams nicht vollstaendig aufgeraeumt und `reject` kann doppelt aufgerufen werden. Erwartet: `settled`-Flag und `destroy()` fuer beide Streams. Betroffen: packages/paratix/src/sftp.ts:24-42."

---

### [R-006] Fehlende Projektname-Validierung in `create-paratix`

- **Schweregrad**: Wichtig
- **Komplexitaet**: Leicht
- **Bereich**: Security
- **Datei**: packages/create-paratix/src/index.ts:124
- **Problem**: Der Projektname aus `process.argv[2]` wird als `cwd` fuer `execSync` verwendet, aber nicht auf erlaubte Zeichen validiert.
- **Empfehlung**: Projektnamen gegen `/^[\w.@/-]+$/` validieren.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "Fehlende Validierung des Projektnamens in `create-paratix`. Erwartet: Regex-Validierung gegen erlaubte Zeichen. Betroffen: packages/create-paratix/src/index.ts:124."

---

### [R-007] Fehlende SIGINT/SIGTERM-Handler fuer SSH-Cleanup

- **Schweregrad**: Wichtig
- **Komplexitaet**: Mittel
- **Bereich**: Best Practices
- **Datei**: packages/paratix/src/runner.ts, packages/paratix/src/cli.ts
- **Problem**: Bei `Ctrl+C` wird die SSH-Verbindung nicht sauber geschlossen. Der `finally`-Block in `runPlaybook` wird bei Signals nicht ausgefuehrt. Offene SSH-Verbindungen und laufende Remote-Befehle bleiben haengen.
- **Empfehlung**: Signal-Handler registrieren, der `ssh.disconnect()` aufruft und den Prozess sauber beendet.
- **Aktion**: `/build-feature`
- **Prompt-Vorschlag**: "Signal-Handler fuer graceful SSH-Shutdown bei SIGINT/SIGTERM. Anforderungen: SSH-Verbindung sauber schliessen, laufende Remote-Befehle beenden, `finally`-Block ausfuehren. Betroffen: packages/paratix/src/runner.ts und packages/paratix/src/cli.ts."

---

### [R-008] `op.resolve` verschluckt Fehlermeldungen

- **Schweregrad**: Wichtig
- **Komplexitaet**: Leicht
- **Bereich**: Error Handling
- **Datei**: packages/paratix/src/modules/op.ts:185-186
- **Problem**: Wenn `resolveRegularReferences` oder `resolveOtpReferences` fehlschlagen, wird der Fehler komplett verschluckt und nur `{ status: "failed" }` zurueckgegeben. Der Benutzer erhaelt keine Information ueber die Fehlerursache.
- **Empfehlung**: Fehlermeldung ueber `console.error` oder die Output-Klasse ausgeben, bevor `{ status: "failed" }` zurueckgegeben wird.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "Verschluckte Fehlermeldung in `op.resolve`. Erwartet: Fehler wird geloggt bevor `{ status: 'failed' }` zurueckgegeben wird. Betroffen: packages/paratix/src/modules/op.ts:185-186."

---

### [R-009] Sudo-Prompt Information Disclosure

- **Schweregrad**: Hinweis
- **Komplexitaet**: Leicht
- **Bereich**: Security
- **Datei**: packages/paratix/src/ssh.ts:103-104
- **Problem**: `sudo -S` erzeugt stderr-Ausgabe wie `[sudo] password for user:`. Obwohl das Passwort selbst maskiert wird, ist der Prompt ein Informationsleck. Harmlos, aber vermeidbar.
- **Empfehlung**: `SUDO_PROMPT=""` vor dem sudo-Aufruf setzen.
- **Aktion**: `/fix`
- **Prompt-Vorschlag**: "Sudo-Prompt unterdruecken: `SUDO_PROMPT=\"\"` vor `sudo -S` setzen um Information Disclosure zu vermeiden. Betroffen: packages/paratix/src/ssh.ts:103-104."

---

### [R-010] Fehlende Validierung von `tag`/`asset` in `download.github`

- **Schweregrad**: Hinweis
- **Komplexitaet**: Leicht
- **Bereich**: Security
- **Datei**: packages/paratix/src/modules/download.ts:206-210
- **Problem**: `repo` wird gegen `..` validiert, aber `tag` und `asset` nicht. Geringes Risiko, da GitHub ungueltige Pfade ablehnt, aber inkonsistent.
- **Empfehlung**: `tag` und `asset` ebenfalls gegen `..`-Sequenzen pruefen.
- **Aktion**: `/fix` (Konsistenz-Fix, geringes Risiko)
- **Prompt-Vorschlag**: "Path-Traversal-Validierung fuer `tag` und `asset` in `download.github` ergaenzen, analog zur bestehenden `repo`-Validierung. Betroffen: packages/paratix/src/modules/download.ts:206-210."

---

### [R-011] Doppeltes sudo in `readFile`

- **Schweregrad**: Hinweis
- **Komplexitaet**: Leicht
- **Bereich**: Code-Qualitaet
- **Datei**: packages/paratix/src/ssh.ts:164
- **Problem**: `readFile` ruft `this.output(\`${this.sudoPrefix()}cat ...\`)`auf, wobei`output()`intern`exec()`aufruft, das nochmals`sudoCommand()`anwendet. Das Ergebnis ist ein doppeltes`sudo sudo cat ...`, das zwar funktioniert, aber redundant ist.
- **Empfehlung**: `sudoPrefix()` aus dem `readFile`-Aufruf entfernen, da `exec()` bereits sudo anwendet.
- **Aktion**: `/refactor`
- **Prompt-Vorschlag**: "Doppeltes sudo in `readFile` entfernen: `sudoPrefix()` wird redundant verwendet, da `exec()` bereits sudo wrapping durchfuehrt. Betroffen: packages/paratix/src/ssh.ts:164."

---

### [R-012] Unvollstaendige Validierung in `collectDefinitionErrors`

- **Schweregrad**: Hinweis
- **Komplexitaet**: Leicht
- **Bereich**: API Design
- **Datei**: packages/paratix/src/cli.ts:31-52
- **Problem**: `collectDefinitionErrors` prueft nur `host` und `run`, aber nicht die Pflichtfelder `name` und `ssh`. Benutzer, die ohne `server()`-Helper exportieren, erhalten keine hilfreiche Fehlermeldung.
- **Empfehlung**: Validierung fuer `name` und `ssh` ergaenzen.
- **Aktion**: `/refactor`
- **Prompt-Vorschlag**: "Validierung in `collectDefinitionErrors` vervollstaendigen: `name` und `ssh` als Pflichtfelder pruefen, analog zu `host` und `run`. Betroffen: packages/paratix/src/cli.ts:31-52."
