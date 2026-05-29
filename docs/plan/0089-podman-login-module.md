# 0089: podman.login() und podman.logout() für Registry-Auth

**Planungsstatus:** Nicht umgesetzt
**Quelle:** /plan
**Empfohlener Workflow:** Feature (`/build`)

## Anforderung

Paratix soll Podman-Registry-Logins idempotent verwalten können, damit Quadlet- und Compose-Workflows auf privaten Registries (z. B. `ghcr.io`) ohne manuelle `podman login`-Schritte funktionieren. Die erste Version liefert ein neues `podman`-Modul mit zwei Methoden:

- `podman.login(...)` — schreibt genau einen Registry-Eintrag in eine `auth.json` und überschreibt andere Einträge nicht.
- `podman.logout(...)` — entfernt genau einen Registry-Eintrag, ohne andere Einträge zu beschädigen.

Begründung der Workflow-Empfehlung: Es handelt sich um neue Produkt­funktionalität (neue Modul-API, neue Datei- und Auth-Pfade, neuer Validierungs- und Sicherheitscode). Das ist klar ein Feature und gehört in `/build`, nicht in `/fix` oder `/refactor`.

## Architekturentscheidungen

- **Neues Modul `podman`** unter `packages/paratix/src/modules/podman.ts` mit den Methoden `login` und `logout`. Damit bleibt die Registry-Authentifizierung sauber neben `quadlet.*` und `compose.*` modelliert und kann später um weitere Podman-Operationen erweitert werden (Pull, Inspect, Network, …).
- **Dedizierte Logout-Variante** statt `state: "absent"`. Folgt dem Pattern von `cron.absent` und `timer.absent`: `podman.logout(registry, options)` verlangt keine Platzhalter für `username`/`passwordFile`.
- **PAT-Speicherort konfigurierbar.** Eine neue Option `passwordFileLocation: "controller" | "target"` (Default `"controller"`) entscheidet, ob die PAT-Datei auf dem Paratix-Controller oder auf dem Ziel-Host liegt. Beide Fälle teilen sich denselben Idempotenz- und Login-Pfad.
- **`user` bewusst nicht im API-Surface.** Der Login-Eintrag landet immer im Home des SSH-Session-Users; ein User-Switch via `sudo -u` ist explizit nicht vorgesehen (siehe Klärung in Phase 2). Wer einen Login-Eintrag für einen anderen User braucht, ruft `podman.login(...)` mit einer expliziten `authFile`-Option in dessen Home auf oder konfiguriert einen separaten Server mit entsprechendem SSH-User.
- **Check-Logik gegen `auth.json`, nicht gegen `podman login --get-login`.** Der vergleich von `auths[registry].auth` mit `base64(<username>:<pat>)` ist deterministisch, fail-closed und vermeidet einen zusätzlichen `podman`-Aufruf im Check-Pfad.
- **PAT verlässt den eigenen Host nicht unnötig.** Wenn `passwordFileLocation === "target"`, läuft sowohl die Idempotenz-Berechnung (`base64 …`) als auch der Login (`podman login --password-stdin`) komplett auf dem Target. Der Controller sieht nur Vergleichs-Hashes, nie das Token im Klartext.
- **`--password-stdin` zwingend.** Das PAT erreicht den Login-Prozess ausschließlich über stdin. Es darf nie in argv, Stdout, Stderr, Logs oder Diff-Outputs auftauchen.
- **Wiederverwendung bestehender Helper.** Pfad-Validierung folgt dem Schema von `validateQuadletAuthFilePath`. Symlink-Schutz nutzt `isSymlink` aus `remoteFileChecks.ts`. Für das atomare Schreiben von `auth.json` wird das vorhandene Snapshot- und Rollback-Pattern aus `quadletFileHelpers.ts` adaptiert.
- **`podman login` schreibt die Datei selbst.** Beim Login wird `auth.json` nicht von Paratix gerendert; `podman login --authfile <path>` mergt den neuen Eintrag in eine vorhandene Datei. Paratix beschränkt sich auf Verzeichnis-/Dateirechte, Symlink-Guard und Idempotenz-Check.
- **`podman logout` für Entfernen.** Genauso wie beim Login wird das Entfernen Podman überlassen (`podman logout --authfile <path> <registry>`). Es bleibt bei einem Tool, das `auth.json` interpretiert.

## Betroffene Dateien

| Datei                                           | Beschreibung                                                                 |
| ----------------------------------------------- | ---------------------------------------------------------------------------- |
| `packages/paratix/src/modules/podman.ts`        | Neues `podman`-Modul mit `podman.login(...)` und `podman.logout(...)`        |
| `packages/paratix/src/modules/podmanHelpers.ts` | Render-, Check- und Validierungs-Helper für die `podman`-Module              |
| `packages/paratix/src/modules/index.ts`         | Export `podman`                                                              |
| `packages/paratix/src/index.ts`                 | Top-Level-Export `podman`                                                    |
| `packages/paratix/test/modules/podman.test.ts`  | Unit-Tests für Validierung, Idempotenz, Apply-Pfad, Logout, Secrets-Handling |
| `packages/paratix/llm-guide.md`                 | API-Referenz: neue Sektion `podman`                                          |
| `packages/paratix/README.md`                    | Hinweis auf Podman-Registry-Login als Teil des Container-Workflows           |
| `cspell.json`                                   | Neue Begriffe falls erforderlich (z. B. `authfile`, falls nicht vorhanden)   |

Keine Änderungen an `quadlet.*`-Modulen — die nutzen weiterhin ihre eigene `authFile`-Option für `podman pull`, jetzt aber sinnvoll vorbereitbar durch `podman.login`.

## Implementierungsdetails

### API-Skizze

Nur als Schnittstellen-Andeutung in natürlicher Sprache; vollständige Typen werden in der Implementierung erzeugt:

- `podman.login(options)` — Parameter:
  - `registry: string` (z. B. `"ghcr.io"`)
  - `username: string`
  - `passwordFile: string` — absoluter Pfad zur PAT-Datei
  - `passwordFileLocation?: "controller" | "target"` — Default `"controller"`
  - `authFile?: string` — Default `/root/.config/containers/auth.json`
- `podman.logout(registry, options?)` — Parameter:
  - `registry: string`
  - `authFile?: string` — Default wie oben

Die konkreten TypeScript-Signaturen werden in der Implementierung festgelegt.

### Vorgehen

1. **Validierung zur Konstruktionszeit.** `registry`, `username`, `passwordFile`, `authFile` werden mit dedizierten Validatoren geprüft. `passwordFile` und `authFile` müssen absolute Pfade ohne `..`-Segmente sein (analog `validateQuadletAuthFilePath`). `registry` darf keine Whitespace, keine Kontrollzeichen und keine Shell-Metazeichen enthalten und muss einer konservativen Pattern-Whitelist genügen. `username` wird gegen eine Whitelist ohne Doppelpunkt (`:`) geprüft, weil der Doppelpunkt das Trennzeichen in `base64(<user>:<password>)` ist und die Auth-Eintragsstruktur sonst kaputt geht.
2. **Permission-Check der PAT-Datei.**
   - Für `passwordFileLocation === "controller"`: lokaler `fs.stat`/`fs.statSync`-Check. Mode darf maximal `0400` sein, Owner muss der laufende Prozess-User sein (Operator). Verletzung → Fail-Fast vor jedem Login.
   - Für `passwordFileLocation === "target"`: remote `stat -c '%a %U' <path>`. Mode maximal `0400`, Owner gleich SSH-Session-User. Verletzung → `failed(...)`.
3. **Auth-Datei vorbereiten.**
   - Parent-Verzeichnis bei Bedarf anlegen (`mkdir -p` mit anschließendem `chmod 0700`).
   - Symlink-Guard: weder `authFile` noch Parent dürfen Symlinks sein. Bei Symlink → `failed(...)` ohne Schreibversuch.
   - Wenn `auth.json` neu angelegt wird, Mode `0600` setzen, sobald `podman login` die Datei erzeugt hat (Podman erzeugt sie oft mit `0600`, der explizite `chmod` macht es deterministisch).
4. **Check-Pfad (idempotent).**
   - `auth.json` existiert nicht oder enthält keinen Eintrag für `registry` → `needs-apply`.
   - Existiert: `auths[<registry>].auth` lesen und mit `base64(<username>:<pat>)` vergleichen.
     - Controller-Lokation: Vergleich auf dem Controller mit `crypto.timingSafeEqual` über die hex-codierten SHA-256-Hashes der beiden Werte (vermeidet PAT im Speicher länger als nötig und nutzt vorhandenen `hexHashesEqual`-Helper).
     - Target-Lokation: Vergleich vollständig remote. Eine kompakte Shell-Pipeline liest die PAT-Datei lokal auf dem Target, baut `base64(<username>:<pat>)`, leitet stdin in einen Aufruf, der mit dem aus `auth.json` geparsten Eintrag verglichen wird. Username und Registry werden via `--input` / Heredoc statt argv übergeben, damit kein Secret-Material in der Prozessliste auftaucht.
   - Gleich → `ok`. Ungleich oder fehlerhaft geparst → `needs-apply`.
   - JSON-Parsing erfolgt fail-closed: ist `auth.json` kein gültiges JSON, ist es kein Match → `needs-apply` (Login wird podman die Datei sauber neu schreiben lassen).
5. **Apply-Pfad Login.**
   - Snapshot der bestehenden `auth.json` für Rollback (analog `snapshotQuadletFile`).
   - Aufruf: `podman login --authfile <authFile> --username <username> --password-stdin <registry>` mit `silent: true`, `secrets: [pat]` und `input: <pat>` (`ssh.exec`-Option).
     - Controller-Lokation: PAT wird im Apply-Schritt einmalig lokal gelesen, an `ssh.exec({ input })` übergeben, sofort wieder aus dem JS-Scope entfernt.
     - Target-Lokation: Statt `input` wird ein Shell-Pipeline-Aufruf genutzt: `cat <passwordFile> | podman login --authfile <authFile> --username <username> --password-stdin <registry>`. Das PAT erreicht den Login-Prozess komplett im Target-Kernel-Space und verlässt den Host nicht.
   - Bei Fehlschlag: `failed(...)` bzw. `failedCommand(...)` ohne PAT in `result.stderr`/`result.stdout`. Rollback der `auth.json` aus dem Snapshot.
   - Nach Erfolg: `chmod 0600 <authFile>` deterministisch nachziehen.
6. **Apply-Pfad Logout.**
   - Wenn `auth.json` fehlt oder keinen Eintrag für `registry` enthält → `ok` (idempotent).
   - Andernfalls Snapshot + `podman logout --authfile <authFile> <registry>` mit `silent: true`.
   - Bei Fehlschlag: `failedCommand(...)` plus Rollback.

### Komponenten-Struktur

- `podman.ts` enthält die zwei öffentlichen Methoden und delegiert an Helper.
- `podmanHelpers.ts` enthält:
  - Validierungen (`registry`, `username`, `passwordFile`-Pfad, `authFile`-Pfad)
  - Permission-Check-Helper (lokal + remote)
  - Snapshot-/Rollback-Helper für `auth.json`
  - Render-Helper für die `podman login`/`podman logout`-Shell-Kommandos (mit `shellQuote`)
  - Auth-JSON-Parsing-Helper (kleines, defensives Parsen — kein Schema-Erzwingen, nur `auths[registry].auth` lesen)

### State-Management

Nicht relevant. Es gibt keinen separaten Flag-Versions-Store; die `auth.json` selbst ist der Wahrheitswert. Token-Rotation wird automatisch erkannt, weil der Hash der erwarteten `base64(<user>:<password>)`-Form sich ändert.

### API-Anbindung

Nicht relevant.

### Styling-Ansatz

Nicht relevant (Backend-Modul, kein UI).

### Barrierefreiheit

Nicht relevant.

### Edge Cases

- **Mehrere Registries pro `auth.json`.** `podman login` mergt neue Einträge per Default, ohne andere zu entfernen. Test deckt: bestehender Eintrag für `docker.io` bleibt nach `podman.login("ghcr.io", …)` unverändert.
- **Logout entfernt nur den eigenen Eintrag.** Test deckt: vor `podman.logout("ghcr.io")` existieren zwei Einträge, danach nur noch der andere; `auth.json` bleibt valides JSON.
- **Logout ohne vorhandenen Eintrag** → `ok`, kein Aufruf von `podman logout`.
- **PAT-Datei existiert nicht** → `failed(...)` mit klarem Hinweis, dass der Operator die Datei vorab erstellen muss. Paratix erzeugt sie nicht.
- **PAT-Datei zu permissiv (Mode > 0400 oder falscher Owner)** → `failed(...)` vor jedem Login-Versuch.
- **PAT-Datei leer** → Fail-Fast mit eindeutiger Fehlermeldung (keine Übergabe einer Leer-Token in `podman login`).
- **`auth.json` ist Symlink** → `failed(...)`, kein Schreiben, kein Login.
- **`auth.json` ist defekter JSON** → Check liefert `needs-apply`; `podman login` schreibt die Datei neu (Snapshot existiert für Rollback).
- **HTTP 401 / Netzwerkfehler beim Login** → `failedCommand(...)` mit Stderr von `podman` (ohne PAT), Rollback der Datei. Kein automatisches Retry.
- **Token-Rotation:** Operator ändert `passwordFile`-Inhalt → nächster Lauf erkennt Hash-Unterschied → Re-Login wird ausgeführt.
- **Registry-Variation:** Eintrag `ghcr.io` vs. `https://ghcr.io/v2/` — Paratix vergleicht 1:1 gegen `auths[<registry>]`; abweichende Schreibweisen, die `podman login` erzeugen könnte, werden im Test mit fixierter Erwartung dokumentiert.
- **Mehrere parallele Aufrufe** für dieselbe `auth.json` werden außerhalb des Moduls vermieden (Server-Run ist sequentiell). Nicht relevant für V1.
- **Concurrent-Drift:** Wenn `auth.json` zwischen Snapshot und Login von einem dritten Prozess geändert wird, gewinnt der `podman login`-Merge. Dokumentiert als bekannte Einschränkung.

## Akzeptanzkriterien

- [ ] `podman.login(...)` und `podman.logout(...)` sind aus `paratix/modules` importierbar und ein Aufruf in `server({ run: [...] })` lässt sich typchecken.
- [ ] Aufruf mit gültigen Parametern und nicht-existierender `auth.json` führt `podman login --authfile … --username … --password-stdin <registry>` aus und schreibt einen `auths[<registry>].auth`-Eintrag.
- [ ] Wiederholter Aufruf mit unverändertem PAT führt zu `status: "ok"` ohne erneuten `podman login`-Aufruf.
- [ ] PAT-Rotation (geänderter Datei-Inhalt) löst genau einen `podman login`-Aufruf im nächsten Run aus.
- [ ] Bestehende Einträge anderer Registries in derselben `auth.json` bleiben nach Login wie Logout unverändert.
- [ ] `podman.logout(...)` entfernt genau einen Registry-Eintrag, lässt andere bestehen und ist idempotent.
- [ ] Schreibversuche durch Symlinks scheitern mit `failed(...)`-Ergebnis, ohne `auth.json` zu mutieren.
- [ ] Tests bestätigen: PAT erscheint in keinem von Paratix protokollierten Stdout-/Stderr-/Diff-Buffer.
- [ ] `podman login` und `podman logout` werden grundsätzlich mit `silent: true` und `secrets: [pat]` ausgeführt; fehlgeschlagene Aufrufe liefern `failedCommand(...)` ohne PAT in den Output-Feldern.
- [ ] Permission-Check der PAT-Datei rejectet Mode > 0400 oder falschen Owner mit `failed(...)`.
- [ ] `passwordFileLocation: "target"` liest die PAT-Datei nicht auf den Controller; ein Mock-SSH-Test zeigt, dass das Kommando die PAT-Datei nur via `cat <passwordFile>` auf dem Target verwendet.

## Validierungsplan

- Unit-Tests mit `createMockSsh` in `test/modules/podman.test.ts`:
  - Validierung wirft zur Konstruktionszeit bei leerem/ungültigem Registry, Username mit `:`, Pfaden mit `..`, relativem `authFile`/`passwordFile`.
  - Check liefert `needs-apply`, wenn `auth.json` fehlt.
  - Check liefert `ok`, wenn der erwartete `auth`-Hash übereinstimmt.
  - Check liefert `needs-apply`, wenn der `auth`-Hash abweicht.
  - Apply führt das erwartete `podman login`-Kommando aus (Mock validiert Kommandozeile inklusive `--authfile`, `--username`, `--password-stdin`).
  - Apply-Fehlerpfad: bei nicht-null exit code Rollback auf den Snapshot.
  - Logout entfernt Eintrag und führt `podman logout` aus; idempotente Wiederholung führt zu `ok` ohne Kommando.
  - Symlink-Guard rejectet das Schreiben.
  - PAT-Permission-Check rejectet Mode `0644` und falschen Owner.
  - Verifikation, dass weder Calls noch Mock-Stderr/Stdout das Token im Klartext enthalten (z. B. via `expect(ssh.calls.join("\n")).not.toContain(pat)`).
  - Spezifischer Test: `passwordFileLocation: "target"` ruft niemals lokale Datei-APIs auf und überträgt die PAT-Datei nicht zum Controller.
- `pnpm agent:check` über das gesamte Paket.
- Smoke-Test in einem Integrationsplaybook (optional, nicht Teil der Akzeptanzkriterien): erstellt PAT-Datei, ruft `podman.login("ghcr.io", …)`, anschließend `podman pull` über `quadlet.updateImage` mit `authFile`.

## Annahmen und offene Punkte

- **Annahme:** `podman` ist auf dem Ziel-Host bereits installiert; das Modul installiert es nicht. Operator nutzt `pkg.installed("podman")` separat.
- **Annahme:** Der SSH-Session-User hat Schreibrechte am Parent-Verzeichnis der `auth.json`. Bei `/root/.config/containers/` setzt das einen Root-Login (oder `ssh.sudoPassword`) voraus.
- **Annahme:** `auth.json`-Format folgt der seit Jahren stabilen Form `{ "auths": { "<registry>": { "auth": "<base64>" } } }`. Andere Felder (`identitytoken`, `credHelpers`, …) werden weder gelesen noch geschrieben; sie überleben Login/Logout, weil `podman` selbst die Datei mergt.
- **Annahme:** Für `passwordFileLocation === "target"` verlässt das PAT den Target-Host nie. Wenn ein Operator das anders modellieren möchte (z. B. PAT-Material zentral auf dem Controller verwahren), wählt er `"controller"`.
- **Offen, bewusst dokumentiert:** Concurrent Writes auf `auth.json` durch andere Prozesse zwischen Snapshot und Login. Akzeptiert als bekannte Einschränkung — `podman login` mergt; ein konkurrierender Schreiber kann seine Änderungen verlieren. Der Hinweis steht im LLM-Guide.
- **Nicht-Anforderungen** (übernommen aus der ursprünglichen Spezifikation):
  - Keine PAT-Erzeugung oder -Rotation durch Paratix.
  - Keine Multi-User-Login-Orchestrierung (pro Aufruf genau ein Registry-Eintrag).
  - Kein Retry-Loop für transiente Netzwerkfehler.
  - Kein User-Switch via `sudo -u`.

## Plan-Review

**Ergebnis:** Freigegeben

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       1 |
| Security    |        0 |       1 |       1 |
| Datenschutz |        0 |       0 |       1 |
| Fehlerfälle |        0 |       1 |       0 |
| Testbarkeit |        0 |       0 |       1 |
| Scope       |        0 |       0 |       1 |
| Wartbarkeit |        0 |       0 |       1 |

### Befunde

- **Architektur (Hinweis):** Eigenes `podman`-Modul statt Erweiterung von `quadlet` ist konsistent mit der bestehenden Trennung zwischen Compose (Lifecycle), Quadlet (Unit-Dateien) und reinen Podman-Operationen. Keine Anpassung nötig.
- **Security (Wichtig):** Das ursprüngliche Konzept ließ offen, wie der `base64(<user>:<password>)`-Vergleich für `passwordFileLocation: "target"` ausgeführt wird, ohne das PAT in Stdout/Stderr oder argv auftauchen zu lassen. Eingearbeitet im Abschnitt „Check-Pfad": Vergleich läuft vollständig remote über eine Shell-Pipeline, die `cat <passwordFile>` und Username via stdin/Heredoc verarbeitet; nichts landet in `result.stdout`.
- **Security (Hinweis):** `username` darf keinen Doppelpunkt enthalten, sonst lässt sich das Login-Tupel nicht eindeutig encodieren. In den Validierungsregeln festgehalten.
- **Datenschutz (Hinweis):** PAT bleibt für `target`-Lokation auf dem Target und für `controller`-Lokation auf dem Controller; ein Cross-Host-Transfer findet nicht statt. Im Plan explizit dokumentiert.
- **Fehlerfälle (Wichtig):** Concurrent-Drift auf `auth.json` zwischen Snapshot und `podman login` ist eine reale, aber begrenzte Schwachstelle. Als bekannte Einschränkung im Abschnitt „Annahmen und offene Punkte" dokumentiert; kein zusätzliches Locking in V1, weil Paratix-Runs grundsätzlich sequenziell sind.
- **Testbarkeit (Hinweis):** Akzeptanzkriterien sind durchgehend mit `createMockSsh`-Mustern abprüfbar; der Validierungsplan listet die konkreten Tests inklusive Secret-Leak-Negativ-Test.
- **Scope (Hinweis):** Nicht-Anforderungen aus der ursprünglichen Spec sind unverändert übernommen. V1 hält den Surface bewusst klein.
- **Wartbarkeit (Hinweis):** Auslagerung der Helper in `podmanHelpers.ts` folgt dem etablierten Pattern aus `quadletHelpers.ts`/`quadletFileHelpers.ts` und hält `podman.ts` lesbar.
