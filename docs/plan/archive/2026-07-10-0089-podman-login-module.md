# 0089: podman.login() und podman.logout() für Registry-Auth

**Planungsstatus:** Umgesetzt
**Quelle:** /plan
**Empfohlener Workflow:** Feature (`/build`)

## Anforderung

Paratix soll einen direkten Podman-Registry-Eintrag idempotent anlegen, nach Änderung der Zugangsdaten aktualisieren und gezielt entfernen können. Dafür entstehen `podman.login(options)` und `podman.logout(registry, options?)`. Paratix besitzt den gesamten adressierten Registry-Eintrag: Login ersetzt ihn vollständig, Logout entfernt ihn vollständig. Andere Registry-Einträge und JSON-Felder außerhalb dieses Eintrags bleiben semantisch erhalten. Das Modul liefert neue Funktionalität; die bestehende Feature-Empfehlung entspricht `effective-flow build`.

Status, Quelle und Legacy-Titel bleiben erhalten; die Login-API wird um provider-neutrale Secret-Bindings ergänzt. Diese Revision vom 21.10.2026 ersetzt die technischen Aussagen des bisherigen Haupttexts; das frühere Review bleibt als Verlauf sichtbar.

### Laufzeitentscheidung im vertieften Review

Entscheidung vom 21.10.2026: Der Nutzer hat den Container-Helper gewählt. Der Host benötigt Linux-Podman und die bereits verwendeten Shell-/Coreutils-Werkzeuge; Python läuft ausschließlich im per Digest fixierten Helper-Image. Der Helper übernimmt Datei- und JSON-Verarbeitung, Registry-Login und Logout bleiben Host-Podman-Aufrufe. Gemeinsame Auth-Dateien bleiben unterstützt. Ein allgemeines Toolstack-Framework oder ein eigener Image-Publishing-Dienst ist nicht Teil dieser Änderung.

Zweite Entscheidung vom 21.10.2026: Paratix verwaltet das vollständige adressierte Registry-Objekt. Zusätzliche Felder innerhalb dieses Objekts dürfen bei Login verloren gehen und werden bei Logout zusammen mit dem Eintrag entfernt. Die Garantie zum Erhalt fremder Daten gilt außerhalb dieses Objekts.

### Ergänzung um bestehende Secret-Provider

Nutzeranforderung vom 21.10.2026: Benutzername und Token direkt aus `secret.provider("1password")` übernehmen und ebenso den bestehenden `secret.provider("manual")` für verdeckte CLI-Eingabe verwenden. Dafür ist keine vorherige Passwortdatei auf dem Controller nötig. Beide Provider bleiben auf dem Controller; der Container-Helper und Host-Podman bleiben unverändert die Ziel-Laufzeit. Die ursprüngliche Passwortdatei-Variante bleibt zusätzlich erhalten.

### Untersuchte Laufzeitalternativen (Entscheidungsverlauf)

| Variante                                                          | Nutzen                                                                                             | Aufwand und Vertragsgrenze                                                                                                                                                                                   |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Python 3 auf dem Host                                             | Vollständige Datei-/JSON-Verarbeitung in einem Prozess mit Host-Podman                             | Zusätzliche Laufzeit auf dem Ziel; bisheriger Lösungskandidat                                                                                                                                                |
| Kurzlebiger Podman-Dateihelper, Login auf dem Host                | Keine zusätzliche Host-Laufzeit; Host-Podman verwendet seine vorhandene Registry-/CA-Konfiguration | Gepinntes Image, Bootstrap und Updates; mehrstufiges lokales Austauschprotokoll; UID-/SELinux-Regeln für Bind-Mounts                                                                                         |
| Vollständiger Auth-Toolstack im Container                         | Laufzeit und Auth-CLI gemeinsam versioniert                                                        | Netzwerk und bewusst bereitgestellte Zertifikate/Registry-Konfiguration nötig; Engine-Initialisierung des gewählten CLI-Images ist noch nicht versionsgenau bewiesen                                         |
| Shell/Coreutils mit jq auf dem Host                               | Kleines Werkzeug für JSON                                                                          | Bleibt zusätzliche Host-Abhängigkeit; löst sichere Dateioperationen nicht allein                                                                                                                             |
| Host-Podman mit lokalem Fingerprint und eigener Datei je Registry | Keine zusätzliche JSON-Laufzeit; Rotation und Dateidrift über vertraulichen Zustand erkennen       | Bewusst engerer Vertrag: keine Übernahme beliebiger vorhandener gemeinsamer Auth-Dateien, fremde Änderungen an eigener Datei dürfen beim Wiederaufbau verloren gehen; sichere Dateioperationen bleiben nötig |
| Statisches natives Helper-Programm                                | Keine zusätzliche Interpreter-Laufzeit und kein Containerstart                                     | Neue Architekturartefakte, sichere Verteilung, Versionierung und Release-Pflege; derzeit für zwei Methoden erheblicher Zusatzumfang                                                                          |

Ein Container-Dateihelper benötigt weder Podman-Socket noch privilegierten Zugriff oder eine verschachtelte Engine. Er verarbeitet ausschließlich ausdrücklich eingebundene Auth-/PAT- und Arbeitsverzeichnisse. Der Container-Rootfs kann schreibgeschützt sein; Schreibzugriff besteht nur auf benötigte Arbeits-/Zielpfade. Ein `auth.json`-Datei-Bind-Mount allein reicht für einen atomaren Austausch nicht: dafür ist eine kontrollierte Verzeichniseinbindung oder eine getrennte Host-Übernahme nötig. Root-/UID-Abbildung, Symlink-/Vorfahrenprüfung und SELinux müssen dabei ausdrücklich geplant und getestet werden; keine pauschalen rekursiven Ownership-/Label-Änderungen. Siehe [Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html).

Das Helper-Image muss ohne den gerade einzurichtenden Registry-Login verfügbar sein: öffentlich und per Digest fixiert oder vorab geladen. Check zieht kein Image automatisch und verändert keine Auth-Daten; temporäre Container-Metadaten sind vom Auth-Zustand zu unterscheiden. Ein fehlendes Image ist eine sichtbare Voraussetzung. Ein netzloser Dateihelper und Host-Podman kommunizieren nur über private Prozesse/Pipes oder Arbeitsdateien auf dem Ziel; Secrets dürfen dabei nie stdout/stderr des SSH-Kanals erreichen. Ein allgemeiner Toolstack für weitere Module wäre eine separate Erweiterung dieses schmalen Auth-Helpers.

Die Fingerprint-Variante benötigt einen privaten Zustandspfad mit Modus `0600`, nicht Tokenhashes im Modulnamen oder in sichtbaren Flag-Dateinamen. Gespeichert werden ein versionierter Fingerprint des normalisierten Credentials-Tupels und ein Hash der veröffentlichten eigenen Auth-Datei. Fehlender Zustand oder Drift löst erneuten Login aus. Das ist eine andere Idempotenzbasis als das Auslesen einzelner JSON-Einträge. `podman login --get-login` allein erkennt keine Token-Rotation, weil es nur den Benutzernamen liefert. Siehe [Podman login](https://docs.podman.io/en/latest/markdown/podman-login.1.html).

### Verifizierter Ausgangszustand

- Geplant gegen HEAD `6afd16a`, 21.10.2026; das Arbeitsverzeichnis war vor dieser Revision sauber. Es gibt noch kein öffentliches `podman`-Modul.
- `packages/paratix/src/types.ts` definiert `Module.check` mit `ok`/`NEEDS_APPLY` sowie `Module.apply` mit `ModuleResult`. `packages/paratix/llm-guide.md`, „Custom Modules“, verlangt `check(null) → NEEDS_APPLY` und `apply(null) → failed(...)`.
- `ssh.exec` unterstützt `input`, `secrets`, `silent` und `ignoreExitCode`. `silent` verhindert Konsolenausgabe, aber keine Erfassung in `ExecResult` oder Fehlerobjekten. `ssh.readFile` überträgt Dateiinhalte auf den Controller.
- `packages/paratix/src/ssh.ts` führt Kommandos für Nicht-Root-Verbindungen über sudo als root aus. `sudoCommand` unterstützt stdin bei passwortlosem sudo oder vorbereiteter sudo-Authentifizierung und scheitert andernfalls geschlossen. Der SSH-Login-User ist nicht die effektive Ausführungsidentität.
- `remoteFileChecks.ts` bietet Leaf- und Vorfahrenprüfungen, warnt aber ausdrücklich vor TOCTOU. Ein Vorabtest allein schützt nachfolgende Schreibzugriffe nicht.
- `quadletFileHelpers.ts` speichert Snapshots einschließlich Inhalt auf dem Controller. Dieses Verfahren eignet sich nicht für eine Auth-Datei mit weiteren unbekannten Secrets.
- Öffentliche Exporte werden in `test/publicApi.test.ts` und `test/postbuild/cli.dist.test.ts` explizit geprüft. Die bisherige Integration nutzt einen unprivilegierten SSH-Docker-Container; dessen Dockerfile installiert Python 3, aber kein Podman. Er beweist keinen realen Helper-Containerstart. Die Testjobs in `.github/workflows/integration-check.yml` und `.github/workflows/publish.yml` laufen auf nativen Ubuntu-Runnern.

- `packages/paratix/src/modules/secret.ts` bietet `SecretResolver.resolve(bindings)` für `"1password"` und `"manual"`; beide erzeugen Environment-Meta für nachfolgende Module. `environment.ts` löst diese über `await resolveEnvironment(env, key)` auf; `process.env` ist dafür nicht der Consumer-Vertrag.
- `secretPrewarm.ts` und `secretResolution.ts` lösen gewöhnliche Secret-Bindings sequenziell vor SSH auf, auch bei `--dry-run`, und cachen pro Run. Environment-Meta wird erst an der Modulposition verfügbar. Ein neues Playbook-Run liest die Quelle erneut; Check/Apply desselben Runs verwenden die etablierte Memoisierung.
- `manualSecretProvider.ts` benötigt TTYs auf stdin und stderr, fragt ohne Echo/Sternchen und ohne Trimmen ab und behandelt Ctrl+C/EOF/Runner-Abbruch. Identische gewöhnliche Bindings derselben Fassade fragen einmal pro Run; parallele Prompts werden abgewiesen. `llm-guide.md`, Abschnitt `secret`, dokumentiert Filter-/Dry-run-Verhalten und Maskierungsgrenzen für kurze Werte.

### Externe Vertragsgrundlage

Die [Podman-Login-Dokumentation](https://docs.podman.io/en/v5.6.0/markdown/podman-login.1.html) bestätigt `--authfile` und `--password-stdin`. Der Linux-Default von Podman liegt im Laufzeitverzeichnis; der Modul-Default ist bewusst ein expliziter persistenter Pfad. [Podman logout](https://docs.podman.io/en/v5.6.0/markdown/podman-logout.1.html) unterstützt ebenfalls `--authfile`.

Die geprüften Funktionen `parse`, `prepareForEdit`, `modifyJSON` und `normalizeRegistry` in [containers/image](https://github.com/containers/image/blob/v5.36.1/pkg/docker/config/config.go) unterscheiden Lese-Aliase, Schreibschlüssel und Credential-Helper. Leeres oder defektes JSON ist kein automatischer Reparaturfall. Unbekannte Felder werden beim normalen Podman-Schreiben nicht zuverlässig bewahrt. Daher kontrolliert Paratix die Übernahme ausschließlich des gewünschten Eintrags.

Recherche: 21.10.2026. Konkrete Vertragsreferenz ist Podman 5.6.0 mit containers/image 5.36.1 und containers/common 0.64.1 gemäß dessen [go.mod](https://github.com/containers/podman/blob/v5.6.0/go.mod). Das ist eine Referenz für die CLI-Semantik, keine Empfehlung einer alten Produktionsversion. Vor Implementierung wird eine unterstützte, exakt fixierte Testversion mit diesen Fähigkeiten ausgewählt, deren Quellen erneut abgeglichen und deren Verhalten im Integrationsfixture bewiesen. Abweichungen verhindern die Freigabe; keine beliebige Podman-Version wird ungeprüft zugesagt.

## Architekturentscheidungen

- Neues öffentliches `podman`-Modul neben `quadlet` und `compose`; `logout` benötigt weder Username noch PAT. Quadlet-/Compose-Verhalten bleibt unverändert.
- Provider-neutrale Credential-Quellen: `usernameEnv`/`passwordEnv` benennen Environment-Bindings, die ein vorgelagertes `SecretResolver.resolve(...)` bereitstellt. Vorhandene `"1password"`- und `"manual"`-Provider nutzen exakt denselben Podman-Pfad. Keine 1Password-Sonderlogik, neue Provider-Implementierung oder CLI-Abfrage im Podman-Modul.
- Pro Feld genau eine Quelle: Benutzername aus `username` oder `usernameEnv`, Token aus `passwordFile` oder `passwordEnv`. Beide Entscheidungen sind unabhängig kombinierbar, insbesondere fester Username plus manuelle Passwortabfrage. Bei der Dateivariante gilt weiter `passwordFileLocation: "controller" | "target"`, Default `"controller"`; im Environment-Pfad ist diese Option unzulässig. Credentials vom Controller werden ausschließlich über SSH-stdin übertragen, Ziel-PAT und vorhandene Auth-Datei-Inhalte bleiben auf dem Ziel.
- Secret-Module stehen in `run` vor `podman.login` und werden mit bestehenden Run-Cache-, Filter- und Dry-run-Regeln verwendet. Die Podman-Konstruktion liest weder Provider noch Environment. Fehler gewöhnlicher Provider-Bindings im bestehenden Prewarm brechen vor SSH ab; fehlende/ungültige Consumer-Bindings und spätere Resolverfehler scheitern vor Auth-Mutation. Kein Fallback auf leere Werte, `process.env`, Dateien oder einen anderen Provider.

- Bestehende effektive Root-Ausführung von SSH-Kommandos bleibt erhalten. `authFile` hat den Default `/root/.config/containers/auth.json`; ein anderer Pfad ändert keinen Benutzer. Rootless-Ausführung und `sudo -u` gehören nicht zu V1.
- **Gewählte Laufzeit:** kurzlebiger Podman-Dateihelper mit Python-Standardbibliothek im Image. Auf dem Ziel-Host sind nur Linux-Podman und die bereits verwendeten Shell-/Coreutils-Werkzeuge nötig. Registry-Login/-Logout laufen mit Host-Podman; keine Engine und kein Podman-Client im Helper.
- Das Paket enthält das Helper-Programm als TypeScript-String sowie eine per Digest fixierte Referenz auf ein öffentliches Upstream-Python-Image. Kein eigener Image-Build-/Publishing-Dienst. Default-Image, unterstützte Architekturen und getestete Podman-Version werden vor Umsetzung konkret geprüft, fixiert und dokumentiert. Ein optionales `helperImage` erlaubt eine gleichwertige Spiegelung; jede Referenz muss vollständig qualifiziert und per SHA-256-Digest fixiert sein. Kein veränderlicher Tag.
- Das Image muss vor dem Modulaufruf im rootful Image-Store derselben Ziel-Podman-Instanz vorhanden sein. Alle Helper-Starts verwenden `--pull=never`; das Modul installiert oder aktualisiert nichts im Check. Dokumentierter separater Provisionierungsschritt lädt das öffentliche oder gespiegelte Image vor dem ersten privaten Registry-Login.
- Helper-Starts sind kurzlebig, ohne Netzwerk, Podman-Socket oder Privilegierung. Ausgangskonfiguration: UID/GID `0:0`, `--userns=host`, `--read-only`, `--read-only-tmpfs=false`, `--cap-drop=all`, `no-new-privileges`, keine Container-Logspeicherung. Nur ausdrücklich benannte Auth-/PAT-/Arbeitsverzeichnisse werden eingebunden. Rohe stdout/stderr werden vor dem SSH-Kanal auf dem Ziel verworfen. Der Helper läuft nicht dauerhaft.
- Die Mounts sind verzeichnisweise: Check erhält Auth- und bei Ziel-PAT dessen Elternverzeichnis read-only; Prepare/Commit erhalten den benötigten Auth-Elternbereich read-write. Ein Auth-Datei-Mount allein würde atomaren Ersatz verhindern. Betreiber wählen dafür dedizierte Verzeichnisse; allgemeine System-/Homeverzeichnisse oder `/` dürfen nicht als breiter Mount dienen. Diese Grenze wird in Validierung und Doku konkretisiert; außerhalb eines dedizierten Auth-Verzeichnisses liegende Pfade werden ohne Mutation abgelehnt. Ein sicheres dediziertes Verzeichnis mit `0755` bleibt zulässig.
- Auf SELinux-Systemen verwendet ausschließlich der Helper `--security-opt label=disable`. Dadurch entfällt für ihn die SELinux-Trennung; der begrenzte Mount-Umfang und das vertrauenswürdige gepinnte Image sind daher Teil des Sicherheitsvertrags. Keine rekursiven `:z/:Z`-/`:U`-Änderungen und keine Änderungen an Hostpolicy. Der Kontext einer ersetzten Auth-Datei muss für Host-Podman erhalten bzw. nachweislich nutzbar bleiben; bei nicht erfüllbarer Label-/Zugriffsbedingung vor Veröffentlichung abbrechen. [Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- Check vergleicht Credentials lokal im Helper und beendet sich mit festen phasenspezifischen Exitcodes. Alle Helper-Starts verwerfen stdout/stderr bereits auf dem Ziel; ein vertrauenswürdiger Host-Wrapper übersetzt ausschließlich erlaubte Exitcodes in feste Statuswerte für SSH, niemals rohe Helper-Ausgabe. Kein PAT, Base64, Auth-JSON, Digest oder roher CLI-Output gelangt in SSH-stdout/stderr. Ein passender lokaler Eintrag beweist keine aktuelle Registry-Gültigkeit; serverseitiger Token-Widerruf allein löst keinen neuen Login aus.
- Prepare, Host-Podman und Commit teilen nur eine root-private Transaktion auf dem Ziel. Host-Podman arbeitet mit einer frisch erzeugten Compat-Datei ohne `credHelpers`. Der referenzgeprüfte `--compat-auth-file`-Edit-Pfad verhindert externe Store-/Erase-Aufrufe; globale Helper-Get-Aufrufe vor Login sind möglich. Der Helper übernimmt anschließend ausschließlich das vollständige adressierte Registry-Objekt ins ursprüngliche normale Podman-Auth-JSON.
- Docker Hubs interner Compat-Schlüssel `https://index.docker.io/v1/` wird vor Übernahme auf den öffentlichen direkten Schlüssel `docker.io` abgebildet. TLS-Prüfung ist explizit aktiviert; Transport-/Mirror-Konfiguration bleibt Host-Podmans Zuständigkeit.

## Betroffene Dateien

| Datei                                                          | Geplante Änderung                                                                                    |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `packages/paratix/src/modules/podman.ts`                       | Öffentliche Login-/Logout-Module und Optionen                                                        |
| `packages/paratix/src/modules/podmanHelpers.ts`                | Validierung, provider-neutrale Binding-Auflösung, optionales PAT-Dateilesen und Fehlerabbildung      |
| `packages/paratix/src/modules/podmanContainer.ts`              | Image-Referenz, sichere Host-Vorprüfungen, Mounts und mehrphasige Helper-/Host-Podman-Orchestrierung |
| `packages/paratix/src/modules/podmanHelperScript.ts`           | Im Paket eingebettetes Python-Programm für Check, Prepare und Commit im Container                    |
| `packages/paratix/src/modules/index.ts`                        | Export von `podman`                                                                                  |
| `packages/paratix/src/index.ts`                                | Root-Reexport                                                                                        |
| `packages/paratix/test/modules/podman.test.ts`                 | Modulvertrag und Transport                                                                           |
| `packages/paratix/test/modules/podmanHelpers.test.ts`          | Lokale Dateiprüfung und strikte Protokollauswertung                                                  |
| `packages/paratix/test/modules/podmanSecrets.test.ts`          | Gemeinsamer Consumer-Vertrag für 1Password, Manual, gemischte Quellen und Run-Cache                  |
| `packages/paratix/test/runner-podman-secrets.test.ts`          | Provider-Reihenfolge, Prewarm, Filter/Dry-run, TTY und Abbruch im echten Runner                      |
| `packages/paratix/test/modules/podmanContainer.test.ts`        | Startoptionen, Mounts, Phasenfehler und Cleanup-Verantwortung                                        |
| `packages/paratix/test/publicApi.test.ts`                      | Öffentliche Exportliste                                                                              |
| `packages/paratix/test/postbuild/cli.dist.test.ts`             | Paket-/Consumer-Tests einschließlich eingebettetem Helper                                            |
| `packages/paratix/test/integration/podman.integration.test.ts` | Reale SSH-/Host-Podman-/Helper-Container-Fälle                                                       |
| `packages/paratix/test/integration/podmanHarness.ts`           | Eigenes natives Linux-SSH-/Podman-Fixture; optional expliziter lokaler SSH-Testhost                  |
| `.github/workflows/integration-check.yml`                      | Voraussetzungen und echtes Podman-Helper-Preflight im bestehenden Testjob                            |
| `.github/workflows/publish.yml`                                | Dieselbe Testvoraussetzung ausschließlich im vorhandenen `validate`-Job                              |
| `packages/paratix/llm-guide.md`                                | API einschließlich 1Password-/Manual-Beispielen, Image-Vorladung, Mounts und Fehler                  |
| `packages/paratix/README.md`                                   | Login vor Quadlet-Pull mit gleichem explizitem `authFile`                                            |
| `cspell.json`                                                  | Nur tatsächlich nötige neue Fachbegriffe, kein `cspell:ignore`                                       |

Keine Änderung an SSH-/readFile-Semantik, vorhandenen Secret-Providern oder deren Cache-/Prompt-/Runner-Verträgen, Paketabhängigkeiten oder Release-/Deployment-Berechtigungen. Der bestehende Docker-SSH-Harness wird nicht privilegiert und erhält keinen Host-Socket. Es gibt keine separat zu paketierende `.py`-Datei und kein allgemeines Toolbox-Framework.

## Implementierungsdetails

### Öffentlicher Vertrag

- `podman.login(options)` erhält `registry`, genau eine Username-Quelle (`username` oder `usernameEnv`) und genau eine Token-Quelle (`passwordFile` oder `passwordEnv`); optional `authFile`, `helperImage` und ausschließlich bei `passwordFile` auch `passwordFileLocation`. TypeScript-Unionen und Runtime-Validierung schließen jeweils beide/fehlende Quellen sowie `passwordFileLocation` bei `passwordEnv` aus. Keine zweite positionsbasierte Login-Signatur und keine neue Klartext-`password`-Option.
- `usernameEnv`/`passwordEnv` sind Environment-Schlüsselnamen, keine `op://`-Referenzen oder aufgelösten Werte. Die Namensregeln einschließlich zulässiger Punktsegmente und verbotener reservierter Namen entsprechen der bestehenden Secret-Fassade. Beide Werte sequenziell über `resolveEnvironment` lesen, Strings verlangen und nicht mit `String(...)` aus Zahlen/Booleans umwandeln. Die statische `username`-Variante wird bei Konstruktion, gebundene Werte erst zur Laufzeit validiert.
- `podman.logout(registry, options?)` erhält optional `authFile` und `helperImage`; Defaults entsprechen Login. Logout benötigt keinen PAT.
- Registry: DNS-Hostname, IPv4 oder `localhost`, optional Port 1–65535; Hostnamen kleinschreiben. Keine Schemata, Pfade, Userinfo, Queries, Whitespace, Steuerzeichen, IPv6 oder führenden Optionszeichen. Docker-Hub-Hostaliase auf `docker.io` vereinheitlichen; abweichende bestehende Alias-/URL-Einträge derselben Registry als nicht unterstützte Altform ablehnen, keine stille Migration.
- Username: nicht leer, ohne Doppelpunkt, Whitespace oder Steuerzeichen. Alle Shell-Argumente unabhängig davon mit `shellQuote` behandeln.
- Pfade: absolut, ohne `.`-/`..`-Segmente oder Steuerzeichen; konservative Pfadregeln aus `quadletValidationHelpers.ts` als Referenz. Auth-Datei und Ziel-PAT liegen in dedizierten Verzeichnissen für die Mount-Grenze. Vorhandene Host-Vorfahren müssen root-eigen, ohne Symlinks und nicht durch Gruppen/Other beschreibbar sein. Bei Ziel-PAT dürfen PAT und Auth-Datei auch per Dateiidentität nicht identisch sein.
- Token: nicht leer, einzeilig, UTF-8, ohne NUL/weitere Steuerzeichen oder Rand-Whitespace, maximal 65.535 Bytes (64 KiB − 1). Environment-Werte unverändert übernehmen und bei Verletzung ablehnen; kein verlustbehaftetes Trimmen und kein Entfernen eines echten Zeilenumbruchs aus dem Providerwert. Nur im Datei-Pfad genau ein optionales abschließendes LF/CRLF entfernen. Vergleich und Login verwenden dieselben resultierenden Bytes.
- Nur bei `passwordFile` gelten die Dateiprüfungen: regulärer Leaf ohne Symlink, exakt `0400`, Owner numerisch effektive Controller-UID bzw. Root-UID des Ziels. Keine numerische Regel „Mode > 0400“. `passwordEnv` benötigt und erzeugt keine persistente oder temporäre Credential-Datei auf dem Controller.
- Ungültige Optionen werfen bei Konstruktion. Runtime-Fehler im Check werfen feste secret-freie Meldungen; Apply liefert `failed(...)`. Ein ausschließlich fehlendes Image ist eine Voraussetzung, kein Anlass für einen versteckten Pull. `changed` bedeutet veröffentlichte Datei-/Rechteänderung, `ok` keine Änderung. Kein Diff und keine Secret-Metadaten.
- Der gesamte adressierte Registry-Eintrag gehört dem Modul: Login ersetzt ihn durch den geprüften neuen Eintrag; Logout entfernt ihn samt unbekannten Feldern. Fremde Registry-Einträge und Top-Level-Felder bleiben als JSON-Werte erhalten. Formatierung und Schlüsselreihenfolge sind keine Erhaltungsgarantie.

### Technische Grenzkorrekturen im Build vom 21.10.2026

Der native Gegencheck mit der unterstützten Podman-Version 4.9.3 hat eine engere stdin-Grenze als die ursprünglich formulierte 64-KiB-Sicherheitsgrenze belegt: 65.535 synthetische Token-Bytes erreichen den Registry-Pfad, 65.536 Bytes scheitern bereits beim Lesen der Zugangsdaten. Die vom autorisierten Workflow-Owner bestätigte Kompatibilitätskorrektur begrenzt deshalb alle Token-Quellen vor einer Auth-Mutation auf 65.535 Bytes. Die separate Username-Grenze von 65.536 Bytes bleibt unverändert. Ein echter erfolgreicher Login an der Token-Grenze und die frühe Ablehnung des nächsten Bytes gehören zum Freigabenachweis; das HTTPS-Testfixture benötigt dafür eine ausreichend große Header-Grenze.

Auth-Dateien und veröffentlichte Kandidaten sind jeweils auf 8 MiB begrenzt. Der private Transaktionszustand erhält eine eigene, aus Base64-Daten und begrenzten Metadaten abgeleitete größere Grenze; die Compat-Datei besitzt ebenfalls eine separate Grenze. Die Kandidatengröße wird vor dem atomaren Austausch geprüft. Die bestehende ASCII-JSON-Serialisierung darf Unicode vergrößern; überschreitet das Ergebnis 8 MiB, scheitert die Operation vor Veröffentlichung und erhält das Original bytegenau. Eine vom Modul veröffentlichte Datei muss vom folgenden Check wieder lesbar sein. Native Regressionen müssen große Originale, fremde Daten, den Folgecheck und den sicheren Abbruch bei Expansion nachweisen.

### Einbindung der Provider

- **1Password:** `secret.provider("1password").resolve(...)` steht vor dem Login und bindet beispielsweise `REGISTRY_USERNAME` an `op://prod/registry/username` und `REGISTRY_TOKEN` an `op://prod/registry/token`. `podman.login` erhält dazu nur `usernameEnv: "REGISTRY_USERNAME"` und `passwordEnv: "REGISTRY_TOKEN"`. Authentifizierte `op`-CLI ausschließlich auf dem Controller; kein 1Password-Zugang auf Ziel oder im Helper.
- **Manuelle CLI-Eingabe:** Derselbe Login-Consumer verwendet `secret.provider("manual", { labels: ... }).resolve(...)` mit denselben Binding-Namen. Die Labels beschreiben Benutzername und Registry-Token; Eingabe erfolgt über den bestehenden verdeckten Prompt. Die Referenzen sind hier wie schon bisher opaque Identitäten; für rein manuelle Bindings sind auch leere Referenzen zulässig. Bei bekanntem Username genügt dessen statische Angabe und ein einziges `passwordEnv`-Binding für das abgefragte Passwort.
- Gewöhnliche Bindings werden gemäß bestehendem Prewarm vor SSH abgefragt bzw. aus 1Password gelesen, auch bei `--dry-run` und wenn der Login später bereits `ok` ergibt. Für identische gewöhnliche Bindings derselben Fassade gibt es in einem Run keine erneute interaktive Passwortabfrage je Check/Apply. Rotation eines Provider-Tokens wird beim nächsten Run erkannt; das frische erneute Datei-Lesen zwischen Check/Apply bleibt ausschließlich eine Eigenschaft der Dateivariante.
- `--filter` kann ein vorgelagertes Secret-Modul entfernen. Ist danach kein anderer Wert für ein benötigtes Binding vorhanden, scheitert der Consumer sicher, statt Provider- oder Datei-Fallbacks auszulösen. Bei `check(null)` löst das Podman-Modul keine Bindings auf; globale Provider-Prewarm-Eingaben im selben Dry-run bleiben davon unberührt. Keine neue TOTP-Sonderbehandlung.

### Ablauf

1. **Modulgrenzen und Vorprüfung:** `check(null)` liest nichts und liefert `NEEDS_APPLY`; `apply(null)` liefert `failed(...)`. Keine lokalen Secrets bei Konstruktion oder im Modulnamen lesen. Image-Referenz und öffentliche Optionen validieren. Vor jedem Helper-Start sämtliche vorhandenen Host-Vorfahren der Mount-Quellen prüfen; Bind-Mounts verstecken diese Herkunft im Container. Nur vertrauenswürdige root-eigene, nicht fremdbeschreibbare Verzeichnisketten akzeptieren. Fehlende dedizierte Auth-Verzeichnisse erst in Apply unter dieser Vertrauensgrenze mit `0700` anlegen. Vorhandene Verzeichnisse weder umchmodieren noch relabeln.
2. **Credentials auflösen und transportieren:** Bei vorhandenem SSH in Check/Apply die gewählten Quellen frisch aus dem jeweils übergebenen Environment auflösen bzw. den Controller-PAT aus der Datei lesen. Gewöhnliche Providerwerte behalten ihre bestehende Run-Memoisierung; keine Credential-Caches im Modulobjekt oder über Run-Grenzen hinweg. Username vor Token sequenziell auflösen und validieren. Im optionalen Controller-Dateipfad weiterhin `O_NOFOLLOW|O_NONBLOCK`, `fstat` desselben Deskriptors, Owner/Typ/Modus/Größenprüfung, begrenztes Lesen und sicheres Schließen verwenden. Environment-Credentials lösen keinerlei Passwortdatei-Lesen/-Schreiben auf dem Controller aus. Username und gegebenenfalls Controller-Token in einem begrenzten eindeutig gerahmten JSON-Payload ausschließlich mit `ExecOptions.input` an den Helper-stdin senden; bei Ziel-PAT enthält dieser Payload nur den Username, das Token wird weiter allein im Helper auf dem Ziel gelesen. Das eingebettete Python-Programm nutzt öffentliche Argumente statt denselben stdin-Kanal. `silent: true`, `ignoreExitCode: true` und explizite Masken für Username, Token und Base64-Credentials verwenden; JSON-/Parsingfehler dürfen den Payload nie ausgeben. Ziel-PAT weder lokal noch über `ssh.readFile`/Download lesen. Keine Behauptung garantierter JavaScript-String-Löschung.
3. **Check-Helper:** Auth-Elternverzeichnis und gegebenenfalls Ziel-PAT-Elternverzeichnis read-only an getrennte interne Pfade binden. Host- und Containerpfade explizit abbilden. Den Ziel-PAT-Leaf descriptor-relativ mit `O_NOFOLLOW|O_NONBLOCK` öffnen und per `fstat` prüfen; kein Datei-Bind-Mount, der den ursprünglichen Leaf-Symlink versteckt. Auth-Leaf ebenfalls descriptor-relativ öffnen: regulär, Root-Owner, keine mehrfachen Hardlinks. JSON streng parsen; doppelte Schlüssel, malformed/leere Datei, falsche Struktur und defekte Base64-Werte sind Fehler ohne Reparaturversuch. Relevante Identity-Token/Helper-Konfigurationen und Altaliase ablehnen. Fehlende Auth-Datei oder fehlendes `auths` bedeutet leerer Eintragssatz; vorhandenes `auths` muss ein Objekt sein.
4. **Check-Ergebnis:** Login ist nur bei passenden normalisierten Credentials und Dateimodus `0600` `ok`; konstantzeitlicher Vergleich im Helper, keine Hashausgabe. Fehlender/abweichender Eintrag oder abweichender Dateimodus ergibt `NEEDS_APPLY`; ungültige Dateien/Vertrauensgrenzen bleiben Fehler. Logout ist bei fehlender Datei oder fehlendem eigenen Eintrag `ok`, ohne PAT und ohne Host-Logout. Soweit dafür kein Helper benötigt wird, ist auch kein Image erforderlich. Fehlende Auth-Datei entbindet Login nicht von der PAT-Prüfung. Container-Metadaten während eines Checks sind zulässig; Auth-Daten werden nicht verändert und es bleibt kein Helper-Container zurück.
5. **Prepare:** Apply prüft Zustand und PAT erneut; kein Wiederverwenden eines früheren Check-Ergebnisses. Bei erreichtem Ziel ohne Mutation `ok`. Nur notwendige Dateirechtekorrektur kann `changed` ohne erneuten Login liefern. Für inhaltliche Änderung eine zufällig benannte root-private Transaktion im Auth-Verzeichnis auf demselben Dateisystem erzeugen: Verzeichnis `0700`, Dateien `0600`, restriktive Umask. Originalzustand einschließlich Identität/Metadaten und Inhaltsvergleich sowie normalisierter Username und PAT für den anschließenden Host-Aufruf bleiben ausschließlich hier. Credential-Arbeitsdateien auf dem Ziel werden mit `0600` erzeugt und gehören zum Cleanup; diese sind keine vorgeschaltete Passwortdatei auf dem Controller. Login-Compat-Datei beginnt mit leerem `auths`; Logout enthält nur den eigenen Eintrag in Compat-Schreibweise. Keine Helper-Zuordnungen oder fremden Credentials an Host-Podman weiterreichen.
6. **Host-Podman:** Login bearbeitet nur die private Compat-Datei mit `--username`, `--password-stdin`, `--tls-verify=true` und Registry. Username auf dem Ziel aus der privaten Transaktion in eine Shell-Variable lesen und als erforderlichen `--username`-Wert verwenden; keine Interpolation des aufgelösten Werts in einen auf dem Controller erzeugten SSH-Kommandostring. Token von der privaten lokalen PAT-Datei direkt auf Prozess-stdin leiten. Logout nutzt dieselbe Compat-Dateigrenze und nur die Registry. Beide Aufrufe verwenden `--compat-auth-file`, niemals `--all`. Stdout/Stderr bereits auf dem Ziel nach `/dev/null` leiten. Es werden nur feste Kategorien und gegebenenfalls numerischer Exitcode weitergegeben, keine rohen CLI-Ausgaben oder Exceptions. Keine Retries und kein Zugriff des Helpers auf Podman-Socket/Engine.
7. **Commit:** Helper prüft Transaktion und Ergebnisdatei streng. Login muss genau den erwarteten Credential-Eintrag liefern; Logout dessen Abwesenheit. Docker-Hub-Compat-Key zurückübersetzen. Das vollständige adressierte Registry-Objekt im Original ersetzen/entfernen; außerhalb davon alle JSON-Werte erhalten. Original unmittelbar vorher erneut auf Inhalt, Existenz, Identität und relevante Metadaten prüfen; bei beobachteter Fremdänderung abbrechen. Kandidat `0600`, Root-Owner und erforderlichen SELinux-Kontext sicherstellen, vollständig schreiben/fsync, dann descriptor-relativ atomar ersetzen und Elternverzeichnis fsync. Jeder Fehler vor Veröffentlichung lässt Originalinhalt und Existenz erhalten; Fehler danach als möglicherweise bereits angewandt melden. Kein zurückschreibender Snapshot-Rollback.
8. **Cleanup und Fehler:** Jede reguläre Rückkehr entfernt ausschließlich eigene Transaktionsdateien und Container. Container-Identitäten pro Versuch erfassen; nie fremde Container aufräumen. Rohe Helper-stdout/-stderr bei jedem `podman run` bereits auf dem Ziel nach `/dev/null` leiten. Phasen liefern feste Exitcodes, die der Host-Wrapper per geschlossener Fallunterscheidung auf konstante Statusausgabe abbildet. Unbekannte Codes, Startfehler und Signale liefern feste Fehler, niemals Helper-Output. Unerwartete, zusätzliche oder abgeschnittene Ausgabe des SSH-Statusprotokolls ohne Echo verwerfen; dies ersetzt nicht die zielseitige Ausgabegrenze. Fehler-/Cause-Ketten dürfen keine Secret-Ausgabe übernehmen. Timeout/SSH-Abbruch nach unbekanntem Fortschritt meldet unbekannten Abschluss; keine automatische Wiederholung. SIGKILL/Hostausfall kann geschützte Restdateien hinterlassen; keine Crash-Cleanup-Garantie. Neu erzeugte leere private Elternverzeichnisse dürfen mit `0700` bleiben.
9. **Exporte und Dokumentation:** Beide Exportpfade und Dist-Verbrauchertests ergänzen. Beispiele laden das gepinnte Helper-Image explizit vor und nutzen einen vorgelagerten austauschbaren `SecretResolver` mit 1Password oder Manual vor `podman.login({ ... })` und `quadlet.updateImage` mit demselben `authFile`. Zusätzlich die weiterhin unterstützte Dateivariante und fester Username plus manuelles Passwort zeigen. Image muss im rootful Store liegen; Rootless-Pull zählt nicht als Voraussetzung. Compose-Kompatibilität nur bei entsprechend konfiguriertem tatsächlichem Provider zusagen.

### Sicherheits- und Zustandsgrenzen

Aufgelöste Usernames aus Secret-Bindings werden wie Token aus Modulnamen, Labels, Diffs, Ergebnissen, Fehlermeldungen und Cause-Ketten ferngehalten bzw. explizit maskiert; auch kurze Werte dürfen sich nicht allein auf den globalen Sink mit Mindestlänge acht verlassen. Das gerahmte Credential-Payload bleibt ausschließlich in SSH-stdin; keine Credential-Werte in SSH-/Helper-Kommandotext oder deren argv und kein Export in Prozess-Environment-Variablen. Die Schlüssel sind Paratix-Environment-Bindings, keine Betriebssystem-Environment-Übertragung.

Die Host-Podman-CLI verlangt einen `--username`-Wert bei `--password-stdin`. Der Username ist daher auf dem Ziel in Podmans tatsächlichem Prozess-argv sichtbar; diese Grenze gilt auch bei Herkunft aus 1Password/Manual und wird dokumentiert. Der Token bleibt aus sämtlichen argv fern. Die Log-/Diff-/SSH-Ausgabe-Garantie gilt weiterhin für beide Werte; es wird keine vollständige Username-Vertraulichkeit gegenüber lokaler Prozessbeobachtung zugesagt. Die bestehende Credential-Datei auf dem Ziel bleibt ohnehin notwendiger Bestandteil eines persistenten Registry-Logins.

Hostseitige Vorprüfungen etablieren die Vertrauenswurzel vor dem Mount; ein containerseitiges `lstat` unter einem Bind-Ziel ersetzt diese Prüfung nicht. Innerhalb der eingebundenen Verzeichnisse erfolgen Dateioperationen descriptor-relativ mit `O_NOFOLLOW`. Ziel-PAT- und Auth-Leaf-Prüfungen bleiben auch bei bereits vorhandenem Mount erforderlich. Gemeinsame Auth-Dateien können mehrere Registries enthalten; das vertrauenswürdige Helper-Image kann deshalb alle Credentials in seinem eingebundenen Auth-Verzeichnis lesen. Dessen Pflege und begrenzter Mount-Umfang sind relevante Betriebsanforderungen.

Unprivilegierte Dritte dürfen keine beteiligten Verzeichnisse austauschen oder beschreiben können. Privilegierte Pfad-/Mount-Austausche und unkooperative Root-Schreiber sind außerhalb der Garantie. Die erneute Konfliktprüfung ist kein Compare-and-Swap im letzten Zeitfenster vor Rename. Betreiber müssen exklusiven Schreibzugriff auf diese Auth-Datei während Apply gewährleisten; geordnete Paratix-Läufe allein beweisen keine Abwesenheit externer Schreiber.

Das SSH-Protokoll transportiert ausschließlich konstante Status-/Fehlerwerte des Host-Wrappers. Container-Exitcodes für die Helper-Phasen werden von Podman-Startfehlern unterschieden. Helper-Ausgabe wird vor diesem Protokoll vollständig auf dem Ziel verworfen, damit auch ein fehlerhafter Helper keine Secrets an SSH ausgeben kann. Transaktionsnamen sind zufällig und enthalten keine Credential-Digests. Private Arbeitsdateien/Pipes befinden sich auf dem Ziel; deren Inhalt darf nicht an SSH-stdout/stderr angeschlossen werden. `silent` allein wäre dafür unzureichend. Host-Podman wird nur für tatsächliche Inhaltsänderungen aufgerufen; der Check benötigt keinen Registry-Netzwerkzugriff und zieht kein Image nach.

## Akzeptanzkriterien

- [ ] `podman` ist aus `paratix` und `paratix/modules` importierbar; Quell-/Dist-Verbrauchertests typprüfen beide Methoden, Defaults, `helperImage`, die exklusiven Quellenoptionen und `server({ run: [...] })`.
- [ ] Konstruktor-/Runtime-Tests prüfen Registry/Port/Aliase, Username, Pfade, digest-fixiertes Image, PAT-Normalisierung/Größe/Typ/Owner und exakt `0400`. Kein Secret-Lesen bei Konstruktion oder `check(null)`.
- [ ] Auf einem Testziel ohne Host-Python funktionieren Check/Apply mit vorgeladenem Helper-Image. Startoptionen, rootful Store, getrennte Pfadabbildung, Netzwerk-/Rootfs-/Capabilities-/Log-Grenzen und minimaler Mount-Umfang sind durch echte Starts belegt. Fehlendes Image zieht im Check und Apply nichts automatisch nach.
- [ ] Beide Datei-Lokationen sowie der provider-neutrale Environment-Pfad zeigen real: erstes Login `changed`, Wiederholung `ok` ohne Login, Rotation genau ein weiterer Login und danach `ok`. Apply berücksichtigt Rotation nach einem früheren Check. Reine Dateirechtekorrektur ist idempotent und löst keinen Netz-Login aus.
- [ ] 1Password-Bindings liefern Username und Token über die bestehende Fassade ohne Credential-Datei auf dem Controller; Manual liefert dieselben Bindings über die vorhandene verdeckte CLI-Eingabe. Derselbe Podman-Consumer funktioniert für beide. Fester Username plus ausschließlich abgefragtem Passwort und `usernameEnv` plus Datei-Token sind ebenfalls abgedeckt.
- [ ] Konstruktor und Runtime lehnen fehlende/konkurrierende Quellen, `passwordFileLocation` bei `passwordEnv`, ungültige Binding-Namen, fehlende Schlüssel, Nicht-String-/leere/ungültige Werte ohne Echo der Inhalte ab. Kein Provider-I/O bei Konstruktion, keine Binding-Auflösung bei Podman-`check(null)` und keine heimlichen Fallbacks oder `process.env`-Zugriffe.
- [ ] Runner-Tests belegen bestehende Reihenfolge und Run-Grenzen: Prewarm vor SSH, Meta erst vor dem Consumer, gewöhnliche Reads/Prompts einmal pro Run trotz Check/Apply, neue Werte im nächsten Run, Dry-run-/Filter-Verhalten sowie sichere Fehler bei `op`-/Authentifizierungsfehlern, fehlendem TTY, Ctrl+C/EOF und Runner-Abbruch. Fehler vor erfolgreicher Credential-Auflösung lösen keine Auth-Mutation aus.
- [ ] Login ersetzt den gesamten eigenen Registry-Eintrag einschließlich bisheriger unbekannter Felder; Logout entfernt ihn vollständig. Andere Registry-Objekte einschließlich unbekannter Unterfelder und unbekannte Top-Level-Felder bleiben semantisch gleich. Relevante unsupported Helper-/Identity-Token-/Alias-Konfigurationen scheitern vor Mutation.
- [ ] Logout benötigt keinen PAT; fehlende Datei oder fehlender Eintrag ergibt `ok` ohne Host-Logout. Malformed/leer/falsch strukturiertes JSON, doppelte Schlüssel, Lesefehler, ungültiges Base64 und unerwartetes Protokoll ergeben sichere Fehler ohne automatische Reparatur.
- [ ] Symlink-Vorfahren werden vor Mounts erkannt; Leaf-Symlinks, Spezialdateien, Hardlink-Auth-Dateien, falsche Owner und fremdbeschreibbare Vorfahren scheitern ohne Zugriff auf ein unzulässiges Secret-/Schreibziel. Containerpfade dürfen eine fehlende Host-Prüfung nicht kaschieren. Unter der dokumentierten Vertrauensgrenze wird ein kontrollierter Austausch im Prüfabschnitt abgewehrt.
- [ ] Neue private Verzeichnisse haben `0700`, veröffentlichte Auth-Dateien `0600`; sichere vorhandene dedizierte Eltern mit `0755` bleiben unverändert. Breite System-/Home-Mounts werden abgelehnt. Kein rekursives Chown/Relabeln; keine Hostpolicy-Änderung. Auf einem SELinux-Enforcing-Testziel bleibt die ersetzte Auth-Datei mit Host-Podman nutzbar oder die Operation bricht vor Veröffentlichung ab.
- [ ] Fehler in Prepare, Host-Podman und vor Commit erhalten das Original bytegenau oder weiterhin abwesend. Beobachtete Fremdänderung verhindert Übernahme; normale Fehler/Erfolg entfernen eigene Arbeitsdateien und Container. Fehler nach Veröffentlichung/Transportabbruch melden unbekannten bzw. möglicherweise angewandten Abschluss ohne Snapshot-Rollback.
- [ ] Terminal, Ergebnisse, Fehler-/Cause-Ketten, Diffs, Containerlogs und tatsächliche SSH-Ausgabestreams enthalten weder aufgelösten Username noch Token/PAT, Base64-Credentials oder fremde Auth-Einträge, selbst bei einem fehlerhaften Podman-/Helper-Prozess. Ziel-PAT erscheint weder in SSH-stdin noch in lokalen Lese-/Download-Aufrufen. Controller-Credentials sind ausschließlich im vorgesehenen stdin-Payload zulässig, nicht in SSH-/Helper-Kommando oder deren argv. Die dokumentierte Username-Ausnahme betrifft ausschließlich den tatsächlichen Host-Podman-Prozess; der Token ist auch dort ausgeschlossen.
- [ ] Mit echtem Host-Podman ist bewiesen: Compat-Dateien ohne Helper-Zuordnungen erhalten das Ergebnis und lösen keine externen Store-/Erase-Aufrufe aus, auch bei abweichender Hauptkonfiguration und Drop-ins. Get-Aufrufe sind zulässig. Native Podman-Version und Helper-Image-Digest sind im Fixture fixiert.
- [ ] `pnpm agent:check` und `pnpm --filter paratix test:integration` bestehen; der vorhandene Docker-Teil und die neuen realen Podman-Helper-Fälle wurden tatsächlich ausgeführt. Guide und README stimmen mit den getesteten Verträgen überein.

## Validierungsplan

Alle Befehle vom Repository-Root, erst im implementierenden Workflow:

| Prüfung                    | Befehl und Erfolgskriterium                                                                                                                                                                                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gezielte Unit-/Exporttests | `pnpm --filter paratix exec vitest run test/modules/podman.test.ts test/modules/podmanHelpers.test.ts test/modules/podmanContainer.test.ts test/modules/podmanSecrets.test.ts test/runner-podman-secrets.test.ts test/publicApi.test.ts` – fachliche und Transportfälle bestehen |
| Distribution               | `pnpm --filter paratix test:dist` – beide Einstiegspunkte enthalten Modul und Helper-Programm                                                                                                                                                                                    |
| Projektprüfung             | `pnpm agent:check` – Exitcode 0                                                                                                                                                                                                                                                  |
| Docker-Voraussetzung       | `docker info` – bestehender Integrationsteil bleibt unverändert verpflichtend in CI                                                                                                                                                                                              |
| Natives Podman-Fixture     | Eigene Preflight-Prüfung: reale SSH-Verbindung, effektive Root-Ausführung, native Linux-Podman-Version und erfolgreicher Start des gepinnten Helpers mit produktiven Einschränkungen                                                                                             |
| Reale Integration          | `pnpm --filter paratix test:integration` – bestehende und neue Fälle ausgeführt, keine fehlenden Voraussetzungen als grüner CI-Skip                                                                                                                                              |

Die Podman-Fälle verwenden ein separates natives Linux-SSH-/Podman-Fixture auf einem kurzlebigen CI-Runner. Es provisioniert einen nur an Loopback gebundenen SSH-Testdienst mit eigenen temporären Schlüsseln/Ports und dedizierten Root-Testverzeichnissen. Der Harness besitzt Start/Cleanup dieses Dienstes und seiner Testcontainer eindeutig. Host-Python ist keine Fixture-Voraussetzung für das Modul. Lokal kann ein explizit konfigurierter isolierter SSH-Podman-Testhost bzw. eine Linux-VM dasselbe Ziel darstellen; ein Test gegen produktive Auth-Dateien ist ausgeschlossen.

Die beiden vorhandenen Ubuntu-Testjobs erhalten die nötigen SSH-/Podman-Voraussetzungen und Image-Vorladung. Ein tatsächlicher Helper-Start ist Preflight, nicht lediglich `podman --version`. In CI müssen fehlende Voraussetzungen oder nicht ausgeführte neue Fälle fehlschlagen. Lokale Fälle ohne geeignetes Podman-Testziel dürfen als nicht ausgeführt gekennzeichnet werden, gelten aber nie als Akzeptanznachweis. Das bestehende Docker-SSHD-Fixture bleibt unprivilegiert; keine Nested-Podman-Annahme, kein Host-Socket-Mount, keine Lockerung seiner Isolation.

Die Registry ist eine lokale authentifizierte HTTPS-Testregistry mit vertrauenswürdiger Test-CA und synthetischen Daten. Sie kann im bestehenden Docker-Umfeld laufen und ist vom nativen Podman-Ziel erreichbar. Kein externer Account oder produktiver PAT. Zusätzlich ist ein tatsächliches SELinux-Enforcing-Ziel für die entsprechende Label-/Dateiersatz-Zusage nötig; ein Ubuntu-Test ohne SELinux beweist diese Aussage nicht. Falls diese Zusage nicht belegbar ist, unterstützt V1 Enforcing-SELinux nicht und bricht dort bereits vor einer Auth-Mutation ab; diese Einschränkung ist vor Freigabe ausdrücklich zu dokumentieren, nicht durch stilles Abschalten der Hostpolicy zu umgehen.

Die Secret-Vertragstests verwenden die bestehenden Fassade-/Runner-Testmuster aus `test/modules/secret.test.ts`, `test/modules/secret-op.test.ts`, `test/runner-secret-facade.test.ts` und `test/secretPrewarm.test.ts`. Eine fake `op`-CLI und kontrollierte TTY-/Prompt-Fixtures liefern ausschließlich synthetische Daten; CI benötigt weder einen echten Vault noch menschliche Eingabe. Bestehende Provider-Tests bleiben Regressionsevidenz; keine Änderung an deren Semantik. Native SSH-/Podman-Tests führen den neuen Consumer mit diesen Provider-Fixtures aus und prüfen die beiden Credential-Werte einschließlich kurzer Usernames auf Leaks, separate Runs für Rotation und fehlende lokale Credential-Dateioperationen.

Mocks prüfen Modulverträge; reale Tests prüfen Datei-/Mount-/Containerverhalten, atomaren Ersatz und Ausgaben. Fehler vor/nach Übernahme und unterbrochene Phasen werden kontrolliert injiziert. Der separate Testharness macht keine Privilegierungsänderung am bisherigen Harness. Dieser Planungslauf führt nur Plan-Lint, Markdown-Formatierung und Diff-Prüfung aus. Später nötige Änderungen an `ssh`/`readFile` benötigen gemäß `AGENTS.md` bereits vor deren Änderung den bestehenden Docker-Integrationstest und eine neue Scope-Entscheidung.

## Annahmen und offene Punkte

- Laufzeitentscheidung, vollständige Eintragsverwaltung und direkte Nutzung der vorhandenen 1Password-/Manual-Secret-Provider wurden im Chat ausdrücklich gewählt. Die vormals erwogene Host-Python-Laufzeit und Fingerprint-/Einzeldateivariante sind verworfen.
- Der Betreiber lädt das vertrauenswürdige gepinnte Image im richtigen rootful Store vor, stellt entweder Secret-Bindings oder die gewählte PAT-Datei sowie benötigte dedizierte Auth-/PAT-Verzeichnisse bereit und verhindert konkurrierende Root-Schreiber während Apply.
- Die Auth-Datei ist bewusst persistent. Rootless-/Multi-User-Orchestrierung, IPv6-/Namespace-Schlüssel, Docker-Config-Verwaltung, externe Credential-Store-Schreiboperationen, PAT-Erzeugung/-Rotation, Retries und weitere Podman-Lifecycle-Methoden bleiben außerhalb V1.
- Vor Umsetzung Quellstand, sudo-/stdin-Vertrag, Exporttests und native Fixture-Möglichkeiten gegen HEAD `6afd16a` prüfen. Gepinnten Image-Digest und konkrete Podman-Testversion anhand aktueller Quellen auswählen; abweichende CLI-/Mount-/Sicherheitsverträge führen zu Plananpassung statt stiller Lockerung.
- Änderungen an CI beschränken sich auf die bestehende Validierung dieser neuen Testgrenze; keine Änderungen an Releases, Deployments oder deren Berechtigungen.

## Plan-Review

### Frühere Prüfung aus dem bisherigen Plan

Die folgende Prüfung ist unveränderte Historie. Bei Widersprüchen gelten der revidierte Haupttext und die datierte Prüfung darunter, insbesondere für Identität, Secret-Transport, beschädigtes JSON und Dateiersatz.

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

### Prüfung vom 21.10.2026

**Ergebnis:** Freigegeben

#### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       0 |
| Umfang      |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

#### Befunde

- Keine verbleibenden Befunde. Unabhängig geprüft wurden Architekturpassung, API-Verträge, Secret-Transport, Erhalt fremder Auth-Daten, Fehler- und Konfliktfälle, Testbarkeit, Umfang, Wartbarkeit und Ausführbarkeit gegen den aktuellen Repository-Stand.
- **Sicherheit/Umfang (Wichtig, eingearbeitet):** Vorhandene Auth-Elternverzeichnisse werden bei unsicherem Modus abgelehnt statt automatisch auf `0700` gesetzt; gemeinsame Systemverzeichnisse bleiben unverändert.
- **Sicherheit/externe Verträge (Wichtig, eingearbeitet):** Die nicht belegte Isolation über eine private `registries.conf` wurde durch den referenzgeprüften Compat-Datei-Edit-Pfad ohne Helper-Zuordnungen ersetzt. Lesende Helper-Aufrufe bleiben möglich; Store/Erase wird durch Quellen und reale Integration abgesichert.
- **Planvalidierung:** Konkrete Dateien und Schritte, messbare Kriterien, verifizierter Codekontext, begründete Feature-Empfehlung und strikte Plan-Schreibgrenze sind erfüllt. Python 3 bleibt eine ausdrücklich dokumentierte Voraussetzung; die Testversion und ihr realer Verhaltensnachweis sind als Implementierungs- und Freigabevoraussetzung festgelegt.

### Vertieftes Review vom 21.10.2026

**Ergebnis:** Überarbeitung nötig

#### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       1 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       1 |       0 |
| Testbarkeit |        0 |       0 |       0 |
| Umfang      |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

#### Befunde

- **Architektur/Wartbarkeit (Wichtig, eingearbeitet):** Entschieden: Container-Helper ohne zusätzliche Host-Laufzeit, Host-Podman für Login/Logout und gemeinsames Auth-JSON. Die Ausgestaltung und ihre Validierung werden entsprechend angepasst.
- **Architektur/Umfang (Wichtig, eingearbeitet):** Die unnötige Beschränkung vorhandener Auth-Elternverzeichnisse auf exakt `0700` entfällt. Root-eigene, nicht fremdbeschreibbare Verzeichnisse wie `0755` sind mit Auth-Datei `0600` zulässig und bleiben unverändert. Neue private Verzeichnisse erhalten weiterhin `0700`.
- **Datenvertrag/Fehlerfälle (Wichtig, offen):** Die allgemeine Erhaltungsgarantie ist nicht eindeutig mit Ersetzen bzw. Entfernen des eigenen Registry-Objekts vereinbar. Entscheiden, ob der gesamte adressierte Eintrag Paratix gehört oder unbekannte Felder darin erhalten bleiben müssen. Danach Login, Logout und Akzeptanzkriterien auf dieselbe Eigentumsgrenze ausrichten.
- Das reguläre Review bleibt Historie; seine Freigabe löst die hier festgehaltenen Entscheidungen nicht vorweg. Keine Implementierungsfreigabe, bevor die blockierenden Punkte geschlossen sind.

### Entscheidungen und Container-Revision vom 21.10.2026

**Ergebnis:** Freigegeben

#### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       0 |
| Umfang      |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

#### Befunde

- **Architektur (Wichtig, eingearbeitet):** Nutzerentscheidung auf Container-Helper umgesetzt. API, Dateien, Phasen, Image-Voraussetzung und Dokumentation verlangen keine Host-Python-Laufzeit mehr. Das Image wird ausdrücklich vorgeladen und per Digest fixiert; allgemeine Toolbox-/Image-Publishing-Infrastruktur gehört nicht dazu.
- **Datenvertrag (Wichtig, eingearbeitet):** Nutzerentscheidung auf vollständige Verwaltung des adressierten Registry-Objekts vereinheitlicht. Login ersetzt und Logout entfernt dieses Objekt; der Erhalt unbekannter JSON-Werte ist auf den Bereich außerhalb dieses Objekts begrenzt.
- **Testbarkeit (Wichtig, eingearbeitet):** Reale Containerstarts werden auf einem separaten nativen Linux-SSH-/Podman-Ziel geprüft. Die bestehende Docker-Fixture wird nicht privilegiert. Die zwei vorhandenen Validierungsjobs provisionieren diese Testgrenze und dürfen fehlende Voraussetzungen nicht als Erfolg überspringen.
- **Sicherheit/Datenschutz (Wichtig, eingearbeitet):** Rohe Helper-Ausgaben werden vor dem SSH-Kanal auf dem Ziel verworfen; nur feste, anhand phasenspezifischer Exitcodes ausgewählte Statuswerte verlassen den Host-Wrapper. Injizierte PAT-/Base64-Ausgabe wird im Integrationstest bereits an der tatsächlichen SSH-Grenze ausgeschlossen.
- Keine verbleibenden Befunde im geprüften Umfang. Die konkrete Image-/Podman-Version und der SELinux-Nachweis bleiben ausdrücklich begrenzte technische Validierungsaufgaben vor Implementierung bzw. Freigabe, keine ungeprüften Kompatibilitätszusagen.

### Provider-Ergänzung vom 21.10.2026

**Ergebnis:** Freigegeben

#### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       0 |
| Umfang      |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

#### Befunde

- Keine Befunde im geprüften Zusatzumfang. Unabhängig geprüft wurden die exklusiven und kombinierbaren Credential-Quellen, bestehende Provider-Fassade und Environment-Meta, sequenzielle Auflösung, Prewarm/Run-Cache/Filter/Dry-run/TTY/Abbruch sowie synthetische Provider-/CI-Fixtures.
- **Architektur (eingearbeitet):** Bestehende 1Password- und Manual-Provider versorgen denselben `usernameEnv`-/`passwordEnv`-Consumer. Keine neue Provider-Implementierung und keine Credential-Datei auf dem Controller; statische und dateibasierte Quellen bleiben kombinierbare Alternativen.
- **Sicherheit (eingearbeitet):** Beide aufgelösten Werte einschließlich kurzer Usernames werden explizit gegen Ausgabe-Leaks geschützt. Der bestehende stdin-Pfad trägt ein begrenztes Credential-Payload; die dokumentierte Username-Sichtbarkeit im tatsächlichen Host-Podman-argv ist von SSH-/Helper-Kommandotext und der weiterhin vollständigen Token-argv-Grenze getrennt.
- **Vertragsprüfung:** Die angeforderte Ergänzung passt zu den vorhandenen Provider-/Environment-Lifecycles. Status und Feature-Empfehlung bleiben erhalten; keine offenen Produktentscheidungen. Die früheren Reviews bleiben als Verlauf erhalten.

## Offene Punkte

- Keine offenen Punkte.

## Umsetzungsnachweis

**Datum:** 21.10.2026

Die öffentliche API `podman.login(...)` und `podman.logout(...)` ist mit beiden Paket-Exportpfaden umgesetzt. Die zusätzlichen Dateien `podmanTypes.ts` und `podmanValidation.ts` trennen Optionen und Validierung; das Python-Programm bleibt eingebettet. Environment-Bindings der bestehenden 1Password-/Manual-Provider sowie Controller- und Ziel-Dateien verwenden denselben Consumer. Globale SSH-/readFile-, Provider-, Prewarm- und Cache-Verträge sowie Paketabhängigkeiten bleiben unverändert.

Der Host-Wrapper verwendet ausschließlich geschlossene Exitcodes und leere SSH-Ausgabestreams; damit kollidieren kurze Secrets nicht mit Statuswörtern. Private Compat-Dateien begrenzen Host-Podman-Schreibzugriffe. Der Helper prüft Dateiidentität, JSON, Konflikte und Größen vor dem atomaren Austausch innerhalb desselben Auth-Mounts. Token sind auf die nativ verifizierte Grenze von 65.535 UTF-8-Bytes begrenzt; eine durch ASCII-JSON vergrößerte Datei wird oberhalb von 8 MiB vor Veröffentlichung abgelehnt. Es gibt keinen Snapshot-Rollback und keinen automatischen Retry.

Das separate native Fixture besitzt HTTPS-Testregistry, Test-CA und SSH-Reverse-Forwarding. Ergänzt wurden `podmanRegistry.ts`, `podmanPty.ts`, `podmanRunner.integration.test.ts` und `podmanLimits.integration.test.ts`. `scripts/runPodmanIntegration.sh` provisioniert ausschließlich eigene kurzlebige Loopback-SSH-Ressourcen; beide bestehenden CI-Validierungsjobs verwenden diesen Wrapper. Die vorhandene Docker-SSHD-Fixture bleibt unprivilegiert.

Guide, Paket-README und öffentliche Kommentare sind abgeglichen. Die Website nennt keine wartungsanfällige feste Modulanzahl mehr. Alle erfassten Dokumentationsflächen wurden aktualisiert oder mit konkreter Begründung als unverändert gültig bewertet.

## Testergebnisse

- `pnpm agent:check`: bestanden; beide Linter, Formatierung, alle Typprüfungen und Builds sowie sämtliche Repository-Prüfungen erfolgreich. Paratix: 5.640 bestandene Unit-Tests, 47 vorhandene lokale Skips und 20 Distributionstests; create-paratix: 273 Unit- und 13 Distributionstests; Website: zwei Tests; Repository-Skripte: 45 Tests. Die Coverage-Schwellen sind erfüllt.
- Gezielte Podman-/Export-/Secret-/Runner-Tests: 101 bestanden. Die neuen nativen Größenregressionen prüfen echte erfolgreiche 65.535-Byte-Logins aller drei Quellen, frühe Ablehnung von 65.536 Bytes, große Base64-Zustände, Folgeoperationen, exakte 8-MiB-Grenzen und bytegenauen Originalerhalt bei Unicode-Expansion.
- `pnpm --filter paratix test:integration`: im finalen unveränderten Wiederholungslauf 99 von 99 Tests in sechs Dateien bestanden, keine Skips; 70 native Podman- und 29 bestehende Docker-/SSH-Fälle. Das isolierte Ziel lief mit Ubuntu 24.04 ARM64 und Podman 4.9.3; Host-Python war während der nativen Prüfungen nachweislich nicht verfügbar.
- Der erste finale Integrationsversuch überschritt beim Download von Debian-Paketen das bestehende 150-Sekunden-Buildlimit der Docker-Fixture. Alle 70 nativen Fälle waren bereits grün. Genau eine autorisierte Wiederholung ohne Quell-, Harness-, Timeout- oder Infrastrukturänderung bestand vollständig; die vorherige Prozess- und Fixture-Bereinigung wurde bestätigt.
- Geprüft sind tatsächliche SSH-Ausgabestreams bei injizierter Secret-Ausgabe, Credential-Helper-Hauptkonfiguration und Drop-ins ohne Store/Erase, kontrollierter Pfadtausch, konkurrierender Schreiber, Fehler nach Veröffentlichung sowie echter SSH-Abbruch ohne Retry/Rollback. Echte CLI-/PTY-Fälle decken verdeckte Eingabe, Ctrl+C, EOF, SIGTERM, fehlendes TTY, Provider-Fehler, Filter, Dry-run und Run-Rotation ab.
- Enforcing-SELinux wird in V1 vor einer Auth-Mutation abgewiesen; der private Enforcing-Test beweist diesen Abbruch, keine Enforcing-Unterstützung. Der CI-Wrapper wurde nativ mit Erfolg und absichtlichem Fehlerexit geprüft; Cleanup war in beiden Fällen vollständig. Hosted-AMD64 wird durch die neuen CI-Jobs geprüft und wurde lokal nicht behauptet.
- Die finalen Checks veränderten keinen der 31 Quell-/Test-/Doku-/Konfigurationshashes. Erwartete Hostkey-, Mock- und Fehlerpfad-Warnungen sind in den lokalen Prüfprotokollen ausgewiesen. Nach den Tests blieben keine eigenen Container oder Testverzeichnisse; das eigens erzeugte VM-Profil wurde nach Wiederherstellung von Host-Python entfernt.

## Review-Befunde

**Datum:** 21.10.2026
**Reviewer:** `effective-flow-nodejs-reviewer`, `effective-flow-generic-product-reviewer`, `effective-flow-frontend-reviewer`

### Zusammenfassung

| Status                  | Anzahl |
| ----------------------- | -----: |
| Behoben                 |      2 |
| Offen / Nicht umgesetzt |      0 |

F1 korrigiert die konsumierbare Token-Grenze von Podman 4.9.3. F2 trennt Auth-, State- und Compat-Grenzen und verhindert die Veröffentlichung eines anschließend nicht mehr lesbaren Kandidaten. Beide wichtigen Befunde wurden in einem Quality-Inkorporationspass behoben und unabhängig nachgeprüft; es verbleiben keine Befunde. Die Python-Prüfung erfolgte als qualitative Generalistenprüfung mit reduzierter sprachspezifischer Tiefe. Ein weiterer Logout-Kandidat wurde durch einen echten Podman-Gegencheck geschlossen. Es entstand kein externer Residualbericht.
