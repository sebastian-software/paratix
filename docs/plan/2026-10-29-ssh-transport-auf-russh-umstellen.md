# SSH-Transport von ssh2 auf eine eigene russh-Anbindung umstellen

**Planungsstatus:** Nicht umgesetzt
**Quelle:** effective-flow plan – Nutzerauftrag vom 29.10.2026 auf Basis der T3-Code-Session „Secrets auf dem T3-Code-Server verwalten“ (36655bc5)
**Empfohlener Workflow:** Feature (`effective-flow build`)

## Anforderung

Paratix soll sich mit kurzlebigen OpenSSH-Zertifikaten anmelden und Hosts über eine Host-CA prüfen können (Epic #252). Mit der heutigen Bibliothek `ssh2` geht beides nicht. `ssh2` 1.17.0 kennt keine `*-cert-v01@openssh.com`-Schlüssel, überspringt Zertifikate im `ssh-agent` still und handelt keine Host-Zertifikat-Algorithmen aus. Der Upstream-PR mscdex/ssh2#1495 wartet auf den Maintainer. Ein ähnlicher PR liegt dort seit über einem Jahr.

In der Session wurden vier Wege verglichen:

- ein `ssh2`-Fork
- System-OpenSSH als Unterprozess
- die vorhandene npm-Anbindung `russh` (0.1.38). Sie bietet keine Zertifikate über die API und ist auf Tabby zugeschnitten.
- eine **eigene, schmale napi-rs-Anbindung an die Rust-Bibliothek `russh`**

Empfohlen wurde die eigene Anbindung, und der Nutzer hat sie gewählt. Die Rust-Bibliothek `russh` (warp-tech/russh, 0.65.0 vom 25.10.2026, neue Versionen etwa alle 2–3 Wochen) kann:

- Benutzerzertifikate aus Datei und aus dem Agent
- Host-Zertifikate aushandeln
- Exec
- Keyboard-Interactive
- SFTP über `russh-sftp`

Entscheidungen des Nutzers vom 29.10.2026:

1. **Kein `ssh2`-Fork, keine Zwischenlösung.** Bis zur Umstellung meldet sich Paratix weiter per Schlüssel an. Das passt zur Reihenfolge im Epic: #250 und #249 rollen die CA-Infrastruktur schon vorher aus.
2. **Fertige Binaries für Linux und macOS:** `linux-x64-gnu`, `linux-arm64-gnu`, `linux-x64-musl`, `linux-arm64-musl`, `darwin-x64` und `darwin-arm64`. Windows gehört nicht dazu. Die gnu-Ziele laufen ab **glibc 2.35**, also ab Ubuntu 22.04 und Debian 12. RHEL 8 und 9 werden als Controller bewusst nicht unterstützt.
3. **Harter Wechsel:** Es gibt kein Opt-in `ssh.transport` und keinen Parallelbetrieb für Nutzer.
4. **Paket im Monorepo:** `packages/ssh-native` mit dem npm-Namen `@paratix/ssh-native`, gemeinsam versioniert mit `paratix` und `create-paratix`.
5. **Laden bei Bedarf:**
   - `paratix` lädt die Anbindung beim ersten Verbindungsaufbau. Die CLI prüft vor dem Secret-Prewarm, ob sie sich laden lässt.
   - `create-paratix` lädt sie nur im Host-Key-Scan.
   - Bibliothek, `--help`, `--version`, Playbook-Unit-Tests und Scaffolding laufen damit auf jeder Plattform.
6. **Toolchain:** `pnpm build` baut die Anbindung immer, inkrementell. Die Rust-Toolchain ist damit für alle Pflicht, die das Repo bauen. `cargo fmt`, `clippy` und `test` laufen lokal nur bei Rust-Änderungen, in CI immer im Job `check` von `ci.yml`.
7. **Erstveröffentlichung mit Platzhaltern:**
   - Der Nutzer legt die npm-Scope `@paratix` an.
   - Er veröffentlicht einmalig `0.0.0`-Platzhalter für die sieben neuen Pakete, mit seiner interaktiven npm-Sitzung und 2FA, ohne Token.
   - Erst unmittelbar vor dem ersten echten Release aus B richtet er je Paket einen Trusted Publisher ein und sperrt Tokens. npm lässt eine neue Trusted-Publisher-Konfiguration nach 2 Tagen verfallen, wenn bis dahin kein Publish darüber gelaufen ist.
   - Stand 29.10.2026: Scope und Platzhalter sind angelegt (erledigt).
8. **RUSTSEC-2023-0071** (Marvin-Angriff, `rsa`-Crate, kein Fix verfügbar): Dafür gibt es eine begründete Ausnahme in `deny.toml`. Advisories prüft ein eigener, nicht blockierender, zeitgesteuerter Job. Lizenzen, Bans und Quellen blockieren weiter.
9. **Tarballs:** Das Publish-Skript schreibt zuerst die `optionalDependencies` in eine Staging-Kopie des Hauptpakets. Erst danach erzeugt es alle Pakete per `pnpm pack`. Vor dem Veröffentlichen prüft es das Manifest im Tarball von `@paratix/ssh-native`. Veröffentlicht wird mit `npm publish <tgz>`.
10. **C in zwei Schritten mit eigenem Release:**
    - C1 zieht die Transport-Schnittstelle ein, mit einem temporären internen `ssh2`-Adapter.
    - C2 wechselt auf den nativen Adapter und entfernt `ssh2`.
11. **Harte Abbruchgründe des Spikes:**
    - Zertifikat per Agent
    - asynchroner Host-Key-Callback
    - Exec-Semantik
    - SFTP mit Modus und Backpressure
    - `destroy`/`exit`
    - Prebuild-Matrix
    - `agentForward`

    Einzelne Schlüsselformate sind weiche Kriterien. Fehlt eines, kommt es mit Begründung ins ADR und ins Changelog.

Dieser Plan umfasst die Umstellung selbst, also die Arbeitspakete A, B, C1 und C2. Die Funktionen, die darauf aufbauen (D = #248 und E), und die Neuordnung des Epics beschreibt er nur, damit die Issues zueinander passen. Sie werden in eigenen Issues umgesetzt.

Als Workflow passt Feature. Die öffentliche API verhält sich gleich, aber es kommen ein neues Paket, eine native Abhängigkeit, eine Plattformgrenze und eine neue Release-Pipeline hinzu.

**Planungsbasis:** `main`, HEAD `b890ef58`, 29.10.2026, sauberer Arbeitsbaum. Die Zeilenangaben beziehen sich auf diesen Stand.

### Verifizierter Ist-Zustand

**Wo `ssh2` steckt**

- Laufzeit-Importe in vier Dateien:
  - `packages/paratix/src/ssh.ts:10`
  - `packages/paratix/src/sshHelpers.ts:2`: `buildConnectConfig` (660), `cleanupFailedSshClient` (698), `tryConnectOnPort` (747) und `collectStreamOutput` (528)
  - `packages/paratix/src/sftp.ts:3`: `client.sftp`, Read-/WriteStream mit `0o600` und die Workarounds aus #37
  - `packages/create-paratix/src/hostFingerprintBootstrap.ts:2`: Host-Key-Scan ohne Anmeldung, mit Schutz gegen halboffenes TCP (R-0000127) und Gesamt-Timeout (R-0000188, Zeilen 251–263 und 341–352)
- Der Scan wird statisch über `index.ts` → `interactivePrompts.ts` importiert. Die Exporte `readHostFingerprintViaSsh2` und `allowSsh2HostKeyScan` sowie der Prompt-Text in `interactivePrompts.ts:89` nennen `ssh2`.
- `packages/paratix/src/index.ts:89` exportiert `shellQuote` aus `ssh.ts`. Ein statischer Import der Anbindung in `ssh.ts` würde sie also bei jedem `import "paratix"` laden.
- Im Testcode:
  - `test/integration/podmanRegistry.ts:9` (Client)
  - `test/postbuild/cli.dist.test.ts:22`: `Server` als In-Process-sshd. `linkRuntimeDependencies` verlinkt dort die Laufzeit-Abhängigkeiten aus dem Workspace (Zeilen 372 und 1689), gepackt wird mit `pnpm pack` (376).
  - Unit-Tests mit Fakes nach der `ssh2`-Semantik: `ssh.test.ts` (5111 Zeilen), `sshHelpers.test.ts`, `sftp.test.ts`, `create-paratix/test/helpers.ts`
- `packages/create-paratix/test/integration/generated-project.install.test.ts:13-37` installiert alles aus der Registry und lenkt nur `paratix` per Override auf den gepackten Tarball um. `test/scaffoldFixtures.ts:128-138` beschreibt das Reihenfolgeproblem bei unveröffentlichten Versionen.
- Modulcode sieht nur `SshConnection` (`types.ts:341`). `SshConnectionImpl` (`ssh.ts:397`), `sshHelpers.ts` und `sftp.ts` nutzen `Client` direkt.

**Genutzte `ssh2`-Funktionen**

- Anmeldung:
  - per Key-Datei (`connect` ab `ssh.ts:1427`). Der Buffer wird nur im Fehlerfall geleert (1450/1455). Im Erfolgsfall bleibt er bewusst stehen, weil `ssh2` eine Referenz hält (R-0000521, 1436–1459).
  - per Agent (`connectViaAgent`, `ssh.ts:1406`)
  - per Passwort mit `tryKeyboard` (`ssh.ts:2685`)
- `agentForward` nur auf ausdrücklichen Wunsch (`sshHelpers.ts:676-678`)
- Host-Prüfung über einen synchronen `hostVerifier(key) => boolean`. Das Laden ist schon asynchron: `buildHostVerifier` lädt die Einträge vorab (`knownHosts.ts:694-737`).
- Verbindungsaufbau mit `readyTimeout` je Port und Abbruch per AbortSignal
- Exec:
  - ohne PTY, mit stdin, Exit-Code und Signal
  - ein Kanal je Exec, vorab auf 4 begrenzt (#178, `ssh.ts:48-74` und `243-246`)
  - Lehnt der Server einen Kanal ab, erkennt Paratix das über `/channel open failure/iv` (`ssh.ts:2419` und `2486`) und meldet einen Fehler ohne Retry.
- `destroy()` beim doppelten SIGINT (`runner.ts:132-197`, `performLastResortCleanup` bei 145)
- Den Event-Loop halten die `ssh2`-Sockets am Leben. `unref` gibt es nur für Timer (`ssh.ts:2626`, `runner.ts:367`).
- Das sudo-Passwort wird mit `fill(0)` geleert (`ssh.ts:1376`).
- Fehler bei der Host-Prüfung kommen als `HostKeyVerificationError`, mit Texten aus `knownHosts.ts`, etwa „not found in known_hosts…“, „HOST KEY CHANGED“ und revoked. Der Reconnect bricht nur bei `instanceof HostKeyVerificationError` ab (`ssh.ts:706-711` und `2055-2060`). R-0000256 wirft den Fehler erneut.
- `knownHosts.ts:286-299` behandelt `@revoked` für rohe Schlüssel schon und verweigert Hosts mit passender `@cert-authority`-Zeile (R-0000204).
- Reihenfolge der Host-Key-Algorithmen: ed25519 → ecdsa → rsa-sha2-512/256 → ssh-rsa. Jeder rohe `known_hosts`-Eintrag mit anderem Schlüssel gilt als Abweichung (`knownHosts.ts:301-313`).

**Nicht genutzt**

- Keepalive-Optionen, `algorithms`, `forwardOut`, `shell` und Exec-Umgebungsvariablen
- `rsync` ruft das System-`ssh` auf (`modules/rsync.ts:255-269`). Seinen Vertrauensanker nimmt es aus `getConnectionInfo().verifiedHostPublicKey` (Algorithmus plus Base64 des Blobs, `ssh.ts:479`, `643-645` und `1491`). Bei Key-Dateien nutzt es `-i <key> -o IdentitiesOnly=yes`.

**Konfiguration**

- `SshConfig` (`types.ts:430`): `user`, `ports`, `privateKey`, `agentForward`, `passwordFallback`, `sudoPassword`, `strictHostKeyChecking`, `expectedHostFingerprint`, `expectedHostPublicKey`, `reconnectTimeout` und `maxReconnectAttempts`
- Eine Passphrase für Schlüssel gibt es nicht.

**Build, Release und Tooling**

- `tsup` (node24) externalisiert `dependencies` von selbst. `engines.node` ist `>=24`.
- `package.json`:
  - Zeile 20: `agent:check` → `pnpm build && pnpm test`
  - Zeile 10: `typecheck:packages` prüft jedes `packages/*` mit `tsc --noEmit` und `tsconfig.typecheck.json`
  - Zeile 13: `test:integration` umfasst nur `paratix` und `create-paratix`
- ESLint (`eslint.config.ts:10-24`) und oxlint (`oxlint.config.ts:36-44`) prüfen alle Pakete.
- `.gitignore` kennt kein `target/`.
- `pnpm-workspace.yaml:4-8` erlaubt Builds für `ssh2` und `cpu-features`. Ausnahmen stehen ausdrücklich auf `false`, etwa `unrs-resolver: false`.
- Die Vorlage `PNPM_WORKSPACE_TEMPLATE` (`create-paratix/src/templates.ts:66-71`) übernimmt das.
- release-please mit `linked-versions`, ohne `node-workspace` und ohne `extra-files`.
- `scripts/publishWorkspacePackages.mjs`:
  - Statische Liste mit zwei Paketen (40–60). Die Drift-Prüfung R-0000740 steht bei 87–118, dazu gibt es `publishWorkspacePackages.test.mjs`.
  - Clean-Tree-Prüfung bei 205–213 und 254.
  - `npm publish <dir>` bei 610, `npm pack --dry-run` bei 631.
  - Recovery nur für `recover-create-paratix` (640–760).
  - tsup-spezifische Frische-Prüfung und `files`-Allowlist (492–541, R-0000661).
- `publish.yml`:
  - OIDC mit `id-token: write` und Environment `npm`
  - `concurrency` mit `cancel-in-progress: true` (19–21)
  - `release_created` steuert die Publish-Jobs (131–139)
- Alle Workflows laufen auf `ubuntu-24.04`. `ci.yml` (Job `check`) hat `timeout-minutes: 20`.
- `renovate.json` kennt nichts zu Cargo. Im Repo gibt es weder Rust- noch napi-Code.

**Tests und Dokumentation**

- Der Docker-sshd unter `packages/paratix/test/integration/docker/` nutzt `debian:bookworm-slim` und erlaubt nur Schlüssel-Login (`sshd_config:8-9`). Er hat nur ed25519- und RSA-Host-Keys (`sshd_config:4-5`).
- Agent, Passwort, `agentForward`, Abbruch während Exec und Kanal-Ablehnung sind nicht integrationsgetestet.
- Zum SSH-Transport gibt es kein ADR. Die ADRs 0001–0007 sind englisch (`language.project: en`).
- `docs/initialbeschreibung.md:1013-1021` und `docs/review-areas.md:22` nennen `ssh2`. `packages/paratix/AGENTS.md:5-7` spricht allgemein von „real SSH/SFTP code paths“.
- Die npm-Scope `@paratix` gehört seit dem 29.10.2026 dem Projekt. Alle sieben Pakete existieren als `0.0.0`-Platzhalter (Maintainer `fastner`, `repository` zeigt auf `sebastian-software/paratix`, `packages/ssh-native`).
- npm-Regeln (Stand 29.10.2026): Neue Trusted-Publisher-Konfigurationen verfallen nach 2 Tagen ohne erfolgreichen Publish. Tokens, die 2FA umgehen, dürfen kein Trusted Publishing mehr verwalten und verlieren ab Januar 2027 auch den direkten Publish.
- russh 0.65.0 laut docs.rs:
  - `authenticate_openssh_cert`, `authenticate_certificate_with`, `authenticate_keyboard_interactive_start` und `Handler::check_server_key(&PublicKeyOrCertificate)`
  - `Preferred.host_key_certificates` ist standardmäßig leer.
  - Abhängigkeiten: `ssh-key =0.7.0-rc.11` und das Default-Feature `rsa` (`rsa =0.10.0-rc.18`, RUSTSEC-2023-0071)
  - Default-Krypto-Backend ist `aws-lc-rs`.

### Nicht verifiziert (im Spike zu bestätigen)

- Agent-Forwarding in russh 0.65
- `russh-sftp` 3.x mit Dateimodus und Backpressure
- Agent-Identitäten mit Zertifikat über `request_identities`
- Zusammenspiel des russh-Clients mit dem `Server` von `ssh2`
- Schlüsselformate und Algorithmen im Vergleich zu `ssh2`: RSA als PEM/PKCS#1, PKCS#8, ECDSA, `rsa-sha2-*` über `server-sig-algs`
- Cross-Build mit `aws-lc-rs` auf alle sechs Ziele, alternativ `ring`

## Architekturentscheidungen

1. **Eigene napi-rs-Anbindung** statt Fork, OpenSSH-Prozess oder fremder npm-Anbindung.
   - Begründung:
     - Zertifikate in beide Richtungen
     - volle Prozesskontrolle wie bei `ssh2`: Reconnect, Abbruch, Maskierung
     - aktiv gepflegte Grundlage
   - Preis: Rust-Toolchain, Prebuild-Matrix, Release-Pipeline und eine Plattformgrenze.
   - Festgehalten wird das in einem englischen ADR `docs/adr/0008-ssh-transport-russh-napi.md` (A). Das ADR enthält die Spike-Ergebnisse selbst, nicht nur Links auf CI-Läufe, die irgendwann ablaufen.

2. **Schmale, Paratix-spezifische API der Anbindung.**
   - Angeboten werden nur:
     - `scan`: Handshake ohne Anmeldung, mit Gesamt-Timeout und Schutz gegen halboffenes TCP
     - `connect`: Timeout und Abbruch über `signal` bzw. `cancel()`. Anmeldung per Agent, Key-Datei oder Passwort mit Keyboard-Interactive, dazu Agent-Forwarding.
     - `exec` mit laufendem stdout/stderr, stdin, Exit-Code und Signal
     - SFTP-Lesen und -Schreiben als Stream mit Dateimodus
     - ein Disconnect-Ereignis
     - `close()` und ein synchrones `destroy()`
   - Keepalive steht nicht in der API und ist fest aus.
   - Zertifikatsoptionen kommen erst mit D und E dazu.
   - Die Anbindung **lehnt jeden Kanal ab, den der Server öffnet**: `forwarded-tcpip`, `x11` und `auth-agent@openssh.com`. Einzige Ausnahme ist `auth-agent` bei `agentForward: true`. Den Agent-Socket verbindet sie für das Forwarding nur dann.

3. **Interne Transport-Schnittstelle unter `SshConnectionImpl`.**
   - `packages/paratix/src/transport.ts` beschreibt Verbindung, Exec-Kanal und SFTP-Sitzung mit Promise- und Stream-Semantik.
   - Adapter:
     - in C1 ein temporärer `transportSsh2.ts`
     - in C2 `transportNative.ts`. `transportSsh2.ts` wird dann gelöscht.
   - Jeder Adapter hat einen eigenen Unit-Test. Die Tests von `ssh.ts`, `sftp.ts` und `sshHelpers.ts` nutzen einen Fake der Schnittstelle.
   - Die Schnittstelle wird nicht exportiert. Einen Opt-in für Nutzer gibt es nicht.
   - `SshConnection` und alle Module bleiben unverändert.

4. **Host-Key-Prüfung: Die Vertrauensentscheidung bleibt in TypeScript.**
   - `buildHostVerifier` bleibt wie es ist. `transportNative.ts` legt den synchronen Verifier hinter den asynchronen Callback der threadsafe function. Der Callback muss innerhalb von `readyTimeout` antworten.
   - **Verdikt:** Nur `true` gilt als Zustimmung, jeder andere Wert lehnt mit `HOST_KEY_REJECTED` ab. `index.d.ts` typisiert den Prüfer als `(info: HostKeyInfo) => boolean | Promise<boolean>`.
   - **Prüfer ohne Antwort:** Antwortet der Prüfer nicht bis `readyTimeout`, endet `connect()` mit `TIMEOUT`. Die russh-Sitzung endet, und ein spätes Verdikt wird verworfen.
   - Erhalten bleiben: Mutex, TOFU-Commit nach `ready`, Pins, „HOST KEY CHANGED“ und R-0000204.
   - **Wirft der Verifier, merkt sich `transportNative.ts` genau dieses Fehlerobjekt** für den Verbindungsversuch. Bei `HOST_KEY_REJECTED` wirft es dieses Objekt erneut. Nur wenn nichts gemerkt ist, kommt ein allgemeiner `HostKeyVerificationError`. So bleiben die Texte erhalten, und der Reconnect bricht weiter ab (fail closed).
   - Host-Zertifikate:
     - In C2 bietet die Anbindung keine Host-Zertifikat-Algorithmen an.
     - `Preferred.key` wird ausdrücklich auf die Reihenfolge von `ssh2` gesetzt.
     - `verifiedHostPublicKey` bleibt der reine Schlüssel im bisherigen Format.
   - In E prüft Rust die Kryptografie eines Zertifikats: CA-Signatur, Typ `host` und Gültigkeit. Dafür nimmt es den Re-Export `russh::keys`, keine eigene `ssh-key`-Abhängigkeit.

5. **Rust ohne Konfigurationslogik, Secrets nur kurz im Speicher.**
   - Pfade, `~`, `SSH_AUTH_SOCK` und Validierung bleiben in TypeScript.
   - Private Schlüssel, Login-Passwort und sudo-stdin kommen als Buffer nach Rust:
     - Rust kopiert sie und löscht sie mit `zeroize`.
     - JS leert den Buffer direkt nach der Übergabe, in jedem Pfad. Die Begründung von R-0000521 entfällt damit, der Test wird mit Begründung ersetzt.
     - Grenzen, wo russh intern Kopien hält, stehen im ADR.
   - Kein Rust-Logger, und `RUST_LOG` hat keine Wirkung.
   - Panics:
     - `panic = "unwind"` mit eigenem Panic-Hook, der nichts ausgibt.
     - Ein Panic oder `JoinError` wird zu `INTERNAL`, damit jeder Promise endet.
   - Fehlercodes mit secret-freien Texten:

     | Code                  | Bedeutung                                |
     | --------------------- | ---------------------------------------- |
     | `AUTH_FAILED`         | Anmeldung abgelehnt                      |
     | `HOST_KEY_REJECTED`   | Host-Key abgelehnt                       |
     | `TIMEOUT`             | Zeitlimit überschritten                  |
     | `ABORTED`             | per Signal abgebrochen                   |
     | `CONNECT_FAILED`      | Verbindungsaufbau gescheitert, mit errno |
     | `PROTOCOL`            | KEX- oder Protokollfehler                |
     | `CHANNEL_OPEN_FAILED` | Kanal abgelehnt                          |
     | `DISCONNECTED`        | Verbindung getrennt                      |
     | `SFTP_STATUS`         | SFTP-Fehler, mit Statuscode              |
     | `UNSUPPORTED_KEY`     | Schlüsselformat nicht unterstützt        |
     | `ENCRYPTED_KEY`       | verschlüsselter Schlüssel                |
     | `INTERNAL`            | interner Fehler oder Panic               |

   - Native Ursachen laufen durch den Secret-Sink.
   - `CHANNEL_OPEN_FAILED` ersetzt das Regex-Muster aus #178.

6. **Laufzeitverhalten wie heute.**
   - Es gilt die prozessweite tokio-Runtime von napi-rs.
   - Eine offene Verbindung hält den Event-Loop am Leben (`ref`), wie ein `ssh2`-Socket. Erst `close()` oder `destroy()` geben ihn frei.
   - `destroy()` kehrt synchron zurück und ist unmittelbar vor `process.exit` im Last-Resort-Cleanup gefahrlos.
   - Kein Keepalive und kein Inaktivitäts-Timeout. So bricht auch ein langer stiller Befehl nicht ab.

7. **Laden und Verteilung.**
   - Laden:
     - `transportNative.ts` lädt `@paratix/ssh-native` per `import()` beim ersten `connect`.
     - `cli.ts` prüft die Ladbarkeit vor `prewarmSecrets` (`runner.ts:36`).
     - `create-paratix` lädt nur im Scan-Pfad und überspringt den Scan mit Hinweis, wenn das Laden scheitert.
   - Verteilung:
     - `@paratix/ssh-native` lädt `@paratix/ssh-native-<triple>` aus den `optionalDependencies`.
     - Der Loader `index.js` ist von Hand geschrieben (`napi build` ohne JS-Erzeugung).
     - `index.d.ts` wird erzeugt und versioniert. CI prüft per Diff, dass sie aktuell ist.
   - Plattformfelder:
     - Das Hauptpaket setzt bewusst kein `os`/`cpu`. Die Plattformpakete setzen `os`, `cpu` und `libc`.
     - Jedes Manifest hat `repository` (`url` und `directory`), `license`, `files` und `engines`. Ohne `repository` lehnt npm Provenance ab.
   - Meldung auf einer nicht unterstützten Plattform:
     - Sie nennt Plattform, Architektur, libc und die unterstützten Ziele.
     - Sie weist auf ausgelassene optionale Abhängigkeiten und auf Lockfiles von anderen Plattformen hin (npm/cli#4828).
     - Es gibt keinen Fallback auf `ssh2`.

8. **Versionen und Veröffentlichung.**
   - Versionen:
     - `packages/ssh-native` kommt in die `linked-versions`-Gruppe.
     - `extra-files` aktualisiert nur die Plattform-Manifeste.
     - Die Crate bleibt fest auf `version = "0.0.0"` und `publish = false`. Die npm-Version ist die einzige Quelle, und `Cargo.lock` bleibt damit stabil.
   - Ablauf des Publish-Skripts:
     1. Nach dem Git-Preflight legt es eine Staging-Kopie von `@paratix/ssh-native` an. Dort schreibt es `optionalDependencies` mit der exakten Version der sechs Plattformpakete ins Manifest. Das Manifest im Repo bleibt unverändert.
     2. Erst danach packt es alle neun Pakete mit `pnpm pack`, also auf demselben Weg wie die Tests. `@paratix/ssh-native` packt es aus der Staging-Kopie, damit der Tarball die `optionalDependencies` enthält. `pnpm pack` löst `workspace:` auf.
     3. Vor jedem `npm publish` liest es `package.json` aus dem Tarball von `@paratix/ssh-native`. Fehlt dort eines der sechs Plattformpakete in `optionalDependencies` oder weicht eine Version von der Release-Version ab, bricht es ab.
     4. Es veröffentlicht mit `npm publish <tgz>`. Reihenfolge: sechs Plattformpakete → `@paratix/ssh-native` → `paratix` → `create-paratix`.
   - Robustheit:
     - Jeder Schritt ist idempotent. Eine schon veröffentlichte Version wird übersprungen.
     - Die Recovery deckt einen Abbruch an jeder Stelle ab.
     - Der Arbeitsbaum bleibt sauber.
     - `publish.yml` setzt für die Publish-Jobs `cancel-in-progress: false`, damit ein Push nicht mitten in eine Veröffentlichung fällt.

9. **`ssh2` nur noch als devDependency** für den Test-sshd in `cli.dist.test.ts`. Im Repo stehen `ssh2: false` und `cpu-features: false` in `pnpm-workspace.yaml`. Aus der Scaffold-Vorlage verschwinden beide Zeilen, weil generierte Projekte `ssh2` nicht mehr enthalten.

10. **Rust-Abhängigkeiten aktiv pflegen.**
    - `Cargo.lock` liegt im Repo. CI baut mit `--locked`, und `target/` steht in der Root-`.gitignore`.
    - `deny.toml`:
      - Lizenzen, Bans und Quellen blockieren.
      - Für RUSTSEC-2023-0071 gibt es eine begründete Ausnahme: Der Client signiert nur, und die Ausnahme wird bei jedem russh-Update geprüft.
      - Advisories laufen als eigener, zeitgesteuerter, nicht blockierender Job mit Meldung.
    - Das Krypto-Backend (`aws-lc-rs` oder `ring`) und die Lizenz-Allowlist legt das ADR fest.
    - Eine Renovate-Gruppe für `russh` und `russh-sftp`.
    - Ein Sicherheits-Release von russh wird auch übernommen, wenn `russh-sftp` hinterherhinkt. Notfalls per `[patch]`.
    - Actions werden per SHA gepinnt.

11. **Toolchain und Prüfungen.**
    - `rust-toolchain.toml` pinnt die Version. `pnpm build` ruft `napi build` inkrementell auf.
    - An der Wurzel gibt es keinen Rust-Workspace. Die Crate in `packages/ssh-native` hat ein eigenes `[workspace]`.
    - Ein Root-Skript `rust:check` (`cargo fmt --check`, `clippy -D warnings`, `cargo test`, `cargo deny check licenses bans sources`) läuft in `agent:check`, gesteuert über `PARATIX_RUST_CHECK`:
      - `always` läuft immer, `skip` nie, `auto` ist der Standard.
      - Ein gesetzter Wert hat Vorrang vor `CI=true`. Ein unbekannter Wert bricht ab.
      - `auto` läuft immer, wenn `CI=true` gesetzt oder `origin/main` nicht auflösbar ist. Sonst läuft es nur bei Änderungen an `packages/ssh-native/src/**`, `build.rs`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` oder `deny.toml` gegenüber `git merge-base HEAD origin/main`, einschließlich Arbeitsbaum und untracked Dateien.
    - In CI läuft `rust:check` nur im Job `check` von `ci.yml`, mit `PARATIX_RUST_CHECK=always`, `actions/cache` und angepasstem Timeout. `integration-check.yml` und `publish.yml` setzen `PARATIX_RUST_CHECK=skip` und bauen nur.
    - Es kommen keine Actions von Dritten hinzu: `Swatinem/rust-cache` wird nicht verwendet, die Allowlist bleibt unverändert.
    - `packages/ssh-native` bekommt `tsconfig.json`/`tsconfig.typecheck.json` für `typecheck:packages`.
    - ESLint, oxlint, Prettier und cspell ignorieren `target/` und `npm/*`.

## Betroffene Dateien

| Datei                                                                                                                                                                      | Beschreibung                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `docs/adr/0008-ssh-transport-russh-napi.md`                                                                                                                                | neu (A), englisch. Inhalt: Entscheidung, Alternativen, Spike-Ergebnisse, Plattformen (glibc 2.35, macOS-Mindestversion), Krypto-Backend, Fehlercodes, Aufteilung der Host-Zertifikate zwischen Rust und TS, `zeroize`-Grenzen, Advisory-Ausnahme, Update-Regel, Abbruchkriterien           |
| `packages/ssh-native/` (`Cargo.toml`, `src/*.rs`, `package.json`, `index.js`, `index.d.ts`, `npm/<triple>/package.json`, `test/`, `tsconfig*.json`)                        | neu (B). napi-rs-Anbindung mit russh und russh-sftp sowie zeroize. Loader von Hand, `index.d.ts` erzeugt.                                                                                                                                                                                  |
| `packages/ssh-native/` (`rust-toolchain.toml`, `Cargo.lock`, `deny.toml`), `.gitignore`                                                                                    | neu bzw. geändert (B). Crate mit eigenem `[workspace]`, kein Rust-Workspace an der Wurzel. Toolchain-Pin, Prüfregeln, `target/`                                                                                                                                                            |
| `pnpm-workspace.yaml`                                                                                                                                                      | B/C2: Paket aufnehmen, `ssh2: false`, `cpu-features: false`                                                                                                                                                                                                                                |
| `release-please-config.json`, `.release-please-manifest.json`                                                                                                              | B: linked-versions, `extra-files` für Plattform-Manifeste                                                                                                                                                                                                                                  |
| `renovate.json`                                                                                                                                                            | B: Gruppe für `russh` und `russh-sftp`                                                                                                                                                                                                                                                     |
| `eslint.config.ts`, `oxlint.config.ts`, `.prettierignore`, `cspell.json`                                                                                                   | B: Ignore-Regeln für `target/` und `npm/*`, neue Begriffe                                                                                                                                                                                                                                  |
| `.github/workflows/ci.yml`                                                                                                                                                 | B: Rust-Toolchain, `actions/cache`, `rust:check` mit `PARATIX_RUST_CHECK=always`, Diff-Check für `index.d.ts`, Timeout                                                                                                                                                                     |
| `.github/workflows/integration-check.yml`                                                                                                                                  | B: Rust-Toolchain, Anbindung bauen, `PARATIX_RUST_CHECK=skip`                                                                                                                                                                                                                              |
| `.github/workflows/rust-advisories.yml`                                                                                                                                    | neu (B): zeitgesteuert `cargo deny check advisories`, nicht blockierend, mit Meldung                                                                                                                                                                                                       |
| `.github/workflows/publish.yml`                                                                                                                                            | B: Build-Matrix und Smoke-Test je Ziel mit dem Artefakt, das veröffentlicht wird. Binaries an `validate`, `verify` und `publish` weitergeben. `cancel-in-progress: false`                                                                                                                  |
| `scripts/publishWorkspacePackages.mjs`, `scripts/publishWorkspacePackages.test.mjs`                                                                                        | B: neun Pakete mit Reihenfolge, Drift-Prüfung für Plattformverzeichnisse, `optionalDependencies` in der Staging-Kopie vor `pnpm pack`, Prüfung des Manifests im Tarball, `npm publish <tgz>`, Frische-Prüfung des `.node` gegen `src/*.rs`/`Cargo.*`, Idempotenz und Recovery              |
| `package.json` (Wurzel)                                                                                                                                                    | B: `rust:check`, Bedingung in `agent:check`, `test:integration` um `ssh-native` erweitert                                                                                                                                                                                                  |
| `packages/paratix/src/transport.ts`                                                                                                                                        | neu (C1): interne Transport-Schnittstelle                                                                                                                                                                                                                                                  |
| `packages/paratix/src/transportSsh2.ts`                                                                                                                                    | neu (C1), in C2 gelöscht: temporärer Adapter auf `ssh2`                                                                                                                                                                                                                                    |
| `packages/paratix/src/transportNative.ts`                                                                                                                                  | neu (C2): Adapter auf `@paratix/ssh-native` mit dynamischem Import, Abbildung der Fehlercodes, Weitergabe der Fehler aus dem Verifier                                                                                                                                                      |
| `packages/paratix/src/ssh.ts`                                                                                                                                              | C1: `Client` durch die Schnittstelle ersetzen. C2: `CHANNEL_OPEN_FAILED` statt Regex, Key-Buffer nach Übergabe leeren                                                                                                                                                                      |
| `packages/paratix/src/sshHelpers.ts`                                                                                                                                       | C1: auf Transport-Optionen umstellen, `ssh2`-Typen entfernen                                                                                                                                                                                                                               |
| `packages/paratix/src/sftp.ts`                                                                                                                                             | C1: SFTP-Sitzung des Transports. C2: prüfen, ob die #37-Workarounds entfallen; Timeout 120 s bleibt                                                                                                                                                                                        |
| `packages/paratix/src/knownHosts.ts`                                                                                                                                       | C2: keine Änderung außer Tests. E: `@cert-authority` und `@revoked` für CA-Schlüssel                                                                                                                                                                                                       |
| `packages/paratix/src/runner.ts`, `packages/paratix/src/cli.ts`                                                                                                            | C1: `destroy()` des Transports. C2: Ladeprüfung vor `prewarmSecrets`                                                                                                                                                                                                                       |
| `packages/paratix/src/modules/rsync.ts`                                                                                                                                    | D/E: `CertificateFile` bzw. `@cert-authority`                                                                                                                                                                                                                                              |
| `packages/paratix/src/types.ts`                                                                                                                                            | D: `SshConfig.certificate?: string`                                                                                                                                                                                                                                                        |
| `packages/paratix/package.json`, `packages/create-paratix/package.json`                                                                                                    | C2: `ssh2`/`@types/ssh2` aus der Laufzeit entfernen (in `paratix` bleibt `ssh2` als devDependency), `@paratix/ssh-native` aufnehmen                                                                                                                                                        |
| `packages/create-paratix/src/hostFingerprintBootstrap.ts`, `interactivePrompts.ts`, `index.ts`, `templates.ts`                                                             | C2: `scan()` über dynamischen Import, neutrale Namen und Prompt-Text, Vorlage ohne `ssh2`/`cpu-features`                                                                                                                                                                                   |
| `packages/paratix/test/ssh.test.ts`, `sshHelpers.test.ts`, `sftp.test.ts`, `knownHosts.test.ts`, `runner-reconnect.test.ts`, `runner-signals.test.ts`, `writeFile.test.ts` | C1: Fakes auf die Schnittstelle. `R-000xxxx` bleiben inhaltlich, Ausnahmen mit Begründung                                                                                                                                                                                                  |
| `packages/paratix/test/transportSsh2.test.ts`, `transportNative.test.ts`                                                                                                   | neu (C1 bzw. C2): Adapter-Tests, in C2 gegen ein gefälschtes natives Modul mit jedem Fehlercode                                                                                                                                                                                            |
| `packages/paratix/test/integration/*`, `test/integration/docker/*`                                                                                                         | C1: Paritätsmatrix auf `ssh2`. C2: dieselbe Matrix auf der Anbindung. sshd-Profile: Passwort/Keyboard-Interactive, `MaxSessions` niedrig, je ein Profil nur mit ed25519-, RSA- oder ECDSA-Host-Key. Der Agent läuft im Testprozess, das Forwarding wird im Container geprüft. D/E: Test-CA |
| `packages/create-paratix/test/helpers.ts`, `host-fingerprint.test.ts`                                                                                                      | C2: Fake-Factory, Test für eine nicht ladbare Anbindung                                                                                                                                                                                                                                    |
| `packages/create-paratix/test/integration/generated-project.install.test.ts`, `test/scaffoldFixtures.ts`                                                                   | C2: Overrides um `@paratix/ssh-native` und das Host-Plattformpaket aus dem Arbeitsbaum erweitern, damit unveröffentlichte Versionen funktionieren                                                                                                                                          |
| `packages/paratix/llm-guide.md`, `docs/user-guide/*`                                                                                                                       | C2: Plattformen, glibc- und macOS-Mindestversion. D/E: Zertifikate                                                                                                                                                                                                                         |
| `docs/initialbeschreibung.md`, `docs/review-areas.md`                                                                                                                      | C2: `ssh2` durch russh/`@paratix/ssh-native` ersetzen, Rust-Abhängigkeiten als Prüfbereich                                                                                                                                                                                                 |
| `AGENTS.md`, `packages/paratix/AGENTS.md`                                                                                                                                  | B: Rust-Toolchain ist Pflicht zum Bauen. Der Integrationstest-Hinweis gilt auch für `packages/ssh-native`.                                                                                                                                                                                 |

## Implementierungsdetails

### Vorgehen

**Reihenfolge:** A → B → C2. C1 hängt nicht an der Anbindung und kann parallel zu A und B laufen. D und E folgen nach C2.

**Voraussetzung (Nutzer, vor dem ersten Release aus B):**

1. ~~Die npm-Scope `@paratix` anlegen.~~ Erledigt am 29.10.2026.
2. ~~`0.0.0`-Platzhalter der sieben neuen Pakete veröffentlichen, mit interaktiver Sitzung und 2FA, ohne Token.~~ Erledigt am 29.10.2026.
3. **Erst unmittelbar vor dem ersten echten Release aus B**, damit die 2-Tage-Frist von npm nicht abläuft: je Paket einen Trusted Publisher einrichten (`sebastian-software/paratix`, `publish.yml`, Environment `npm`, `--allow-publish`) und danach „Require two-factor authentication and disallow tokens“ aktivieren. Das geht interaktiv mit `npm trust github <paket> --repo sebastian-software/paratix --file publish.yml --env npm --allow-publish`. Verfällt eine Konfiguration, wird sie gelöscht und neu angelegt.

**Arbeitspaket A – ADR und Spike (neues Issue, blockiert B)**

1. **Wegwerf-Spike** unter `packages/ssh-native` auf einem Spike-Branch. Er wird per `push` oder `pull_request` ausgelöst, nicht per `workflow_dispatch`. Er weist gegen einen Docker-sshd mit Test-CA nach:
   - **hart:** Anmeldung per Agent mit Benutzerzertifikat
   - **hart:** asynchroner Host-Key-Callback und Weitergabe eines geworfenen Fehlers
   - **hart:** Exec mit stdout, stderr, stdin und Exit-Code
   - **hart:** SFTP-Schreiben mit `0600` und Backpressure
   - **hart:** `destroy()` vor `process.exit()` bei laufendem Exec endet ohne Abort. Nach `close()` endet der Prozess. Mit offener, untätiger Verbindung bleibt er aktiv wie bei `ssh2`.
   - **hart:** `agentForward`. Ohne die Option lehnt die Anbindung `auth-agent` ab.
   - Anmeldung per Agent ohne Zertifikat, per Key-Datei und per Passwort bzw. Keyboard-Interactive
   - abgelehnter Kanal liefert `CHANNEL_OPEN_FAILED`
   - `scan()` ohne Anmeldung
   - Übergabe eines Host-Zertifikats, wenn Zertifikat-Algorithmen angeboten werden
   - weich: Format-Matrix mit ed25519 (OpenSSH), RSA (PEM und OpenSSH), ECDSA und PKCS#8, jeweils aus Datei und Agent
   - Zusammenspiel mit dem `Server` von `ssh2`
2. **Prebuild-Matrix** (sechs Ziele) einmal grün, mit festgelegter Toolchain, z. B. `cargo-zigbuild` mit `x86_64-unknown-linux-gnu.2.35` und `aarch64-unknown-linux-gnu.2.35`, sowie festem `MACOSX_DEPLOYMENT_TARGET`.
   - **hart:** Laut `objdump -T` ist die höchste `GLIBC_`-Symbolversion ≤ 2.35.
   - Smoke-Test je Ziel (`require` plus `scan()`):
     - musl in `node:24-alpine`
     - arm64 auf `ubuntu-24.04-arm` oder per QEMU
     - gnu zusätzlich in `ubuntu:22.04`
     - darwin gegen den In-Process-`Server` von `ssh2` oder ein lokal gestartetes `sshd`, weil die macOS-Runner kein Docker haben
   - Krypto-Backend: Entweder baut `aws-lc-rs` auf allen Zielen, oder es wird `ring` gewählt.
3. **ADR `0008`** mit Ergebnissen, Alternativen und den harten und weichen Kriterien:
   - Scheitert ein harter Nachweis ohne Workaround: Status „rejected“ und ein neuer Plan für einen OpenSSH-Unterprozess-Transport.
   - Fehlt ein weicher Nachweis: dokumentierte Einschränkung.

**Arbeitspaket B – Paket `@paratix/ssh-native` (neues Issue, blockiert C2)**

1. `packages/ssh-native` mit eigenem `[workspace]`, `deny.toml`, Toolchain-Pin und Tooling-Integration wie in den Entscheidungen 7, 10 und 11.
2. Die API aus Entscheidung 2 umsetzen. Signaturskizze, nur als Beispiel: `connect(options: ConnectOptions & { signal?: AbortSignal }, verifyHost: (info: HostKeyInfo) => Promise<void>): Promise<NativeSession>` und `scan(options: ScanOptions): Promise<HostKeyInfo>`. `NativeSession` bietet `exec`, `sftp`, `onDisconnect`, `close` und `destroy`.
3. Fehlercodes, Panics, Secrets und Event-Loop wie in den Entscheidungen 5 und 6.
4. Tests:
   - `cargo test`, darunter ein Panic-Auslöser, der nur unter einem Test-Feature existiert
   - Node-Tests der Anbindung gegen den Docker-sshd über `pnpm --filter @paratix/ssh-native test:integration`, in die Root-Suite eingehängt
   - Die harten Nachweise aus A.1 und das Zertifikats-Login werden Dauertests.
5. CI, Advisory-Job, Release-Matrix, Smoke-Tests, Publish-Skript und `publish.yml` wie unter „Betroffene Dateien“.
6. Vor dem ersten echten Release `publish.yml` im Modus `verify` laufen lassen.

**Arbeitspaket C1 – Transport-Schnittstelle mit `ssh2`-Adapter (neues Issue, eigenes Release, parallel zu A und B)**

1. `transport.ts` und `transportSsh2.ts` anlegen.
2. `ssh.ts`, `sshHelpers.ts`, `sftp.ts` und `runner.ts` auf die Schnittstelle umbauen, ohne Verhaltensänderung.
3. Unit-Tests auf den Transport-Fake umstellen, `transportSsh2.test.ts` ergänzen.
4. Integrations-Suite um die **Paritätsmatrix** erweitern, zuerst gegen `ssh2`:
   - Key-Datei
   - Agent
   - Passwort/Keyboard-Interactive
   - `agentForward` positiv und negativ
   - Abbruch während Exec mit Reconnect
   - Kanal-Ablehnung
   - Host-Key-Typ je sshd-Profil
5. Release als `refactor(paratix):`. Für Nutzer ändert sich nichts.

**Arbeitspaket C2 – Wechsel auf die Anbindung und Entfernen von `ssh2` (neues Issue, ein Release, nach B und C1)**

1. `transportNative.ts` mit dynamischem Import, Fehlerabbildung und Weitergabe der Verifier-Fehler umsetzen. Dazu `transportNative.test.ts`.
2. `cli.ts` prüft vor `prewarmSecrets`, ob sich die Anbindung laden lässt.
3. Der Key-Buffer wird nach der Übergabe geleert. Der Test zu R-0000521 wird mit Begründung ersetzt.
4. `create-paratix` umstellen: `scan()`, dynamischer Import, neutrale Namen und Vorlage.
5. `transportSsh2.ts` und seinen Test löschen. `ssh2` aus den Laufzeit-Abhängigkeiten entfernen und `pnpm-workspace.yaml` anpassen.
6. Install-Test des generierten Projekts auf Overrides aus dem Arbeitsbaum umstellen.
7. Die Paritätsmatrix aus C1.4 läuft unverändert gegen die Anbindung. Zusätzlich prüft ein Test, dass `verifiedHostPublicKey` für ed25519-, RSA- und ECDSA-Hosts byte-gleich zu `ssh2` ist und denselben Host-Key-Typ aushandelt. Als Referenz-Client dient `ssh2` aus den devDependencies.
8. Manuelle Läufe gegen echte Hosts von macOS arm64 und Linux x64. Datum und Version kommen in den PR.
9. Dokumentation anpassen, Release als `feat(paratix)!:`. Ins Changelog kommen: unterstützte Plattformen, glibc- und macOS-Mindestversion, Rust-Toolchain für Beitragende und nicht unterstützte Schlüsselformate.

**Folgearbeiten, jeweils eigenes Issue, nicht Teil dieses Plans**

- **D = #248, Benutzerzertifikate** (nach C2):
  - Agent-Identitäten mit Zertifikat
  - `ssh.certificate` für eine Zertifikatsdatei
  - `rsync` mit `CertificateFile`
  - verständliche Fehler bei abgelaufenem Zertifikat oder falschem Principal
  - Meldung, wenn der Agent nur unbrauchbare Identitäten liefert
  - Key-ID und Principals erscheinen in Meldungen nur gekürzt oder maskiert.
  - Integrationstest mit einem sshd, der nur `TrustedUserCAKeys` kennt
- **E, Host-Zertifikate auf dem Controller** (neues Issue, nach C2):
  - `@cert-authority` statt der heutigen Ablehnung (R-0000204) und `@revoked` für CA- und Zertifikatsschlüssel
  - Zertifikat-Algorithmen nur anbieten, wenn eine `@cert-authority`-Zeile passt
  - Der Hostname muss zu den Principals passen.
  - kein TOFU-Eintrag für zertifizierte Hosts
  - `rsync` mit `@cert-authority`-Anker

### Komponentenstruktur

Module → `SshConnection` (unverändert) → `SshConnectionImpl` → `transport.ts` → `transportSsh2.ts` (nur C1) bzw. `transportNative.ts` → `@paratix/ssh-native` (Rust, russh) → Plattformpaket.

`knownHosts.ts` bleibt die einzige Stelle, die über Vertrauen entscheidet. `create-paratix` nutzt nur `scan()`.

### Zustandsverwaltung

- Die tokio-Runtime von napi-rs entsteht beim ersten Aufruf. Das native Modul wird je Prozess nur einmal geladen, deshalb ist ADR-0007 nicht berührt.
- Den Verbindungs-Lebenszyklus steuert weiter `SshConnectionImpl`: Reconnect-Budget, Host-Key-Cache und Slot-Vergabe.

### API-Integration

Nicht relevant: Es kommt keine externe Dienst-API hinzu. Die öffentliche Paratix-API bleibt in A–C2 gleich. Erst D ergänzt `ssh.certificate`.

### Styling-Ansatz

Nicht relevant: keine Oberfläche.

### Barrierefreiheit

Nicht relevant: keine Oberfläche.

### Randfälle

- **Nicht unterstützte Plattform** (Windows, FreeBSD, glibc unter 2.35, macOS unter der Mindestversion):
  - `import "paratix"`, `--help` und `--version` funktionieren.
  - Ein Lauf bricht vor der ersten Secret-Abfrage mit der Meldung aus Entscheidung 7 ab.
  - `create-paratix` scaffoldet ohne Scan und gibt einen Hinweis aus.
- **Optionale Abhängigkeiten ausgelassen** oder Lockfile von einer anderen Plattform: dieselbe Meldung, mit Hinweis auf die Ursache.
- **Verifier wirft:** Derselbe `HostKeyVerificationError` erreicht den Aufrufer, und der Reconnect bricht ab. Antwortet der Callback nicht innerhalb von `readyTimeout`, endet `connect()` mit `TIMEOUT`.
- **Host mit `HostCertificate` vor E:** Ohne angebotene Zertifikat-Algorithmen präsentiert er seinen reinen Schlüssel. Pins und `known_hosts` greifen. Eine passende `@cert-authority`-Zeile führt weiter zur Ablehnung (R-0000204).
- **Server öffnet einen Kanal:** wird abgelehnt. Nur `auth-agent` bei `agentForward: true` ist erlaubt.
- **Abbruch während Exec:** `DISCONNECTED` führt in die Reconnect-Logik wie heute. Späte native Ereignisse werden verworfen.
- **Kanal abgelehnt:** `CHANNEL_OPEN_FAILED` liefert die Meldung aus #178, ohne Retry.
- **Langer stiller Befehl:** wird nicht abgebrochen, weil weder Keepalive noch Inaktivitäts-Timeout aktiv sind.
- **Panic in Rust:** `INTERNAL`, der Promise endet, nichts landet auf stderr.
- **Doppelter SIGINT:** `destroy()` kehrt synchron zurück, ohne offene Handles und ohne Abort.
- **Mehrere Ports:** Jeder Port bekommt die verbleibende Zeit bis zur Deadline.
- **Schlüssel:**
  - Nicht unterstütztes Format: `UNSUPPORTED_KEY` mit Format und einem Hinweis zur Umwandlung.
  - Verschlüsselter Schlüssel: `ENCRYPTED_KEY`.
  - Beide Meldungen enthalten keinen Schlüsselinhalt.
- **Große Dateien per SFTP:** Stream mit Backpressure. Timeout 120 s je Übertragung.
- **Veröffentlichung bricht mittendrin ab:** Ein neuer Lauf überspringt die schon veröffentlichten Versionen. Ein Push während des Laufs bricht ihn nicht ab.
- **Neues Advisory für eine Rust-Abhängigkeit:** Der Advisory-Job meldet es. PRs und Releases laufen weiter.

## Akzeptanzkriterien

- [ ] [A] ADR `docs/adr/0008-ssh-transport-russh-napi.md` liegt englisch mit Status „accepted“ vor. Es enthält die Ergebnisse jedes Nachweises aus A.1/A.2 selbst. Jeder harte Nachweis ist bestanden. Jeder weiche ist bestanden oder als Einschränkung begründet.
- [ ] [B] Die Matrix baut alle sechs Ziele. Der Smoke-Test besteht je Ziel mit dem Artefakt, das veröffentlicht wird. `linux-x64-gnu` besteht zusätzlich in `ubuntu:22.04`. Laut `objdump -T` liegt keine `GLIBC_`-Version über 2.35.
- [ ] [B] `publish.yml` im Modus `verify` erzeugt neun Tarballs. Jedes Manifest hat `repository`, und die Plattformpakete haben korrekte `os`/`cpu`/`libc`. `@paratix/ssh-native`, `paratix` und `create-paratix` enthalten exakte Versionen statt `workspace:`. Das Manifest im Tarball von `@paratix/ssh-native` listet alle sechs Plattformpakete in `optionalDependencies` mit exakter Release-Version.
- [ ] [B] Ein Node-Test der Anbindung meldet sich per Agent mit Schlüssel und Benutzerzertifikat an einem Docker-sshd an, der nur `TrustedUserCAKeys` akzeptiert.
- [ ] [B] In CI sind `rust:check` (fmt, clippy, test, `deny` für Lizenzen, Bans und Quellen) und der Diff-Check von `index.d.ts` grün. Der Advisory-Job existiert und läuft zeitgesteuert.
- [ ] [C1] Release mit `transport.ts` und `transportSsh2.ts`. Unit-Tests laufen gegen den Transport-Fake. `pnpm --filter paratix test:integration` ist mit der Paritätsmatrix aus C1.4 grün, gegen `ssh2`.
- [ ] [C2] `pnpm why ssh2 --prod` zeigt weder für `paratix` noch für `create-paratix` einen Eintrag. `transportSsh2.ts` ist gelöscht. In `pnpm-workspace.yaml` stehen `ssh2: false` und `cpu-features: false`.
- [ ] [C2] `pnpm agent:check`, `pnpm test:integration` und `bash scripts/runPodmanIntegration.sh pnpm agent:check:integration` sind grün. Die Paritätsmatrix aus C1.4 läuft unverändert gegen die Anbindung. Gelöschte oder ersetzte Tests stehen im PR einzeln mit Begründung, mindestens R-0000521.
- [ ] [C2] Ein Test belegt für ed25519-, RSA- und ECDSA-Hosts: gleicher ausgehandelter Host-Key-Typ wie bei `ssh2`, und `verifiedHostPublicKey` ist byte-gleich.
- [ ] [C2] `transportNative.test.ts` deckt jeden Fehlercode ab und belegt: Ein vom Verifier geworfener `HostKeyVerificationError` kommt als dasselbe Objekt beim Aufrufer an.
- [ ] [C2] Ein Test mit überschriebenem `process.platform`/`arch` belegt drei Punkte:
  - `import "paratix"` gelingt.
  - Die CLI bricht vor `prewarmSecrets` mit der dokumentierten Meldung ab.
  - `create-paratix` scaffoldet ohne Scan.
- [ ] [C2] `generated-project.install.test.ts` ist grün auf einem Commit mit erhöhter, nicht veröffentlichter Version und nutzt dabei das im Arbeitsbaum gebaute Binary.
- [ ] [C2] Die manuellen Läufe von macOS arm64 und Linux x64 gegen echte Hosts sind im PR mit Datum und Version dokumentiert.

## Validierungsplan

- **Rust:** `pnpm rust:check` lokal bei Änderungen, in CI immer im Job `check` von `ci.yml`. Der Advisory-Job wird einmal manuell ausgelöst.
- **Unit-Tests:** `pnpm agent:check`
  - `R-000xxxx` laufen gegen den Transport-Fake.
  - Die Adapter-Tests laufen gegen `ssh2` (C1) bzw. gegen ein gefälschtes natives Modul (C2).
- **Integration:**
  - `pnpm test:integration` (paratix, create-paratix, ssh-native) gegen die Docker-sshd-Profile, laut `AGENTS.md` Pflicht vor Änderungen an der `ssh`-Semantik
  - die Podman-Suite wie in `integration-check.yml`
- **Release:**
  - `publish.yml` im Modus `verify` auf dem Branch
  - Smoke-Tests je Ziel
  - Inhalt aller neun Tarballs prüfen, insbesondere die `optionalDependencies` im Tarball von `@paratix/ssh-native`
- **Manuell:**
  - Lauf von macOS arm64 und Linux x64 gegen einen echten Host per Agent
  - doppelter SIGINT während eines Reconnects
  - `--dry-run`

## Annahmen und offene Punkte

- „Nicht verifiziert“ wird in A bestätigt oder widerlegt, bevor B beginnt.
- Die Paketnamen unter `@paratix` sind reserviert. Eine Namensänderung ist nicht mehr zu erwarten.
- Aufwand laut Schätzung aus der Session: etwa 2–4 Wochen bis zur Parität. Dazu kommen Release-Pipeline, Paritätsmatrix und der Zwischenschritt C1.
- `~/.ssh/config` und `ProxyJump` nutzt Paratix heute nicht. Beides bleibt außerhalb des Umfangs und ist später über `direct-tcpip` nachrüstbar.
- Neuordnung des Epics #252, mit dem Nutzer abgestimmt:
  - neue Unter-Issues für A, B, C1, C2 und E
  - #248 wird auf den russh-Weg umgeschrieben und hängt von C2 ab.
  - #249, #250 und #251 bleiben inhaltlich und bekommen Verweise auf E.

## Plan-Review

**Ergebnis:** Freigegeben

### Prüfung vom 29.10.2026, Runde 2 (tiefer interaktiver Review)

Geprüft mit `effective-delivery` und `effective-engineering`. 29 Befunde: 2 kritisch, 16 wichtig, 11 Hinweise. Alle sind eingearbeitet. Sechs davon hat der Nutzer entschieden:

- Anbindung immer bauen, Lint nur bei Änderungen
- Advisory-Ausnahme und eigener Job
- `pnpm pack` mit Staging
- Laden bei Bedarf mit CLI-Vorabprüfung
- C1/C2 mit `ssh2`-Adapter
- harte Spike-Gates einschließlich `agentForward`

Es bleiben keine offenen Punkte.

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        1 |       3 |       0 |
| Sicherheit  |        0 |       4 |       1 |
| Datenschutz |        0 |       1 |       1 |
| Fehlerfälle |        0 |       4 |       1 |
| Testbarkeit |        1 |       3 |       1 |
| Umfang      |        0 |       2 |       2 |
| Wartbarkeit |        0 |       4 |       5 |

Mehrfach zugeordnete Befunde zählen in jedem betroffenen Bereich.

**Kritisch**

- **Lokales Binary für `agent:check`:** Woher es kommt, war ungeklärt. Eingearbeitet: Entscheidung 6 und 11 (immer bauen).
- **Install-Test des generierten Projekts:** Er hätte jeden Release-Commit blockiert. Eingearbeitet: Overrides aus dem Arbeitsbaum, eigenes Kriterium.

**Wichtig**

- **Verifier-Fehler:** Die Abbildung auf `HOST_KEY_REJECTED` verlor `HostKeyVerificationError`. Eingearbeitet: Das Fehlerobjekt wird weitergegeben.
- **RUSTSEC-2023-0071:** `cargo deny` war damit rot. Eingearbeitet: Ausnahme und eigener Job (Nutzerentscheidung).
- **Packweg:** `workspace:`, `optionalDependencies` und `napi prepublish` passten nicht zum Skript. Eingearbeitet: `pnpm pack` mit Staging (Nutzerentscheidung).
- **Plattform-Manifeste:** `repository`, `files` und die Frische-Prüfung fehlten. Eingearbeitet.
- **Versionen und Arbeitsbaum:** `Cargo.toml` per `extra-files` hätte `Cargo.lock` veralten lassen, generierte Dateien und `target/` den Baum verschmutzt. Eingearbeitet: Crate fest auf 0.0.0, Loader von Hand, `--locked`, `.gitignore`.
- **Tooling:** Typecheck, Lint, `test:integration` und Skript-Tests kannten das neue Paket nicht. Eingearbeitet.
- **Abbruch der Veröffentlichung:** `cancel-in-progress` hätte einen laufenden Publish abbrechen können. Eingearbeitet: `false`.
- **darwin-Smoke-Test:** Auf macOS-Runnern gibt es kein Docker. Eingearbeitet: In-Process-`Server` oder lokales `sshd`.
- **Kanäle des Servers:** Kanäle, die der Server öffnet, wurden nicht abgelehnt, was Agent-Missbrauch erlaubt hätte. Eingearbeitet: Ablehnung und Negativtest.
- **Panics:** Ohne Behandlung drohten Hänger, Abbrüche oder Ausgaben an der Maskierung vorbei. Eingearbeitet: `unwind`, stiller Hook, `INTERNAL`.
- **Ladezeitpunkt:** Wann die Anbindung geladen wird, war offen. Eingearbeitet: bei Bedarf mit CLI-Vorabprüfung (Nutzerentscheidung).
- **Host-Key-Algorithmen:** Die Reihenfolge war nicht festgelegt, und ECDSA/RSA waren nicht testbar. Eingearbeitet: `Preferred.key` gepinnt, sshd-Profile je Schlüsseltyp.
- **Schnitt von C:** Umbau und Wechsel steckten in einem Paket. Eingearbeitet: C1/C2 (Nutzerentscheidung).
- **Fehlercodes:** Die Liste war unvollständig. Eingearbeitet.
- **Akzeptanzkriterien:** Sie waren keinem Arbeitspaket zugeordnet, und das ADR-Kriterium widersprach A.3. Eingearbeitet: Kennzeichnung [A]/[B]/[C1]/[C2], umformuliert, Kriterium für die manuellen Läufe ergänzt.
- **Spike-Abbruchkriterien:** Sie waren unbestimmt. Eingearbeitet: harte und weiche Gates (Nutzerentscheidung).

**Hinweise**

- `knownHosts.ts` braucht keinen asynchronen Umbau.
- Keepalive ist aus der API gestrichen.
- `ssh-key` wird nur über `russh::keys` genutzt.
- `@revoked` gibt es schon, und R-0000204 bleibt bis E.
- R-0000521 wird ersetzt.
- In der Vorlage entfallen `ssh2` und `cpu-features` ganz.
- Die Angabe zu `packages/paratix/AGENTS.md` ist korrigiert.
- Toolchain für glibc und macOS-Mindestversion sind festgelegt und werden geprüft.
- Die Platzhalter werden ohne Token veröffentlicht (Nachtrag vom 29.10.2026: interaktive Sitzung mit 2FA, dazu die 2-Tage-Frist der Trusted-Publisher-Konfiguration).
- Unklare Formulierungen zu Event-Loop, Test-Agent, Abbruch und Callback-Timeout sind präzisiert.
- Die Bedingung für `rust:check` ist präzisiert.

### Prüfung vom 29.10.2026, Runde 1 (Lückenanalyse und Plan-Review)

24 Befunde: 1 kritisch, 11 wichtig, 12 Hinweise. Alle sind eingearbeitet. Vier davon hat der Nutzer entschieden: glibc 2.35, Laden bei Bedarf in `create-paratix`, Rust-Prüfungen bei Änderungen, Platzhalter-Erstveröffentlichung.

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        1 |       4 |       2 |
| Sicherheit  |        0 |       2 |       0 |
| Datenschutz |        0 |       0 |       1 |
| Fehlerfälle |        0 |       3 |       4 |
| Testbarkeit |        0 |       2 |       1 |
| Umfang      |        0 |       2 |       1 |
| Wartbarkeit |        0 |       2 |       3 |

Die Befunde betrafen:

- glibc-Untergrenze
- Smoke-Tests je Ziel
- Mechanismus für Versionen
- Recovery beim Publish
- Trusted-Publishing-Bootstrap
- Abhängigkeit von `rsync` von `verifiedHostPublicKey`
- keine Host-Zertifikat-Algorithmen vor E
- `ref`-Semantik
- Paritätsmatrix
- Format-Matrix
- Pflege der Rust-Abhängigkeiten
- Laden in `create-paratix`
- `allowBuilds`
- Kanal-Ablehnung
- Keepalive
- `zeroize`-Umfang
- Anzahl der Tarballs
- Publish-Skript für `.node`
- `scan()`
- Zuordnung der Agent-Meldung
- ADR-Sprache
- Toolchain in `agent:check`
- Installationsfallen
- Trennung verifiziert/unverifiziert

### Zusammenfassung

| Bereich     | Kritisch | Wichtig | Hinweis |
| ----------- | -------: | ------: | ------: |
| Architektur |        0 |       0 |       0 |
| Sicherheit  |        0 |       0 |       0 |
| Datenschutz |        0 |       0 |       0 |
| Fehlerfälle |        0 |       0 |       0 |
| Testbarkeit |        0 |       0 |       0 |
| Umfang      |        0 |       0 |       0 |
| Wartbarkeit |        0 |       0 |       0 |

Offene Befunde nach beiden Runden: keine.

### Befunde

- Keine offenen Befunde. Alle Befunde aus Runde 1 und 2 sind oben dokumentiert und eingearbeitet.

## Offene Punkte

- Keine offenen Punkte.
