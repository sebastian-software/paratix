# Paratix — Idempotentes VPS-Setup-Tool in TypeScript

## Überblick

Paratix ist ein CLI-Tool, das lokal läuft und sich per SSH auf Zielserver
verbindet. Der Benutzer beschreibt seinen Server in einer TypeScript-Datei und
führt diese über das CLI aus:

```
paratix apply ./my-server.ts
```

Paratix führt die darin definierten Schritte sequenziell aus. Jeder Schritt
prüft vor seiner Aktion, ob der gewünschte Zustand bereits erreicht ist. Ein
Lauf kann jederzeit abgebrochen und neu gestartet werden — bereits erledigte
Schritte überspringen sich in Millisekunden.

---

## Architektur: Playbook → Recipe → Modul

Paratix hat drei Hierarchieebenen:

```
Playbook (die TypeScript-Datei des Benutzers)
│
├── Recipe: "hardening"
│   ├── Modul: apt.installed("ufw", "fail2ban")
│   ├── Modul: sshd.port(22022)
│   ├── Modul: file.copy("/etc/ssh/sshd_config")
│   ├── Modul: ufw.rule("allow", [22022, 80, 443])
│   └── Signal: service.restart("sshd")  ← nur wenn etwas changed war
│
├── Recipe: "podman"
│   ├── Modul: apt.installed("podman")
│   ├── Modul: file.copy("/etc/containers/registries.conf")
│   └── Signal: service.restart("podman")
│
└── Modul: apt.upgrade("2024-03-10")  ← einzelnes Modul direkt im Playbook
```

### Modul (Plugin)

Ein Modul ist die kleinste Einheit. Es bildet eine einzelne idempotente
Operation auf dem Server ab und implementiert die **Plugin-Schnittstelle**:

```typescript
/** Einfacher Wert oder lazy evaluierte Funktion (z.B. für OTPs) */
type EnvValue = string | number | (() => string | number) | (() => Promise<string | number>);

type Env = Record<string, EnvValue>;

interface ModuleResult {
  status: "ok" | "changed" | "skipped" | "failed";
  /** Optionale Metadaten, die in den Env einfließen */
  meta?: Env;
}

interface Module {
  /** Menschenlesbarer Name für die Ausgabe */
  name: string;
  /** Prüft ob der gewünschte Zustand bereits erreicht ist */
  check(ssh: SshConnection, env: Env): Promise<"ok" | "needs-apply">;
  /** Führt die Änderung durch */
  apply(ssh: SshConnection, env: Env): Promise<ModuleResult>;
}
```

Jedes Modul erhält bei `check` und `apply` den aktuellen `env` — eine
aggregierte Map aller bisherigen Meta-Einträge plus der initialen Env-Werte
aus CLI, `.env`-Datei und Playbook.

**Lazy Env-Werte:** Ein Env-Wert kann statt eines direkten Strings auch eine
Funktion sein, die den Wert erst bei Zugriff erzeugt (optional asynchron).
Das ist notwendig für zeitkritische Werte wie OTPs, die erst zum
Verwendungszeitpunkt generiert werden dürfen — nicht bereits beim Auflösen.
Der Runner bietet eine Hilfsfunktion `resolveEnv(env, key)` die den Wert
transparent auflöst:

```typescript
/** Löst einen Env-Wert auf (direkt oder lazy) */
async function resolveEnv(env: Env, key: string): Promise<string | number> {
  const value = env[key];
  if (typeof value === "function") return await value();
  return value;
}
```

Templates und Module nutzen `resolveEnv` statt direktem Zugriff auf `env[key]`,
damit lazy Werte korrekt aufgelöst werden.

### Recipe

Eine Recipe bündelt mehrere Module zu einer logischen Einheit (z.B.
"SSH-Hardening" = Port ändern + Key-Only-Auth + fail2ban + Firewall-Regeln).

**Recipes implementieren dieselbe Plugin-Schnittstelle wie Module.** Ein
Playbook muss nicht unterscheiden, ob es ein einzelnes Modul oder eine Recipe
ausführt (Composite Pattern). Die Recipe reicht dabei die Einzelergebnisse
ihrer Module transparent nach oben durch, sodass die Ausgabe die volle
Granularität behält.

### Playbook (Serverdefinition)

Das Playbook ist die TypeScript-Datei, die der Benutzer schreibt. Es definiert
den Server und eine geordnete Liste von Recipes und Modulen:

```typescript
import { server, recipe } from "paratix";
import { apt, sshd, file, ufw, service } from "paratix/modules";

export default server({
  name: "vps-primary",
  host: "1.2.3.4",
  ssh: {
    user: "root",
    ports: [22, 22022], // Ports werden der Reihe nach durchprobiert
    privateKey: "~/.ssh/id_ed25519",
    passwordFallback: true, // bei Key-Fehler interaktiv nach Passwort fragen
  },

  env: {
    "app.domain": "example.com",
    "app.port": 3000,
  },

  run: [
    recipe("hardening", [
      apt.installed("ufw", "fail2ban"),
      sshd.port(22022),
      file.template("/etc/ssh/sshd_config", "./templates/sshd_config.tpl"),
      ufw.rule("allow", [22022, 80, 443]),
    ], {
      signals: [service.restart("sshd")],
    }),

    recipe("podman", [
      apt.installed("podman"),
      file.copy("/etc/containers/registries.conf", "./configs/registries.conf"),
    ], {
      signals: [service.restart("podman")],
    }),

    recipe("app", [
      file.template("/etc/nginx/sites-available/app", "./templates/nginx-app.tpl"),
    ], {
      signals: [service.restart("nginx")],
    }),

    apt.upgrade("2024-03-10"),
  ],
});
```

Die **Definitionsreihenfolge bestimmt die Ausführungsreihenfolge**. Es gibt
keine implizite Abhängigkeitsauflösung — der Benutzer kontrolliert die
Reihenfolge explizit.

---

## Kernkonzept 1: Echte Idempotenz

### Prinzip

Jedes Modul folgt dem Muster **Check → Apply**:

```
Ist der gewünschte Zustand bereits erreicht?
  JA  → Status "ok",      nichts tun
  NEIN → Status "changed", Aktion ausführen
```

Der Server wird nie in einen undefinierten Zwischenzustand gebracht, weil jede
Aktion vor ihrer Ausführung gegen den tatsächlichen Serverzustand geprüft
wird — nicht gegen irgendein gespeichertes Protokoll.

### Beispiel: Paketinstallation

```
CHECK:  dpkg -l nginx → nicht installiert
APPLY:  apt-get install -y nginx
STATUS: changed

--- zweiter Run ---

CHECK:  dpkg -l nginx → installiert (Version 1.24)
APPLY:  (entfällt)
STATUS: ok
```

### Beispiel: Konfigurationsdatei

```
CHECK:  sha256sum /etc/ssh/sshd_config → a3f9...
        sha256sum ./configs/sshd_config → a3f9...  (identisch)
APPLY:  (entfällt)
STATUS: ok

--- nach lokaler Änderung an sshd_config ---

CHECK:  sha256sum /etc/ssh/sshd_config → a3f9...
        sha256sum ./configs/sshd_config → 7c21...  (unterschiedlich)
APPLY:  scp ./configs/sshd_config → /etc/ssh/sshd_config
STATUS: changed
```

### Warum das ausreicht

Nach einem Netzwerkabbruch wird `paratix apply` einfach erneut ausgeführt.
Alle bereits erfolgreich abgeschlossenen Schritte erkennen ihren Zielzustand
und überspringen sich selbst. Paratix setzt dort fort, wo es tatsächlich noch
Arbeit zu tun gibt — ohne explizites Resume-Protokoll.

---

## Kernkonzept 2: Optionales State-Flag (für teure Operationen)

### Wann ist das nötig?

Manche Operationen sind **nicht günstig zu prüfen** oder **nicht sicher
wiederholbar**:

| Situation                   | Problem                                                |
| --------------------------- | ------------------------------------------------------ |
| `apt upgrade` (100+ Pakete) | Dauert Minuten, jedes Mal neu zu starten ist teuer     |
| Großer Datei-Download       | Netzwerk-intensiv, kein effizienter Hash-Check möglich |
| Einmaliges Init-Skript      | Darf nur einmal laufen (z.B. Datenbankinitialisierung) |
| Komplexe Neukonfiguration   | Seiteneffekte machen Wiederholung riskant              |

Für diese Module wird nach erfolgreichem Abschluss eine **Flag-Datei auf dem
Server** hinterlassen.

### Mechanismus

```
/var/lib/paratix/flags/
├── apt-upgrade-20240310
├── podman-install
└── db-init
```

```
CHECK:  [ -f /var/lib/paratix/flags/apt-upgrade-20240310 ]
          → Datei existiert nicht
APPLY:  apt-get upgrade -y
        (bei Erfolg): touch /var/lib/paratix/flags/apt-upgrade-20240310
STATUS: changed

--- nach Abbruch und Neustart ---

CHECK:  [ -f /var/lib/paratix/flags/apt-upgrade-20240310 ]
          → Datei existiert
APPLY:  (entfällt)
STATUS: skipped (flag)
```

### Versionsbasierte Flags

Soll ein teures Modul bei einer neuen Version erneut laufen, enthält der
Flag-Name eine Version oder ein Datum:

```
apt-upgrade-20240310   ← läuft beim nächsten Upgrade mit neuem Datum erneut
podman-install-v5.0    ← läuft erneut wenn auf v5.1 aktualisiert wird
```

---

## Kernkonzept 3: Stabile SSH-Verbindung

### Multi-Port-Verbindung

Jeder Server kann mit mehreren SSH-Ports definiert werden:

```typescript
ssh: {
  user: "root",
  ports: [22, 22022],
  privateKey: "~/.ssh/id_ed25519",
  passwordFallback: true,
}
```

### Authentifizierung

Paratix authentifiziert sich bevorzugt per **SSH-Key**. Der Pfad zum privaten
Schlüssel wird in der Serverdefinition angegeben (`privateKey`). Mit
`passwordFallback: true` wird der Benutzer interaktiv im Terminal nach dem
Passwort gefragt, falls die Key-Authentifizierung fehlschlägt — z.B. bei der
Ersteinrichtung eines frischen Servers, auf dem der eigene Key noch nicht
hinterlegt ist. Passwörter werden nicht in der Serverdefinition gespeichert.

Reihenfolge der Authentifizierung:
1. Key-basiert (`privateKey`)
2. Interaktive Passwortabfrage im Terminal (falls `passwordFallback: true`)

### Multi-Port-Verbindung

Beim Verbindungsaufbau probiert Paratix die Ports **der Reihe nach durch**,
bis eine Verbindung steht. Das ermöglicht:

- **Ersteinrichtung:** Port 22 funktioniert initial, nach Umlegung auf 22022
  verbindet sich Paratix beim nächsten Lauf über den neuen Port.
- **Kein lokaler State nötig:** Der Verbindungsport wird zur Laufzeit ermittelt.

### Port-Umlegung zur Laufzeit

Wenn ein Modul den SSH-Port ändert (z.B. `sshd.port(22022)`), meldet es den
neuen Port über `meta` zurück (`{ "sshd.port": 22022 }`). Paratix erkennt
diesen Key und stellt die SSH-Verbindung auf den neuen Port um.

**Sicherheitsprüfung:** Das `sshd.port`-Modul validiert vor der Umlegung, dass
der Zielport in der `ssh.ports`-Liste der Serverdefinition eingetragen ist.
Andernfalls würde Paratix sich nach einem Reboot nicht mehr verbinden können.

### Reconnect bei Verbindungsverlust

Bei einem Verbindungsabbruch (Netzwerkfehler, Server-Reboot) versucht Paratix
automatisch, die Verbindung wiederherzustellen:

```
1. Verbindungsverlust erkannt
2. Warte kurz (exponentielles Backoff)
3. Probiere alle konfigurierten Ports der Reihe nach
4. Verbindung steht → fahre mit dem aktuellen Modul fort (check erneut)
5. Timeout erreicht → Abbruch mit Fehlermeldung
```

Das Timeout ist per CLI-Parameter konfigurierbar:

```
paratix apply ./my-server.ts --reconnect-timeout 300
```

Standardmäßig wartet Paratix unbegrenzt (interaktiver Modus). Für
automatisierte Läufe (Cronjob, CI/CD) sollte ein Timeout gesetzt werden.

### Server-Reboot

Wenn ein Modul einen Server-Reboot auslöst (z.B. nach einem Kernel-Update),
pollt Paratix aktiv auf allen konfigurierten Ports, bis der Server wieder
erreichbar ist. Danach setzt es den Lauf fort — alle bereits erledigten
Schritte überspringen sich via Idempotenz-Check.

### Output-Streaming

Die Ausgabe von SSH-Befehlen wird in Echtzeit auf das lokale Terminal
gestreamt. Das ist wichtig für:

- **Lange Operationen:** `apt upgrade` oder `docker build` können Minuten
  dauern — der Benutzer sieht den Fortschritt live statt auf ein stilles
  Terminal zu starren.
- **Fehlerdiagnose:** Fehlermeldungen erscheinen sofort, nicht erst nach
  Abschluss des Befehls.
- **Interaktive Kontrolle:** Der Benutzer kann bei hängenden Prozessen
  frühzeitig Ctrl+C drücken.

Das Streaming ist standardmäßig aktiv. Module können es pro Befehl steuern:

```typescript
// Ausgabe wird live gestreamt (Standard bei apply)
await ssh.exec("apt-get upgrade -y");

// Ausgabe wird unterdrückt, nur Rückgabewert zählt (Standard bei check)
const result = await ssh.exec("dpkg -l nginx", { silent: true });
```

Bei `check()` wird die Ausgabe standardmäßig unterdrückt (silent), da Checks
schnell und unauffällig laufen sollen. Bei `apply()` wird sie gestreamt, damit
der Benutzer den Fortschritt verfolgen kann. Module können dieses Verhalten
bei Bedarf überschreiben.

### SshConnection-API

Die `SshConnection` ist das zentrale Objekt, das Module für alle
Server-Interaktionen nutzen. Sie bietet Hilfsmethoden für typische
Operationen, damit Module nicht selbst SSH-Befehle zusammenbauen und
Ausgaben parsen müssen.

```typescript
interface ExecResult {
  /** Exit-Code des Befehls */
  code: number;
  /** Gesamte stdout-Ausgabe */
  stdout: string;
  /** Gesamte stderr-Ausgabe */
  stderr: string;
}

interface ExecOptions {
  /** Ausgabe unterdrücken (Standard: false bei apply, true bei check) */
  silent?: boolean;
  /** Timeout in Millisekunden (Standard: kein Timeout) */
  timeout?: number;
  /** Bei Exit-Code != 0 keinen Fehler werfen (Standard: false) */
  ignoreExitCode?: boolean;
  /** Umgebungsvariablen für den Befehl */
  env?: Record<string, string>;
}

interface SshConnection {
  // --- Befehlsausführung ---

  /** Führt einen Shell-Befehl aus. Wirft bei Exit-Code != 0. */
  exec(command: string, options?: ExecOptions): Promise<ExecResult>;

  /**
   * Führt einen Befehl aus und gibt nur den Exit-Code zurück.
   * Wirft nie — ideal für Checks.
   *
   * Beispiel:
   *   const installed = await ssh.test("dpkg -l nginx");
   *   const exists = await ssh.test("[ -f /etc/nginx/nginx.conf ]");
   */
  test(command: string): Promise<boolean>;

  /**
   * Führt einen Befehl aus und gibt stdout zurück (getrimmt).
   * Wirft bei Exit-Code != 0.
   *
   * Beispiel:
   *   const hostname = await ssh.output("hostname");
   *   const hash = await ssh.output("sha256sum /etc/ssh/sshd_config | cut -d' ' -f1");
   */
  output(command: string, options?: ExecOptions): Promise<string>;

  /**
   * Führt einen Befehl aus und gibt stdout als Zeilen-Array zurück.
   *
   * Beispiel:
   *   const packages = await ssh.lines("dpkg --get-selections | grep -v deinstall | awk '{print $1}'");
   */
  lines(command: string, options?: ExecOptions): Promise<string[]>;

  // --- Dateioperationen ---

  /**
   * Liest eine Datei vom Server.
   *
   * Beispiel:
   *   const config = await ssh.readFile("/etc/ssh/sshd_config");
   */
  readFile(remotePath: string): Promise<string>;

  /**
   * Schreibt eine Datei auf den Server. Erstellt Elternverzeichnisse
   * automatisch. Setzt optional Berechtigungen und Besitzer.
   *
   * Beispiel:
   *   await ssh.writeFile("/etc/nginx/sites-available/app", renderedConfig, {
   *     mode: "644",
   *     owner: "root:root",
   *   });
   */
  writeFile(remotePath: string, content: string, options?: {
    mode?: string;
    owner?: string;
  }): Promise<void>;

  /**
   * Kopiert eine lokale Datei auf den Server.
   *
   * Beispiel:
   *   await ssh.uploadFile("./configs/sshd_config", "/etc/ssh/sshd_config");
   */
  uploadFile(localPath: string, remotePath: string, options?: {
    mode?: string;
    owner?: string;
  }): Promise<void>;

  /**
   * Lädt eine Datei vom Server herunter.
   *
   * Beispiel:
   *   await ssh.downloadFile("/var/log/auth.log", "./logs/auth.log");
   */
  downloadFile(remotePath: string, localPath: string): Promise<void>;

  /**
   * Prüft ob eine Datei/ein Verzeichnis existiert.
   * Shortcut für ssh.test("[ -e <path> ]").
   */
  exists(remotePath: string): Promise<boolean>;

  /**
   * Gibt den SHA-256-Hash einer Remote-Datei zurück.
   * Gibt null zurück wenn die Datei nicht existiert.
   *
   * Beispiel:
   *   const remoteHash = await ssh.sha256("/etc/ssh/sshd_config");
   *   const localHash = sha256(fs.readFileSync("./configs/sshd_config"));
   *   if (remoteHash === localHash) return "ok";
   */
  sha256(remotePath: string): Promise<string | null>;
}
```

### Warum Hilfsmethoden?

Ohne Hilfsmethoden müsste jedes Modul SSH-Befehle als Strings
zusammenbauen, Exit-Codes manuell prüfen und Ausgaben parsen:

```typescript
// Ohne Hilfsmethoden (fehleranfällig, repetitiv)
const result = await ssh.exec("dpkg -l nginx 2>/dev/null | grep -q '^ii'", {
  ignoreExitCode: true,
});
if (result.code === 0) return "ok";

// Mit Hilfsmethoden (klar, kurz)
if (await ssh.test("dpkg -l nginx | grep -q '^ii'")) return "ok";
```

```typescript
// Ohne Hilfsmethoden
const result = await ssh.exec("sha256sum /etc/ssh/sshd_config");
const hash = result.stdout.split(" ")[0].trim();

// Mit Hilfsmethoden
const hash = await ssh.sha256("/etc/ssh/sshd_config");
```

Die Hilfsmethoden eliminieren Boilerplate und sorgen dafür, dass Module sich
auf ihre Domänenlogik konzentrieren können statt auf SSH-Plumbing.

---

## Kernkonzept 4: Env-System und Templates

### Env — der gemeinsame Kontext

Alle Module teilen sich einen gemeinsamen `Env` — eine flache
`Record<string, EnvValue>`-Map (siehe `EnvValue`-Typ oben). Werte sind in der
Regel Strings oder Zahlen; für zeitkritische Werte wie OTPs können sie auch
lazy Funktionen sein. Der Env wird aus drei Quellen befüllt, wobei spätere
Quellen frühere überschreiben:

```
1. .env-Datei    (z.B. .env.production)
2. CLI-Parameter (--env key=value)
3. Playbook      (env: { ... } in der Serverdefinition)
4. Module        (meta-Einträge aus ModuleResult zur Laufzeit)
```

Jedes Modul erhält bei `check()` und `apply()` den **aktuellen, aggregierten
Env**. Setzt ein Modul `meta`-Einträge im `ModuleResult`, werden diese in den
Env übernommen und stehen allen nachfolgenden Modulen zur Verfügung.

**Best Practice:** Der Key eines Meta-Eintrags beginnt mit dem Modulnamen,
um Konflikte zu vermeiden:

```typescript
// sshd.port-Modul setzt nach Umlegung:
{ meta: { "sshd.port": 22022 } }

// user.present-Modul setzt nach Erstellung:
{ meta: { "user.home": "/home/deploy" } }
```

### Templates

Für die Generierung von Konfigurationsdateien bietet Paratix ein
Template-System. Templates haben Zugriff auf alle Env-Einträge:

```
# ./templates/nginx-app.tpl
server {
    listen 80;
    server_name {{app.domain}};

    location / {
        proxy_pass http://127.0.0.1:{{app.port}};
    }
}
```

Das Modul `file.template` rendert das Template mit dem aktuellen Env und
vergleicht das Ergebnis per SHA-256 mit der Datei auf dem Server:

```
CHECK:  sha256(render(template, env)) vs. sha256(remote file)
        → unterschiedlich
APPLY:  gerenderte Datei auf den Server kopieren
STATUS: changed
```

Da der Env auch Meta-Einträge vorheriger Module enthält, können Templates
auf dynamische Werte zugreifen, die erst zur Laufzeit bekannt werden.

### Env in der Serverdefinition

```typescript
export default server({
  // ...
  env: {
    "app.domain": "example.com",
    "app.port": 3000,
  },
  // ...
});
```

### Env via CLI und .env-Datei

```
paratix apply ./my-server.ts --env app.domain=staging.example.com
paratix apply ./my-server.ts --env-file .env.production
```

CLI-Parameter überschreiben Werte aus dem Playbook. So kann dasselbe Playbook
für verschiedene Umgebungen (Staging, Production) verwendet werden, ohne den
Code zu ändern.

---

## Signaling: Service-Neustarts

Module können Änderungen an Konfigurationsdateien vornehmen, die erst nach
einem Service-Neustart wirksam werden. Dafür gibt es ein Signal-System.

### Auf Recipe-Ebene

Signale werden am Ende einer Recipe deklariert und **nur ausgeführt, wenn
mindestens ein Modul innerhalb der Recipe `changed` zurückgegeben hat**:

```typescript
recipe("hardening", [
  sshd.port(22022),
  file.copy("/etc/ssh/sshd_config", "./configs/sshd_config"),
  ufw.rule("allow", [22022, 80, 443]),
], {
  signals: [service.restart("sshd")],
})
```

Wenn weder `sshd.port` noch `file.copy` etwas geändert haben, wird `sshd`
nicht neu gestartet.

### Auf Playbook-Ebene

Signale können auch auf Playbook-Ebene definiert werden. Sie werden am Ende
des gesamten Laufs ausgewertet:

```typescript
export default server({
  // ...
  run: [ /* ... */ ],
  signals: [service.restart("nginx")],
});
```

### Signale als Module

Signale implementieren ebenfalls die Plugin-Schnittstelle. Ihr `check` ist
immer `needs-apply` (wenn getriggert) oder `ok` (wenn nicht getriggert).
Dadurch sind sie in der Ausgabe wie jedes andere Modul sichtbar.

---

## Modul-Typen im Überblick

### Idempotente Module (Standard)

| Modul             | Check-Strategie              |
| ----------------- | ---------------------------- |
| `apt.installed`   | `dpkg -l <paket>` prüfen     |
| `apt.absent`      | `dpkg -l <paket>` prüfen     |
| `file.copy`       | SHA-256 Hash vergleichen     |
| `file.line`       | `grep -qF` nach Zeile suchen |
| `service.enabled` | `systemctl is-enabled`       |
| `service.running` | `systemctl is-active`        |
| `user.present`    | `id <user>` prüfen           |
| `ufw.rule`        | `ufw status` parsen          |
| `sshd.port`       | `sshd_config` auslesen       |

### State-Flag-Module (für teure Operationen)

| Modul             | Flag-Strategie                 |
| ----------------- | ------------------------------ |
| `apt.upgrade`     | Flag mit Datum                 |
| `apt.distUpgrade` | Flag mit Datum                 |
| `script.once`     | Flag mit Script-Name + Version |
| `download.large`  | Flag mit URL-Hash              |

---

## CLI

### Aufruf

```
paratix apply ./my-server.ts
```

Die TypeScript-Datei wird via `tsx` ausgeführt.

### Parameter

| Parameter              | Beschreibung                                          |
| ---------------------- | ----------------------------------------------------- |
| `--reconnect-timeout`  | Timeout in Sekunden für SSH-Reconnect (Standard: ∞)   |
| `--dry-run`            | Nur Check ausführen, keine Änderungen vornehmen       |
| `--env key=value`      | Env-Eintrag setzen (überschreibt Playbook-Werte)      |
| `--env-file <path>`    | Env-Einträge aus DotEnv-Datei laden                   |

---

## Ablauf eines vollständigen Runs

```
1. Serverdefinition laden (TypeScript-Datei via tsx)
2. Env initialisieren (.env-Datei → CLI-Parameter → Playbook-env)
3. SSH-Verbindung herstellen (Ports der Reihe nach durchprobieren)
4. State-Flags vom Server einlesen (/var/lib/paratix/flags/)
5. Recipes und Module sequenziell ausführen:
   a. Prüfe State-Flag (falls vorhanden) → skip
   b. Führe Check aus (mit aktuellem Env) → ok / needs-apply
   c. Führe Apply aus (falls nötig)       → changed / failed
   d. Setze State-Flag (falls vorhanden und erfolgreich)
   e. Merge meta in Env (z.B. "sshd.port" → SSH-Reconnect)
5. Signale der Recipe auswerten (falls etwas changed war)
6. Nächste Recipe / nächstes Modul
7. Signale des Playbooks auswerten
8. Abschlussbericht ausgeben
```

### Abbruchverhalten

```
Abbruch nach Modul 3 von 8:

Nächster Run:
  Modul 1: Check → ok      (0.05s)
  Modul 2: Check → ok      (0.03s)
  Modul 3: Check → ok      (0.04s)  ← war bereits erfolgreich
  Modul 4: Check → changed (tatsächlich noch offen)
  ...
```

Bei Verbindungsabbruch wird nicht neu gestartet, sondern die SSH-Verbindung
wiederhergestellt und der Lauf fortgesetzt.

---

## Ausgabe

```
[hardening]
  ✓  apt: fail2ban ufw              ok
  ↺  sshd: port → 22022             changed
  ↺  file: /etc/ssh/sshd_config     changed
  ✓  ufw: allow 22022,80,443        ok
  ↺  signal: restart sshd           triggered
  ✓  service: fail2ban              ok

[podman]
  ✓  apt: podman                    ok
  ↺  file: /etc/containers/...      changed
  ↺  signal: restart podman         triggered

  ✓  apt: upgrade (2024-03-10)      ok

──────────────────────────────────────
3 changed · 5 ok · 0 skipped · 0 failed · 2 signals triggered
```

---

## Reproduzierbarkeit auf mehreren Servern

Da kein zentraler State existiert, kann dasselbe Playbook auf beliebig vielen
Servern ausgeführt werden:

```typescript
// vps-primary.ts
export default server({
  name: "vps-primary",
  host: "1.2.3.4",
  ssh: { user: "root", ports: [22, 22022] },
  run: [hardening, podman],
});

// vps-backup.ts
export default server({
  name: "vps-backup",
  host: "5.6.7.8",
  ssh: { user: "root", ports: [22, 22022] },
  run: [hardening, podman],
});
```

```
paratix apply ./vps-primary.ts
paratix apply ./vps-backup.ts
```

---

## Abgrenzung zu Ansible

| Merkmal         | Ansible        | Paratix                    |
| --------------- | -------------- | -------------------------- |
| Sprache         | YAML + Python  | TypeScript                 |
| Typsicherheit   | Nein           | Ja                         |
| Idempotenz      | Ja (Module)    | Ja (Module)                |
| State           | zustandslos    | zustandslos + opt. Flags   |
| Modulökosystem  | riesig (3000+) | selbst gebaut, klein       |
| Agentless       | Ja             | Ja                         |
| Lernkurve       | moderat        | gering (plain TypeScript)  |
| Erweiterbarkeit | Plugins/Roles  | Plugin-Schnittstelle (TS)  |
| SSH-Resilienz   | begrenzt       | Multi-Port + Auto-Reconnect|
