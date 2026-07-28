# Paratix — Idempotentes VPS-Setup-Tool in TypeScript

> **Historical document (2026-03-12):** This is the original project description,
> not a normative reference for the current feature set. The current module and
> agent reference is the
> [Paratix LLM Guide](../packages/paratix/llm-guide.md).

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
│   ├── Modul: package.installed("ufw", "fail2ban")
│   ├── Modul: sshd.port(22022)
│   ├── Modul: file.copy("/etc/ssh/sshd_config")
│   ├── Modul: ufw.rule("allow", [22022, 80, 443])
│   └── Signal: service.restart("sshd")  ← nur wenn etwas changed war
│
├── Recipe: "podman"
│   ├── Modul: package.installed("podman")
│   ├── Modul: file.copy("/etc/containers/registries.conf")
│   └── Signal: service.restart("podman")
│
└── Modul: package.upgrade("2024-03-10")  ← einzelnes Modul direkt im Playbook
```

### Modul (Plugin)

Ein Modul ist die kleinste Einheit. Es bildet eine einzelne idempotente
Operation auf dem Server ab und implementiert die **Plugin-Schnittstelle**:

```typescript
/** Einfacher Wert oder lazy evaluierte Funktion (z.B. für OTPs) */
type EnvValue =
  | string
  | number
  | boolean
  | (() => string | number | boolean)
  | (() => Promise<string | number | boolean>)

type Env = Record<string, EnvValue>

type ModuleMetaEntry =
  | {
      kind: "env"
      name: string
      resolve: () => Promise<string | number | boolean>
      valueType: "string" | "number" | "boolean"
    }
  | { kind: "sshd.port"; port: number }
  | { kind: "system.host"; host: string }
  | { kind: "system.reboot" }

interface ModuleResult {
  status: "ok" | "changed" | "skipped" | "failed"
  /** Optionale typisierte Meta-Einträge fuer Env und Runner-Steuerung */
  meta?: ModuleMetaEntry[]
}

interface Module {
  /** Menschenlesbarer Name für die Ausgabe */
  name: string
  /** Prüft ob der gewünschte Zustand bereits erreicht ist */
  check(ssh: SshConnection, env: Env): Promise<"ok" | "needs-apply">
  /** Führt die Änderung durch */
  apply(ssh: SshConnection, env: Env): Promise<ModuleResult>
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
  const value = env[key]
  if (typeof value === "function") return await value()
  return value
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
ihrer Module als `ModuleResult[]` transparent nach oben durch, sodass die
Ausgabe die volle Granularität behält.

**Status-Aggregation:** Der aggregierte Status einer Recipe ergibt sich aus
den Einzelergebnissen: Wenn mindestens ein Modul `failed` → `failed`. Wenn
mindestens ein Modul `changed` → `changed`. Sonst `ok`.

### Playbook (Serverdefinition)

Das Playbook ist die TypeScript-Datei, die der Benutzer schreibt. Es definiert
den Server und eine geordnete Liste von Recipes und Modulen:

```typescript
import { server, recipe } from "paratix"
import { apt, sshd, file, ufw, service, package as pkg } from "paratix/modules"

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
    recipe(
      "hardening",
      [
        pkg.installed("ufw", "fail2ban"),
        sshd.port(22022),
        file.template("/etc/ssh/sshd_config", "./files/sshd_config.tmpl"),
        ufw.rule("allow", [22022, 80, 443]),
      ],
      {
        signals: [service.restart("sshd")],
      }
    ),

    recipe(
      "podman",
      [
        pkg.installed("podman"),
        file.copy("/etc/containers/registries.conf", "./files/registries.conf"),
      ],
      {
        signals: [service.restart("podman")],
      }
    ),

    recipe(
      "app",
      [file.template("/etc/nginx/sites-available/app", "./files/nginx-app.tmpl.conf")],
      {
        signals: [service.restart("nginx")],
      }
    ),

    pkg.upgrade("2024-03-10"),
  ],
})
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
        sha256sum ./files/sshd_config → a3f9...  (identisch)
APPLY:  (entfällt)
STATUS: ok

--- nach lokaler Änderung an sshd_config ---

CHECK:  sha256sum /etc/ssh/sshd_config → a3f9...
        sha256sum ./files/sshd_config → 7c21...  (unterschiedlich)
APPLY:  scp ./files/sshd_config → /etc/ssh/sshd_config
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

### Flag-Cleanup (Prefix-basiert)

Beim Setzen eines neuen Flags werden alte Flags mit demselben Prefix
automatisch geloescht. Jedes State-Flag-Modul kennt seinen Prefix (z.B.
`apt-upgrade-`). Wird `apt-upgrade-20240310` gesetzt, loescht das Modul
alle bestehenden Flags die mit `apt-upgrade-` beginnen und nicht dem neuen
Flag-Namen entsprechen:

```
VORHER:
  /var/lib/paratix/flags/apt-upgrade-20230815
  /var/lib/paratix/flags/apt-upgrade-20240201

APPLY: package.upgrade("2024-03-10")
  → rm apt-upgrade-20230815, apt-upgrade-20240201
  → touch apt-upgrade-20240310

NACHHER:
  /var/lib/paratix/flags/apt-upgrade-20240310
```

Dadurch wachsen die Flags nicht unbegrenzt, und es ist kein manuelles
Cleanup noetig.

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
  sudoPassword: "...",       // optional, fuer non-root User
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

### Sudo (Privilege Escalation)

Wenn `ssh.user` nicht `root` ist, fuehrt Paratix automatisch alle Befehle
mit `sudo` aus. Module muessen sich nicht darum kuemmern — die
`SshConnection` prefixed Befehle transparent mit `sudo`.

**Sudo-Passwort — Reihenfolge:**

1. Versuche `sudo` ohne Passwort (NOPASSWD-Konfiguration auf dem Server)
2. Falls ein Passwort noetig ist und `ssh.sudoPassword` gesetzt ist → verwende es
3. Falls kein `sudoPassword` gesetzt → interaktive Abfrage im Terminal (einmalig)
4. Passwort wird fuer die Dauer des Runs im Speicher gecacht

Das Passwort wird via `sudo -S` ueber stdin uebergeben.

**Konfiguration:**

```typescript
// Variante 1: Passwortloses sudo (NOPASSWD in sudoers)
ssh: {
  user: "deploy",
  ports: [22],
  privateKey: "~/.ssh/id_ed25519",
}

// Variante 2: Sudo-Passwort explizit (z.B. aus process.env oder einer
// vor dem Serverdefinitions-Import gesetzten Variablen). `SshConfig`
// wird beim Import synchron validiert; `op.resolve()` und andere Module
// laufen erst spaeter im run und koennen `ssh.sudoPassword` deshalb
// nicht mehr befuellen.
ssh: {
  user: "deploy",
  ports: [22],
  privateKey: "~/.ssh/id_ed25519",
  sudoPassword: process.env.SUDO_PASSWORD,
}

// Variante 3: Interaktive Abfrage (kein sudoPassword, Paratix fragt im Terminal)
ssh: {
  user: "deploy",
  ports: [22],
  privateKey: "~/.ssh/id_ed25519",
}
```

Variante 1 und 3 sehen identisch aus — der Unterschied ergibt sich zur
Laufzeit: Hat der User NOPASSWD konfiguriert, laeuft sudo ohne Passwort.
Wenn nicht, fragt Paratix interaktiv.

**Dateioperationen als Non-Root:**

SFTP als non-root User kann nicht direkt nach `/etc/` schreiben. Die
`SshConnection` loest das transparent:

- `ssh.writeFile()` nutzt intern `sudo tee` statt SFTP
- `ssh.uploadFile()` laedt nach `/tmp/` hoch, dann `sudo mv` ans Ziel
- `ssh.readFile()` nutzt `sudo cat`
- `ssh.sha256()` nutzt `sudo sha256sum`

Module bemerken keinen Unterschied — die API bleibt identisch.

**Scope:** Sudo eskaliert immer zu `root`. `sudo -u <anderer-user>` ist
aktuell nicht vorgesehen.

### Multi-Port-Verbindung

Beim Verbindungsaufbau probiert Paratix die Ports **der Reihe nach durch**,
bis eine Verbindung steht. Das ermöglicht:

- **Ersteinrichtung:** Port 22 funktioniert initial, nach Umlegung auf 22022
  verbindet sich Paratix beim nächsten Lauf über den neuen Port.
- **Kein lokaler State nötig:** Der Verbindungsport wird zur Laufzeit ermittelt.

### Port-Umlegung zur Laufzeit

Wenn ein Modul den SSH-Port ändert (z.B. `sshd.port(22022)`), meldet es den
neuen Port über `meta` zurück (`[meta.sshdPort(22022)]`). Paratix fuegt den
neuen Port dynamisch zur internen Port-Liste hinzu, damit er bei einem
Reconnect beruecksichtigt wird. Die Portaenderung im SSHD wird erst nach
einem Service-Restart wirksam — der Reconnect erfolgt automatisch, wenn die
bestehende Verbindung dabei abbricht.

**Sicherheitsprüfung:** Das `sshd.port`-Modul validiert vor der Umlegung, dass
der Zielport in der statischen `ssh.ports`-Liste der Serverdefinition
eingetragen ist. Diese Prüfung läuft auch im Dry-Run vor Schreib-,
Validierungs- und Restart-Schritten. Andernfalls würde Paratix sich nach einem
Reboot nicht mehr verbinden können.

**Fehlerfall:** Wenn der Reconnect auf dem neuen Port fehlschlaegt (Timeout
erreicht), bricht der gesamte Run mit einem Fehler ab.

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

Standardmäßig wartet Paratix 120 Sekunden. Für automatisierte Läufe (Cronjob,
CI/CD) kann ein abweichendes Timeout gesetzt werden.

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
await ssh.exec("apt-get upgrade -y")

// Ausgabe wird unterdrückt, nur Rückgabewert zählt (Standard bei check)
const result = await ssh.exec("dpkg -l nginx", { silent: true })
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
  code: number
  /** Gesamte stdout-Ausgabe */
  stdout: string
  /** Gesamte stderr-Ausgabe */
  stderr: string
}

interface ExecOptions {
  /** Ausgabe unterdrücken (Standard: false bei apply, true bei check) */
  silent?: boolean
  /** Timeout in Millisekunden (Standard: kein Timeout) */
  timeout?: number
  /** Bei Exit-Code != 0 keinen Fehler werfen (Standard: false) */
  ignoreExitCode?: boolean
  /** Umgebungsvariablen für den Befehl */
  env?: Record<string, string>
  /** Werte, die in Logs und Diagnosen als [REDACTED] maskiert werden */
  secrets?: string[]
}

interface SshConnection {
  // --- Befehlsausführung ---

  /** Führt einen Shell-Befehl aus. Wirft bei Exit-Code != 0. */
  exec(command: string, options?: ExecOptions): Promise<ExecResult>

  /**
   * Führt einen Befehl aus und gibt nur den Exit-Code zurück.
   * Wirft nie — ideal für Checks.
   *
   * Beispiel:
   *   const installed = await ssh.test("dpkg -l nginx");
   *   const exists = await ssh.test("[ -f /etc/nginx/nginx.conf ]");
   */
  test(command: string): Promise<boolean>

  /**
   * Führt einen Befehl aus und gibt stdout zurück (getrimmt).
   * Wirft bei Exit-Code != 0.
   *
   * Beispiel:
   *   const hostname = await ssh.output("hostname");
   *   const hash = await ssh.output("sha256sum /etc/ssh/sshd_config | cut -d' ' -f1");
   */
  output(command: string, options?: ExecOptions): Promise<string>

  /**
   * Führt einen Befehl aus und gibt stdout als Zeilen-Array zurück.
   *
   * Beispiel:
   *   const packages = await ssh.lines("dpkg --get-selections | grep -v deinstall | awk '{print $1}'");
   */
  lines(command: string, options?: ExecOptions): Promise<string[]>

  // --- Dateioperationen ---

  /**
   * Liest eine Datei vom Server.
   *
   * Beispiel:
   *   const config = await ssh.readFile("/etc/ssh/sshd_config");
   */
  readFile(remotePath: string): Promise<string>

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
  writeFile(
    remotePath: string,
    content: string,
    options?: {
      mode?: string
      owner?: string
    }
  ): Promise<void>

  /**
   * Kopiert eine lokale Datei auf den Server.
   *
   * Beispiel:
   *   await ssh.uploadFile("./files/sshd_config", "/etc/ssh/sshd_config");
   */
  uploadFile(
    localPath: string,
    remotePath: string,
    options?: {
      mode?: string
      owner?: string
    }
  ): Promise<void>

  /**
   * Lädt eine Datei vom Server herunter.
   *
   * Beispiel:
   *   await ssh.downloadFile("/var/log/auth.log", "./logs/auth.log");
   */
  downloadFile(remotePath: string, localPath: string): Promise<void>

  /**
   * Prüft ob eine Datei/ein Verzeichnis existiert.
   * Shortcut für ssh.test("[ -e <path> ]").
   */
  exists(remotePath: string): Promise<boolean>

  /**
   * Gibt den SHA-256-Hash einer Remote-Datei zurück.
   * Gibt null zurück wenn die Datei nicht existiert.
   *
   * Beispiel:
   *   const remoteHash = await ssh.sha256("/etc/ssh/sshd_config");
   *   const localHash = sha256(fs.readFileSync("./files/sshd_config"));
   *   if (remoteHash === localHash) return "ok";
   */
  sha256(remotePath: string): Promise<string | null>

  // --- Verbindungsinformationen ---

  /**
   * Gibt die aktuelle Verbindungskonfiguration zurück.
   * Wird von lokalen Transfer-Modulen benötigt, die SSH-Parameter
   * außerhalb der bestehenden SSH-Session brauchen.
   */
  getConnectionInfo(): {
    agentSocket?: string
    authMethod?: "agent" | "password" | "privateKey"
    host: string
    port: number
    user: string
    privateKeyPath?: string
    verifiedHostPublicKey?: string
  }
}
```

### Warum Hilfsmethoden?

Ohne Hilfsmethoden müsste jedes Modul SSH-Befehle als Strings
zusammenbauen, Exit-Codes manuell prüfen und Ausgaben parsen:

```typescript
// Ohne Hilfsmethoden (fehleranfällig, repetitiv)
const result = await ssh.exec("dpkg -l nginx 2>/dev/null | grep -q '^ii'", {
  ignoreExitCode: true,
})
if (result.code === 0) return "ok"

// Mit Hilfsmethoden (klar, kurz)
if (await ssh.test("dpkg -l nginx | grep -q '^ii'")) return "ok"
```

```typescript
// Ohne Hilfsmethoden
const result = await ssh.exec("sha256sum /etc/ssh/sshd_config")
const hash = result.stdout.split(" ")[0].trim()

// Mit Hilfsmethoden
const hash = await ssh.sha256("/etc/ssh/sshd_config")
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
2. Playbook      (env: { ... } in der Serverdefinition)
3. CLI-Parameter (--env key=value)
4. Module        (meta-Einträge aus ModuleResult zur Laufzeit)
```

Jedes Modul erhält bei `check()` und `apply()` den **aktuellen, aggregierten
Env**. Setzt ein Modul `meta`-Einträge im `ModuleResult`, werden diese in den
Env übernommen und stehen allen nachfolgenden Modulen zur Verfügung.

**Best Practice:** Der Key eines Meta-Eintrags beginnt mit dem Modulnamen,
um Konflikte zu vermeiden:

```typescript
import { meta } from "paratix"

// sshd.port-Modul setzt nach Umlegung:
{
  meta: [meta.sshdPort(22022)]
}

// user.present-Modul setzt nach Erstellung:
{
  meta: [meta.env("user.home", "/home/deploy")]
}
```

### Templates

Für die Generierung von Konfigurationsdateien bietet Paratix ein
Template-System. Templates haben Zugriff auf alle Env-Einträge:

```
# ./files/nginx-app.tmpl.conf
server {
    listen 80;
    server_name {{app.domain|raw}};

    location / {
        proxy_pass http://127.0.0.1:{{app.port|raw}};
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
})
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
recipe(
  "hardening",
  [
    sshd.port(22022),
    file.copy("/etc/ssh/sshd_config", "./files/sshd_config"),
    ufw.rule("allow", [22022, 80, 443]),
  ],
  {
    signals: [service.restart("sshd")],
  }
)
```

Wenn weder `sshd.port` noch `file.copy` etwas geändert haben, wird `sshd`
nicht neu gestartet.

### Auf Playbook-Ebene

Signale können auch auf Playbook-Ebene definiert werden. Sie werden am Ende
des gesamten Laufs ausgewertet:

```typescript
export default server({
  // ...
  run: [/* ... */],
  signals: [service.restart("nginx")],
})
```

### Signale als Module

Signale implementieren ebenfalls die Plugin-Schnittstelle. Ihr `check` ist
immer `needs-apply` (wenn getriggert) oder `ok` (wenn nicht getriggert).
Dadurch sind sie in der Ausgabe wie jedes andere Modul sichtbar.

---

## Modul-Typen im Überblick

### Idempotente Module (Standard)

| Modul               | Check-Strategie              |
| ------------------- | ---------------------------- |
| `package.installed` | `dpkg -l <paket>` prüfen     |
| `package.absent`    | `dpkg -l <paket>` prüfen     |
| `file.copy`         | SHA-256 Hash vergleichen     |
| `file.line`         | `grep -qF` nach Zeile suchen |
| `service.enabled`   | `systemctl is-enabled`       |
| `service.running`   | `systemctl is-active`        |
| `user.present`      | `id <user>` prüfen           |
| `ufw.rule`          | `ufw status` parsen          |
| `sshd.port`         | `sshd_config` auslesen       |

### State-Flag-Module (für teure Operationen)

| Modul             | Flag-Strategie                 |
| ----------------- | ------------------------------ |
| `package.upgrade` | Flag mit Datum                 |
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

| Parameter             | Beschreibung                                          |
| --------------------- | ----------------------------------------------------- |
| `--reconnect-timeout` | Timeout in Sekunden für SSH-Reconnect (Standard: 120) |
| `--dry-run`           | Nur Check ausführen, keine Änderungen vornehmen       |
| `--env key=value`     | Env-Eintrag setzen (überschreibt Playbook-Werte)      |
| `--env-file <path>`   | Env-Einträge aus DotEnv-Datei laden                   |

---

## Ablauf eines vollständigen Runs

```
1. Serverdefinition laden (TypeScript-Datei via tsx)
2. Env initialisieren (.env-Datei → Playbook-env → CLI-Parameter)
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
})

// vps-backup.ts
export default server({
  name: "vps-backup",
  host: "5.6.7.8",
  ssh: { user: "root", ports: [22, 22022] },
  run: [hardening, podman],
})
```

```
paratix apply ./vps-primary.ts
paratix apply ./vps-backup.ts
```

---

## Abgrenzung zu Ansible

| Merkmal         | Ansible        | Paratix                     |
| --------------- | -------------- | --------------------------- |
| Sprache         | YAML + Python  | TypeScript                  |
| Typsicherheit   | Nein           | Ja                          |
| Idempotenz      | Ja (Module)    | Ja (Module)                 |
| State           | zustandslos    | zustandslos + opt. Flags    |
| Modulökosystem  | riesig (3000+) | selbst gebaut, klein        |
| Agentless       | Ja             | Ja                          |
| Lernkurve       | moderat        | gering (plain TypeScript)   |
| Erweiterbarkeit | Plugins/Roles  | Plugin-Schnittstelle (TS)   |
| SSH-Resilienz   | begrenzt       | Multi-Port + Auto-Reconnect |

---

## Implementierungsentscheidungen

Die folgenden Entscheidungen konkretisieren die technische Umsetzung der oben
beschriebenen Architektur.

---

### Runner: Laden der TypeScript-Datei

Die Playbook-Datei wird per `await import()` mit tsx als ESM-Loader direkt in
den Runner-Prozess geladen (`--import tsx/esm`). Kein Child-Process, kein IPC.
Der Runner importiert das Default-Export (`ServerDefinition`) und verarbeitet
es direkt.

### Runner: Fehlerbehandlung

Bei `status: "failed"` bricht der gesamte Run sofort ab. Nachfolgende Module
und Recipes werden nicht mehr ausgefuehrt. Es gibt kein `continueOnError` —
ein Fehler ist ein unerwarteter Zustand, bei dem Weiterausfuehrung riskant
waere, da nachfolgende Module auf dem Ergebnis aufbauen koennten.

Das gilt auch fuer Signals: Ein fehlgeschlagenes Signal bricht die restlichen
Signals derselben Liste ab. Weiterlaufen wuerde neuen Zustand auf einer bereits
gescheiterten Voraussetzung aufbauen — genau so wurde ein Container-Stack ueber
zwei Netzwerke hinweg gesplittet (ADR-0006).

### SSH-Library

Paratix nutzt `ssh2` (npm) fuer die SSH-Verbindung. Die Library bietet volle
Kontrolle ueber Connections, SFTP, Streaming und Reconnect-Logik. Die
`SshConnection`-API mappt direkt auf `ssh2`-Primitiven.

### SSH: Connection-Modell

Eine einzelne persistente SSH-Verbindung pro Run. Sequenzielle Ausfuehrung
benoetigt keine parallelen Connections. Die `SshConnection`-Klasse kapselt
eine `ssh2`-Connection mit integrierter Reconnect-Logik.

### SSH: Reconnect-Backoff

```
Initial:    1s
Faktor:     2x
Maximum:    30s
Jitter:     ±25%
Timeout:    konfigurierbar (--reconnect-timeout), Default: 120s
```

Verlauf: 1s → 2s → 4s → 8s → 16s → 30s → 30s → ... (jeweils ±25% Jitter).
Bei jedem Reconnect-Versuch werden alle konfigurierten Ports der Reihe nach
durchprobiert.

### Template-Engine

Bewusst minimalistisch — Env-Zugriffe mit explizitem Kontext:

- `{{key|raw}}` wird durch `resolveEnv(env, key)` ersetzt und unverändert
  eingefügt. Das ist passend für Konfigurationswerte, nicht für Shell-Befehle.
- `{{key|shell}}` rendert den Wert als Shell-Argument. Nutze diesen Modifier,
  sobald der Wert in einem Shell-Kontext landet.
- Bare-Placeholder wie `{{key}}` werfen im Strict Mode einen Fehler. Strict Mode
  ist der Default von `file.template`; `strict: false` ist nur eine bewusste
  Ausnahme für Legacy-Templates.
- **Fehlende Keys werfen einen Fehler.** Stilles Ignorieren würde zu kaputten
  Konfigurationsdateien führen.
- **Escaping:** `\{{` für literales `{{`.
- **Kein Looping, kein Conditional** — dafür gibt es TypeScript im Playbook.
  Komplexe Logik gehört in die Playbook-Datei, nicht in Templates.
- **Encoding:** immer UTF-8.

### file.copy / file.template: Berechtigungen

Beide Module akzeptieren optionale Parameter `mode` und `owner`:

```typescript
file.copy("/etc/ssh/sshd_config", "./files/sshd_config", {
  mode: "644",
  owner: "root:root",
})
```

- **Default `mode`:** nicht gesetzt → Datei erhaelt Standard-Permissions (`644`).
- **Default `owner`:** nicht gesetzt → bleibt beim SSH-User (typisch: `root`).

### Verschachtelte Recipes

Erlaubt. Da Recipe das Module-Interface implementiert (Composite Pattern),
koennen Recipes andere Recipes enthalten. Das ergibt sich natuerlich aus der
Architektur und erfordert keinen zusaetzlichen Code.

### Parallele Ausfuehrung

Nicht vorgesehen. Alle Module und Recipes laufen streng sequenziell, wie in
der Architektur beschrieben. Parallelisierung waere ein Breaking Change im
mentalen Modell und kann spaeter als explizites Opt-in ergaenzt werden.

### Dry-Run-Modus

`--dry-run` stellt eine SSH-Verbindung her und fuehrt alle `check()`-Methoden
aus, aber kein `apply()`. Der Benutzer sieht den **tatsaechlichen**
Server-Zustand: welche Module bereits erfuellt sind (`ok`) und welche
Aenderungen anstehen (`needs-apply`).

### Ausgabe und Terminal

- **Kein Logging-Framework.** Direkte Terminal-Ausgabe mit eigenem Renderer
  (die Ausgabeformatierung ist spezifisch fuer Paratix).
- **Farben:** `picocolors` — winzig, keine Abhaengigkeiten.
- **Kein `--verbose`/`--quiet`** im ersten Release. Die Ausgabe ist bereits
  kompakt (eine Zeile pro Modul). SSH-Output-Streaming bei `apply()` liefert
  Details wenn noetig.

### Fehlerausgabe bei failed

Bei `status: "failed"` wird die Modul-Zeile rot markiert. Darunter werden
stderr und stdout eingerueckt ausgegeben. Der Run bricht sofort ab (kein
`continueOnError`).

```
[hardening]
  ✓  apt: fail2ban ufw              ok
  ✗  sshd: port → 22022             failed
     │ Error: Could not write to /etc/ssh/sshd_config
     │ Permission denied
```

Der eingerueckte Block mit `│`-Prefix zeigt die kombinierte stderr/stdout-
Ausgabe des fehlgeschlagenen Befehls. Das gibt dem Benutzer sofort Kontext
fuer die Fehlerdiagnose.

### CLI Exit-Codes

```
Exit-Code 0: Alle Module ok oder changed — Run erfolgreich
Exit-Code 1: Mindestens ein Modul failed — Run abgebrochen
Exit-Code 2: Usage-Error (ungueltige Parameter, Datei nicht gefunden, Syntaxfehler)
```

### Signal-Ausfuehrung im Runner

Signal-Module (`service.restart`, `service.reload`, `compose.restart`)
implementieren das Module-Interface, werden aber vom Runner anders aufgerufen
als normale Module. Der Runner fuehrt Signale NICHT im normalen sequenziellen
Durchlauf aus, sondern:

- Nach Abschluss aller Module einer Recipe prueft der Runner, ob mindestens
  ein Modul `changed` zurueckgegeben hat.
- Falls ja: Alle Signal-Module der Recipe werden sequenziell ausgefuehrt
  (`check` wird uebersprungen, direkt `apply`).
- Falls nein: Alle Signal-Module werden mit Status `ok` in der Ausgabe
  angezeigt, aber nicht ausgefuehrt.
- Dasselbe gilt fuer Playbook-level Signale am Ende des gesamten Runs.

Signal-Module haben keinen sinnvollen `check` — ihr `check` gibt immer
`needs-apply` zurueck. Die Entscheidung ob sie ausgefuehrt werden trifft der
Runner basierend auf dem aggregierten `changed`-Status, nicht das Signal-Modul
selbst.

### rsync — Verbindungsdaten

`SshConnection` bietet eine Methode `getConnectionInfo()`, die die tatsächlich
genutzten Verbindungsdaten zurückgibt. `privateKeyPath` ist nur gesetzt, wenn
die aktuelle Session per Private Key aufgebaut wurde. Bei Agent-Authentifizierung
stehen stattdessen `authMethod: "agent"` und `agentSocket` aus `SSH_AUTH_SOCK`
zur Verfügung. Bei Passwort-Authentifizierung ist `authMethod: "password"`
gesetzt; lokale Transfer-Module müssen diesen Pfad entweder ablehnen oder einen
eigenen Passwort-fähigen Transport nutzen.

Lokale Module wie `rsync.sync` müssen Private-Key- und Agent-Auth getrennt
behandeln: für Private-Key-Auth können sie `-i <privateKeyPath>` und
`IdentitiesOnly=yes` setzen, für Agent-Auth `IdentityAgent=<agentSocket>`.
`verifiedHostPublicKey` enthält den verifizierten Host-Key im OpenSSH-Format
und kann für temporäre, pinningbasierte `known_hosts`-Dateien genutzt werden.

### command.shell (kein command.run)

Nur `command.shell` wird implementiert. Ein separates `command.run` ohne
Shell-Interpretation entfaellt, da ueber SSH ohnehin alles durch eine Shell
laeuft. `command.shell` fuehrt einen Befehl via `/bin/sh -c` aus und gibt
immer `changed` zurueck, es sei denn ein benutzerdefinierter Check-Befehl
ist angegeben.

### Template-Namenskonvention

Alle lokalen Dateien (Templates und statische Konfigurationen) liegen in einem
gemeinsamen `files/`-Verzeichnis. Ob eine Datei ein Template ist, wird im Code
durch die Wahl von `file.template` vs. `file.copy` entschieden — nicht durch
das Verzeichnis.

Fuer menschliche Lesbarkeit und IDE-Unterstuetzung gilt folgende
Namenskonvention:

- **Template mit Extension:** `*.tmpl.*` — das `.tmpl` steht vor der
  Original-Extension, damit die IDE den Dateityp erkennt.
  Beispiel: `nginx-app.tmpl.conf`, `traefik-compose.tmpl.yml`
- **Template ohne Extension:** `*.tmpl` — da die Originaldatei keine
  Extension hat, wird `.tmpl` als Extension angehaengt.
  Beispiel: `sshd_config.tmpl`
- **Statische Datei:** Originalname ohne `.tmpl`.
  Beispiel: `registries.conf`

Die Konvention ist rein informativ — `file.template` und `file.copy`
unterscheiden sich durch den Funktionsaufruf, nicht durch den Dateinamen.

### Projekt-Scaffolding (`create-paratix`)

Ein neues Server-Projekt wird per Scaffolding erstellt:

```
pnpm create paratix vps-01-mailcow
npm create paratix vps-01-mailcow
```

Dies erzeugt folgende Verzeichnisstruktur:

```
vps-01-mailcow/
├── package.json              # Dependency auf paratix
├── tsconfig.json             # TypeScript-Konfiguration fuer IDE-Support
├── .gitignore                # node_modules, .env, dist
├── .env.example              # Beispiel-Env-Werte (Template fuer .env)
├── server.ts                 # Beispiel-Playbook
└── files/                    # Templates und Konfigurationsdateien
    └── .gitkeep
```

**Paketmanager-Erkennung:** `create-paratix` erkennt den aufrufenden
Paketmanager via `process.env.npm_config_user_agent` (z.B. `pnpm/10.30.3`
oder `npm/10.8.0`) und traegt ihn in die `package.json` des generierten
Projekts ein (`packageManager`-Feld). Anschliessend wird automatisch
`install` ausgefuehrt.

**Beispiel-Playbook (`server.ts`):**

```typescript
import { server } from "paratix"
import { hostname, package as pkg } from "paratix/modules"

export default server({
  name: "vps-01",
  host: "1.2.3.4",
  ssh: {
    user: "root",
    ports: [22],
    privateKey: "~/.ssh/id_ed25519",
  },

  run: [hostname.set("vps-01"), pkg.upgrade("2024-03-10")],
})
```

Das Beispiel ist bewusst minimal aber funktional — es setzt den Hostnamen
und fuehrt ein Systemupdate durch. Der Benutzer erweitert es nach Bedarf.

### Projekt-Setup und Tooling

| Aspekt           | Wahl          | Begruendung                           |
| ---------------- | ------------- | ------------------------------------- |
| Runtime          | Node.js >= 24 | Fuer `import()`, Top-Level-Await, tsx |
| Build            | `tsup`        | Schnell, esbuild-basiert, erzeugt ESM |
| Test             | `vitest`      | Schnell, TypeScript-nativ             |
| CLI-Parser       | `commander`   | Etabliert, grosse Community, stabil   |
| Package-Struktur | pnpm Monorepo | `paratix` + `create-paratix`          |
| Paketmanager     | `pnpm`        | Bereits konfiguriert                  |

### Projektstruktur (Monorepo)

```
paratix/                         # Repository-Root
├── pnpm-workspace.yaml
├── package.json                 # Workspace-Root (private: true)
├── docs/                        # Dokumentation
│   ├── initialbeschreibung.md
│   └── module.md
│
├── packages/
│   ├── paratix/                 # Hauptpackage (npm: paratix)
│   │   ├── package.json
│   │   └── src/
│   │       ├── cli.ts           # Commander-Setup, Entry-Point
│   │       ├── runner.ts        # Sequenzieller Executor
│   │       ├── ssh.ts           # SshConnection-Klasse
│   │       ├── env.ts           # Env-Handling, resolveEnv
│   │       ├── template.ts      # Template-Engine
│   │       ├── types.ts         # Module, ModuleResult, Env, etc.
│   │       ├── output.ts        # Terminal-Renderer (picocolors)
│   │       ├── recipe.ts        # recipe()-Funktion
│   │       ├── server.ts        # server()-Funktion
│   │       └── modules/
│   │           ├── index.ts     # Re-Export aller Module
│   │           ├── apt.ts
│   │           ├── file.ts
│   │           ├── service.ts
│   │           ├── sshd.ts
│   │           ├── ufw.ts
│   │           ├── user.ts
│   │           ├── group.ts
│   │           └── op.ts
│   │
│   └── create-paratix/          # Scaffolding-Tool (npm: create-paratix)
│       ├── package.json
│       ├── src/
│       │   └── index.ts         # CLI-Entry-Point
│       └── template/            # Dateien die ins neue Projekt kopiert werden
│           ├── server.ts
│           ├── tsconfig.json
│           ├── gitignore        # Wird zu .gitignore umbenannt
│           ├── env.example      # Wird zu .env.example umbenannt
│           └── files/
│               └── .gitkeep
```

Zwei Export-Pfade in `packages/paratix/package.json`:

```json
{
  "exports": {
    ".": "./dist/index.js",
    "./modules": "./dist/modules/index.js"
  }
}
```

`src/index.ts` exportiert `server`, `recipe`, `when`, `assert`, `debug`,
`fail`, `pause`. Das Package `paratix/modules` exportiert alle Modul-Namespaces
(`apt`, `file`, `service`, etc.).

### Lokale Module (Controller-seitig)

Module koennen sich als `local` markieren. Der Runner uebergibt ihnen dann
kein SSH-Objekt. So koennen neben `op.resolve` spaeter weitere lokale Module
hinzukommen (z.B. `local.exec`, `terraform.apply`) ohne Sonderbehandlung.

```typescript
interface Module {
  name: string
  local?: boolean
  check(ssh: SshConnection | null, env: Env): Promise<"ok" | "needs-apply">
  apply(ssh: SshConnection | null, env: Env): Promise<ModuleResult>
}
```

Bei `local: true` wird `ssh` als `null` uebergeben. Lokale Module fuehren
Befehle auf dem Controller aus (z.B. via `child_process`), nicht ueber SSH.

### Secret-Masking

Paratix maskiert konkrete Secret-Werte, die Module oder SSH-/Exec-Aufrufe beim
zentralen Secret-Register anmelden. Diese Werte werden in Konsolenausgaben als
`[REDACTED]` angezeigt. Das betrifft zum Beispiel durch `op.resolve`
aufgelöste Secrets und OTP-Codes, SSH-/Sudo-Passwörter,
User-Passwort-Hashes und explizit über `ExecOptions.secrets` registrierte
Werte.

Env-Key-Namen allein lösen keine automatische Maskierung aus. Eigene Module
müssen sensible Werte explizit registrieren oder sie über APIs übergeben, die
Secrets registrieren. Die Werte selbst bleiben intern unverändert; nur die
Anzeige wird maskiert.

### Temp-Dateien

Keine Temp-Dateien. Gerenderte Templates werden im Speicher gehalten und
direkt via `ssh.writeFile()` auf den Server geschrieben. Kein lokales
Zwischenspeichern, kein Cleanup noetig.

### server() und recipe(): Rueckgabetypen

```typescript
interface SshConfig {
  user: string
  /** Statische Port-Kandidaten; sshd.port-Zielports müssen hier eingetragen sein. */
  ports: number[]
  /** Private-Key-Pfad. Optional; ohne Wert nutzt Paratix SSH_AUTH_SOCK. */
  privateKey?: string
  /** Lokalen SSH-Agent an die Remote-Session weiterreichen. */
  agentForward?: boolean
  /** Erwarteter SHA256-Host-Fingerprint als Trust Anchor. */
  expectedHostFingerprint?: string
  /** Erwarteter OpenSSH-Host-Public-Key als Trust Anchor. */
  expectedHostPublicKey?: string
  /** Host-Key-Prüfung: "yes" ist Default, "accept-new" ist explizites TOFU. */
  strictHostKeyChecking?: "accept-new" | "no" | "yes"
  passwordFallback?: boolean
  reconnectTimeout?: number
  maxReconnectAttempts?: number
  /** Sudo-Passwort für non-root User. Optional — wenn nicht gesetzt und
   *  sudo ein Passwort verlangt, wird interaktiv im Terminal gefragt. */
  sudoPassword?: string
}

interface ServerDefinition {
  name: string
  host: string
  ssh: SshConfig
  env?: Env
  run: Module[]
  signals?: Module[]
}

function server(config: ServerDefinition): ServerDefinition
// Identity-Funktion mit Typ-Validierung.

function recipe(
  name: string,
  modules: Module[],
  options?: {
    signals?: Module[]
  }
): Module
// Gibt ein Module zurueck (Composite Pattern).
```

`server()` validiert die uebergebene Konfiguration und gibt sie typisiert
zurueck. `recipe()` erzeugt ein Composite-Module, das seine Kinder sequenziell
ausfuehrt und Signale nur bei `changed`-Status triggert.

### Built-in-Funktionen als Module

Die Ablaufsteuerungsfunktionen `assert`, `debug`, `fail` und `pause`
implementieren die Module-Schnittstelle. Dadurch bleibt der Runner einfach
(nur `Module[]`, kein Union-Typ) und die Funktionen erscheinen in der Ausgabe
wie jedes andere Modul.

```typescript
function assert(condition: (env: Env) => boolean, message: string): Module
// check: condition(env) ? "ok" : wirft Fehler mit message
// apply: wird nie aufgerufen (check wirft bei Fehler)

function debug(message: string): Module
// check: immer "ok" (gibt message auf der Konsole aus)
// apply: wird nie aufgerufen

function fail(message: string): Module
// check: wirft immer einen Fehler mit message
// apply: wird nie aufgerufen

function pause(message?: string): Module
// check: immer "needs-apply"
// apply: wartet auf Benutzerbestaetigung im Terminal, gibt "changed" zurueck
```

Ausgabe-Beispiel:

```
  ✓  assert: Port muss positiv sein    ok
  ✓  debug: Starting deployment...     ok
  ⏸  pause: Continue?                  waiting
```

### Bedingte Ausfuehrung mit when()

Da das `run`-Array zur **Importzeit** (beim Laden der TypeScript-Datei)
ausgewertet wird, steht der Env zu diesem Zeitpunkt noch nicht zur Verfuegung.
Bedingte Logik, die auf Env-Werten basiert (z.B. Ergebnisse von
`system.facts`), kann daher nicht mit normalen Spread-Ausdruecken realisiert
werden.

Paratix bietet dafuer den `when()`-Wrapper:

```typescript
function when(condition: (env: Env) => boolean, ...modules: Module[]): Module
```

`when()` gibt ein Module zurueck, dessen `check` und `apply` nur ausgefuehrt
werden, wenn die Bedingung zur **Laufzeit** (mit dem aktuellen Env) erfuellt
ist. Andernfalls gibt es `{ status: "skipped" }` zurueck.

**Beispiel:**

```typescript
import { server, recipe, when } from "paratix"
import { system, apt, file, package as pkg } from "paratix/modules"

export default server({
  // ...
  run: [
    system.facts(),

    // Bedingt: nur auf Ubuntu
    when((env) => env["system.os"] === "ubuntu", apt.repository("ppa:nginx/stable")),

    // Mehrere Module bedingt ausfuehren
    when(
      (env) => Number(env["system.ram.total"]) >= 4096,
      pkg.installed("elasticsearch"),
      file.template("/etc/elasticsearch/elasticsearch.yml", "./files/elasticsearch.tmpl.yml")
    ),
  ],
})
```

**Ausgabeverhalten:** Bei nicht erfuellter Bedingung zeigt `when()` eine
einzelne Zeile mit Status `skipped` an:

```
  ⊘  when: system.os === ubuntu        skipped (condition)
```

Bei erfuellter Bedingung werden die enthaltenen Module einzeln mit ihrem
jeweiligen Status angezeigt — `when()` selbst erscheint dann nicht in der
Ausgabe. Das ergibt minimale Ausgabe bei Skip und volle Granularitaet bei
Ausfuehrung:

```
  ✓  apt: ppa:nginx/stable             ok
```

`when()` kann auch innerhalb von Recipes verwendet werden.

**when() und Signals:** Wenn alle Module innerhalb eines `when()` in einer
Recipe `skipped` sind (Bedingung nicht erfuellt), zaehlt dies als
"kein `changed`" fuer die Signal-Ausloesung. Signale werden nur getriggert,
wenn mindestens ein Modul tatsaechlich `changed` zurueckgegeben hat.
