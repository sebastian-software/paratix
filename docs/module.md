# Paratix — Modulkatalog

Alle Module, die durch das Paratix Plugin-System implementiert werden sollen.
Jedes Modul implementiert die Plugin-Schnittstelle (`check` / `apply`) und ist
idempotent, sofern nicht anders vermerkt.

> Abgeleitet aus [initialbeschreibung.md](./initialbeschreibung.md) und
> [ansible.md](./ansible.md).

---

## package — Paketverwaltung

| Modul               | Beschreibung                                                                                                                                     | Check-Strategie                                        | Aufwand |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ | ------- |
| `package.installed` | Stellt sicher, dass eines oder mehrere Pakete installiert sind. Akzeptiert Paketnamen als Argumente.                                             | Delegiert an den erkannten Paketmanager                | einfach |
| `package.absent`    | Stellt sicher, dass Pakete nicht installiert sind. Entfernt sie bei Bedarf.                                                                      | Delegiert an den erkannten Paketmanager                | einfach |
| `package.update`    | Aktualisiert Paketlisten einmal pro angegebenem Datum.                                                                                           | State-Flag: `/var/lib/paratix/flags/package-update-*`  | einfach |
| `package.upgrade`   | Führt ein Paket-Upgrade einmal pro angegebenem Datum aus. Nutzt State-Flags, da die Operation teuer ist und nicht effizient geprüft werden kann. | State-Flag: `/var/lib/paratix/flags/package-upgrade-*` | einfach |

## apt — Debian/Ubuntu-Konfiguration

| Modul             | Beschreibung                                                                                                                                                                                                                                                                                           | Check-Strategie                                                                   | Aufwand |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- | ------- |
| `apt.distUpgrade` | Führt ein `apt-get dist-upgrade` durch. Nutzt State-Flag mit Datum.                                                                                                                                                                                                                                    | State-Flag: `/var/lib/paratix/flags/apt-dist-upgrade-<datum>`                     | einfach |
| `apt.key`         | Fügt einen GPG-Schlüssel für APT hinzu. Lädt den Key nur via HTTPS, prüft den heruntergeladenen Schlüssel gegen einen expliziten OpenPGP-Fingerprint und speichert ihn unter `/etc/apt/keyrings/<name>.gpg` (moderne Methode, kein `apt-key`). Wird von `apt.repository` via `signed-by` referenziert. | Prüfung ob `/etc/apt/keyrings/<name>.gpg` existiert und denselben Fingerprint hat | einfach |
| `apt.repository`  | Fügt ein APT-Repository hinzu oder entfernt es. Verwaltet Dateien in `/etc/apt/sources.list.d/`. Unterstützt `signed-by` Parameter für Verknüpfung mit einem via `apt.key` installierten GPG-Schlüssel (wird automatisch aus dem Key-Namen abgeleitet, falls nicht explizit angegeben).                | Prüfung ob Datei in `/etc/apt/sources.list.d/` existiert und korrekt ist          | einfach |
| `apt.debconf`     | Setzt vorkonfigurierte Antworten für interaktive Paketinstallationen (z. B. Postfix-Konfigurationstyp).                                                                                                                                                                                                | `debconf-show <paket>` parsen                                                     | mittel  |

---

## file — Dateiverwaltung

| Modul             | Beschreibung                                                                                                                                                                                                                                                                                                                              | Check-Strategie                                                | Aufwand |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ------- |
| `file.copy`       | Kopiert eine lokale Datei auf den Server. Vergleicht per SHA-256-Hash, ob die Datei bereits identisch ist.                                                                                                                                                                                                                                | SHA-256-Vergleich lokal vs. remote                             | einfach |
| `file.template`   | Rendert ein Template mit dem aktuellen Env und kopiert das Ergebnis auf den Server. Templates laufen standardmäßig im Strict Mode: Env-Zugriffe brauchen explizite Modifier wie `{{key\|raw}}` oder `{{key\|shell}}`.                                                                                                                     | SHA-256 des gerenderten Templates vs. Remote-Datei             | einfach |
| `file.line`       | Stellt sicher, dass eine bestimmte Zeile in einer Datei vorhanden ist. Ohne `match`-Parameter: fuegt die Zeile am Ende hinzu, falls nicht vorhanden. Mit `match`-Parameter (Regex): ersetzt die erste Zeile die auf das Muster passt. Beispiel: `file.line("/etc/ssh/sshd_config", "PermitRootLogin no", { match: "^PermitRootLogin" })`. | `grep -qF` nach Zeile oder `grep` nach `match`-Pattern         | mittel  |
| `file.block`      | Fuegt einen Textblock mit Marker-Zeilen in eine Datei ein oder aktualisiert ihn. Marker-Format: `# BEGIN paratix: <block-name>` / `# END paratix: <block-name>`. Der Kommentar-Prefix (`#`, `//`, `;`) ist konfigurierbar (Default: `#`). Ermoeglicht wiederholtes Aktualisieren desselben Blocks.                                        | `grep` nach Marker-Zeilen, Inhalt zwischen Markern vergleichen | mittel  |
| `file.replace`    | Ersetzt alle Vorkommen eines regulaeren Ausdrucks in einer Datei.                                                                                                                                                                                                                                                                         | `grep` nach Pattern, pruefen ob Ersetzung noetig               | mittel  |
| `file.assemble`   | Setzt eine Konfigurationsdatei aus mehreren Fragmentdateien zusammen. Nützlich fuer modulare Konfigurationen (z.B. sudoers.d-Stil).                                                                                                                                                                                                       | SHA-256 der konkatenierten Fragmente vs. Zieldatei             | mittel  |
| `file.properties` | Verwaltet Dateieigenschaften: Berechtigungen (mode), Besitzer (owner), Gruppe (group), Typ (file/directory/symlink/absent).                                                                                                                                                                                                               | `stat`-Befehl, Vergleich aller Properties                      | mittel  |
| `file.directory`  | Stellt sicher, dass ein Verzeichnis existiert, optional mit bestimmten Berechtigungen und Besitzer.                                                                                                                                                                                                                                       | `test -d` + `stat`                                             | einfach |
| `file.absent`     | Stellt sicher, dass eine Datei oder ein Verzeichnis nicht existiert.                                                                                                                                                                                                                                                                      | `test -e`                                                      | einfach |
| `file.stat`       | Ruft Datei-Metadaten ab (Groesse, Berechtigungen, Timestamps, etc.) und schreibt sie als Meta-Eintraege in den Env. Aendert nichts am Server.                                                                                                                                                                                             | Immer `ok` (reines Lesen)                                      | einfach |

---

## service — Dienstverwaltung

| Modul              | Beschreibung                                                                                                                                                      | Check-Strategie                             | Aufwand |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | ------- |
| `service.running`  | Stellt sicher, dass ein Dienst laeuft. Startet ihn bei Bedarf.                                                                                                    | `systemctl is-active <dienst>`              | einfach |
| `service.stopped`  | Stellt sicher, dass ein Dienst gestoppt ist.                                                                                                                      | `systemctl is-active <dienst>`              | einfach |
| `service.enabled`  | Stellt sicher, dass ein Dienst beim Systemstart aktiviert ist.                                                                                                    | `systemctl is-enabled <dienst>`             | einfach |
| `service.disabled` | Stellt sicher, dass ein Dienst beim Systemstart deaktiviert ist.                                                                                                  | `systemctl is-enabled <dienst>`             | einfach |
| `service.restart`  | Startet einen Dienst neu. Wird primaer als **Signal** in Recipes verwendet und nur ausgefuehrt, wenn innerhalb der Recipe ein Modul `changed` zurueckgegeben hat. | Signal-basiert (kein eigenstaendiger Check) | einfach |
| `service.reload`   | Laedt die Konfiguration eines Dienstes neu (ohne Neustart). Wird wie `service.restart` als Signal verwendet.                                                      | Signal-basiert (kein eigenstaendiger Check) | einfach |
| `service.facts`    | Sammelt Statusinformationen aller Dienste und schreibt sie als Meta-Eintraege in den Env. Aendert nichts am Server.                                               | Immer `ok` (reines Lesen)                   | einfach |

---

## systemd — Systemd-spezifisch

| Modul          | Beschreibung                                                                                                                  | Check-Strategie                  | Aufwand |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ------- |
| `systemd.unit` | Deployt eine eigene Systemd-Unit-Datei auf den Server und fuehrt `systemctl daemon-reload` aus, falls sie sich geaendert hat. | SHA-256-Vergleich der Unit-Datei | einfach |

---

## user — Benutzerverwaltung

| Modul          | Beschreibung                                                                                                                                               | Check-Strategie                        | Aufwand |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- | ------- |
| `user.present` | Stellt sicher, dass ein Benutzerkonto existiert. Kann UID, Shell, Home-Verzeichnis, Gruppen und Passwort-Hash konfigurieren. Schreibt `user.home` in Meta. | `id <user>` + Vergleich der Properties | einfach |
| `user.absent`  | Stellt sicher, dass ein Benutzerkonto nicht existiert. Kann optional das Home-Verzeichnis loeschen.                                                        | `id <user>`                            | einfach |

---

## group — Gruppenverwaltung

| Modul           | Beschreibung                                                             | Check-Strategie       | Aufwand |
| --------------- | ------------------------------------------------------------------------ | --------------------- | ------- |
| `group.present` | Stellt sicher, dass eine Systemgruppe existiert. Kann GID konfigurieren. | `getent group <name>` | einfach |
| `group.absent`  | Stellt sicher, dass eine Systemgruppe nicht existiert.                   | `getent group <name>` | einfach |

---

## sshd — SSH-Server-Konfiguration

| Modul         | Beschreibung                                                                                                                                                                                                                         | Check-Strategie                             | Aufwand |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- | ------- |
| `sshd.port`   | Aendert den SSH-Port in der `sshd_config`. Validiert, dass der Zielport in der `ssh.ports`-Liste der Serverdefinition eingetragen ist. Schreibt `sshd.port` in Meta, wodurch Paratix die SSH-Verbindung auf den neuen Port umstellt. | `sshd_config` auslesen und Port vergleichen | einfach |
| `sshd.config` | Setzt einzelne Konfigurationsoptionen in `sshd_config` (z.B. `PermitRootLogin`, `PasswordAuthentication`). Akzeptiert Key-Value-Paare.                                                                                               | `sshd_config` parsen, Werte vergleichen     | einfach |

---

## ssh — SSH-Client-Konfiguration

| Modul                | Beschreibung                                                                                                    | Check-Strategie                      | Aufwand |
| -------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ------- |
| `ssh.knownHosts`     | Fuegt einen Host zur `known_hosts`-Datei hinzu oder entfernt ihn.                                               | `ssh-keygen -F <host>`               | einfach |
| `ssh.authorizedKeys` | Verwaltet SSH-Public-Keys in der `authorized_keys`-Datei eines Benutzers. Kann Keys hinzufuegen oder entfernen. | `grep` nach Key in `authorized_keys` | einfach |

---

## ufw — Firewall (Uncomplicated Firewall)

| Modul         | Beschreibung                                                              | Check-Strategie     | Aufwand |
| ------------- | ------------------------------------------------------------------------- | ------------------- | ------- |
| `ufw.rule`    | Fuegt eine Firewall-Regel hinzu (allow/deny fuer Ports oder Port-Listen). | `ufw status` parsen | einfach |
| `ufw.enabled` | Stellt sicher, dass UFW aktiviert ist.                                    | `ufw status`        | einfach |

---

## cron — Cronjob-Verwaltung

| Modul      | Beschreibung                                                                                                                                                    | Check-Strategie                         | Aufwand |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------- |
| `cron.job` | Verwaltet Eintraege in der Crontab eines Benutzers. Kann Jobs hinzufuegen, aendern oder entfernen. Identifiziert Jobs ueber einen eindeutigen Kommentar-Marker. | `crontab -l` parsen, nach Marker suchen | einfach |

---

## hostname — Hostnamen-Verwaltung

| Modul          | Beschreibung                               | Check-Strategie                     | Aufwand |
| -------------- | ------------------------------------------ | ----------------------------------- | ------- |
| `hostname.set` | Setzt den Hostnamen des Servers dauerhaft. | `hostname` abfragen und vergleichen | einfach |

---

## git — Git-Deployments

| Modul       | Beschreibung                                                                                                                               | Check-Strategie                                                  | Aufwand |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ------- |
| `git.clone` | Klont ein Git-Repository oder aktualisiert es auf einen bestimmten Branch, Tag oder Commit. Nützlich fuer Code-Deployments auf den Server. | `git rev-parse HEAD` im Zielverzeichnis vs. gewuenschte Referenz | mittel  |

> **Hinweis:** Authentifizierung fuer private Repositories (SSH-Agent-Forwarding,
> Deploy-Keys) ist aktuell nicht im Scope. `git.clone` funktioniert mit
> oeffentlichen Repositories und Repositories, die ueber bereits auf dem Server
> konfigurierte SSH-Keys erreichbar sind.

---

## download — Datei-Downloads

| Modul            | Beschreibung                                                                                                                                                                                                                                                            | Check-Strategie                                          | Aufwand |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------- |
| `download.url`   | Lädt eine Datei von einer HTTPS-URL auf den Server herunter. Nutzt `curl` (Default) mit Fallback auf `wget` falls curl nicht installiert ist. Verlangt `sha256` oder explizit `allowUnverifiedDownload: true`; `http://` ist nur mit `allowInsecureHttp: true` erlaubt. | Checksum der existierenden Datei vs. erwartete Checksum  | mittel  |
| `download.large` | Wie `download.url`, aber für große Dateien. Nutzt zusätzlich ein State-Flag, da der Download teuer ist; der gleiche HTTPS- und Integritätsvertrag gilt auch für große Dateien.                                                                                          | State-Flag: `/var/lib/paratix/flags/download-<url-hash>` | mittel  |

Downloads brauchen immer eine explizite Integritätsentscheidung: entweder
`sha256` für die Prüfung der heruntergeladenen und bereits vorhandenen Datei
oder `allowUnverifiedDownload: true`, wenn ein ungeprüfter Download bewusst
akzeptiert wird. HTTPS ist der Standard; `http://`-URLs und HTTP-Redirects
laufen nur mit `allowInsecureHttp: true`.

---

## archive — Archiv-Verwaltung

| Modul             | Beschreibung                                                                                      | Check-Strategie                                        | Aufwand |
| ----------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------- |
| `archive.extract` | Entpackt ein Archiv (tar, zip, gz) auf dem Server. Optional mit vorherigem Upload vom Controller. | Pruefung ob Zielverzeichnis existiert und Inhalt passt | mittel  |

---

## script — Skript-Ausfuehrung

| Modul         | Beschreibung                                                                                                                                                      | Check-Strategie                                              | Aufwand |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ------- |
| `script.once` | Kopiert ein lokales Skript auf den Server und fuehrt es einmalig aus. Nutzt State-Flag mit Skriptname und Version, sodass es bei Versionsaenderung erneut laeuft. | State-Flag: `/var/lib/paratix/flags/script-<name>-<version>` | einfach |

---

## command — Befehlsausfuehrung

| Modul           | Beschreibung                                                                                                                                                                                             | Check-Strategie                                            | Aufwand |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------- |
| `command.shell` | Fuehrt einen Befehl auf dem Server via `/bin/sh -c` aus. Ermoeglicht Pipes, Redirects und Shell-Variablen. Gibt immer `changed` zurueck, es sei denn ein benutzerdefinierter Check-Befehl ist angegeben. | Kein Check (always changed) oder benutzerdefinierter Check | trivial |

---

## net — Netzwerk-Konfiguration

| Modul           | Beschreibung                                                                                                                                                                                                                                                      | Check-Strategie                                                      | Aufwand |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------- |
| `net.hosts`     | Verwaltet Eintraege in `/etc/hosts`. Fuegt eine IP-Hostname-Zuordnung hinzu oder entfernt sie. Akzeptiert eine IP-Adresse, eine Liste von Hostnamen und ein optionales `state`-Flag (`"present"` oder `"absent"`, Standard: `"present"`).                         | `/etc/hosts` lesen, nach erwarteter Zeile suchen                     | einfach |
| `net.interface` | Konfiguriert eine Netzwerkschnittstelle via Netplan (wenn `/etc/netplan/` vorhanden) oder systemd-networkd. Erkennt automatisch, welche Methode aktiv ist, und schreibt die Konfigurationsdatei in den passenden Pfad. Wendet die Konfiguration danach direkt an. | Konfigurationsdatei lesen und mit Sollzustand vergleichen            | mittel  |
| `net.resolv`    | Verwaltet `/etc/resolv.conf` (Nameserver und Suchdomaenen). Entfernt vorhandene Symlinks (z.B. von systemd-resolved) und schreibt die Datei direkt.                                                                                                               | `/etc/resolv.conf` lesen und mit Sollinhalt vergleichen              | einfach |
| `net.route`     | Verwaltet persistente statische Routen. Wendet die Route sofort via `ip route replace` an und persistiert sie als systemd-networkd Drop-in unter `/etc/systemd/network/`. Unterstuetzt `state: "absent"` zum Entfernen.                                           | `ip route show <destination>` ausfuehren und Gateway-Eintrag pruefen | einfach |
| `net.waitFor`   | Wartet darauf, dass eine Bedingung erfuellt ist: Port offen, Datei vorhanden, oder String in Datei. Nützlich nach Service-Starts oder Deployments. Polling-Intervall: 2s (konfigurierbar). Default-Timeout: 60s (konfigurierbar).                                 | Polling mit Timeout                                                  | mittel  |
| `net.request`   | Fuehrt einen HTTP-Request vom Server aus und prueft die Antwort (Statuscode, Body). Nützlich fuer Health-Checks.                                                                                                                                                  | HTTP-Statuscode und optionaler Body-Check                            | mittel  |

**`net.hosts` — Beispiel:**

```typescript
// Eintrag hinzufuegen
net.hosts("10.0.0.5", ["internal.example.com", "internal"])

// Eintrag entfernen
net.hosts("10.0.0.5", ["internal.example.com"], { state: "absent" })
```

**`net.interface` — Beispiel:**

```typescript
// Statische IP (Netplan oder networkd, automatisch erkannt)
net.interface("eth0", {
  addresses: ["10.0.0.10/24"],
  gateway: "10.0.0.1",
  nameservers: ["1.1.1.1", "8.8.8.8"],
})

// DHCP
net.interface("eth1", { dhcp: true })
```

**`net.resolv` — Beispiel:**

```typescript
net.resolv({
  nameservers: ["1.1.1.1", "8.8.8.8"],
  search: ["example.com"],
})
```

**`net.route` — Beispiel:**

```typescript
// Route hinzufuegen
net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

// Route entfernen
net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
```

**`net.waitFor` — Beispiel:**

```typescript
// Warten bis Port 5432 (PostgreSQL) erreichbar ist
net.waitFor({ port: 5432 })

// Warten bis eine Datei existiert (z.B. nach einem Service-Start)
net.waitFor({ file: "/var/run/myapp.pid" })

// Warten bis eine Datei einen bestimmten String enthaelt
net.waitFor({ file: "/var/log/myapp.log", contains: "Server started" })

// Timeout und Polling-Intervall anpassen (Werte in Millisekunden)
net.waitFor({ port: 8080, timeout: 120_000, interval: 5000 })
```

**`net.request` — Beispiel:**

```typescript
// Health-Check: HTTP 200 erwarten
net.request("http://localhost/health")

// Bestimmten Statuscode und Body-String pruefen
net.request("http://localhost/api/status", { status: 200, body: '"ok"' })

// POST-Request mit Header
net.request("http://localhost/api/ping", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
})
```

> **Hinweis:** `net.interface` schreibt bei Netplan nach
> `/etc/netplan/60-paratix-<name>.yaml` und fuehrt `netplan apply` aus.
> Bei systemd-networkd wird `/etc/systemd/network/60-paratix-<name>.network`
> geschrieben und `networkctl reload` ausgefuehrt. `net.route` schreibt Drop-ins
> nach `/etc/systemd/network/50-paratix-route-<destination>.network`.

---

## system — Systemoperationen

| Modul           | Beschreibung                                                                                                                                                                                                                                                        | Check-Strategie                                       | Aufwand   |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | --------- |
| `system.reboot` | Startet den Server neu und wartet auf Reconnect. Paratix pollt alle konfigurierten SSH-Ports, bis der Server wieder erreichbar ist.                                                                                                                                 | Signal-basiert oder bedingt (z.B. nach Kernel-Update) | mittel    |
| `system.facts`  | Sammelt System-Informationen und schreibt sie als Meta-Eintraege in den Env. Aendert nichts am Server. Nachfolgende Module und Templates koennen auf die Werte zugreifen (z.B. `{{system.os}}` in Templates, `env["system.os"]` in Modulen). Siehe Meta-Keys unten. | Immer `ok` (reines Lesen)                             | aufwendig |

### system.facts — Meta-Keys

`system.facts` fuehrt mehrere Befehle auf dem Server aus und schreibt die
Ergebnisse als flache Key-Value-Paare in den Env:

```typescript
// Beispiel-Output im Env nach system.facts():
{
  "system.os":           "debian",        // oder "ubuntu"
  "system.os.version":   "12",            // Major-Version
  "system.os.codename":  "bookworm",      // Codename der Distribution
  "system.arch":         "x86_64",        // Architektur
  "system.hostname":     "vps-primary",
  "system.kernel":       "6.1.0-18-amd64",
  "system.ram.total":    "4096",          // in MB
  "system.cpu.cores":    "4",
  "system.ip.public":    "1.2.3.4",       // primaere oeffentliche IPv4
  "system.ip.private":   "10.0.0.5",      // primaere private IPv4 (falls vorhanden)
  "system.disk.root":    "49152",         // Groesse von / in MB
}
```

**Umsetzung:** Jeder Key wird durch einen einzelnen SSH-Befehl ermittelt:

| Key                  | Befehl                                          |
| -------------------- | ----------------------------------------------- |
| `system.os`          | `lsb_release -si` oder `/etc/os-release` parsen |
| `system.os.version`  | `lsb_release -sr` oder `/etc/os-release` parsen |
| `system.os.codename` | `lsb_release -sc` oder `/etc/os-release` parsen |
| `system.arch`        | `uname -m`                                      |
| `system.hostname`    | `hostname`                                      |
| `system.kernel`      | `uname -r`                                      |
| `system.ram.total`   | `free -m` parsen                                |
| `system.cpu.cores`   | `nproc`                                         |
| `system.ip.public`   | `ip -4 route get 1.1.1.1` parsen                |
| `system.ip.private`  | `ip -4 addr` parsen (erster RFC-1918-Bereich)   |
| `system.disk.root`   | `df -m /` parsen                                |

**Fehlerverhalten:** Wenn ein einzelner Befehl fehlschlaegt (z.B. `lsb_release`
nicht installiert), gibt `system.facts` `failed` zurueck. Alle Befehle muessen
erfolgreich sein, da nachfolgende Module und `when()`-Bedingungen sich auf
vollstaendige System-Informationen verlassen.

**Nutzung in Templates:**

```
# ./files/nginx.tmpl.conf
# Konfiguriert für {{system.hostname|raw}} ({{system.os|raw}} {{system.os.version|raw}})
worker_processes {{system.cpu.cores|raw}};
```

**Nutzung in Playbooks (bedingte Logik via `when()`):**

```typescript
import { server, when } from "paratix"
import { system, apt } from "paratix/modules"

export default server({
  // ...
  run: [
    system.facts(),

    // Bedingt: nur auf Ubuntu
    when((env) => env["system.os"] === "ubuntu", apt.repository("ppa:nginx/stable")),
  ],
})
```

> **Hinweis:** Bedingte Logik, die auf Env-Werten basiert, muss `when()`
> verwenden, da das `run`-Array zur Importzeit ausgewertet wird und der Env
> erst zur Laufzeit zur Verfuegung steht. Siehe `when()` in der
> [Initialbeschreibung](./initialbeschreibung.md).

> **Hinweis:** `system.facts` muss nicht am Anfang jedes Playbooks stehen.
> Es ist ein normales Modul — wer die Werte nicht braucht, laesst es weg.
> Module wie `package.installed` rufen `system.facts` **nicht** implizit auf;
> sie erwarten, dass `system.os` im Env steht (entweder durch `system.facts`
> oder durch manuelle Env-Konfiguration).

---

## package — Generischer Paketmanager

| Modul               | Beschreibung                                                                                                                                                                                   | Check-Strategie                         | Aufwand |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------- |
| `package.installed` | Abstrahiert ueber `apt`, `dnf` und andere Paketmanager. Erkennt automatisch das Betriebssystem und waehlt den passenden Paketmanager. Erfordert `system.facts` oder manuelle OS-Angabe im Env. | Delegiert an den erkannten Paketmanager | mittel  |
| `package.absent`    | Gegenstueck zu `package.installed`. Entfernt Pakete unabhaengig vom Paketmanager.                                                                                                              | Delegiert an den erkannten Paketmanager | mittel  |

---

## quadlet — Podman-Quadlet-Container

Verwaltet Podman-Quadlet-Definitionen unter `/etc/containers/systemd/` und
unterstuetzt ausserdem gezielte Image-Updates fuer genau einen Quadlet-Service.

| Modul                 | Beschreibung                                                                                                                                                                                             | Check-Strategie                                                       | Aufwand |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------- |
| `quadlet.container`   | Schreibt eine deklarative `.container`-Datei fuer einen Podman-Service und fuehrt bei Aenderungen `systemctl daemon-reload` aus.                                                                         | Remote-Datei mit gerendertem Soll-Inhalt vergleichen                  | mittel  |
| `quadlet.updateImage` | Zieht genau ein Container-Image via `podman pull`, ermittelt danach bevorzugt den neuen Registry-Digest und startet den zugehoerigen systemd-Service nur dann neu, wenn ein neueres Image geladen wurde. | Signal-artig: Pull ausfuehren, Ausgabe auf Download-Indikator pruefen | einfach |

**Beispiel im Playbook:**

```typescript
const managerQuadlet = {
  authFile: "/run/containers/auth.json",
  image: "ghcr.io/acme/convex-manager:latest",
  name: "convex-manager",
  publishPorts: ["127.0.0.1:3210:3210"],
  restart: "always",
}

recipe("convex-manager", [
  quadlet.container(managerQuadlet),
  service.enabled("convex-manager"),
  service.running("convex-manager"),
])

recipe("convex-manager image update", [quadlet.updateImage(managerQuadlet)])
```

**Hinweis:** `quadlet.updateImage(...)` akzeptiert dieselben `name`- und
`image`-Felder wie `quadlet.container(...)`. Damit kann dieselbe
Konfigurationsquelle fuer Deployment und spaetere Image-Refreshes verwendet
werden, ohne `command.shell("podman pull ...")` in Projekt-Code einzubauen.
Bei einem tatsaechlich aktualisierten Image erscheint hinter `changed` zudem
bevorzugt der neue Registry-Digest in Klammern, mit lokaler Image-ID als
Fallback wenn kein `RepoDigest` vorhanden ist.

---

## compose — Container-Compose-Verwaltung (Docker & Podman)

Verwaltet Container-Stacks ueber `docker compose` oder `podman compose`.
Das Modul erkennt automatisch, welche Runtime verfuegbar ist, oder akzeptiert
eine explizite Angabe (`runtime: "docker" | "podman"`). Alle Operationen
arbeiten relativ zu einem `projectDirectory`, in dem die `compose.yml` (bzw.
`docker-compose.yml`) liegt.

| Modul             | Beschreibung                                                                                                                                                                                                                                                | Check-Strategie                                                                      | Aufwand |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------- |
| `compose.up`      | Stellt sicher, dass alle Services eines Compose-Projekts laufen. Fuehrt `compose up -d` aus, falls Container fehlen oder nicht laufen. Akzeptiert ein `projectDirectory` (Pfad auf dem Server zur `compose.yml`) und optional eine Liste von Service-Namen. | `compose ps --format json` parsen — alle erwarteten Container muessen `running` sein | mittel  |
| `compose.pull`    | Zieht die neuesten Images fuer alle Services eines Compose-Projekts. Gibt `changed` zurueck, wenn mindestens ein Image aktualisiert wurde.                                                                                                                  | `compose pull` ausfuehren und Ausgabe auf `Pulling`/`Downloaded` pruefen             | mittel  |
| `compose.down`    | Stoppt und entfernt alle Container eines Compose-Projekts. Optional mit `--volumes` zum Entfernen persistenter Volumes.                                                                                                                                     | `compose ps --format json` parsen — keine Container duerfen existieren               | einfach |
| `compose.config`  | Deployt eine `compose.yml`-Datei auf den Server (via `file.copy` oder `file.template` als Komposition) und validiert sie mit `compose config`. Kombiniert Datei-Deployment mit Syntax-Pruefung.                                                             | SHA-256-Vergleich der Compose-Datei                                                  | mittel  |
| `compose.restart` | Signal-Modul: Fuehrt `compose down && compose up -d` aus. Wird nur als Signal in Recipes verwendet und nur getriggert, wenn innerhalb der Recipe ein Modul `changed` zurueckgegeben hat.                                                                    | Signal-basiert (kein eigenstaendiger Check)                                          | einfach |

**Runtime-Erkennung:**

```typescript
// Automatisch (prueft erst docker, dann podman)
compose.up({ projectDirectory: "/opt/traefik" })

// Explizit
compose.up({ projectDirectory: "/opt/traefik", runtime: "podman" })
```

**Beispiel im Playbook:**

```typescript
recipe(
  "traefik",
  [
    file.directory("/opt/traefik"),
    file.template("/opt/traefik/compose.yml", "./files/traefik-compose.tmpl.yml"),
    compose.pull({ projectDirectory: "/opt/traefik" }),
    compose.up({ projectDirectory: "/opt/traefik" }),
  ],
  {
    signals: [compose.restart({ projectDirectory: "/opt/traefik" })],
  }
)
```

> **Hinweis:** `compose.restart` ist ein Signal-Modul analog zu `service.restart`.
> Es fuehrt `compose down && compose up -d` aus und wird nur getriggert, wenn
> innerhalb der Recipe ein Modul `changed` zurueckgegeben hat.

---

## sysctl — Kernel-Parameter

| Modul        | Beschreibung                                                                                                                                                                                                                                                                                                       | Check-Strategie                                          | Aufwand |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- | ------- |
| `sysctl.set` | Setzt einen einzelnen Kernel-Parameter zur Laufzeit und persistiert ihn pro Key in `/etc/sysctl.d/`. Signatur: `sysctl.set(key, value, options?)`. Der Parameter wird sofort via `sysctl -w` angewendet und in eine eigene Datei `99-paratix-<sanitized-key>-<hash>.conf` geschrieben, damit er Reboots ueberlebt. | `sysctl -n <key>` abfragen und mit Soll-Wert vergleichen | einfach |

**Beispiel:**

```typescript
run(server, [
  sysctl.set("net.ipv6.conf.all.forwarding", "1"),
  sysctl.set("net.ipv4.ip_forward", "1"),
  sysctl.set("kernel.core_pattern", "/dev/null"), // Core-Dumps deaktivieren
])
```

**Persistenz:** Pro Aufruf wird genau eine Datei
`/etc/sysctl.d/99-paratix-<sanitized-key>-<hash>.conf` mit dem Inhalt
`<key> = <value>` geschrieben (z.B.
`/etc/sysctl.d/99-paratix-net-ipv4-ip_forward-<hash>.conf`). Mehrere Keys
liegen damit in getrennten Dateien; `sysctl -w` setzt den Live-Wert sofort,
ein separater Reload-Schritt ist nicht noetig.

---

## mount — Dateisystem-Mounts

| Modul           | Beschreibung                                                                                                                                                                                                                                                | Check-Strategie                                            | Aufwand |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------- |
| `mount.present` | Stellt sicher, dass ein Dateisystem gemountet ist. Unterstuetzt Block-Devices, tmpfs, NFS und andere Dateisysteme. Kann den Mount in `/etc/fstab` persistieren, sodass er Reboots ueberlebt. Erstellt den Mountpoint automatisch, falls er nicht existiert. | `findmnt <mountpoint>` pruefen + fstab-Eintrag vergleichen | mittel  |
| `mount.absent`  | Stellt sicher, dass ein Mountpoint nicht gemountet ist. Entfernt optional den fstab-Eintrag und den Mountpoint-Ordner.                                                                                                                                      | `findmnt <mountpoint>` pruefen                             | einfach |

**Parameter fuer `mount.present`:**

```typescript
mount.present({
  path: "/tmp", // Mountpoint
  src: "tmpfs", // Device oder "tmpfs", "none", NFS-Pfad, ...
  fstype: "tmpfs", // Dateisystemtyp
  opts: "noexec,nosuid,nodev,size=512m", // Mount-Optionen
  persist: true, // In /etc/fstab eintragen (Standard: true)
})
```

**Beispiele:**

```typescript
// tmpfs mit Sicherheitsoptionen (Hardening)
mount.present({
  path: "/tmp",
  src: "tmpfs",
  fstype: "tmpfs",
  opts: "noexec,nosuid,nodev,size=512m",
})

// Shared Memory absichern
mount.present({
  path: "/run/shm",
  src: "tmpfs",
  fstype: "tmpfs",
  opts: "noexec,nosuid,nodev",
})

// Block-Device mounten
mount.present({
  path: "/mnt/data",
  src: "/dev/sdb1",
  fstype: "ext4",
  opts: "defaults,noatime",
})
```

**fstab-Management:** Das Modul identifiziert fstab-Eintraege ueber den
Mountpoint (`path`). Existiert bereits ein Eintrag fuer denselben Mountpoint
mit abweichenden Optionen, wird er aktualisiert. Bei `mount.absent` mit
`persist: true` wird der fstab-Eintrag entfernt.

---

## rsync — Datei-Synchronisation

| Modul        | Beschreibung                                                                                                                                                                                                                | Check-Strategie                                                           | Aufwand |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------- |
| `rsync.sync` | Synchronisiert Dateien vom Controller (lokal) auf den Server via rsync ueber SSH. Unterstuetzt Include/Exclude-Patterns, Delete-Modus und Berechtigungen. Ideal fuer Application-Deployments mit komplexen Dateistrukturen. | rsync im `--dry-run`-Modus ausfuehren und pruefen ob Aenderungen anstehen | mittel  |

**Parameter:**

```typescript
rsync.sync({
  src: "./dist/", // Lokaler Quellpfad (auf dem Controller)
  dest: "/opt/myapp/", // Zielpfad auf dem Server
  exclude: [".git", "node_modules"], // Ausgeschlossene Patterns
  include: ["dist/**", "package.json"], // Eingeschlossene Patterns (vor exclude ausgewertet)
  delete: true, // Dateien im Ziel loeschen, die in der Quelle fehlen
  owner: "deploy", // Besitzer der Dateien auf dem Server (optional)
  group: "deploy", // Gruppe (optional)
  chmod: "D755,F644", // Berechtigungen (optional, rsync-Syntax)
})
```

**Beispiel — Monorepo-Deployment:**

```typescript
rsync.sync({
  src: "./",
  dest: "/opt/convex-manager/",
  include: ["packages/backend/dist/***", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"],
  exclude: ["*"], // Alles andere ausschliessen
  delete: true,
})
```

**Umsetzung:** Das Modul ruft `rsync` lokal auf dem Controller auf und nutzt
die bestehende SSH-Verbindungskonfiguration (Port, Key) fuer den Transfer.
Die SSH-Optionen werden automatisch aus der Serverdefinition abgeleitet.

---

## op — 1Password Secret-Aufloesung

| Modul        | Beschreibung                                                                                                                                                                                                                                                                               | Check-Strategie                                 | Aufwand |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------- | ------- |
| `op.resolve` | Löst `op://`-Referenzen über die 1Password CLI (`op`) auf dem Controller auf. Akzeptiert ein `Record<string, string>` mit Env-Keys und `op://`-URIs als Werte. Die echten Werte werden als Meta-Einträge in den Env geschrieben. **Läuft lokal auf dem Controller, nicht auf dem Server.** | Immer `ok` (reines Lesen, keine Serveränderung) | mittel  |

**Wichtig:** Dieses Modul ist ein **lokales Modul** — es nutzt kein SSH,
sondern ruft `op` auf dem Controller-Rechner auf. Es implementiert dennoch
die Plugin-Schnittstelle und gibt seine Ergebnisse über `meta` zurück.

**Parameter:**

```typescript
op.resolve({
  "db.password": "op://Employee/Database/password",
  "api.token": "op://Employee/API-Service/credential",
  "admin.otp": "op://Employee/Palamedes Admin/one-time-password",
  "backup.passphrase": "op://Infrastructure/Restic/password",
})
```

**Rueckgabe (meta):**

```typescript
import { meta } from "paratix"

{
  meta: [
    meta.env("db.password", "s3cret!"),
    meta.env("api.token", "tok_abc123..."),
    meta.env("admin.otp", () => calculateOTP("otpauth://totp/...?secret=JBSWY3DPEHPK3PXP")),
    meta.env("backup.passphrase", "correct-horse-battery-staple"),
  ]
}
```

**Lazy OTP-Aufloesung:** OTP-Felder (`one-time-password`) werden als
**lazy Env-Werte** (Funktionen) in den Env geschrieben. Der TOTP-Code wird
erst berechnet, wenn ein Modul oder Template tatsaechlich auf den Wert
zugreift (via `resolveEnv`). Das ist notwendig, weil OTPs nur 30 Sekunden
gueltig sind und zwischen `op.resolve()` und der tatsaechlichen Verwendung
beliebig viel Zeit vergehen kann.

Regulaere Secrets (Passwoerter, Tokens, etc.) werden sofort als Strings
aufgeloest, da sie sich nicht zeitlich aendern.

**Umsetzung via `op read`:** Das Modul nutzt `op read <reference>`, um jede
reguläre Referenz direkt als Rohwert aufzulösen. Dadurch bleiben Anführungs-
zeichen, Backslashes und Zeilenumbrüche unverändert erhalten:

```bash
op read op://Employee/Database/password
# → s3cret!
```

Das Ergebnis wird als String in den Env geschrieben und als Secret-Wert für
die Ausgabe-Maskierung registriert.

**OTP-Felder** werden separat behandelt:

- OTP-Referenzen (Feld endet auf `one-time-password` oder `otp`) werden
  separat behandelt.
- Für jedes OTP-Feld wird einmalig via `op read <reference>` die
  `otpauth://`-URI abgerufen (enthält das TOTP-Secret).
- In den Env wird eine Funktion `() => string` geschrieben, die bei jedem
  Zugriff aus dem Secret einen frischen TOTP-Code berechnet (lokal, ohne
  erneuten `op`-Aufruf).

**Sicherheit:**

- Aufgeloeste Werte werden **nie in der Konsolenausgabe** angezeigt.
  Das Modul zeigt nur die Keys an, nicht die Werte (`✓ op: db.password, api.token, admin.otp, backup.passphrase`).
- Die `op`-CLI muss auf dem Controller installiert und authentifiziert sein
  (`op signin` oder biometrische Entsperrung).

**Beispiel im Playbook:**

```typescript
export default server({
  name: "backend",
  host: "1.2.3.4",
  ssh: { user: "bs5", ports: [2222] },

  run: [
    op.resolve({
      "convex.jwt_secret": "op://Infrastructure/Convex/jwt-secret",
      "convex.admin_pw_hash": "op://Infrastructure/Convex/admin-password-hash",
      "restic.password": "op://Infrastructure/Restic/password",
    }),

    // Ab hier stehen die Secrets im Env zur Verfuegung:
    file.template("/opt/convex-manager/.env", "./files/convex.tmpl.env"),
    // Template kann {{convex.jwt_secret|raw}} verwenden
  ],
})
```

---

# Built-in-Funktionen (keine Module)

Die folgenden Ansible-Aequivalente werden als **eingebaute Funktionen im
Runner** implementiert, nicht als Module. Sie folgen nicht dem Check→Apply-Muster,
benoetigen kein SSH und sind reine Ablaufsteuerung.

| Funktion                     | Beschreibung                                       | Ansible-Aequivalent |
| ---------------------------- | -------------------------------------------------- | ------------------- |
| `assert(condition, message)` | Prueft eine Bedingung und bricht bei Fehler ab.    | `assert`            |
| `debug(message)`             | Gibt eine Nachricht in der Konsolenausgabe aus.    | `debug`             |
| `fail(message)`              | Bricht die Ausfuehrung mit einer Fehlermeldung ab. | `fail`              |
| `pause(message?)`            | Pausiert und wartet auf Benutzerbestaetigung.      | `pause`             |

Der `set_fact`-Mechanismus wird durch das bestehende **Env-System** abgedeckt:
Module setzen `meta`-Eintraege in ihrem `ModuleResult`, die automatisch in den
Env uebernommen werden.

---

---

# Fuer spaeter: Nicht-Debian-Paketmanager

Module fuer RHEL/Fedora/CentOS-basierte Systeme. Werden erst implementiert,
wenn Paratix ueber Debian/Ubuntu hinaus erweitert wird.

| Modul              | Beschreibung                                                     | Aufwand |
| ------------------ | ---------------------------------------------------------------- | ------- |
| `dnf.installed`    | Installiert Pakete via dnf (Fedora/RHEL 8+).                     | einfach |
| `dnf.absent`       | Entfernt Pakete via dnf.                                         | einfach |
| `yum.repository`   | Verwaltet YUM-Repository-Dateien in `/etc/yum.repos.d/`.         | einfach |
| `rpm.key`          | Fuegt GPG-Schluessel zur RPM-Datenbank hinzu.                    | einfach |
| `pip.installed`    | Installiert Python-Pakete via pip.                               | einfach |
| `pip.absent`       | Entfernt Python-Pakete via pip.                                  | einfach |
| `sysvinit.service` | Verwaltet SysV-Init-Dienste (fuer aeltere Systeme ohne systemd). | einfach |
