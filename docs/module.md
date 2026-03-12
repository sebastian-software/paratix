# Paratix — Modulkatalog

Alle Module, die durch das Paratix Plugin-System implementiert werden sollen.
Jedes Modul implementiert die Plugin-Schnittstelle (`check` / `apply`) und ist
idempotent, sofern nicht anders vermerkt.

> Abgeleitet aus [initialbeschreibung.md](./initialbeschreibung.md) und
> [ansible.md](./ansible.md).

---

## apt — Debian/Ubuntu-Paketverwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `apt.installed` | Stellt sicher, dass eines oder mehrere Pakete installiert sind. Akzeptiert Paketnamen als Argumente. | `dpkg -l <paket>` pruefen | einfach |
| `apt.absent` | Stellt sicher, dass ein Paket nicht installiert ist. Entfernt es bei Bedarf. | `dpkg -l <paket>` pruefen | einfach |
| `apt.upgrade` | Fuehrt ein vollstaendiges `apt-get upgrade` durch. Nutzt State-Flag mit Datum, da die Operation teuer ist und nicht effizient geprueft werden kann. | State-Flag: `/var/lib/paratix/flags/apt-upgrade-<datum>` | einfach |
| `apt.distUpgrade` | Fuehrt ein `apt-get dist-upgrade` durch. Wie `apt.upgrade`, aber mit Distribution-Upgrade. Nutzt State-Flag mit Datum. | State-Flag: `/var/lib/paratix/flags/apt-dist-upgrade-<datum>` | einfach |
| `apt.key` | Fuegt einen GPG-Schluessel fuer APT hinzu oder entfernt ihn. Wird benoetigt, um Drittanbieter-Repositories zu authentifizieren. | Pruefung ob Key-ID in `apt-key list` vorhanden | einfach |
| `apt.repository` | Fuegt ein APT-Repository hinzu oder entfernt es. Verwaltet Dateien in `/etc/apt/sources.list.d/`. | Pruefung ob Datei in `/etc/apt/sources.list.d/` existiert und korrekt ist | einfach |
| `apt.debconf` | Setzt vorkonfigurierte Antworten fuer interaktive Paketinstallationen (z.B. Postfix-Konfigurationstyp). | `debconf-show <paket>` parsen | mittel |

---

## file — Dateiverwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `file.copy` | Kopiert eine lokale Datei auf den Server. Vergleicht per SHA-256-Hash, ob die Datei bereits identisch ist. | SHA-256-Vergleich lokal vs. remote | einfach |
| `file.template` | Rendert ein Template mit dem aktuellen Env und kopiert das Ergebnis auf den Server. Templates nutzen `{{key}}`-Syntax fuer Env-Zugriff. | SHA-256 des gerenderten Templates vs. Remote-Datei | einfach |
| `file.line` | Stellt sicher, dass eine bestimmte Zeile in einer Datei vorhanden ist. Kann optional eine Zeile ersetzen, die einem Muster entspricht. | `grep -qF` nach Zeile oder Muster | mittel |
| `file.block` | Fuegt einen Textblock mit Marker-Zeilen in eine Datei ein oder aktualisiert ihn. Marker ermoglichen wiederholtes Aktualisieren desselben Blocks. | `grep` nach Marker-Zeilen, Inhalt zwischen Markern vergleichen | mittel |
| `file.replace` | Ersetzt alle Vorkommen eines regulaeren Ausdrucks in einer Datei. | `grep` nach Pattern, pruefen ob Ersetzung noetig | mittel |
| `file.assemble` | Setzt eine Konfigurationsdatei aus mehreren Fragmentdateien zusammen. Nützlich fuer modulare Konfigurationen (z.B. sudoers.d-Stil). | SHA-256 der konkatenierten Fragmente vs. Zieldatei | mittel |
| `file.properties` | Verwaltet Dateieigenschaften: Berechtigungen (mode), Besitzer (owner), Gruppe (group), Typ (file/directory/symlink/absent). | `stat`-Befehl, Vergleich aller Properties | mittel |
| `file.directory` | Stellt sicher, dass ein Verzeichnis existiert, optional mit bestimmten Berechtigungen und Besitzer. | `test -d` + `stat` | einfach |
| `file.absent` | Stellt sicher, dass eine Datei oder ein Verzeichnis nicht existiert. | `test -e` | einfach |
| `file.stat` | Ruft Datei-Metadaten ab (Groesse, Berechtigungen, Timestamps, etc.) und schreibt sie als Meta-Eintraege in den Env. Aendert nichts am Server. | Immer `ok` (reines Lesen) | einfach |

---

## service — Dienstverwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `service.running` | Stellt sicher, dass ein Dienst laeuft. Startet ihn bei Bedarf. | `systemctl is-active <dienst>` | einfach |
| `service.stopped` | Stellt sicher, dass ein Dienst gestoppt ist. | `systemctl is-active <dienst>` | einfach |
| `service.enabled` | Stellt sicher, dass ein Dienst beim Systemstart aktiviert ist. | `systemctl is-enabled <dienst>` | einfach |
| `service.disabled` | Stellt sicher, dass ein Dienst beim Systemstart deaktiviert ist. | `systemctl is-enabled <dienst>` | einfach |
| `service.restart` | Startet einen Dienst neu. Wird primaer als **Signal** in Recipes verwendet und nur ausgefuehrt, wenn innerhalb der Recipe ein Modul `changed` zurueckgegeben hat. | Signal-basiert (kein eigenstaendiger Check) | einfach |
| `service.reload` | Laedt die Konfiguration eines Dienstes neu (ohne Neustart). Wird wie `service.restart` als Signal verwendet. | Signal-basiert (kein eigenstaendiger Check) | einfach |
| `service.facts` | Sammelt Statusinformationen aller Dienste und schreibt sie als Meta-Eintraege in den Env. Aendert nichts am Server. | Immer `ok` (reines Lesen) | einfach |

---

## systemd — Systemd-spezifisch

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `systemd.unit` | Deployt eine eigene Systemd-Unit-Datei auf den Server und fuehrt `systemctl daemon-reload` aus, falls sie sich geaendert hat. | SHA-256-Vergleich der Unit-Datei | einfach |

---

## user — Benutzerverwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `user.present` | Stellt sicher, dass ein Benutzerkonto existiert. Kann UID, Shell, Home-Verzeichnis, Gruppen und Passwort-Hash konfigurieren. Schreibt `user.home` in Meta. | `id <user>` + Vergleich der Properties | einfach |
| `user.absent` | Stellt sicher, dass ein Benutzerkonto nicht existiert. Kann optional das Home-Verzeichnis loeschen. | `id <user>` | einfach |

---

## group — Gruppenverwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `group.present` | Stellt sicher, dass eine Systemgruppe existiert. Kann GID konfigurieren. | `getent group <name>` | einfach |
| `group.absent` | Stellt sicher, dass eine Systemgruppe nicht existiert. | `getent group <name>` | einfach |

---

## sshd — SSH-Server-Konfiguration

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `sshd.port` | Aendert den SSH-Port in der `sshd_config`. Validiert, dass der Zielport in der `ssh.ports`-Liste der Serverdefinition eingetragen ist. Schreibt `sshd.port` in Meta, wodurch Paratix die SSH-Verbindung auf den neuen Port umstellt. | `sshd_config` auslesen und Port vergleichen | einfach |
| `sshd.config` | Setzt einzelne Konfigurationsoptionen in `sshd_config` (z.B. `PermitRootLogin`, `PasswordAuthentication`). Akzeptiert Key-Value-Paare. | `sshd_config` parsen, Werte vergleichen | einfach |

---

## ssh — SSH-Client-Konfiguration

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `ssh.knownHosts` | Fuegt einen Host zur `known_hosts`-Datei hinzu oder entfernt ihn. | `ssh-keygen -F <host>` | einfach |
| `ssh.authorizedKeys` | Verwaltet SSH-Public-Keys in der `authorized_keys`-Datei eines Benutzers. Kann Keys hinzufuegen oder entfernen. | `grep` nach Key in `authorized_keys` | einfach |

---

## ufw — Firewall (Uncomplicated Firewall)

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `ufw.rule` | Fuegt eine Firewall-Regel hinzu (allow/deny fuer Ports oder Port-Listen). | `ufw status` parsen | einfach |
| `ufw.enabled` | Stellt sicher, dass UFW aktiviert ist. | `ufw status` | einfach |

---

## cron — Cronjob-Verwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `cron.job` | Verwaltet Eintraege in der Crontab eines Benutzers. Kann Jobs hinzufuegen, aendern oder entfernen. Identifiziert Jobs ueber einen eindeutigen Kommentar-Marker. | `crontab -l` parsen, nach Marker suchen | einfach |

---

## hostname — Hostnamen-Verwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `hostname.set` | Setzt den Hostnamen des Servers dauerhaft. | `hostname` abfragen und vergleichen | einfach |

---

## git — Git-Deployments

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `git.clone` | Klont ein Git-Repository oder aktualisiert es auf einen bestimmten Branch, Tag oder Commit. Nützlich fuer Code-Deployments auf den Server. | `git rev-parse HEAD` im Zielverzeichnis vs. gewuenschte Referenz | mittel |

---

## download — Datei-Downloads

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `download.url` | Laedt eine Datei von einer HTTP/HTTPS-URL auf den Server herunter. Unterstuetzt Checksum-Verifikation (SHA-256). | Checksum der existierenden Datei vs. erwartete Checksum | mittel |
| `download.large` | Wie `download.url`, aber fuer grosse Dateien. Nutzt State-Flag, da der Download teuer ist und die Checksum-Pruefung bei sehr grossen Dateien langsam sein kann. | State-Flag: `/var/lib/paratix/flags/download-<url-hash>` | mittel |

---

## archive — Archiv-Verwaltung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `archive.extract` | Entpackt ein Archiv (tar, zip, gz) auf dem Server. Optional mit vorherigem Upload vom Controller. | Pruefung ob Zielverzeichnis existiert und Inhalt passt | mittel |

---

## script — Skript-Ausfuehrung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `script.once` | Kopiert ein lokales Skript auf den Server und fuehrt es einmalig aus. Nutzt State-Flag mit Skriptname und Version, sodass es bei Versionsaenderung erneut laeuft. | State-Flag: `/var/lib/paratix/flags/script-<name>-<version>` | einfach |

---

## command — Befehlsausfuehrung

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `command.run` | Fuehrt einen Befehl auf dem Server aus (ohne Shell-Interpretation). Gibt immer `changed` zurueck, da keine Idempotenz-Pruefung moeglich. Optional: benutzerdefinierter Check-Befehl. | Kein Check (always changed) oder benutzerdefinierter Check | trivial |
| `command.shell` | Wie `command.run`, aber mit Shell-Interpretation (`/bin/sh -c`). Ermoeglicht Pipes, Redirects und Shell-Variablen. | Kein Check (always changed) oder benutzerdefinierter Check | trivial |

---

## net — Netzwerk-Utilities

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `net.waitFor` | Wartet darauf, dass eine Bedingung erfuellt ist: Port offen, Datei vorhanden, oder String in Datei. Nützlich nach Service-Starts oder Deployments. | Polling mit Timeout | mittel |
| `net.request` | Fuehrt einen HTTP-Request vom Server aus und prueft die Antwort (Statuscode, Body). Nützlich fuer Health-Checks. | HTTP-Statuscode und optionaler Body-Check | mittel |

---

## system — Systemoperationen

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `system.reboot` | Startet den Server neu und wartet auf Reconnect. Paratix pollt alle konfigurierten SSH-Ports, bis der Server wieder erreichbar ist. | Signal-basiert oder bedingt (z.B. nach Kernel-Update) | mittel |
| `system.facts` | Sammelt System-Informationen und schreibt sie als Meta-Eintraege in den Env. Aendert nichts am Server. Nachfolgende Module und Templates koennen auf die Werte zugreifen (z.B. `{{system.os}}` in Templates, `env["system.os"]` in Modulen). Siehe Meta-Keys unten. | Immer `ok` (reines Lesen) | aufwendig |

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

| Key | Befehl |
|---|---|
| `system.os` | `lsb_release -si` oder `/etc/os-release` parsen |
| `system.os.version` | `lsb_release -sr` oder `/etc/os-release` parsen |
| `system.os.codename` | `lsb_release -sc` oder `/etc/os-release` parsen |
| `system.arch` | `uname -m` |
| `system.hostname` | `hostname` |
| `system.kernel` | `uname -r` |
| `system.ram.total` | `free -m` parsen |
| `system.cpu.cores` | `nproc` |
| `system.ip.public` | `ip -4 route get 1.1.1.1` parsen |
| `system.ip.private` | `ip -4 addr` parsen (erster RFC-1918-Bereich) |
| `system.disk.root` | `df -m /` parsen |

**Nutzung in Templates:**

```
# ./templates/nginx.tpl
# Konfiguriert fuer {{system.hostname}} ({{system.os}} {{system.os.version}})
worker_processes {{system.cpu.cores}};
```

**Nutzung in Playbooks (bedingte Logik):**

```typescript
run: [
  system.facts(),

  // Bedingt: nur auf Ubuntu
  ...(env["system.os"] === "ubuntu" ? [
    apt.repository("ppa:nginx/stable"),
  ] : []),
]
```

> **Hinweis:** `system.facts` muss nicht am Anfang jedes Playbooks stehen.
> Es ist ein normales Modul — wer die Werte nicht braucht, laesst es weg.
> Module wie `package.installed` rufen `system.facts` **nicht** implizit auf;
> sie erwarten, dass `system.os` im Env steht (entweder durch `system.facts`
> oder durch manuelle Env-Konfiguration).

---

## package — Generischer Paketmanager

| Modul | Beschreibung | Check-Strategie | Aufwand |
|---|---|---|---|
| `package.installed` | Abstrahiert ueber `apt`, `dnf` und andere Paketmanager. Erkennt automatisch das Betriebssystem und waehlt den passenden Paketmanager. Erfordert `system.facts` oder manuelle OS-Angabe im Env. | Delegiert an den erkannten Paketmanager | mittel |
| `package.absent` | Gegenstueck zu `package.installed`. Entfernt Pakete unabhaengig vom Paketmanager. | Delegiert an den erkannten Paketmanager | mittel |

---

---

# Built-in-Funktionen (keine Module)

Die folgenden Ansible-Aequivalente werden als **eingebaute Funktionen im
Runner** implementiert, nicht als Module. Sie folgen nicht dem Check→Apply-Muster,
benoetigen kein SSH und sind reine Ablaufsteuerung.

| Funktion | Beschreibung | Ansible-Aequivalent |
|---|---|---|
| `assert(condition, message)` | Prueft eine Bedingung und bricht bei Fehler ab. | `assert` |
| `debug(message)` | Gibt eine Nachricht in der Konsolenausgabe aus. | `debug` |
| `fail(message)` | Bricht die Ausfuehrung mit einer Fehlermeldung ab. | `fail` |
| `pause(message?)` | Pausiert und wartet auf Benutzerbestaetigung. | `pause` |

Der `set_fact`-Mechanismus wird durch das bestehende **Env-System** abgedeckt:
Module setzen `meta`-Eintraege in ihrem `ModuleResult`, die automatisch in den
Env uebernommen werden.

---

---

# Fuer spaeter: Nicht-Debian-Paketmanager

Module fuer RHEL/Fedora/CentOS-basierte Systeme. Werden erst implementiert,
wenn Paratix ueber Debian/Ubuntu hinaus erweitert wird.

| Modul | Beschreibung | Aufwand |
|---|---|---|
| `dnf.installed` | Installiert Pakete via dnf (Fedora/RHEL 8+). | einfach |
| `dnf.absent` | Entfernt Pakete via dnf. | einfach |
| `yum.repository` | Verwaltet YUM-Repository-Dateien in `/etc/yum.repos.d/`. | einfach |
| `rpm.key` | Fuegt GPG-Schluessel zur RPM-Datenbank hinzu. | einfach |
| `pip.installed` | Installiert Python-Pakete via pip. | einfach |
| `pip.absent` | Entfernt Python-Pakete via pip. | einfach |
| `sysvinit.service` | Verwaltet SysV-Init-Dienste (fuer aeltere Systeme ohne systemd). | einfach |
