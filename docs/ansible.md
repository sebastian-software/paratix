# Ansible Builtin - Standard-Funktionen

Vollstaendige Liste aller Plugins und Module aus der `ansible.builtin` Collection (ansible-core),
bewertet nach Umsetzbarkeit in Paratix.

> Quelle: [Ansible Builtin Collection](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/index.html)

### Bewertungsskala

| Kuerzel | Bedeutung |
|---|---|
| `trivial` | Wenige Zeilen, klares Check→Apply-Muster |
| `einfach` | Ueberschaubarer Aufwand, klare SSH-Befehle |
| `mittel` | Mehrere Pruefungen, Edge Cases, Parsing noetig |
| `aufwendig` | Erheblicher Aufwand, viele Sonderfaelle |
| `sehr aufwendig` | Komplex, braeuchte eigene Subsysteme |

---

# Teil 1: Umsetzbar in Paratix

Alle Ansible-Funktionen, die als Paratix-Module implementiert werden muessten.

---

## Modules

### trivial

| Modul | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `assert` | Prueft, ob gegebene Ausdruecke wahr sind | `trivial` | Reine Logik im TS-Code, kein SSH noetig |
| `command` | Fuehrt Befehle auf Zielsystemen aus (ohne Shell) | `trivial` | Direkter SSH-Exec, Check entfaellt (always changed) oder benutzerdefiniert |
| `debug` | Gibt Nachrichten waehrend der Ausfuehrung aus | `trivial` | `console.log`, kein SSH noetig |
| `fail` | Bricht die Ausfuehrung mit einer benutzerdefinierten Nachricht ab | `trivial` | `throw new Error()` |
| `pause` | Pausiert die Playbook-Ausfuehrung | `trivial` | `await sleep()` oder `readline` fuer Benutzerbestaetigung |
| `ping` | Testet die Verbindung zum Host | `trivial` | SSH-Verbindung testen (Python-Check entfaellt bei Paratix) |
| `raw` | Fuehrt einen Befehl ohne Python-Abhaengigkeit aus (Low-Level) | `trivial` | Direkter SSH-Exec, identisch mit `command` in Paratix |
| `set_fact` | Setzt Host-Variablen und Fakten | `trivial` | Entspricht `meta`-Eintraegen im Env-System |
| `set_stats` | Definiert und zeigt Statistiken fuer den aktuellen Ansible-Lauf an | `trivial` | Zaehler im Runner fuehren |
| `shell` | Fuehrt Shell-Befehle auf Zielsystemen aus (mit Shell-Interpretation) | `trivial` | SSH-Exec mit Shell-Interpretation |
| `tempfile` | Erstellt temporaere Dateien und Verzeichnisse | `trivial` | `mktemp` |

### einfach

| Modul | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `apt` | Verwaltet apt-Pakete (Debian/Ubuntu) | `einfach` | Bereits im Design vorgesehen (`apt.installed`), Check via `dpkg -l` |
| `apt_key` | Fuegt einen apt-Schluessel hinzu oder entfernt ihn | `einfach` | Check via `apt-key list`, Apply via `apt-key add` |
| `apt_repository` | Fuegt APT-Repositories hinzu oder entfernt sie | `einfach` | Check ob Datei in `/etc/apt/sources.list.d/` existiert |
| `copy` | Kopiert Dateien auf entfernte Systeme | `einfach` | Bereits im Design (`file.copy`), SHA-256-Vergleich |
| `cron` | Verwaltet cron.d- und crontab-Eintraege | `einfach` | Check via `crontab -l`, Apply via `crontab` |
| `dnf` | Verwaltet Pakete mit dem dnf-Paketmanager (Fedora/RHEL) | `einfach` | Analog zu `apt`, Check via `rpm -q` |
| `dnf5` | Verwaltet Pakete mit dem dnf5-Paketmanager | `einfach` | Analog zu `dnf` |
| `dpkg_selections` | Verwaltet dpkg-Paketauswahl | `einfach` | Check/Apply via `dpkg --get-selections`/`--set-selections` |
| `fetch` | Holt Dateien von entfernten Systemen | `einfach` | SCP/SFTP vom Remote, Gegenstueck zu `copy` |
| `find` | Gibt eine Liste von Dateien zurueck, die bestimmten Kriterien entsprechen | `einfach` | `find`-Befehl auf Remote, Ergebnis parsen |
| `getent` | Wrapper fuer das Unix-Dienstprogramm getent | `einfach` | `getent` ausfuehren, Ausgabe parsen |
| `group` | Fuegt Gruppen hinzu oder entfernt sie | `einfach` | Check via `getent group`, Apply via `groupadd`/`groupmod` |
| `hostname` | Verwaltet den Hostnamen | `einfach` | Check via `hostname`, Apply via `hostnamectl set-hostname` |
| `known_hosts` | Fuegt einen Host zur known_hosts-Datei hinzu oder entfernt ihn | `einfach` | Check via `ssh-keygen -F`, Apply via `ssh-keyscan` |
| `mount_facts` | Ruft Mount-Informationen ab | `einfach` | `mount` oder `/proc/mounts` parsen |
| `pip` | Verwaltet Python-Bibliotheksabhaengigkeiten | `einfach` | Check via `pip show`, Apply via `pip install` |
| `rpm_key` | Fuegt GPG-Schluessel zur RPM-Datenbank hinzu oder entfernt sie | `einfach` | Analog zu `apt_key` |
| `script` | Fuehrt ein lokales Skript auf einem entfernten Knoten aus | `einfach` | Bereits im Design als `script.once`, SCP + Execute |
| `service` | Verwaltet Dienste (Start, Stop, Restart, Enable) | `einfach` | Bereits im Design, Check via `systemctl is-active/is-enabled` |
| `service_facts` | Gibt Service-Statusinformationen als Fakten zurueck | `einfach` | `systemctl list-units` parsen |
| `slurp` | Liest eine Datei vom entfernten Knoten (Base64-kodiert) | `einfach` | `base64 < /path/to/file` |
| `stat` | Ruft Datei- oder Dateisystem-Status ab | `einfach` | `stat`-Befehl, Ausgabe parsen |
| `systemd_service` | Verwaltet systemd-Units | `einfach` | Bereits im Design vorgesehen, `systemctl`-Befehle |
| `sysvinit` | Verwaltet SysV-Dienste | `einfach` | `service`-Befehle, Check via `/etc/init.d/` |
| `template` | Rendert eine Jinja2-Vorlage und kopiert sie auf den Zielhost | `einfach` | Bereits im Design (`file.template`), Env-basiertes Rendering + SHA-256 |
| `user` | Verwaltet Benutzerkonten | `einfach` | Bereits im Design (`user.present`), Check via `id`, Apply via `useradd`/`usermod` |
| `wait_for_connection` | Wartet, bis das entfernte System erreichbar/nutzbar ist | `einfach` | Bereits im Paratix-Design (Reconnect-Logik) |
| `yum_repository` | Fuegt YUM-Repositories hinzu oder entfernt sie | `einfach` | Analog zu `apt_repository`, Datei in `/etc/yum.repos.d/` |

### mittel

| Modul | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `assemble` | Setzt Konfigurationsdateien aus Fragmenten zusammen | `mittel` | Fragmente lesen, konkatenieren, Hash vergleichen |
| `blockinfile` | Fuegt einen Textblock ein/aktualisiert/entfernt ihn (mit Marker-Zeilen) | `mittel` | Check via `grep` nach Markern, Apply via `sed`/Datei-Manipulation |
| `deb822_repository` | Fuegt deb822-formatierte Repositories hinzu oder entfernt sie | `mittel` | Spezifisches Format muss generiert und geprueft werden |
| `debconf` | Konfiguriert ein .deb-Paket | `mittel` | Check via `debconf-show`, Apply via `debconf-set-selections` |
| `file` | Verwaltet Dateien und Dateieigenschaften (Rechte, Besitzer, Symlinks) | `mittel` | Viele Properties (mode, owner, group, state, link), jeweils eigener Check |
| `get_url` | Laedt Dateien von HTTP, HTTPS oder FTP auf den Zielknoten herunter | `mittel` | Download via `curl`/`wget`, Checksum-Vergleich |
| `git` | Deployt Software oder Dateien aus Git-Checkouts | `mittel` | Clone/Pull, Branch/Tag-Handling, Check via `git rev-parse` |
| `iptables` | Aendert iptables-Regeln | `mittel` | Check via `iptables -L`, komplexes Regel-Parsing |
| `lineinfile` | Verwaltet einzelne Zeilen in Textdateien | `mittel` | Bereits im Design als `file.line`, Check via `grep`, Apply via `sed` |
| `package` | Generischer OS-Paketmanager (abstrahiert ueber apt, dnf, etc.) | `mittel` | Muss OS erkennen und richtigen Paketmanager waehlen |
| `package_facts` | Sammelt Paketinformationen als Fakten | `mittel` | `dpkg -l` / `rpm -qa` parsen, plattformabhaengig |
| `reboot` | Startet eine Maschine neu | `mittel` | Reboot + Reconnect-Logik, bereits im Paratix-Design vorgesehen |
| `replace` | Ersetzt alle Vorkommen eines Strings in einer Datei per Regex | `mittel` | Check via `grep`, Apply via `sed`, Backup-Handling |
| `subversion` | Deployt ein Subversion-Repository | `mittel` | Analog zu `git`, aber selten benoetigt |
| `unarchive` | Entpackt ein Archiv (optional nach Kopie vom Controller) | `mittel` | SCP + tar/unzip, Check ob Zielverzeichnis bereits existiert |
| `uri` | Interagiert mit Webservices (HTTP-Requests) | `mittel` | `curl` auf Remote oder lokaler HTTP-Client, Response-Parsing |
| `wait_for` | Wartet auf eine Bedingung (Port offen, Datei vorhanden, etc.) | `mittel` | Polling-Loop mit Timeout, verschiedene Bedingungstypen |

### aufwendig / sehr aufwendig

| Modul | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `expect` | Fuehrt einen Befehl aus und reagiert auf Eingabeaufforderungen | `aufwendig` | Interaktive Terminal-Steuerung ueber SSH, PTY-Handling noetig |
| `gather_facts` | Sammelt Fakten ueber entfernte Hosts | `aufwendig` | Dutzende System-Informationen sammeln und strukturieren |
| `setup` | Sammelt Fakten ueber entfernte Hosts (System-Facts) | `aufwendig` | Viele Subsysteme abfragen (CPU, RAM, Netzwerk, OS, Disks, ...) |
| `async_status` | Ruft den Status einer asynchronen Aufgabe ab | `sehr aufwendig` | Paratix ist synchron, braeuchte ein Async-Subsystem |

---

## Become Plugins

| Plugin | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `sudo` | Fuehrt Befehle mit erhoehten Rechten via `sudo` aus | `einfach` | SSH-Befehle mit `sudo` prefixen, Paratix verbindet sich typischerweise als root |
| `su` | Wechselt den Benutzer mit `su` | `mittel` | SSH-Befehle mit `su -c` wrappen, Passwort-Handling |

---

## Callback Plugins

| Plugin | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `minimal` | Minimale Bildschirmausgabe | `trivial` | Weniger loggen |
| `oneline` | Einzeilige Bildschirmausgabe | `trivial` | Formatierungsvariante |
| `default` | Standard-Bildschirmausgabe von Ansible | `einfach` | Bereits im Design vorgesehen (Ausgabeformat in initialbeschreibung.md) |
| `tree` | Speichert Host-Ereignisse als Dateien | `einfach` | Events in JSON-Dateien schreiben |
| `junit` | Schreibt Playbook-Ausgabe in eine JUnit-XML-Datei | `mittel` | Event-System + XML-Serialisierung |

---

## Connection Plugins

| Plugin | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `local` | Fuehrt Befehle auf dem Controller selbst aus | `einfach` | `child_process.exec` statt SSH |
| `ssh` | Verbindung ueber den SSH-Client | `einfach` | Kernfunktion von Paratix, bereits im Design |
| `psrp` | Verbindung ueber Microsoft PowerShell Remoting Protocol | `sehr aufwendig` | Windows-Protokoll, weit ausserhalb des Paratix-Scope |
| `winrm` | Verbindung ueber Microsofts WinRM | `sehr aufwendig` | Windows-Protokoll, weit ausserhalb des Paratix-Scope |

---

## Filter Plugins (umsetzungsrelevant)

> Die meisten Ansible-Filter sind in Paratix native TS-Funktionen (siehe Teil 2).
> Hier nur die wenigen, die eigenstaendige Implementierung benoetigen:

| Filter | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `comment` | Kommentiert einen String aus (z.B. mit #) | `trivial` | Zeilen mit Prefix versehen |
| `quote` | Shell-sicheres Quoting | `einfach` | Wichtig fuer SSH-Befehle, `shell-quote`-Paket oder Eigenbau |
| `password_hash` | Konvertiert ein Passwort in einen Passwort-Hash | `einfach` | `crypto` oder `mkpasswd` auf Remote |
| `vault` | Verschluesselt Daten mit Ansible Vault | `aufwendig` | Eigenes Verschluesselungssystem muesste gebaut werden |
| `unvault` | Entschluesselt Ansible-Vault-Daten | `aufwendig` | Eigenes Verschluesselungssystem muesste gebaut werden |

---

## Strategy Plugins

| Plugin | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `debug` | Fuehrt Tasks in einer interaktiven Debug-Sitzung aus | `mittel` | Breakpoint-System mit interaktivem Prompt |

---

## Test Plugins (umsetzungsrelevant)

> Die meisten Ansible-Tests sind in Paratix native TS-Ausdruecke (siehe Teil 2).
> Hier nur die mit eigenstaendiger Implementierung:

| Test | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `changed` | Hat der Task Aenderungen vorgenommen? | `trivial` | `result.status === 'changed'` |
| `failed` | Ist der Task fehlgeschlagen? | `trivial` | `result.status === 'failed'` |
| `reachable` | Endete der Task nicht wegen Unerreichbarkeit? | `trivial` | SSH-Verbindungsstatus pruefen |
| `skipped` | Wurde der Task uebersprungen? | `trivial` | `result.status === 'skipped'` |
| `success` | War der Task erfolgreich? | `trivial` | `result.status === 'ok'` |
| `timedout` | Hat der Task ein Timeout erreicht? | `trivial` | Timeout-Flag im Error |
| `unreachable` | Endete der Task wegen Unerreichbarkeit? | `trivial` | SSH-Verbindungsstatus pruefen |
| `version` | Vergleicht Versionsstrings | `einfach` | Semver-Vergleich, `semver`-Paket |
| `vault_encrypted` | Ist dies ein verschluesselter Vault-String? | `aufwendig` | Eigenes Vault-System noetig |
| `vaulted_file` | Ist diese Datei eine verschluesselte Vault-Datei? | `aufwendig` | Eigenes Vault-System noetig |

---

## Lookup Plugins (umsetzungsrelevant)

> Die meisten Ansible-Lookups sind in Paratix native TS-Aufrufe (siehe Teil 2).
> Hier nur die mit eigenstaendiger Implementierung:

| Plugin | Beschreibung | Aufwand | Hinweis |
|---|---|---|---|
| `template` | Gibt den Inhalt einer Datei nach Jinja2-Rendering zurueck | `einfach` | Bereits im Design (Template-System) |
| `password` | Ruft ein Passwort ab oder generiert ein zufaelliges (gespeichert in Datei) | `mittel` | Passwort generieren + in Datei speichern + bei erneutem Lauf wiederverwenden |
| `unvault` | Liest den Inhalt verschluesselter Vault-Dateien | `aufwendig` | Eigenes Verschluesselungssystem noetig |

---
---

# Teil 2a: Ausserhalb Paratix-Scope

Ansible-Funktionen, die Paratix **bewusst nicht unterstuetzt** — weil sie auf
Konzepte abzielen, die in der Paratix-Architektur nicht existieren oder nicht geplant sind.

---

### Windows (kein Support geplant)

| Typ | Plugin | Ansible-Beschreibung |
|---|---|---|
| Become | `runas` | Befehle als anderer Benutzer ausfuehren (Windows) |
| Connection | `psrp` | PowerShell Remoting Protocol |
| Connection | `winrm` | Microsofts WinRM |
| Shell | `cmd` | Windows Command Prompt |
| Shell | `powershell` | Windows PowerShell |
| Filter | `win_basename` | Windows-Pfad: Dateiname |
| Filter | `win_dirname` | Windows-Pfad: Verzeichnis |
| Filter | `win_splitdrive` | Windows-Pfad: Laufwerksbuchstabe |

### Multi-Host / Inventory (Paratix ist Single-Host by Design)

Paratix definiert Server als einzelne TypeScript-Dateien. Es gibt kein dynamisches
Inventory, keine Host-Gruppen und keine parallele Ausfuehrung ueber mehrere Hosts.

| Typ | Plugin | Ansible-Beschreibung |
|---|---|---|
| Module | `add_host` | Host dynamisch zum Inventory hinzufuegen |
| Module | `group_by` | Gruppen basierend auf Fakten erstellen |
| Strategy | `free` | Tasks ohne Warten auf alle Hosts ausfuehren |
| Strategy | `host_pinned` | Alle Tasks pro Host, dann naechster Host |
| Strategy | `linear` | Alle Hosts pro Task (Ansible-Standard) |
| Inventory | `advanced_host_list` | Host-Liste mit Bereichen parsen |
| Inventory | `auto` | Inventory-Plugin aus YAML laden |
| Inventory | `constructed` | Variablen/Gruppen via Jinja2 aus Inventory |
| Inventory | `generator` | Hosts/Gruppen aus Mustern generieren |
| Inventory | `host_list` | Host-Listen-String parsen |
| Inventory | `ini` | INI-Datei als Inventory-Quelle |
| Inventory | `script` | Inventory-Skript (JSON-Output) |
| Inventory | `toml` | TOML-Datei als Inventory-Quelle |
| Inventory | `yaml` | YAML-Datei als Inventory-Quelle |
| Lookup | `inventory_hostnames` | Inventory-Hosts nach Muster auflisten |

### Ansible-interne Mechanismen (kein Aequivalent in Paratix)

| Typ | Plugin | Grund |
|---|---|---|
| Module | `meta` | Ansible-interne Aktionen (flush_handlers, end_play) — Paratix hat eigene Ablaufsteuerung |
| Connection | `paramiko_ssh` | Python-SSH-Implementierung — Paratix nutzt eigene SSH-Lib (z.B. ssh2) |
| Test | `filter` | Prueft ob Ansible-Filter existiert — kein Plugin-Registry in Paratix |
| Test | `test` | Prueft ob Ansible-Test existiert — kein Plugin-Registry in Paratix |
| Test | `finished` | Async-Task fertig? — Paratix ist synchron |
| Test | `started` | Async-Task gestartet? — Paratix ist synchron |

---
---

# Teil 2b: Durch TypeScript/Node.js abgedeckt

Ansible-Funktionen, die in Paratix kein eigenes Aequivalent brauchen, weil
TypeScript/Node.js sie nativ als Sprachmittel oder Standardbibliothek bereitstellt.
Ansible braucht dafuer eigene Plugins, weil YAML keine Programmiersprache ist.

---

## Modules → TypeScript-Imports / Env-System

| Modul | TS-Aequivalent |
|---|---|
| `import_playbook` | `import` |
| `import_role` | `import` + Recipe-Konzept |
| `import_tasks` | `import` |
| `include_role` | Dynamische Imports oder Funktionsaufrufe |
| `include_tasks` | Dynamische Imports oder Funktionsaufrufe |
| `include_vars` | Env-System + TS-Imports |
| `validate_argument_spec` | TypeScript-Typsystem |

## Sonstige Plugin-Typen → Paratix-Design

| Typ | Plugin | Paratix-Aequivalent |
|---|---|---|
| Cache | `jsonfile` | Zustandslos — State-Flags auf dem Server |
| Cache | `memory` | Env-System (In-Memory-Kontext) |
| Shell | `sh` | Paratix nutzt immer Standard-Shell via SSH |
| Strategy | `linear` | Paratix ist bereits sequenziell |
| Vars | `host_group_vars` | Env-System + TS-Imports |

## Lookup Plugins → TypeScript-Bordmittel

| Plugin | TS-Aequivalent |
|---|---|
| `config` | Paratix-Konfiguration direkt in TS |
| `csvfile` | `fs.readFile` + CSV-Parser |
| `dict` | `Object.entries()` |
| `env` | `process.env` / Env-System |
| `file` | `fs.readFileSync()` |
| `fileglob` | `glob`-Paket |
| `first_found` | TS-Logik mit `fs.existsSync()` |
| `indexed_items` | `.entries()` |
| `ini` | `ini`-Paket |
| `items` | TS-Arrays |
| `lines` | `execSync().split('\n')` |
| `list` | Identity-Funktion |
| `nested` | Verschachtelte Schleifen in TS |
| `pipe` | `execSync()` |
| `random_choice` | `Math.random()` |
| `sequence` | `Array.from({length: n})` |
| `subelements` | `flatMap()` |
| `together` | `zip`-Hilfsfunktion |
| `url` | `fetch()` |
| `varnames` | Env-Schluessel filtern |
| `vars` | Env-System |

## Filter Plugins → TypeScript-Funktionen (komplett)

### Datentyp-Konvertierung → TS-Casting

| Filter | TS-Aequivalent |
|---|---|
| `bool` | `Boolean()` |
| `float` | `parseFloat()` |
| `int` | `parseInt()` |
| `list` | `Array.from()` |
| `string` | `String()` |
| `type_debug` | `typeof` |

### String-Manipulation → TS-String-Methoden

| Filter | TS-Aequivalent |
|---|---|
| `capitalize` | JS-Einzeiler |
| `center` | `padStart`/`padEnd` |
| `escape` / `e` | Template-Engine oder Hilfsfunktion |
| `forceescape` | Wie `escape` |
| `format` | Template-Literale |
| `indent` | String-Manipulation |
| `join` | `Array.join()` |
| `lower` | `toLowerCase()` |
| `upper` | `toUpperCase()` |
| `title` | JS-Hilfsfunktion |
| `trim` | `trim()` |
| `truncate` | `slice()` |
| `replace` | `replaceAll()` |
| `reverse` | `reverse()` |
| `split` | `split()` |
| `striptags` | Regex |
| `wordcount` | `split(/\s+/).length` |
| `wordwrap` | Hilfsfunktion |
| `urlencode` | `encodeURIComponent()` |
| `urldecode` | `decodeURIComponent()` |
| `urlize` | Selten relevant fuer Server-Setup |
| `pprint` | `JSON.stringify(x, null, 2)` |
| `safe` | Abhaengig von Template-Engine |
| `tojson` | `JSON.stringify()` |
| `xmlattr` | Selten relevant |

### Regex → TS-RegExp

| Filter | TS-Aequivalent |
|---|---|
| `regex_escape` | Hilfsfunktion oder `escapeRegExp` |
| `regex_findall` | `matchAll()` |
| `regex_replace` | `replace()` mit Regex |
| `regex_search` | `match()` |

### Listen und Mengen → TS-Array-Methoden

| Filter | TS-Aequivalent |
|---|---|
| `batch` | Hilfsfunktion |
| `combinations` | Hilfsfunktion |
| `combine` | `{...a, ...b}` |
| `count` / `length` | `.length` |
| `difference` | `filter()` |
| `dict2items` | `Object.entries()` |
| `dictsort` | `Object.entries().sort()` |
| `extract` | Bracket-Notation |
| `first` | `[0]` / `.at(0)` |
| `flatten` | `flat()` |
| `groupby` | `reduce()` |
| `intersect` | `filter()` + `Set` |
| `items` | `Object.entries()` |
| `items2dict` | `Object.fromEntries()` |
| `last` | `.at(-1)` |
| `map` | `.map()` |
| `max` | `Math.max()` |
| `min` | `Math.min()` |
| `permutations` | Hilfsfunktion |
| `product` | Hilfsfunktion |
| `random` | `Math.random()` |
| `reject` | `.filter()` |
| `rejectattr` | `.filter()` |
| `rekey_on_member` | `reduce()` |
| `select` | `.filter()` |
| `selectattr` | `.filter()` |
| `shuffle` | Fisher-Yates |
| `slice` | `.slice()` |
| `sort` | `.sort()` |
| `subelements` | `flatMap()` |
| `symmetric_difference` | `Set`-Operationen |
| `union` | `new Set([...a, ...b])` |
| `unique` | `[...new Set()]` |
| `zip` | Hilfsfunktion |
| `zip_longest` | Hilfsfunktion |

### Pfade und Dateien → Node.js `path`-Modul

| Filter | TS-Aequivalent |
|---|---|
| `basename` | `path.basename()` |
| `dirname` | `path.dirname()` |
| `commonpath` | Hilfsfunktion |
| `expanduser` | `os.homedir()` + Ersetzung |
| `expandvars` | `process.env` + Ersetzung |
| `fileglob` | `glob`-Paket |
| `normpath` | `path.normalize()` |
| `realpath` | `path.resolve()` / `fs.realpath()` |
| `relpath` | `path.relative()` |
| `splitext` | `path.parse()` |

### Hashing und Encoding → Node.js `crypto`-Modul

| Filter | TS-Aequivalent |
|---|---|
| `b64decode` | `Buffer.from(s, 'base64')` |
| `b64encode` | `Buffer.from(s).toString('base64')` |
| `checksum` | `crypto.createHash()` |
| `hash` | `crypto.createHash()` |
| `md5` | `crypto.createHash('md5')` |
| `sha1` | `crypto.createHash('sha1')` |

### Mathematik → JS `Math`

| Filter | TS-Aequivalent |
|---|---|
| `abs` | `Math.abs()` |
| `log` | `Math.log()` |
| `pow` | `**` |
| `root` | `Math.pow(x, 1/n)` |
| `round` | `Math.round()` |
| `sum` | `.reduce((a,b) => a+b)` |
| `filesizeformat` | Hilfsfunktion |
| `human_readable` | Hilfsfunktion |
| `human_to_bytes` | Hilfsfunktion |

### Datum und Zeit → JS `Date`

| Filter | TS-Aequivalent |
|---|---|
| `strftime` | `Intl.DateTimeFormat` |
| `to_datetime` | `new Date()` |

### Serialisierung → `JSON` / `yaml`-Paket

| Filter | TS-Aequivalent |
|---|---|
| `from_json` | `JSON.parse()` |
| `from_yaml` | `yaml`-Paket |
| `from_yaml_all` | `yaml`-Paket mit Multi-Doc |
| `to_json` | `JSON.stringify()` |
| `to_nice_json` | `JSON.stringify(x, null, 2)` |
| `to_yaml` | `yaml`-Paket |
| `to_nice_yaml` | `yaml`-Paket |

### Sonstige → TS-Operatoren

| Filter | TS-Aequivalent |
|---|---|
| `attr` | Punkt-Notation |
| `default` / `d` | `??` (Nullish Coalescing) |
| `mandatory` | TypeScript-Typsystem oder Runtime-Check |
| `ternary` | `? :` |
| `to_uuid` | `uuid`-Paket |
| `urlsplit` | `new URL()` |

## Test Plugins → TypeScript-Sprachmittel (komplett)

### Datentyp-Tests → `typeof` / Type Guards

| Test | TS-Aequivalent |
|---|---|
| `boolean` | `typeof x === 'boolean'` |
| `callable` | `typeof x === 'function'` |
| `defined` | `x !== undefined` |
| `undefined` | `x === undefined` |
| `escaped` | Template-Engine-spezifisch |
| `even` | `x % 2 === 0` |
| `odd` | `x % 2 !== 0` |
| `float` | `typeof x === 'number' && !Number.isInteger(x)` |
| `integer` | `Number.isInteger(x)` |
| `iterable` | `Symbol.iterator in Object(x)` |
| `lower` | `x === x.toLowerCase()` |
| `upper` | `x === x.toUpperCase()` |
| `mapping` | `typeof x === 'object'` |
| `nan` | `Number.isNaN(x)` |
| `none` | `x === null` |
| `number` | `typeof x === 'number'` |
| `sequence` | `Array.isArray(x)` |
| `string` | `typeof x === 'string'` |
| `true` | `x === true` |
| `false` | `x === false` |
| `truthy` | `!!x` |
| `falsy` | `!x` |

### Vergleiche → TS-Operatoren

| Test | TS-Aequivalent |
|---|---|
| `eq` / `equalto` | `===` |
| `ne` | `!==` |
| `gt` / `greaterthan` | `>` |
| `ge` | `>=` |
| `lt` / `lessthan` | `<` |
| `le` | `<=` |
| `sameas` | `Object.is()` |

### Listen-Tests → Array-Methoden

| Test | TS-Aequivalent |
|---|---|
| `all` | `.every()` |
| `any` | `.some()` |
| `contains` | `.includes()` |
| `in` | `.includes()` |
| `subset` | `.every(x => other.includes(x))` |
| `superset` | Umgekehrter Subset-Check |

### Pfad-Tests → `fs`/`path`

| Test | TS-Aequivalent |
|---|---|
| `abs` | `path.isAbsolute()` |
| `directory` | `fs.statSync().isDirectory()` |
| `exists` | `fs.existsSync()` |
| `file` | `fs.statSync().isFile()` |
| `link` | `fs.lstatSync().isSymbolicLink()` |
| `link_exists` | `fs.lstatSync()` |
| `mount` | Plattformspezifisch |
| `same_file` | Inode-Vergleich via `fs.statSync()` |

### Regex-Tests → TS-RegExp

| Test | TS-Aequivalent |
|---|---|
| `match` | `/^pattern/.test()` |
| `regex` | `/^pattern/.test()` |
| `search` | `/pattern/.test()` |

### URI-Tests → `URL` API

| Test | TS-Aequivalent |
|---|---|
| `uri` | `new URL()` mit try/catch |
| `url` | `new URL()` mit try/catch |
| `urn` | Regex-Pruefung |
