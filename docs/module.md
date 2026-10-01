# Paratix — Modulkatalog

> **Historical document (2026-03-12):** This planned module catalog is not a
> normative reference for the current feature set. The current module and agent
> reference is the [Paratix LLM Guide](../packages/paratix/llm-guide.md).

Alle Module, die durch das Paratix Plugin-System implementiert werden sollen.
Jedes Modul implementiert die Plugin-Schnittstelle (`check` / `apply`) und ist
idempotent, sofern nicht anders vermerkt.

> Abgeleitet aus [initialbeschreibung.md](./initialbeschreibung.md). For a current comparison with
> other automation tools, see [Choosing an automation tool](./user-guide/comparison.md).

---

## package — Paketverwaltung

| Modul               | Beschreibung                                                                                                                                                                                                                                               | Check-Strategie                                        | Aufwand |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------- |
| `package.installed` | Stellt sicher, dass eines oder mehrere Pakete installiert sind. Akzeptiert Paketnamen als Argumente.                                                                                                                                                       | Delegiert an den erkannten Paketmanager                | einfach |
| `package.absent`    | Stellt sicher, dass Pakete nicht installiert sind. Entfernt sie bei Bedarf. Optional `{ purge: true }`: unter apt per `apt-get purge` inkl. Konfigurationsdateien bzw. `rc`-Resten (entfernt auch abhängige Pakete), unter apk/dnf/yum normales Entfernen. | Delegiert an den erkannten Paketmanager                | einfach |
| `package.update`    | Aktualisiert Paketlisten einmal pro angegebenem Datum.                                                                                                                                                                                                     | State-Flag: `/var/lib/paratix/flags/package-update-*`  | einfach |
| `package.upgrade`   | Führt ein Paket-Upgrade einmal pro angegebenem Datum aus. Nutzt State-Flags, da die Operation teuer ist und nicht effizient geprüft werden kann.                                                                                                           | State-Flag: `/var/lib/paratix/flags/package-upgrade-*` | einfach |

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
| `file.properties` | Verwaltet Dateieigenschaften eines bereits existierenden Pfads: Berechtigungen (`mode`), Besitzer (`owner`), Gruppe (`group`). Aendert weder den Datei-Typ noch erstellt oder loescht es Pfade. Fuer Verzeichnisse `file.directory`, fuer Loeschen `file.absent`, fuer Typ-Pruefungen `when.fileExists` / `when.symlinkExists` verwenden. | `stat`-Befehl, Vergleich aller gesetzten Properties            | mittel  |
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

| Modul         | Beschreibung                                                                                                                                                                                                                                                   | Check-Strategie                             | Aufwand |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- | ------- |
| `sshd.port`   | Ändert den SSH-Port in der `sshd_config`. Validiert auch im Dry-Run, dass der Zielport in der statischen `ssh.ports`-Liste der Serverdefinition eingetragen ist. Schreibt `sshd.port` in Meta, wodurch Paratix die SSH-Verbindung auf den neuen Port umstellt. | `sshd_config` auslesen und Port vergleichen | einfach |
| `sshd.config` | Setzt einzelne Konfigurationsoptionen in `sshd_config` (z.B. `PermitRootLogin`, `PasswordAuthentication`). Akzeptiert Key-Value-Paare.                                                                                                                         | `sshd_config` parsen, Werte vergleichen     | einfach |

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

Tar-Symlinks und -Hardlinks werden nur entpackt, wenn ihr Ziel – bei Symlinks vom eigenen
Verzeichnis aus, bei Hardlinks vom Archiv-Stamm aus und auch über die Symlinks des Archivs hinweg
aufgelöst – innerhalb von `destination` bleibt; absolute Ziele, ein Link anstelle des
Zielverzeichnisses selbst, Einträge unterhalb eines Archiv-Symlinks, Hardlinks auf oder durch einen
Archiv-Symlink, ein mehrfach vorkommender Pfad mit einem Symlink unter seinen Vorkommen und
abweichenden Typen oder Zielen sowie Zip-Symlinks werden abgelehnt. Die Archivliste wird als
striktes UTF-8 gelesen, nie mit Ersatzzeichen. `tar` listet das Archiv unter einer UTF-8-C-Locale
(`C.UTF-8` oder `C.utf8`), wenn der Host eine hat, sonst unter `LC_ALL=C` (bsdtar immer unter
`LC_ALL=C`); bei GNU tar und bsdtar werden die Escape-Sequenzen der Liste (`\NNN`, `\\` und die
Ein-Buchstaben-Escapes für Steuerzeichen) in die gespeicherten Bytes zurückübersetzt, sodass
Nicht-ASCII-Namen unabhängig von der Locale der SSH-Sitzung akzeptiert werden. Ein Eintrag, dessen
zurückübersetzter Name kein gültiges UTF-8 ist oder der eine andere Escape-Sequenz enthält, wird
abgelehnt, weil er sich nicht dem entpackten Namen zuordnen lässt. Ein Eintrag, dessen Pfad oder
Link-Ziel einen Backslash oder U+FFFD enthält, wird in jeder Liste abgelehnt – auch nach dem
Zurückübersetzen –, weil ein anderes `tar` (etwa BusyBox) und `unzip` Escape-Sequenzen und echte
Backslashes gleich ausgeben. Ist die Archivliste geprüft, liest `archive.extract` noch vor dem
Anlegen oder Prüfen des Zielverzeichnisses in einem Befehl alle Containment-Einträge dieses
Zielverzeichnisses und legt seinen eigenen Eintrag `in-progress` an (siehe unten) – lässt er sich
nicht anlegen, endet der Durchlauf, bevor das Zielverzeichnis berührt wird. Ist das
Containment-Verzeichnis ein Symlink oder kein Verzeichnis, ist ein Containment-Eintrag oder die alte
Flag-Datei ein Symlink oder keine reguläre Datei oder lässt sich ein Containment-Eintrag oder die
alte Flag-Datei nicht lesen, verweigert der Durchlauf, bevor das Zielverzeichnis berührt wird; ein
Containment-Eintrag ohne verwertbare Liste betroffener Links verweigert dagegen nicht (siehe unten).
Noch bevor etwas entpackt wird, lehnt es dann einen Eintrag ab, dessen Pfad oder übergeordnete
Verzeichnisse auf dem Host vorhandene Symlinks sind (ein Archiv-Symlink darf den Link an seinem
eigenen Pfad ersetzen), eine Datei, einen Hardlink oder Symlink dort, wo der Host ein echtes
Verzeichnis hat, sowie ein Verzeichnis – auch ein implizites Elternverzeichnis – dort, wo der Host
kein Verzeichnis hat. Weiterhin vor jeder Kopie löst es die bereits unter `destination` vorhandenen
Symlinks gemeinsam mit denen des Archivs auf: Ein Archiv-Symlink ersetzt einen vorhandenen Symlink
am selben Pfad, vorhandene absolute Ziele innerhalb von `destination` sind erlaubt; jede andere
Typ-Kombination am Pfad eines Eintrags, ein Eintrag unterhalb eines vorhandenen Symlinks, ein Link,
der außerhalb von `destination` auflöst, oder ein Link, dessen Ziel durch einen Pfad führt, der sich
von einem vorhandenen Symlink (des Archivs oder bereits auf dem Host) nur in Groß- und
Kleinschreibung (U+1E9E, das große ẞ, zählt wie `ß` als `ss`), Unicode-Normalisierung (NFC, NFD oder
Kompatibilitätsformen) oder ignorierbaren Zeichen wie U+200D, U+200C, U+FEFF oder U+00AD
unterscheidet, verhindert das Entpacken, weil ein Dateisystem, das Groß- und Kleinschreibung nicht
unterscheidet oder Namen normalisiert, diesem Symlink folgen kann. Die Link-Regeln des Archivs
selbst (außer der Regel für den Stamm) vergleichen die Pfade der Einträge unter derselben Faltung:
Der Symlink `x/L -> y` verhindert den Eintrag `x/l/f`, der Symlink `a/b/S -> ../../x` einen Hardlink
`h` auf `a/b/s` und der Symlink `Foo -> bar` eine Datei `foo`; mehrfache Einträge ohne Symlink, etwa
die regulären Dateien `Makefile` und `makefile`, bleiben erlaubt. Dieser Vergleich ist rein
lexikalisch, verweigert also auf Hosts mit Unterscheidung von Groß- und Kleinschreibung dieselben
Archive, und er fasst womöglich mehr Schreibweisen zusammen als ein bestimmtes Dateisystem – das
verweigert nur mehr, nie weniger. Ein vorhandener Link, der nach außen zeigt, muss dann entfernt
oder nach innen umgelenkt werden.

Geprüft werden nur die Links, auf die das Archiv wirken kann: die Symlinks des Archivs selbst und
jeder vorhandene Symlink, dessen Auflösung durch einen Pfad führt, den das Archiv schreibt (den Pfad
eines Eintrags oder eines seiner Elternverzeichnisse, verglichen unter derselben Faltung von Groß-
und Kleinschreibung und Normalisierung), direkt oder über einen weiteren solchen Link. Ein
vorhandener Symlink, dessen Pfad sich von einem Symlink des Archivs nur in Groß- und
Kleinschreibung, Unicode-Normalisierung oder ignorierbaren Zeichen unterscheidet (etwa wenn der Host
das `a/s` des Archivs als `A/S` auflistet), wird vor und nach dem Zusammenführen wie dieser Link des
Archivs geprüft: Zeigt er nach außen, verhindert er das Entpacken, nach dem Zusammenführen lässt er
den Durchlauf fehlschlagen, und der Containment-Eintrag des Durchlaufs hält ihn fest. Da dieser
Vergleich lexikalisch ist, prüft er auf Hosts mit Unterscheidung von Groß- und Kleinschreibung
womöglich auch einen unbeteiligten Link – das verweigert nur mehr, nie weniger. Jeder andere
vorhandene Symlink – auch einer, der aus `destination` hinauszeigt, eine Schleife bildet oder einen
ungewöhnlichen Namen trägt, etwa das `bin/python3 -> /usr/bin/python3` einer virtuellen
Python-Umgebung – bleibt unbeachtet (außer von der unten beschriebenen Prüfung des ganzen
Zielverzeichnisses) und unverändert. Ein Archiv ohne Symlinks (darunter jedes Zip-Archiv) kann nicht
ändern, wie ein Pfad auflöst; für es führt diese Prüfung keinen Befehl aus, und die Prüfung nach dem
Zusammenführen läuft nur, solange Containment-Einträge des Zielverzeichnisses Links festhalten oder
keine verwertbare Liste enthalten (siehe unten). Für ein Archiv mit Symlinks listet ein Befehl alle
Symlinks unter `destination` mit Pfaden relativ dazu auf, bis zu einer Obergrenze von 64 MiB
erfasster Ausgabe; ein Zielverzeichnis mit mehr Symlinks lässt die Prüfung mit der Meldung
fehlschlagen, es enthalte zu viele Symlinks für die Prüfung. Die Liste überträgt jeden Namen
außerhalb von druckbarem ASCII hexadezimal kodiert und dekodiert ihn Byte für Byte: Ein gültiger
UTF-8-Name behält seine genaue Schreibweise (auch ein wörtliches U+FFFD), ein geprüfter Link, dessen
Pfad oder Ziel kein gültiges UTF-8 ist oder der über einen solchen Link auflöst, lässt sich dagegen
nicht prüfen und verhindert das Entpacken, bis er umbenannt oder entfernt ist; eine fehlerhaft
aufgebaute Liste oder ein doppelter Link-Pfad lässt die Prüfung fehlschlagen. Mit GNU `find` auf dem
Host wird ein Verzeichnis unter `destination`, das sich nicht lesen oder durchsuchen lässt,
gemeldet, statt die Liste scheitern zu lassen: Ein geprüfter Link, der hinein auflöst, oder ein
Eintrag des Archivs darin oder darunter verhindert das Entpacken, weil er sich nicht prüfen lässt;
die Links in einem solchen Verzeichnis selbst werden nicht geprüft (eine bekannte Grenze). Ohne GNU
`find` (busybox, die BSDs) lässt jedes nicht lesbare Verzeichnis unter `destination` die Prüfung
fehlschlagen.

Der Host bricht das Zusammenführen per GNU `timeout` nach 100 Sekunden ab (10 Sekunden später
erzwungen), also vor dem Befehls-Timeout von 120 Sekunden; fehlt `timeout`, scheitert das
Zusammenführen, bevor etwas kopiert wird. Hat das Zusammenführen begonnen, läuft für ein Archiv mit
Symlinks – und, solange Containment-Einträge Links festhalten oder keine verwertbare Liste enthalten
(siehe unten), für jedes Archiv – immer eine Prüfung derselben Links (der Symlinks des Archivs und
jedes Symlinks, dessen Auflösung durch einen Pfad führt, den das Archiv schreibt), auch nach einem
fehlgeschlagenen oder abgebrochenen Zusammenführen, das bereits Einträge kopiert haben kann: Sie
löst die Links wie die Prüfung vor dem Zusammenführen auf, ohne den Host auflösen zu lassen, und
wertet Namensvarianten ebenfalls als Verstoß. Danach fragt sie den Kernel in einem gebündelten
Befehl (`test -e` und `test -ef`, begrenzt durch das Symlink-Limit des Kernels; nie `realpath` oder
`readlink -f`), ob jeder geprüfte Link, den sie als innen liegend einstuft, tatsächlich den
aufgelösten Pfad erreicht. Ein Link, der ein vorhandenes Objekt erreicht, muss genau diesen Pfad
erreichen. Ein Link, der nichts erreicht, gilt deshalb allein noch nicht als unbedenklich, denn wer
durch ihn schreibt, legt den fehlenden Namen dort an, wohin der Kernel den Rest seines Ziels
auflöst: Die Prüfung geht den Zielpfad des Links von seiner vollen Länge zurück bis zum Verzeichnis
des Links und vergleicht den ersten Punkt, der auf dem Host oder im Modell existiert, mit der
Stelle, an die das Modell denselben Punkt legt; beide müssen existieren und dasselbe Objekt sein.
Löst der Kernel einen Link zu einem anderen Objekt auf, weicht der nächste vorhandene Punkt ab oder
existiert er nur auf einer Seite (etwa bei einem Ziel, das mit `..` aus einem fehlenden Verzeichnis
heraussteigt, auch wenn sich durch den Link noch nichts schreiben lässt), oder existiert kein Punkt
seines Zielpfads, gilt das als Verstoß. Lässt sich dieser Abgleich nicht vollständig durchführen,
schlägt der Durchlauf fehl – auch dann, wenn der Eintrag eines geprüften Links für den Abgleich
größer als 64 KiB würde (ein Ziel mit sehr vielen Segmenten). Ein Baum ohne Verstoß kostet zwei
Befehle, wenn ein geprüfter Symlink als innen liegend eingestuft wird, sonst einen und für ein
Archiv ohne Symlinks keinen (solange Containment-Einträge Links festhalten oder keine verwertbare
Liste enthalten: eine Liste und höchstens einen Abgleich), unabhängig von der Zahl der Einträge; ein
Verstoß kostet keinen weiteren, die erneute Prüfung festgehaltener Links oder des ganzen
Zielverzeichnisses für ein Archiv mit Symlinks ebenfalls nicht. Diese Prüfung meldet nur: Sie
entfernt, verschiebt oder ändert nichts. Jeder verstoßende Link – einer, der außerhalb auflöst,
einer, der sich innerhalb des Symlink-Limits nicht auflösen lässt, etwa bei einer Schleife, eine
Namensvariante, eine Abweichung des Kernels oder ein Link, der sich wegen eines nicht lesbaren
Verzeichnisses oder eines Namens ohne gültiges UTF-8 nicht prüfen lässt – lässt den Durchlauf
fehlschlagen. Die Meldung nennt die ersten 10 betroffenen Links mit Pfad, gespeichertem Ziel und
Grund, fasst den Rest als `(and N more)` zusammen und hält fest, dass nichts entfernt oder geändert
wurde. Die betroffenen Links müssen von Hand entfernt oder nach innen umgelenkt werden.

Jeder Durchlauf hält sein Ergebnis in seinem eigenen Containment-Eintrag fest, einer Datei
`run-<hex>` mit 32 Hex-Ziffern im Containment-Verzeichnis des Zielverzeichnisses,
`/var/lib/paratix/flags/archive-containment-<sha256>.d/` (`<sha256>` ist der SHA-256-Hash des
normalisierten Zielpfads). Er legt diesen Eintrag als `in-progress` an, bevor er das Zielverzeichnis
berührt, ohne dabei einen vorhandenen Namen zu ersetzen, und er schreibt nur seinen eigenen Eintrag
neu, nie den eines anderen Durchlaufs. Schlägt ein Durchlauf fehl, nachdem das Zusammenführen
begonnen hat, hält sein Eintrag die Links fest, die die Prüfung danach ermittelt hat, relativ zu
`destination` (höchstens 256); ein Fehlschlag, bevor das Zusammenführen begonnen hat, hat nichts
veröffentlicht und hält eine leere Liste fest, während die Links, die andere Einträge festhalten, in
diesen Einträgen bleiben. Ein späterer Durchlauf mit beliebiger Quelle für dieses Zielverzeichnis
liest alle Einträge, bevor er das Zielverzeichnis berührt, und prüft die Links, die sie alle
festhalten, in seiner eigenen Prüfung nach dem Zusammenführen erneut, mit derselben lexikalischen
Auflösung und demselben Abgleich durch den Kernel: Jeder muss verschwunden sein oder nun innerhalb
von `destination` auflösen, sonst schlägt der Durchlauf mit seinem Namen fehl, und sein eigener
Eintrag hält ihn fest. Enthält ein Eintrag keine verwertbare Liste – weil ein früherer Durchlauf
nicht zu Ende kam (er wurde unterbrochen oder konnte sein Ergebnis nicht festhalten, oder ein
anderer Durchlauf für dieses Zielverzeichnis läuft noch), seine Prüfung die Links nicht ermitteln
konnte (etwa bei einer gescheiterten Liste oder einem Eintrag des Archivs in einem nicht lesbaren
Verzeichnis), es für das Festhalten zu viele waren (mehr als 256 Links oder 64 KiB) oder er
beschädigt ist –, und ebenso, wenn die einzelne Flag-Datei `archive-containment-<sha256>.failed`
älterer paratix-Versionen besteht oder es mehr als 16 Einträge gibt, läuft der Durchlauf trotzdem
normal. Seine Prüfung nach dem Zusammenführen prüft dann das ganze Zielverzeichnis: Jeder Symlink
unter `destination`, nicht nur die, auf die das Archiv wirken kann, muss mit derselben lexikalischen
Auflösung und demselben Abgleich durch den Kernel innerhalb davon auflösen, bevor `owner` angewendet
und die Marker-Dateien geschrieben werden. Findet die Prüfung Links, die nach außen zeigen oder sich
nicht auflösen lassen, schlägt der Durchlauf fehl und nennt sie wie oben, entfernt nichts, und sein
eigener Eintrag hält genau diese Links fest; die gelesenen Einträge bleiben ebenfalls stehen, sodass
der nächste Durchlauf diese Links und wieder das ganze Zielverzeichnis prüft. Lässt sich die Prüfung
nicht vollständig durchführen (eine gescheiterte Liste, ein nicht lesbares Verzeichnis oder zu viele
Symlinks), schlägt der Durchlauf mit dem Grund fehl, sein Eintrag enthält keine verwertbare Liste,
und der nächste Durchlauf prüft wieder das ganze Zielverzeichnis. Diese Prüfung nutzt die Liste und
den Abgleich der Prüfung nach dem Zusammenführen mit: Solange ein Eintrag keine verwertbare Liste
enthält, kostet sie für ein Archiv ohne Symlinks höchstens eine Liste und einen Abgleich zusätzlich,
für ein Archiv mit Symlinks keinen weiteren Befehl. Das Lesen der Einträge und das Anlegen des
eigenen kosten einen Befehl, das Entfernen nach einem Erfolg einen weiteren, unabhängig von der Zahl
der Einträge. Nach einem unterbrochenen Durchlauf oder dem Aktualisieren von paratix ist deshalb
nichts von Hand zu tun: Die alte Flag-Datei wird wie ein Eintrag ohne verwertbare Liste gelesen, und
das ganze Zielverzeichnis wird geprüft, bevor sie entfernt wird. Ein Zielverzeichnis, das
absichtlich einen nach außen zeigenden Symlink enthält, besteht diese Prüfung nicht, solange ein
Eintrag keine verwertbare Liste enthält, etwa ein Interpreter-Link eines virtualenv nach `/usr/bin`
im Arbeitsverzeichnis eines Runners nach einem unterbrochenen Durchlauf. Bleiben Verstöße bestehen,
sind die betroffenen Links zu entfernen oder umzulenken und der Durchlauf zu wiederholen. Sind die
betroffenen Links gewollt, scheitert auch jede spätere Prüfung an ihnen: Dann sind nach eigener
Prüfung des Zielverzeichnisses seine `run-*`-Einträge mit
`rm -f -- /var/lib/paratix/flags/archive-containment-<sha256 des Zielverzeichnisses>.d/run-*` zu
löschen (die Fehlermeldung nennt das genaue Verzeichnis), falls noch vorhanden auch die alte
Flag-Datei, und der Durchlauf ist zu wiederholen. Bei einem Fehlschlag wird weder die Marker-Datei geschrieben noch `owner`
angewendet.

Nur ein Durchlauf, der einschließlich der erneuten Prüfung festgehaltener Links oder des ganzen
Zielverzeichnisses, `owner` und Marker-Dateien vollständig gelingt, entfernt Einträge, und zwar in
einem letzten Befehl: jeden Eintrag, den er gelesen hat und dessen Inhalt sich seitdem nicht
geändert hat (er übernimmt jeden per atomarem Umbenennen und vergleicht dessen SHA-256 mit dem
gelesenen), die alte Flag-Datei eingeschlossen, und danach seinen eigenen. Ein Eintrag, der
inzwischen neu geschrieben wurde, bleibt stehen, und der nächste Durchlauf liest ihn. Eine Ablehnung
beim Anlegen oder Prüfen des Zielverzeichnisses, durch die Prüfungen vor dem Entpacken, durch die
Prüfung vor dem Zusammenführen, beim Zusammenführen oder durch die Prüfung danach lässt den Eintrag
des Durchlaufs stehen. Solange ein Eintrag oder die alte Flag-Datei besteht, und solange das
Containment-Verzeichnis ein Symlink, kein Verzeichnis oder nicht lesbar ist, meldet `check` für
jedes Archiv mit diesem Zielverzeichnis `needs-apply`.

Mehr als ein `archive.extract` gleichzeitig für dasselbe Zielverzeichnis wird nicht unterstützt:
Pro Zielverzeichnis darf höchstens ein Durchlauf zur selben Zeit laufen; parallele Durchläufe für
verschiedene Zielverzeichnisse sind unproblematisch. Geschieht es trotzdem, bleiben bekannte
Wettläufe. Ein
`in-progress`-Eintrag eines Durchlaufs, der noch läuft, lässt sich nicht von einem unterscheiden,
den ein unterbrochener Durchlauf hinterlassen hat; ein anderer Durchlauf, dessen Prüfung des ganzen
Zielverzeichnisses sauber ist, kann ihn deshalb entfernen. Schlägt der laufende Durchlauf danach
fehl, legt er seinen Eintrag mit seinem Ergebnis neu an; wird er dagegen abgebrochen, prüft niemand
die Links, die sein Zusammenführen nach dieser Prüfung veröffentlicht hat. Einen Eintrag, der
entsteht, nachdem ein Durchlauf die Einträge gelesen hat, fasst dieser Durchlauf nie an. Stürzt ein
Durchlauf beim Entfernen der Einträge ab, bleibt ein Eintrag `run-…-claim-<n>` zurück, der ein
gewöhnlicher Eintrag ist und `check` bei `needs-apply` hält. Ältere und neuere paratix-Versionen,
die gleichzeitig für ein Zielverzeichnis laufen, stimmen sich nicht ab, weil ältere Versionen
weiterhin die einzelne Flag-Datei verwenden.

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

| Modul           | Beschreibung                                                                                                                                                                                                                                                                                          | Check-Strategie                                                                        | Aufwand |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------- |
| `net.hosts`     | Verwaltet Eintraege in `/etc/hosts`. Fuegt eine IP-Hostname-Zuordnung hinzu oder entfernt sie. Akzeptiert eine IP-Adresse, eine Liste von Hostnamen und ein optionales `state`-Flag (`"present"` oder `"absent"`, Standard: `"present"`).                                                             | `/etc/hosts` lesen, nach erwarteter Zeile suchen                                       | einfach |
| `net.interface` | Konfiguriert eine Netzwerkschnittstelle via Netplan (wenn `/etc/netplan/` vorhanden) oder systemd-networkd. Erkennt automatisch, welche Methode aktiv ist, und schreibt die Konfigurationsdatei in den passenden Pfad. Wendet die Konfiguration danach direkt an.                                     | Konfigurationsdatei lesen und mit Sollzustand vergleichen                              | mittel  |
| `net.resolv`    | Verwaltet `/etc/resolv.conf` (Nameserver und Suchdomaenen). Entfernt vorhandene Symlinks (z.B. von systemd-resolved) und schreibt die Datei direkt.                                                                                                                                                   | `/etc/resolv.conf` lesen und mit Sollinhalt vergleichen                                | einfach |
| `net.route`     | Verwaltet persistente statische Routen. Erfordert `options.device`, wendet die Route sofort via `ip route replace` an und persistiert sie als systemd-networkd Drop-in am Paratix-Interface unter `/etc/systemd/network/60-paratix-<device>.network.d/`. Unterstützt `state: "absent"` zum Entfernen. | `ip route show <destination>` ausführen, Gateway/Device prüfen und Drop-in vergleichen | einfach |
| `net.waitFor`   | Wartet darauf, dass eine Bedingung erfuellt ist: Port offen, Datei vorhanden, oder String in Datei. Nützlich nach Service-Starts oder Deployments. Polling-Intervall: 2s (konfigurierbar). Default-Timeout: 60s (konfigurierbar).                                                                     | Polling mit Timeout                                                                    | mittel  |
| `net.request`   | Fuehrt einen HTTP-Request vom Server aus und prueft die Antwort (Statuscode, Body). Nützlich fuer Health-Checks.                                                                                                                                                                                      | HTTP-Statuscode und optionaler Body-Check                                              | mittel  |

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
net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
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
> geschrieben und `networkctl reload` ausgefuehrt. `net.route` schreibt
> `[Route]`-Drop-ins in
> `/etc/systemd/network/60-paratix-<device>.network.d/50-paratix-route-<destination>-<route-hash>.conf`.
> Der Hash enthält Destination, Gateway und Device, damit mehrere Routen zur
> gleichen Destination nicht kollidieren.
> Alte Paratix-Standalone-Dateien unter
> `/etc/systemd/network/50-paratix-route-<destination>.network` werden beim
> Entfernen nur gelöscht, wenn der Inhalt exakt dem früheren Paratix-Inhalt
> entspricht.

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

| Modul               | Beschreibung                                                                                                                                                                                                                                   | Check-Strategie                         | Aufwand |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------- |
| `package.installed` | Abstrahiert ueber `apt`, `dnf` und andere Paketmanager. Erkennt automatisch das Betriebssystem und waehlt den passenden Paketmanager. Erfordert `system.facts` oder manuelle OS-Angabe im Env.                                                 | Delegiert an den erkannten Paketmanager | mittel  |
| `package.absent`    | Gegenstueck zu `package.installed`. Entfernt Pakete unabhaengig vom Paketmanager. Mit `purge: true` unter apt per `apt-get purge` inkl. Konfigurationsdateien bzw. `rc`-Resten (auch abhaengige Pakete), unter apk/dnf/yum normales Entfernen. | Delegiert an den erkannten Paketmanager | mittel  |

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

**Conflict Guard:** Beide Module pruefen vor der eigentlichen Arbeit, ob ein
Container mit dem verwalteten Namen bereits existiert und _nicht_ zu dieser Unit
gehoert. Podman kann einen fremden Container nicht ersetzen; ohne diese Pruefung
scheiterte der Rollout erst spaeter mit `systemctl restart failed (exit code 1)`
oder blieb bei unveraendertem Image sogar unbemerkt.

Der verwaltete Containername ist `containerName ?? systemd-<name>` — dieselbe
Konvention, die Quadlet selbst verwendet. Wird `containerName` bei
`quadlet.container(...)` gesetzt, gehoert derselbe Wert auch in
`quadlet.updateImage(...)`.

Gemeldet wird ein Konflikt nur bei **positiver** Evidenz: ein Compose-Projekt-Label
(`com.docker.compose.project` oder `io.podman.compose.project`, also der typische
Rest einer Compose-zu-Quadlet-Migration) oder ein `PODMAN_SYSTEMD_UNIT`, das eine
andere Unit nennt. Fehlt jede Kennzeichnung, laeuft der Apply unveraendert weiter —
ein Fehlalarm waere teurer als eine Erkennungsluecke. Der eigene Container der Unit
gilt nie als Konflikt: `PODMAN_SYSTEMD_UNIT` enthaelt den vollen Unit-Namen (`%n`),
beide Seiten werden vor dem Vergleich normalisiert.

`quadlet.container` traegt `_dryRunBlocker: true`, der Konflikt erscheint also
bereits in einem normalen `--dry-run` ohne `--diff`.

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

| Modul           | Beschreibung                                                                                                                                                                                                                                                                                   | Check-Strategie                                                                                                                                                                     | Aufwand |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `mount.present` | Stellt sicher, dass ein Dateisystem gemountet ist. Unterstuetzt Block-Devices, tmpfs, NFS und andere Dateisysteme sowie Bind-Mounts (`bind`/`rbind`). Kann den Mount in `/etc/fstab` persistieren, sodass er Reboots ueberlebt. Erstellt den Mountpoint automatisch, falls er nicht existiert. | Obersten Mount per `findmnt --mountpoint <mountpoint>` pruefen + fstab-Eintrag vergleichen; bei Bind-Mounts zusaetzlich die Quelle per `readlink -f` + `findmnt --target` aufloesen | mittel  |
| `mount.absent`  | Stellt sicher, dass ein Mountpoint nicht gemountet ist. Entfernt optional den fstab-Eintrag und den Mountpoint-Ordner.                                                                                                                                                                         | `findmnt <mountpoint>` pruefen                                                                                                                                                      | einfach |

**Parameter fuer `mount.present`:**

```typescript
mount.present({
  path: "/tmp", // Mountpoint
  src: "tmpfs", // Device oder "tmpfs", "none", NFS-Pfad, Bind-Quellverzeichnis, ...
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

**Bind-Mounts:** Enthaelt `opts` das Token `bind` oder `rbind`, haengt
`mount.present` ein vorhandenes Verzeichnis an `path` ein. Beispiel: ein
Daten-Volume, dessen Unterverzeichnisse per Bind an ihre Zielorte kommen.

```typescript
// Daten-Volume
mount.present({
  path: "/srv/data",
  src: "/dev/mapper/data",
  fstype: "ext4",
  opts: "defaults,noatime",
})

// Unterverzeichnisse per Bind einhaengen
mount.present({
  path: "/var/lib/docker",
  src: "/srv/data/docker",
  fstype: "none",
  opts: "bind",
})

mount.present({
  path: "/opt/app",
  src: "/srv/data/app",
  fstype: "none",
  opts: "bind,nosuid,nodev",
})
```

- **Identitaet:** Ein Bind gilt als korrekt, wenn der oberste Mount an `path`
  dieselbe `MAJ:MIN` und dasselbe FSROOT hat wie die aufgeloeste Quelle.
  `fstype` und die von `findmnt` gemeldete SOURCE werden ignoriert. Korrekt
  gebundene Ziele werden nie ausgehaengt, auch nicht, wenn sie gerade in
  Benutzung sind.
- **VFS-Flags:** Durchgesetzt werden nur die VFS-Flags, die explizit in `opts`
  stehen: `ro`/`rw`, `nosuid`/`suid`, `nodev`/`dev`, `noexec`/`exec`,
  `noatime`/`relatime`/`strictatime`, `nodiratime` und `nosymfollow`. Nicht
  genannte Flags erbt der Bind vom Quell-Mount (z. B. `nosuid,nodev` eines
  gehaerteten Daten-Mounts); sie werden nicht geprueft. Wer etwa `suid`
  erzwingen will, schreibt es explizit in `opts`.
- **Konvergenz:** Weichen nur explizite Flags ab, korrigiert
  `mount -o remount,bind,<flags> -- <src> <path>` sie ohne Unmount. Der
  Remount nennt dabei den vollstaendigen VFS-Flag-Zustand (Live-Flags, von den
  expliziten Flags ueberschrieben), damit nicht genannte Flags wie ein geerbtes
  `nosuid` auch mit util-linux vor 2.39 erhalten bleiben. Weicht die
  Identitaet ab, folgen `umount` + `mount`.
- **`rbind`:** Wird wie `bind` geprueft, aber nur am obersten Mount;
  Submounts werden nicht verifiziert.
- **Quelle:** `src` muss ein absoluter, normalisierter Verzeichnispfad sein und
  darf nicht unterhalb von `path` liegen; sonst schlaegt schon das Erzeugen des
  Moduls fehl. Fehlt die Quelle oder ist sie eine regulaere Datei, meldet
  `check` Handlungsbedarf und `apply` schlaegt fehl, bevor irgendetwas
  ausgehaengt wird.
- **Self-Bind** (`src` gleich `path`): Erlaubt, aber der Check ist
  eingeschraenkt. Die Quelle loest sich auf den Mount an `path` selbst auf,
  daher bestaetigt der Check nur, dass ein Bind dieses Pfads mit den
  expliziten Flags gemountet ist.
- **fstab:** Die Zeile wird exakt wie angegeben geschrieben, z. B.
  `/srv/data/docker /var/lib/docker none bind 0 0`.
- **Reihenfolge beim Boot:** systemd ergaenzt fuer die Quelle eines Bind-Mounts
  bereits `RequiresMountsFor=`, `x-systemd.requires-mounts-for` ist daher
  optional. Liegt die Quelle auf einem `_netdev`-Mount, gehoert `_netdev` (und
  optional `nofail`) auch in die `opts` des Binds, z. B.
  `opts: "bind,_netdev,nofail"`.

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

**Vorab-Auflösung zu Lauf-Beginn:** Alle `op read`-Aufrufe eines Laufs
werden gebündelt **vor dem SSH-Connect** ausgeführt — unabhängig davon, an
welcher Position `op.resolve(...)` in `run` steht, und auch dann, wenn es
innerhalb eines `recipe(...)`, eines `when(...)`-Guards oder in `signals`
liegt. Dadurch erscheint ein biometrischer Unlock oder ein `op
signin`-Prompt sofort nach dem Kommando-Aufruf statt irgendwann mitten im
Lauf. Vor dem ersten `op read` gibt Paratix eine Statuszeile aus, die
diese Wartesituation erklärt.

Im weiteren Verlauf des Laufs verwendet `op.resolve(...)` an seiner
eigentlichen Position in `run` ausschließlich die bereits gelesenen Werte
aus einem lauf-gebundenen Cache — es ruft `op` dafür kein zweites Mal auf.
Nennen mehrere `op.resolve`-Module dieselbe Referenz, wird sie trotzdem
nur einmal pro Lauf gelesen.

Scheitert die Vorab-Auflösung — `op`-CLI fehlt, Session nicht angemeldet,
Timeout, abgebrochene Biometrie —, bricht der gesamte Lauf **vor dem
SSH-Connect** mit Exit-Code 2 ab. Das ist eine Verhaltensänderung
gegenüber bisherigen Playbooks: bislang meldete `op.resolve` einen
Fehlschlag als fehlgeschlagenes Modul an seiner Position in `run`; jetzt
verhindert ein Fehlschlag den gesamten Lauf, bevor überhaupt eine
Verbindung aufgebaut oder ein Task ausgeführt wurde.

`--dry-run` löst die Vorab-Auflösung ebenfalls aus, damit nachgelagerte
Module im Dry-Run dieselbe Umgebung sehen wie im echten Lauf. Schließt
`--filter` ein `op.resolve`-Modul aus dem Lauf aus, gibt Paratix eine
Warnung aus, weil Module, die den ausgeschlossenen Wert erwarten, ihn dann
nicht im Env finden — das Laufverhalten selbst ändert sich dadurch nicht.

Ein `op.resolve` in einem `when(...)`-Zweig wird ebenfalls immer vorab
aufgelöst — auch dann, wenn die Guard-Bedingung später `false` ergibt und
der Wert nie gebraucht wird. Das ist der bewusste Preis dafür, dass kein
Prompt mitten im Lauf auftauchen kann.

**Lazy OTP-Aufloesung:** OTP-Felder (`one-time-password`) werden als
**lazy Env-Werte** (Funktionen) in den Env geschrieben. Die zugrunde
liegende `otpauth://`-URI (der TOTP-Seed) wird bereits in der
Vorab-Auflösung einmalig per `op read` gelesen; der TOTP-**Code** selbst
wird erst berechnet, wenn ein Modul oder Template tatsaechlich auf den
Wert zugreift (via `resolveEnv`) — und das rein lokal, ohne weiteren
`op`-Aufruf und ohne erneute Biometrie. Das ist notwendig, weil OTPs nur
30 Sekunden gueltig sind und zwischen dem Lesen des Seeds und der
tatsaechlichen Verwendung beliebig viel Zeit vergehen kann. Der Seed
rotiert innerhalb eines Laufs nicht; eine Rotation in 1Password wird erst
mit dem naechsten `paratix apply`-Lauf sichtbar, der die Referenz erneut
liest.

Regulaere Secrets (Passwoerter, Tokens, etc.) werden bereits in der
Vorab-Auflösung als Strings aufgeloest, da sie sich nicht zeitlich
aendern.

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
