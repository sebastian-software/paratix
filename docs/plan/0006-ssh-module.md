# 0006: SSH-Client-Modul

## Anforderung

Implementierung des `ssh`-Moduls gemäß Spezifikation in `docs/module.md`. Das Modul verwaltet SSH-Client-Konfiguration auf Remote-Servern: `known_hosts`-Einträge und `authorized_keys`-Dateien.

## Architekturentscheidungen

### Home-Verzeichnis-Auflösung

Statt einer statischen Zuordnung (`root` → `/root`, andere → `/home/<user>`) wird das Home-Verzeichnis dynamisch via `getent passwd <user> | cut -d: -f6` aufgelöst. Dies unterstützt auch System-Benutzer mit nicht-standardmäßigem Home-Verzeichnis (z.B. `www-data` → `/var/www`).

### `grep -vF || true` Pattern

Beim Entfernen eines Keys aus `authorized_keys` wird `{ grep -vF -- <key> <file> || true; }` verwendet, da `grep` Exit-Code 1 zurückgibt wenn keine Zeilen übrig bleiben (z.B. wenn die Datei nur den zu entfernenden Key enthielt). Ohne `|| true` würde die `&&`-Kette abbrechen.

### Defensive grep-Optionen

Alle `grep`-Aufrufe verwenden `--` nach den Flags, um zu verhindern, dass ein Argument (theoretisch) als Option interpretiert wird.

### `~/.ssh`-Verzeichnis in `knownHosts`

`knownHosts.apply()` erstellt `~/.ssh` mit korrekten Berechtigungen (700) bevor `ssh-keyscan` schreibt — analog zu `authorizedKeys`, das ebenfalls das Verzeichnis sicherstellt.

### Parameter-Benennung `conn` statt `ssh`

Um eine Namenskollision mit dem exportierten `ssh`-Objekt zu vermeiden, verwenden die Methoden `conn` als Parameter-Name für die SSH-Verbindung.

## Betroffene Dateien

| Datei                                       | Aktion                                            |
| ------------------------------------------- | ------------------------------------------------- |
| `packages/paratix/src/modules/ssh.ts`       | Neu — Modul mit `knownHosts` und `authorizedKeys` |
| `packages/paratix/src/modules/index.ts`     | Edit — Export hinzugefügt                         |
| `packages/paratix/test/modules/ssh.test.ts` | Neu — 18 Unit-Tests                               |

## API

### `ssh.knownHosts(host, options?)`

| Parameter       | Typ                     | Default     | Beschreibung                       |
| --------------- | ----------------------- | ----------- | ---------------------------------- |
| `host`          | `string`                | —           | Hostname oder IP-Adresse           |
| `options.state` | `"present" \| "absent"` | `"present"` | Ob der Eintrag vorhanden sein soll |

- **Check:** `ssh-keygen -F <host>`
- **Apply (present):** `mkdir -p ~/.ssh && ssh-keyscan -H <host> >> ~/.ssh/known_hosts`
- **Apply (absent):** `ssh-keygen -R <host>`

### `ssh.authorizedKeys(user, key, options?)`

| Parameter       | Typ                     | Default     | Beschreibung                    |
| --------------- | ----------------------- | ----------- | ------------------------------- |
| `user`          | `string`                | —           | Ziel-Benutzer                   |
| `key`           | `string`                | —           | Vollständiger Public-Key-String |
| `options.state` | `"present" \| "absent"` | `"present"` | Ob der Key vorhanden sein soll  |

- **Check:** `grep -qF -- <key> <authorized_keys>`
- **Apply (present):** Verzeichnis erstellen (chmod 700), Key anhängen, Berechtigungen setzen (chmod 600), Ownership setzen
- **Apply (absent):** `{ grep -vF -- <key> <file> || true; } > <tmp> && mv <tmp> <file>`

## Testergebnisse

18 Tests, alle bestanden:

- `ssh.knownHosts`: 8 Tests (check present/absent/null, apply present/absent/null)
- `ssh.authorizedKeys`: 10 Tests (check present/absent/null, apply present/absent/null, dynamische Home-Auflösung für root und non-root)

## Review-Findings und deren Behebung

| #   | Schweregrad | Problem                                    | Lösung                                                |
| --- | ----------- | ------------------------------------------ | ----------------------------------------------------- |
| 1   | Kritisch    | `grep -vF` gibt exit 1 bei leerem Ergebnis | `{ grep -vF ... \|\| true; }` Pattern                 |
| 2   | Wichtig     | Fehlendes `--` bei grep-Aufrufen           | `--` nach Flags eingefügt                             |
| 3   | Wichtig     | Statische Home-Dir-Zuordnung               | Dynamisch via `getent passwd`                         |
| 4   | Hinweis     | `knownHosts` erstellt `~/.ssh` nicht       | `mkdir -p ~/.ssh && chmod 700 ~/.ssh` vor ssh-keyscan |
