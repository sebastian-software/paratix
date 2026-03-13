# 0009 — Download Module

## Anforderung

Neues Modul `download` mit zwei Methoden:

- `download.url(dest, url, options?)` — Datei per `curl -fsSL` von einer URL herunterladen
- `download.github(dest, options)` — GitHub Release Asset herunterladen

## Architekturentscheidungen

- **Idempotenz:** SHA-256-Vergleich (wenn angegeben), sonst Datei-Existenz. `force: true` überspringt den Check.
- **Download-Tool:** `curl -fsSL` — Standard auf Ubuntu/Debian, kein wget-Fallback nötig.
- **Shared Logic:** Gemeinsame Hilfsfunktionen (`buildCurlCommand`, `verifyChecksum`, `applyFileAttributes`, `performDownload`, `checkDownload`) extrahiert, die von beiden Methoden genutzt werden.
- **GitHub-URL:** Direkt gebaut als `https://github.com/{repo}/releases/download/{tag}/{asset}`. Private Repos nutzen `Authorization: token {token}` Header.
- **Repo-Validierung:** `options.repo` wird auf `owner/repo`-Format validiert (kein Path-Traversal).
- **Shell-Quoting:** `dirname`-Aufruf in doppelten Anführungszeichen gegen Word-Splitting geschützt.

## Betroffene Dateien

| Datei                                            | Aktion                                |
| ------------------------------------------------ | ------------------------------------- |
| `packages/paratix/src/modules/download.ts`       | Neu erstellt                          |
| `packages/paratix/src/modules/index.ts`          | Export hinzugefügt                    |
| `packages/paratix/test/modules/download.test.ts` | Neu erstellt                          |
| `cspell.json`                                    | "hashicorp" und "mytoken" hinzugefügt |

## API

### `download.url(destination, url, options?)`

| Option    | Typ                      | Beschreibung                  |
| --------- | ------------------------ | ----------------------------- |
| `sha256`  | `string`                 | Erwarteter SHA-256 Hex-Digest |
| `mode`    | `string`                 | Dateimodus (z.B. `"0755"`)    |
| `owner`   | `string`                 | Dateieigentümer               |
| `group`   | `string`                 | Dateigruppe                   |
| `headers` | `Record<string, string>` | Zusätzliche HTTP-Header       |
| `force`   | `boolean`                | Download erzwingen            |

### `download.github(destination, options)`

| Option   | Typ      | Beschreibung                      |
| -------- | -------- | --------------------------------- |
| `repo`   | `string` | Repository im Format `owner/repo` |
| `tag`    | `string` | Release-Tag                       |
| `asset`  | `string` | Asset-Dateiname                   |
| `token`  | `string` | GitHub PAT für private Repos      |
| `sha256` | `string` | Erwarteter SHA-256 Hex-Digest     |
| `mode`   | `string` | Dateimodus                        |
| `owner`  | `string` | Dateieigentümer                   |
| `group`  | `string` | Dateigruppe                       |

## Testergebnisse

31 Tests in 2 describe-Blöcken:

- `download.url` (20 Tests): check (SHA-256, Existenz, force, null), apply (curl, mkdir, chmod, chown, headers, SHA-256-Verifikation, null), name
- `download.github` (11 Tests): check (Existenz, SHA-256, null), apply (URL, Token-Header, kein Header, mkdir, null), validation (Path-Traversal, kein Slash, gültiges Format), name

## Review-Findings und Behebung

| Finding                                          | Schweregrad | Behebung                              |
| ------------------------------------------------ | ----------- | ------------------------------------- |
| GitHub-URL Path-Traversal über `repo`            | Wichtig     | Repo-Format-Validierung hinzugefügt   |
| `$(dirname ...)` nicht gequotet (Word-Splitting) | Hinweis     | In doppelte Anführungszeichen gesetzt |
| Extra-Properties im DownloadParameters-Objekt    | Hinweis     | Destructuring statt Spread            |
| oxlint `prefer-spread` False-Positive            | Hinweis     | Variable statt Literal `null`         |
