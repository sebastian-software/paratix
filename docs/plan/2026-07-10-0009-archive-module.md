# 0009 — archive Module

## Anforderung

Implementiere das Modul `archive` mit der Methode `archive.extract`, das Archive (tar, tar.gz, tar.bz2, tar.xz, zip) auf dem Server entpackt. Optional kann eine lokale Datei vorher per SFTP hochgeladen werden. Idempotenz wird über eine Marker-Datei mit SHA256-Checksum sichergestellt.

## API

```typescript
archive.extract(source: string, destination: string, options?: {
  owner?: string
  upload?: boolean
}): Module
```

- `source` — Pfad zum Archiv (Remote-Pfad, oder lokaler Pfad bei `upload: true`)
- `destination` — Zielverzeichnis auf dem Server
- `owner` — Optional: `chown -R` nach dem Entpacken (z.B. `"www-data:www-data"`)
- `upload` — Optional: Lokale Datei erst per SFTP hochladen, dann entpacken

## Architekturentscheidungen

### Helper-Funktionen

Fünf interne Helper für Lesbarkeit und ESLint-Konformität (max-params, max-statements):

- `markerPath()` — Berechnet den Marker-Datei-Pfad aus dem SHA256-Hash des Source-Pfades
- `extractCommand()` — Gibt den passenden Shell-Befehl basierend auf der Dateiendung zurück
- `resolveRemoteSource()` — Lädt bei `upload: true` die lokale Datei hoch und gibt den Remote-Pfad zurück
- `writeMarkerAndCleanup()` — Schreibt die Marker-Datei und räumt temporäre Uploads auf
- `applyExtract()` — Orchestriert den gesamten Apply-Ablauf

### Check-Strategie (Marker-Datei)

1. Kein SSH → `NEEDS_APPLY`
2. Zielverzeichnis existiert nicht → `NEEDS_APPLY`
3. Marker-Datei existiert nicht → `NEEDS_APPLY`
4. SHA256 des Archivs ≠ Marker-Inhalt → `NEEDS_APPLY`
5. Sonst → `"ok"`

Bei `upload: true` wird im Check die lokale SHA256 berechnet (via `localSha256`) — kein Upload im Check-Schritt.

Marker-Dateien liegen unter `/var/lib/paratix/flags/archive-<sha256(source-pfad)>.sha256`.

### Apply-Logik

1. Kein SSH → `{ status: "failed" }`
2. Upload (optional) → `conn.uploadFile()` nach `/tmp/paratix-upload-<hash>`
3. `mkdir -p <destination>`
4. Format erkennen und entpacken (tar/unzip)
5. `chown -R` (optional)
6. Marker-Datei schreiben mit SHA256 des Archivs
7. Temporäre Upload-Datei löschen (auch bei Fehlern)

### Format-Erkennung

| Endung             | Befehl     |
| ------------------ | ---------- |
| `.tar`             | `tar xf`   |
| `.tar.gz` / `.tgz` | `tar xzf`  |
| `.tar.bz2`         | `tar xjf`  |
| `.tar.xz`          | `tar xJf`  |
| `.zip`             | `unzip -o` |

### Fehlerbehandlung

- Unsupported Format → `{ status: "failed" }`
- Extraktion schlägt fehl → `{ status: "failed" }` + Cleanup der temp-Datei
- `sha256` gibt `null` zurück → `{ status: "failed" }`

## Betroffene Dateien

| Datei                                           | Aktion                                      |
| ----------------------------------------------- | ------------------------------------------- |
| `packages/paratix/src/modules/archive.ts`       | Neu — Modul-Implementierung                 |
| `packages/paratix/src/modules/index.ts`         | Export hinzugefügt                          |
| `packages/paratix/test/modules/archive.test.ts` | Neu — 20 Unit-Tests                         |
| `README.md`                                     | archive in implementierte Module verschoben |

## Testergebnisse

- 20 Tests (6 check, 13 apply + name), alle bestanden
- Gesamte Test-Suite: 316 Tests bestanden
- Lint, TypeScript, Prettier: fehlerfrei

## Review-Findings und Behebung

### Finding 1: Verwaiste temp-Dateien bei Extraktionsfehler (Wichtig)

**Problem:** Bei `upload: true` wurde die hochgeladene temporäre Datei nicht aufgeräumt, wenn die Extraktion fehlschlug.
**Lösung:** Cleanup (`rm -f`) wird jetzt auch bei fehlgeschlagener Extraktion und bei unsupported Format ausgeführt.

### Finding 2: Fehlender Test für sha256 === null (Hinweis)

**Problem:** Der Pfad in `writeMarkerAndCleanup` bei `sha256 === null` war nicht getestet.
**Lösung:** Test hinzugefügt der prüft, dass `status: "failed"` zurückgegeben wird.
