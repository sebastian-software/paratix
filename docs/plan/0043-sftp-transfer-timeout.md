# 0043: SFTP Transfer Timeout

## Anforderung

SFTP-Operationen (sftpDownload/sftpUpload) in `packages/paratix/src/sftp.ts` hatten keinen Timeout. Bei einem stalled Transfer (z.B. eingefrorenes Netzwerk) wartete die Promise unbegrenzt. Anforderung: Timeout-Mechanismus analog zu `COMMAND_TIMEOUT` (120s) fuer SFTP-Transfers implementieren. Bei Timeout soll der Stream abgebrochen und ein beschreibender Fehler geworfen werden.

## Architekturentscheidungen

- **Eigene Konstante `SFTP_TIMEOUT = 120_000`** statt Import von `COMMAND_TIMEOUT` aus `ssh.ts` — entkoppelt die SFTP-Timeout-Konfiguration von der Command-Timeout-Konfiguration, erlaubt spaetere unabhaengige Anpassung.
- **`wireStreams()` Hilfsfunktion** extrahiert — dedupliziert die identische Stream-Event-Handler + Timeout-Logik aus `sftpDownload` und `sftpUpload`. Behebt nebenbei die dokumentierten BUG-Defekte (fehlende `destroy()` auf Counterpart-Streams).
- **`setTimeout` + `stream.destroy()` + `sftp.end()` + `reject`** Pattern — konsistent mit dem `exec()`-Timeout-Pattern in `ssh.ts` (Zeilen 158-163).
- **`clearTimeout(timer)` VOR dem `settled`-Check** in allen Event-Handlers — Timer wird auch bei doppelten Events (Error + Close Race) zuverlaessig geloescht.
- **Default-Parameter statt Options-Objekt** — minimaler API-Eingriff, rueckwaertskompatibel.

## Betroffene Dateien

| Datei                                | Beschreibung                                                           |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `packages/paratix/src/sftp.ts`       | Timeout-Mechanismus, `wireStreams()` Extraktion, `SFTP_TIMEOUT` Export |
| `packages/paratix/test/sftp.test.ts` | 8 neue Timeout-Tests (4 pro Funktion)                                  |

## Implementierungsdetails

### sftp.ts

- `SFTP_TIMEOUT = 120_000` als benannter Export
- `wireStreams()` private Hilfsfunktion mit Parametern: `readStream`, `writeStream`, `sftp`, `resolve`, `reject`, `timeout`, `timeoutMessage`
- Timeout-Handler: `readStream.destroy()`, `writeStream.destroy()`, `sftp.end()`, `reject(new Error(timeoutMessage))`
- Fehlermeldungen: `"SFTP download timed out after ${timeout}ms: ${remotePath}"` / `"SFTP upload timed out after ${timeout}ms: ${remotePath}"`
- Beide Funktionen erhalten optionalen `timeout`-Parameter (4. Argument, Default `SFTP_TIMEOUT`)

### Tests

8 neue Tests mit `vi.useFakeTimers()`:

- `sftpDownload`/`sftpUpload`: "rejects when transfer times out"
- `sftpDownload`/`sftpUpload`: "destroys both streams and ends sftp session on timeout"
- `sftpDownload`/`sftpUpload`: "clears timeout on successful transfer"
- `sftpDownload`/`sftpUpload`: "clears timeout on stream error"

### Validierung

- Lint (oxlint + eslint): 0 Fehler
- Prettier: bestanden
- TypeScript: 0 Fehler
- Tests: 1235 bestanden (41 Test-Dateien)

## Review-Findings

| ID    | Schweregrad | Bereich        | Status                                                         |
| ----- | ----------- | -------------- | -------------------------------------------------------------- |
| R-001 | Wichtig     | Resource Leaks | False Positive (Code hat readStream.destroy() in Zeile 54)     |
| R-002 | Hinweis     | Code-Qualitaet | Kein Fix noetig (Streams bei Erfolg nicht destroyed — korrekt) |
| R-003 | Hinweis     | Code-Qualitaet | Nicht umgesetzt (inkonsistente typeof-Guards, pre-existing)    |
