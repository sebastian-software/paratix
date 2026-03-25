# 0080: Disk-Full-Erkennung bei 0-Byte-Schreibfehlern

## Anforderung

Wenn Paratix beim Schreiben einer Datei (z.B. `file.copy`, `writeFile`) nur eine 0-Byte-Datei erzeugt und dies als Fehler erkennt, soll geprüft werden, ob die Festplatte voll ist. Falls ja, wird eine spezifische „Festplatte voll"-Fehlermeldung ausgegeben statt der generischen „remote file is empty"-Meldung.

## Architekturentscheidungen

- **Best-Effort-Diagnose:** `df -P` wird nur im Fehlerfall aufgerufen (kein Pre-Flight-Check), um kein zusätzliches Overhead im Normalfall zu erzeugen.
- **Zwei Integrationsstellen:** `ensureRemoteWriteFile()` (für `writeFile`) und `assertRemoteFileSize()` (für `uploadFile`) — die beiden zentralen Schreibpfade.
- **Graceful Fallback:** Wenn `df` fehlschlägt (z.B. auf minimalistischen Containern), wird die bisherige generische Fehlermeldung beibehalten.
- **POSIX-kompatibles Parsing:** `df -P` erzwingt POSIX-Format (einzeilige Ausgabe pro Filesystem), was zuverlässiges Spalten-Parsing ermöglicht.

## Betroffene Dateien

| Datei                                     | Beschreibung                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `packages/paratix/src/ssh.ts`             | Neue Methode `checkRemoteDiskSpace()`, Integration in `ensureRemoteWriteFile()` und `assertRemoteFileSize()` |
| `packages/paratix/test/writeFile.test.ts` | 2 neue Tests: Disk-Full-Erkennung und Fallback auf generische Meldung                                        |
| `packages/paratix/test/ssh.test.ts`       | Bestehender uploadFile-Test angepasst (neuer df-P Mock-Call)                                                 |
| `cspell.json`                             | „mountpoint" hinzugefügt                                                                                     |

## Implementierungsdetails

### Neue Methode `checkRemoteDiskSpace(remotePath)`

- Extrahiert das Verzeichnis aus dem Remote-Pfad
- Führt `df -P <directory>` aus
- Parst die Ausgabe: Available-Spalte (Index 3) × 1024 = verfügbare Bytes, Mountpoint (Index 5)
- Gibt `{ availableBytes, mountpoint }` zurück oder `null` bei Parse-/Exec-Fehler

### Integration in `ensureRemoteWriteFile()`

Wenn nach SFTP-Upload und Shell-Fallback die Datei immer noch 0 Bytes hat (`fallbackVerification === "empty"`), wird `checkRemoteDiskSpace()` aufgerufen. Wenn weniger Platz als die erwartete Dateigröße verfügbar ist:

```
[ssh.writeFile: /path] disk full – 0 bytes available on / ; the file was written as 0 bytes because there is no space left on the device
```

### Integration in `assertRemoteFileSize()`

Wenn `actualSize === 0` und `expectedSize > 0`, gleiche Prüfung wie oben.

## Testergebnisse

- 1632 Tests bestanden (15 davon writeFile.test.ts, davon 2 neu)
- TypeScript-Checks bestanden
- Lint fehlerfrei (0 Errors)
