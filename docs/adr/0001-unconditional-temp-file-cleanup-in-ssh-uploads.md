# ADR-0001: Unconditional temp file cleanup in SSH uploads

**Status:** Accepted
**Datum:** 2026-03-19
**Kontext:** /refactor — Design-Review von `uploadFile`/`writeFile`

## Kontext

Die Methoden `uploadFile` (ssh.ts:296-314) und `writeFile` (ssh.ts:332-366) verwenden ein
atomic-write-Pattern: Inhalt wird in eine Temp-Datei geschrieben und per `mv` an den Zielort
verschoben. Im `finally`-Block wird `rm -f` auf die Temp-Datei ausgeführt — unabhängig davon,
ob `mv` erfolgreich war.

Ein Refactoring-Vorschlag war, ein `moved`-Flag einzuführen und `rm -f` nur auszuführen wenn
`mv` nicht erfolgreich war (moved-Flag-Pattern). Dadurch würde der redundante `rm -f`-Aufruf
nach erfolgreichem `mv` vermieden.

## Entscheidung

Das aktuelle Verhalten (unconditional `rm -f` im `finally`-Block) wird beibehalten.

## Begründung

- **Harmloser No-Op:** Nach erfolgreichem `mv` existiert die Temp-Datei nicht mehr. `rm -f`
  gibt bei nicht existierenden Dateien keinen Fehler zurück — der Aufruf ist ein No-Op.
- **Robuste Cleanup-Garantie:** Der `finally`-Block stellt sicher, dass die Temp-Datei in
  jedem Fehlerfall aufgeräumt wird — bei Fehlern in `sftpUpload`, `chmod` oder `mv`.
  Ein `moved`-Flag würde zusätzliche Komplexität einführen ohne das Verhalten zu verbessern.
- **Einfachheit:** Das unconditional Pattern ist leichter zu lesen und zu warten. Ein
  `moved`-Flag müsste korrekt gesetzt werden und wäre eine zusätzliche Fehlerquelle.
- **Kein Performance-Impact:** Ein einzelner `rm -f`-Aufruf auf eine nicht existierende Datei
  hat keine messbare Performance-Auswirkung.

## Quelle

- **Finding:** uploadFile/writeFile finally-Block cleanup
- **Schweregrad:** Hinweis
- **Dateien:** packages/paratix/src/ssh.ts:296-314, packages/paratix/src/ssh.ts:332-366
