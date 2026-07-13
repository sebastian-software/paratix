# 0037 — dotenv-Parser-Erweiterungen

## Anforderung

Den `.env`-Parser in `environment.ts` um dotenv-kompatible Features erweitern:
(1) Escape-Sequenzen in doppelt-gequoteten Werten (`\n`, `\"`, `\\`).
(2) Inline-Kommentare (`#` nach unquoted values) erkennen und entfernen.

## Architekturentscheidungen

- **`processValue()` extrahiert:** Wert-Verarbeitung in separate Funktion ausgelagert,
  damit `loadDotEnvironment` unter dem `max-statements`-Lint-Limit bleibt.
- **Sentinel-Ansatz fuer Escape-Reihenfolge:** `\\` wird zuerst durch `\0` (Null-Byte)
  ersetzt, dann `\n` und `\"` verarbeitet, dann `\0` zurueck zu `\`. Sicher, da
  `.env`-Dateien keine Null-Bytes enthalten.
- **Single-quoted = literal:** Keine Escape-Verarbeitung in single-quoted Values
  (wie bash und dotenv).
- **Inline-Kommentare nur bei unquoted:** `" #"` (Space+Hash) als Kommentar-Start.
  Quoted Values behalten `#` literal.
- **Mindestlaenge-Pruefung:** `raw.length >= 2` vor Quote-Erkennung, damit ein
  einzelnes `'` oder `"` als Literal-Wert behandelt wird.

## Betroffene Dateien

| Datei                      | Aenderung                                                       |
| -------------------------- | --------------------------------------------------------------- |
| `src/environment.ts`       | `processValue()` neu, `loadDotEnvironment` vereinfacht          |
| `test/environment.test.ts` | 11 neue Tests fuer Escape-Sequenzen, Inline-Kommentare, Quoting |

## Testergebnisse

- 1100 Tests bestanden (vorher 1089), 0 fehlgeschlagen
- 0 TypeScript-Fehler, 0 Lint-Fehler

## Review-Findings

| #     | Schweregrad | Status  | Beschreibung                                              |
| ----- | ----------- | ------- | --------------------------------------------------------- |
| R-001 | Hinweis     | Offen   | `\t` und `\r` Escape-Sequenzen fehlen                     |
| R-002 | Hinweis     | Behoben | Sentinel-Kommentar fehlte                                 |
| R-003 | Wichtig     | Offen   | Tab-vor-Hash nicht als Kommentar erkannt (dotenv-konform) |
| R-004 | Hinweis     | Offen   | Edge Cases `KEY=` und `KEY=""` nicht explizit getestet    |
| R-005 | Wichtig     | Behoben | Einzelnes Quote-Zeichen als leerer Value geparst          |
| R-007 | Hinweis     | Offen   | `export`-Praefix nicht unterstuetzt                       |
