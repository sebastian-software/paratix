# 0003 — file-Modul vollständig implementieren

**Datum:** 2026-03-13
**Status:** Abgeschlossen

## Anforderung

Das `file`-Modul war teilweise implementiert (5 von 10 Sub-Modulen). Die fehlenden 5 Sub-Module aus der Spezifikation in `docs/module.md` mussten implementiert werden:

- `file.assemble` — Datei aus Fragmenten zusammensetzen
- `file.block` — Textblock mit Markern verwalten
- `file.properties` — Berechtigungen/Besitzer verwalten
- `file.replace` — Regex-Ersetzung in Datei
- `file.stat` — Datei-Metadaten lesen

## Architekturentscheidungen

### Datei-Aufteilung

Die ESLint `max-lines`-Regel (300 Zeilen) erforderte ein Split in 3 Dateien:

- `file.ts` — Hauptmodul mit den 5 bestehenden Sub-Modulen (absent, copy, directory, line, template) + Re-Exports der neuen
- `fileExtra.ts` — 5 neue Sub-Module + private Hilfsfunktionen (replaceBlock, extractBlockContent, concatFragments)
- `fileHelpers.ts` — Shared SHA-256 Utilities (localSha256, sha256String)

### file.block Signatur

Statt 4 einzelner Parameter (`remotePath, name, content, options?`) nutzt `file.block` ein `BlockOptions`-Objekt als zweiten Parameter (`remotePath, options`), da die ESLint `max-params`-Regel maximal 3 Parameter erlaubt.

### file.replace — readFile/writeFile statt sed

Ursprünglich per `sed -i` implementiert, wurde `file.replace` im Review auf den sichereren Ansatz umgestellt: Datei via `ssh.readFile` lesen, Ersetzung in TypeScript via `String.replaceAll(new RegExp(...))` durchführen, Ergebnis via `ssh.writeFile` zurückschreiben. Grund: Shell-Injection-Risiko durch unzureichendes Escaping der sed-Argumente.

### file.stat — check gibt needs-apply zurück

`file.stat` ist ein read-only Modul, das Metadaten in `result.meta` schreibt. Da der Runner `apply` nur bei `check === "needs-apply"` aufruft, muss `check` immer `"needs-apply"` zurückgeben, damit die Metadaten gesammelt werden.

### file.properties — Mode-Normalisierung

`stat -c '%a'` gibt oktale Berechtigungen ohne führende Null aus (z.B. `644`). Die Check-Logik entfernt führende Nullen vom User-Input (`"0644"` → `"644"`) vor dem Vergleich, um Idempotenz zu gewährleisten.

## Betroffene Dateien

| Datei                                         | Änderung                                                       |
| --------------------------------------------- | -------------------------------------------------------------- |
| `packages/paratix/src/modules/file.ts`        | Erweitert um Imports + Re-Exports der 5 neuen Sub-Module       |
| `packages/paratix/src/modules/fileExtra.ts`   | Neu: 5 Sub-Module (assemble, block, properties, replace, stat) |
| `packages/paratix/src/modules/fileHelpers.ts` | Neu: Extrahierte SHA-256 Utilities                             |
| `packages/paratix/test/modules/file.test.ts`  | Erweitert: 41 neue Tests (6→47 Tests)                          |

## Testergebnisse

- **149 Tests** insgesamt (47 davon file-Modul)
- **0 Lint-Fehler**, 29 Warnings (alle vorbestehend oder acceptable wie `security/detect-non-literal-fs-filename` in Tests)
- **TypeCheck:** Bestanden
- **Prettier:** Bestanden

## Review-Findings und deren Behebung

| Finding                                                       | Schweregrad | Behebung                                                             |
| ------------------------------------------------------------- | ----------- | -------------------------------------------------------------------- |
| Shell-Injection in `file.replace` via sed                     | KRITISCH    | Umgestellt auf readFile + TypeScript Regex + writeFile               |
| Mode-Vergleich `"0644" !== "644"` bricht Idempotenz           | WICHTIG     | Leading-Zero-Normalisierung im Check                                 |
| `file.block` auf nicht-existierende Datei                     | WICHTIG     | exists-Check vor readFile, neuen Block als gesamten Inhalt schreiben |
| `file.stat` check "ok" verhindert apply                       | WICHTIG     | check gibt "needs-apply" zurück                                      |
| `file.copy`/`file.directory` prüfen mode/owner nicht im check | WICHTIG     | Vorbestehender Code, nicht in Scope                                  |
| `file.line` sed-Semantik (nur erste Zeile)                    | WICHTIG     | Vorbestehender Code, nicht in Scope                                  |
