# 0085: Apply-Schutz für flag-basierte Module

## Anforderung

`apt.distUpgrade`, `script.once` und `download.large` sollen auch bei direkten `apply`-Aufrufen erneut prüfen, ob ihre Flag-Datei bereits existiert. Parallele Anwendungen desselben flag-basierten Moduls sollen über einen atomaren Remote-Lock abgesichert werden, damit teure oder einmalige Operationen nicht doppelt laufen.

## Architekturentscheidungen

- **Zentraler Lock-Helper:** `applyWithFlagLock()` kapselt Flag-Recheck, atomaren `mkdir`-Lock, Wartepfad für konkurrierende Läufe und Lock-Cleanup in `moduleHelpers.ts`.
- **Atomarer Remote-Lock:** Der Lock nutzt ein Verzeichnis `<flag>.lock` unter `/var/lib/paratix/flags/`. `mkdir` ist auf dem Zielsystem atomar und eignet sich daher als Acquire-Primitiv über parallele SSH-Sessions hinweg.
- **Zweiter Flag-Recheck im Lock:** Nach erfolgreichem Acquire prüft der Helper das Flag erneut, bevor die eigentliche Apply-Funktion ausgeführt wird. Damit werden direkte `apply`-Aufrufe und Race Conditions zwischen `check` und `apply` abgefangen.
- **Lock-Erhalt bei versionierten Flags:** `setVersionedFlag()` schließt `*.lock` vom Prefix-Cleanup aus, damit versionierte Flag-Rotationen den aktiven Lock nicht entfernen.
- **Warteverhalten für parallele Läufe:** Wenn ein anderer Lauf den Lock hält, wartet der Helper remote bis entweder das Flag gesetzt oder der Lock freigegeben wurde. Danach prüft er erneut und führt nur bei weiterhin fehlendem Flag selbst aus.

## Betroffene Dateien

| Datei                                                 | Beschreibung                                                                               |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `packages/paratix/src/modules/moduleHelpers.ts`       | Neuer `applyWithFlagLock()`-Helper und Lock-sicherer `setVersionedFlag()`-Cleanup          |
| `packages/paratix/src/modules/apt.ts`                 | `apt.distUpgrade.apply()` nutzt den zentralen Flag-Lock                                    |
| `packages/paratix/src/modules/script.ts`              | `script.once.apply()` nutzt den zentralen Flag-Lock                                        |
| `packages/paratix/src/modules/download.ts`            | `download.large.apply()` nutzt den zentralen Flag-Lock                                     |
| `packages/paratix/test/modules/moduleHelpers.test.ts` | Tests für direkten Apply-Skip und parallelen Lock-Wartepfad                                |
| `packages/paratix/test/modules/apt.test.ts`           | Tests für direkten `apt.distUpgrade.apply()`-Skip und aktualisierte Flag-Cleanup-Kommandos |
| `packages/paratix/test/modules/script.test.ts`        | Tests für direkten `script.once.apply()`-Skip und aktualisierte Lock-/Flag-Kommandos       |
| `packages/paratix/test/modules/download.test.ts`      | Test für direkten `download.large.apply()`-Skip                                            |
| `packages/paratix/test/modules/package.test.ts`       | Erwartete versionierte Flag-Cleanup-Kommandos um `*.lock`-Ausschluss ergänzt               |
| `packages/paratix/test/modules/quadlet.test.ts`       | Erwartete versionierte Flag-Cleanup-Kommandos um `*.lock`-Ausschluss ergänzt               |

## Implementierungsdetails

`applyWithFlagLock()` validiert den Flag-Namen mit derselben Policy wie `hasFlag()` und `setFlag()`. Der Helper prüft zuerst das Flag. Wenn es fehlt, stellt er das Flag-Verzeichnis sicher und versucht per `mkdir /var/lib/paratix/flags/<flag>.lock` atomar zu acquiren. Erfolgreiche Acquirer prüfen das Flag innerhalb des Locks erneut, führen dann die modul-spezifische Apply-Funktion aus und geben den Lock im `finally` per `rmdir` frei.

Konkurrierende Läufe, die den Lock nicht erhalten, führen keinen lokalen Busy-Loop aus. Stattdessen läuft ein remote Shell-Wait mit Timeout, der auf Lock-Freigabe oder gesetztes Flag wartet. Danach startet der Helper den Recheck erneut. Wenn der erste Lauf erfolgreich war, gibt der zweite Lauf `{ status: "ok" }` zurück; wenn der Lock ohne Flag verschwindet, darf der zweite Lauf selbst acquiren und apply ausführen.

`setVersionedFlag()` löscht weiterhin alte Flags mit demselben Prefix, schließt aber `*.lock` aus. Das schützt aktive Locks von `apt.distUpgrade`, `script.once` und anderen versionierten Flag-Callsites wie `package.update`, `package.upgrade`, `apt.repository`, `apt.debconf` und Quadlet-Reload-Flags.

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/modules/moduleHelpers.test.ts test/modules/apt.test.ts test/modules/script.test.ts test/modules/download.test.ts` — bestanden, 226 Tests.
- `pnpm agent:check` — bestanden: Lint, Format, Typecheck, Build, Unit- und Distribution-Tests.

## Review-Findings

**Datum:** 2026-05-04
**Reviewer:** sf-nodejs-reviewer

Keine Findings gefunden.
