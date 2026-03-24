# 0077: `file.chmod(...)` und `file.chown(...)`

## Anforderung

Paratix soll dedizierte deklarative Module für `chmod` und `chown` bekommen, statt diese Operationen nur indirekt über andere Module oder Optionen abzubilden.

## Architekturentscheidungen

- Die neuen Operationen werden in den bestehenden `file`-Namespace integriert.
- Neue API:
  - `file.chmod(remotePath, mode)`
  - `file.chown(remotePath, owner)`
- Die Implementierung verwendet die bestehende Metadata-Logik aus `file.ts` (`readOwnership`, `ownershipMatches`, `validateMode`) statt neue Spezialpfade einzuführen.
- Das Verhalten bleibt idempotent:
  - `check()` liest den aktuellen Zustand via `stat`
  - `apply()` führt nur den jeweiligen Einzelbefehl aus

## Betroffene Dateien

| Datei                                        | Beschreibung                                        |
| -------------------------------------------- | --------------------------------------------------- |
| `packages/paratix/src/modules/file.ts`       | Neue Module `file.chmod(...)` und `file.chown(...)` |
| `packages/paratix/test/modules/file.test.ts` | Regressionen für Check-/Apply-Pfade                 |
| `packages/paratix/llm-guide.md`              | API-Referenz ergänzt                                |
| `packages/paratix/README.md`                 | Nutzerdoku ergänzt                                  |

## Implementierungsdetails

- `file.chmod(...)`
  - prüft Pfad-Existenz
  - vergleicht den aktuellen Modus mit dem gewünschten Wert
  - ruft bei Bedarf `chmod` auf
- `file.chown(...)`
  - prüft Pfad-Existenz
  - vergleicht Owner/Group mit dem gewünschten Wert
  - ruft bei Bedarf `chown` auf
- Fehlender SSH-Kontext bleibt konsistent mit den anderen `file.*`-Modulen und liefert `needs-apply` in `check()` bzw. `failed` in `apply()`.

## Testergebnisse

- Unit-Tests für `file.chmod(...)`
  - `ok` bei passendem Modus
  - `needs-apply` bei fehlendem Pfad oder abweichendem Modus
  - `apply()` führt `chmod` aus
- Unit-Tests für `file.chown(...)`
  - `ok` bei passendem Owner/Group
  - `needs-apply` bei fehlendem Pfad oder abweichendem Owner
  - `apply()` führt `chown` aus
- Gesamtvalidierung über `pnpm agent:check`

## Review-Findings und Behebung

- Keine zusätzlichen Findings aus der Implementierung.
