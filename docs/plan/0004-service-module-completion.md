# 0004 — Service Module Completion

## Anforderung

Das `service`-Modul vollständig implementieren: fehlende `service.facts()`-Methode ergänzen und vollständige Testabdeckung für alle 7 Methoden herstellen.

## Ausgangslage

- 6 von 7 spezifizierten Methoden waren implementiert: `running`, `stopped`, `enabled`, `disabled`, `restart`, `reload`
- `service.facts` fehlte (spezifiziert in `docs/module.md`)
- Testabdeckung: nur `running.check` und `enabled.check` (6 Tests)

## Architekturentscheidungen

### service.facts() Design

- **Check:** Gibt immer `"ok"` zurück — Facts ändern nichts am Server
- **Apply:** Führt `systemctl list-units --type=service --all --no-pager --no-legend` aus
- **Parsing:** Jede Zeile wird nach Whitespace gesplittet → UNIT (Index 0), ACTIVE-State (Index 2)
- **Meta-Keys:** `service.<name>` = Active-State (z.B. `"active"`, `"inactive"`, `"failed"`)
- **Unicode-Bullet-Handling:** systemd stellt fehlgeschlagenen Units ein `●` (U+25CF) oder `○` (U+25CB) voran — wird vor dem Parsing entfernt
- **Exit-Code:** Bei `code !== 0` wird `{ status: "failed" }` zurückgegeben

## Betroffene Dateien

| Datei                                           | Änderung                                     |
| ----------------------------------------------- | -------------------------------------------- |
| `packages/paratix/src/modules/service.ts`       | `facts()` Methode hinzugefügt (Zeilen 62–95) |
| `packages/paratix/test/modules/service.test.ts` | 33 neue Tests ergänzt (39 total)             |

## Testergebnisse

- **Vorher:** 6 Tests für service (nur `running.check`, `enabled.check`)
- **Nachher:** 39 Tests für service (alle 7 Methoden mit check + apply + Edge Cases)
- **Gesamt:** 188 Tests grün, 0 Fehler, 0 Type-Errors

### Testabdeckung pro Methode

| Methode  | check (ok/needs-apply/null) | apply (success/failure/null) | Edge Cases                                   |
| -------- | --------------------------- | ---------------------------- | -------------------------------------------- |
| running  | ✓ ✓ ✓                       | ✓ ✓ ✓                        | —                                            |
| stopped  | ✓ ✓ ✓                       | ✓ ✓ ✓                        | —                                            |
| enabled  | ✓ ✓ ✓                       | ✓ ✓ ✓                        | —                                            |
| disabled | ✓ ✓ ✓                       | ✓ ✓ ✓                        | —                                            |
| restart  | ✓ (always needs-apply)      | ✓ ✓ ✓                        | —                                            |
| reload   | ✓ (always needs-apply)      | ✓ ✓ ✓                        | —                                            |
| facts    | ✓ (always ok)               | ✓ ✓ ✓                        | leerer Output, non-zero exit, Unicode-Bullet |

## Review-Findings und Behebung

| Finding                                      | Schweregrad | Behebung                                                     |
| -------------------------------------------- | ----------- | ------------------------------------------------------------ |
| Exit-Code von systemctl ignoriert            | Muss        | `if (result.code !== 0) return { status: "failed" }` ergänzt |
| Unicode-Bullet vor failed Units              | Muss        | Regex-Strip `[\u25CF\u25CB]` vor Parsing                     |
| `Record<string, string>` statt `Environment` | Kann        | Beibehalten — ist Subtyp, TypeScript akzeptiert kovariant    |
