# 0021 — CLI Import Runtime Validation

## Anforderung

Laufzeit-Validierung fuer den dynamischen Import in `paratix apply <file>`. Pruefen ob der exportierte Wert ein Objekt mit `host` (string) und `run` (array) Properties ist, bei Fehler eine hilfreiche Fehlermeldung ausgeben.

## Problem

In `packages/paratix/src/cli.ts` wurde der dynamische Import blind per `as ServerDefinition` gecastet. Wenn die importierte Datei keinen gueltigen Export lieferte (z.B. `export default 42`), crashte der CLI mit einem kryptischen `TypeError: Cannot read properties of undefined`.

## Loesung

Drei Funktionen in `cli.ts` hinzugefuegt:

1. **`collectDefinitionErrors(value: unknown): string[]`** — Sammelt alle Validierungsfehler mit differenzierten Meldungen ("Missing property" vs. "Invalid property")
2. **`isServerDefinitionLike(value: unknown): value is ServerDefinition`** — Type Guard, delegiert an `collectDefinitionErrors` (Single Source of Truth)
3. **`validateServerDefinition(value: unknown, file: string): asserts value is ServerDefinition`** — Assertion-Funktion die bei Fehler hilfreiche Meldung ausgibt und mit `process.exit(2)` beendet

## Betroffene Dateien

- `packages/paratix/src/cli.ts` — Validierungsfunktionen + Aufruf in der `apply`-Action
- `packages/paratix/test/cli.test.ts` — 18 neue Tests (9 isServerDefinitionLike + 9 collectDefinitionErrors)

## Architekturentscheidungen

- **asserts-Signatur** statt einfachem boolean-Return: TypeScript erkennt nach dem Call den korrekten Typ
- **DRY**: `isServerDefinitionLike` delegiert an `collectDefinitionErrors`, eine Quelle der Wahrheit
- **Differenzierte Fehlermeldungen**: "Missing property 'host'" wenn Property fehlt, "Invalid property 'host' (expected string, got number)" wenn falscher Typ
- **Export** von `isServerDefinitionLike` und `collectDefinitionErrors` fuer direkte Unit-Tests

## Testergebnisse

- 793 Tests bestanden (davon 24 in cli.test.ts)
- Lint: 0 Fehler, 0 Warnungen
- TypeScript: keine Fehler
- Prettier: alle Dateien konform

## Review-Findings

| ID    | Schweregrad | Titel                                                            | Status          |
| ----- | ----------- | ---------------------------------------------------------------- | --------------- |
| R-001 | Wichtig     | Redundante Validierung in Zeile 108                              | Nicht umgesetzt |
| R-002 | Wichtig     | DRY: isServerDefinitionLike auf collectDefinitionErrors aufbauen | Behoben         |
| R-003 | Hinweis     | Missing vs. Invalid Fehlermeldungen differenzieren               | Behoben         |
| R-004 | Hinweis     | Absoluten Pfad in Fehlermeldung verwenden                        | Behoben         |
| R-005 | Hinweis     | `any`-Typ fuer exitSpy im Test                                   | Nicht umgesetzt |

### Nicht umgesetzte Findings

- **R-001**: Die bestehende Pruefung `host.length === 0 || run.length === 0` existierte vor diesem Feature und validiert inhaltlich (nicht nur strukturell). Eine Aenderung wuerde den Scope dieses Features ueberschreiten.
- **R-005**: `ReturnType<typeof vi.spyOn>` verursacht einen Typfehler wegen komplexer Overload-Signaturen von `process.exit`. `any` ist der pragmatische Workaround.
