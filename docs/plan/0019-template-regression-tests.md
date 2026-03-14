# 0019 — Regressionstests für renderTemplate

## Anforderung

Ergänze Regressionstests für `renderTemplate` in `template.test.ts`:

1. Gleicher Platzhalter zweimal im Template
2. Wert mit Platzhalter-Syntax `{{B}}`
3. Dollar-Zeichen im Wert

## Architekturentscheidungen

- Alle drei Fälle testen Edge Cases der String-Interpolation in `renderTemplate`
- `renderTemplate` nutzt Single-Pass `matchAll` + manuelle String-Konkatenation (kein `String.replace`), was Dollar-Zeichen und Re-Interpolation strukturell verhindert
- Tests sichern dieses Verhalten als Regression ab, falls die Implementierung refactored wird

## Betroffene Dateien

- `packages/paratix/test/template.test.ts` — 3 neue Testfälle hinzugefügt

## Implementierungsdetails

### Test 1: Gleicher Platzhalter zweimal

```typescript
it("replaces the same placeholder used twice", async () => {
  const env: Environment = { A: "x" }
  const view = await renderTemplate("{{A}} and {{A}}", env)
  expect(view).toBe("x and x")
})
```

Verifiziert, dass `matchAll` alle Vorkommen findet und jedes separat ersetzt wird.

### Test 2: Wert mit Platzhalter-Syntax

```typescript
it("inserts a value containing placeholder syntax verbatim (single-pass)", async () => {
  const env: Environment = { A: "{{B}}", B: "SHOULD_NOT_APPEAR" }
  const view = await renderTemplate("result: {{A}}", env)
  expect(view).toBe("result: {{B}}")
})
```

Verifiziert, dass Werte, die wie Platzhalter aussehen, literal eingefügt werden (Single-Pass-Design).

### Test 3: Dollar-Zeichen im Wert

```typescript
it("preserves dollar signs in resolved values", async () => {
  const env: Environment = { PRICE: "$100" }
  const view = await renderTemplate("Cost: {{PRICE}}", env)
  expect(view).toBe("Cost: $100")
})
```

Verifiziert, dass `$`-Zeichen nicht als `String.replace`-Referenzen interpretiert werden.

## Testergebnisse

- 773 Tests in 33 Dateien bestanden (inkl. 9 Tests in `template.test.ts`)
- 0 Lint-Fehler, 0 TypeScript-Fehler, Prettier konform

## Review-Findings

| #     | Schweregrad | Finding                                                                     | Status          |
| ----- | ----------- | --------------------------------------------------------------------------- | --------------- |
| R-001 | Hinweis     | Testname könnte präziser formulieren, dass Single-Pass-Design getestet wird | Nicht umgesetzt |
| R-002 | Hinweis     | Kommentar zu Dollar-Zeichen-Risiko bei replace() könnte helfen              | Nicht umgesetzt |
| R-003 | Hinweis     | Lazy-Function bei doppeltem Platzhalter nicht getestet                      | Nicht umgesetzt |

Alle Findings sind Hinweise — keine kritischen oder wichtigen Issues gefunden.
