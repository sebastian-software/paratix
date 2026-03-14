# 0020 – Test: Lazy-Function-Aufruf bei doppeltem Platzhalter

## Anforderung

Ergänze einen Test für `renderTemplate`, der dokumentiert, dass eine lazy Function als Environment-Wert bei doppeltem Platzhalter **zweimal aufgerufen** wird (kein Caching/Memoization).

## Architekturentscheidung

`renderTemplate` (template.ts:24–26) ruft `resolveEnvironment` per `Promise.all` für jeden Match einzeln auf. `resolveEnvironment` (environment.ts:23–24) ruft Function-Werte direkt auf — ohne Cache. Jedes Vorkommen eines Platzhalters ist ein eigener Match, daher ein eigener Funktionsaufruf.

Dieses Verhalten ist gewollt: Lazy Functions können bei jedem Aufruf unterschiedliche Werte liefern (z. B. Timestamps, rotierende Secrets). Caching würde diese Semantik brechen.

## Betroffene Dateien

- `packages/paratix/test/template.test.ts` — neuer Test hinzugefügt

## Implementierung

```typescript
it("calls a lazy function value once per placeholder occurrence", async () => {
  const lazy = vi.fn(() => "val")
  const env: Environment = { A: lazy }
  const view = await renderTemplate("{{A}} and {{A}}", env)
  expect(view).toBe("val and val")
  expect(lazy).toHaveBeenCalledTimes(2)
})
```

## Testergebnis

- Vorher: 779 Tests bestanden
- Nachher: 780 Tests bestanden (+1 neuer Test)
- 0 TypeScript-Fehler, 0 Lint-Fehler, Build OK
