# 0045: stats.signals zaehlt alle versuchten Signals

## Anforderung

`stats.incrementSignals()` in `runner.ts` wurde nur im Erfolgsfall (innerhalb des `try`-Blocks) aufgerufen. Fehlgeschlagene Signals wurden nicht gezaehlt, wodurch `stats.signals` in der Zusammenfassung nur erfolgreiche Ausfuehrungen anzeigte.

## Architekturentscheidungen

- **`incrementSignals()` vor den `try`-Block verschoben** — jedes Signal wird gezaehlt sobald es versucht wird, unabhaengig vom Ergebnis. Das entspricht der Semantik "Signals triggered" (ausgeloest, nicht erfolgreich).
- **Minimaler Fix** — nur eine Zeile verschoben, keine Aenderung an der Zaehler-Semantik oder der `RunStats`-Klasse noetig.

## Betroffene Dateien

| Datei                                  | Beschreibung                                                                |
| -------------------------------------- | --------------------------------------------------------------------------- |
| `packages/paratix/src/runner.ts`       | `stats.incrementSignals()` vor den `try`-Block in `runSignals()` verschoben |
| `packages/paratix/test/runner.test.ts` | Regressionstest: fehlgeschlagenes Signal wird trotzdem gezaehlt             |

## Implementierungsdetails

### Vorher

```typescript
for (const signal of signals) {
  try {
    // ...
    stats.incrementSignals() // nur im Erfolgsfall
  } catch (error) {
    // stats.incrementSignals() fehlte hier
  }
}
```

### Nachher

```typescript
for (const signal of signals) {
  stats.incrementSignals() // zaehlt jeden Versuch
  try {
    // ...
  } catch (error) {
    // ...
  }
}
```

### Tests

- "increments stats.signals even when a signal throws" — prueft dass `stats.signals` auch bei fehlgeschlagenem Signal inkrementiert wird

### Validierung

- Lint (oxlint + eslint): 0 Fehler
- Prettier: bestanden
- TypeScript: 0 Fehler
- Tests: 1242 bestanden (41 Test-Dateien)

## Review-Findings

Keine Findings. Fix ist minimal und eindeutig.
