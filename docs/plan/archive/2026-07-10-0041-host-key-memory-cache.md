# 0041 — In-Memory Host Key Cache and Improved Warning

## Anforderung

Wenn `appendHostKey` fehlschlägt (z.B. wegen Dateisystem-Berechtigungen), soll der akzeptierte Host-Key im Speicher gecacht werden als Fallback. Außerdem soll die Warnung eine Handlungsempfehlung enthalten.

## Architekturentscheidungen

- **Cache-Strategie:** Module-level `Map<string, Buffer>` (`inMemoryHostKeys`), Key-Format via `formatHostNeedle`
- **Cache-Population:** Immer bei accept-new (vor `appendHostKey`), nicht nur bei Fehler — ermöglicht Reconnects innerhalb desselben Prozesses
- **Cache-Lebensdauer:** Prozesslaufzeit, kein Eviction — in der Praxis <10 Hosts pro Paratix-Run
- **Warnung:** ssh-keyscan Hint mit Port-Handling (`-p <port>` nur bei non-standard Port)

## Betroffene Dateien

| Datei                                      | Änderung                                                                      |
| ------------------------------------------ | ----------------------------------------------------------------------------- |
| `packages/paratix/src/knownHosts.ts`       | In-Memory-Cache, `clearHostKeyCache`, `acceptAndPersistHostKey`, Cache-Lookup |
| `packages/paratix/test/knownHosts.test.ts` | 5 neue Tests für Cache-Verhalten und Warnungen                                |

## Implementierungsdetails

### `inMemoryHostKeys` (Map)

Module-level Cache für akzeptierte Host-Keys. Wird bei jedem `accept-new` Key sofort befüllt, bevor das fire-and-forget `appendHostKey` läuft.

### `clearHostKeyCache()`

Exportierte Funktion zum Zurücksetzen des Caches. Primär für Tests, damit diese isoliert bleiben.

### `acceptAndPersistHostKey(host, port, key)`

Private Hilfsfunktion, extrahiert aus `buildHostVerifier`:

1. Gibt Fingerprint-Warnung auf stderr aus
2. Schreibt Key in den In-Memory-Cache
3. Ruft `appendHostKey` fire-and-forget auf
4. Bei Fehler: verbesserte Warnung mit ssh-keyscan Handlungsempfehlung

### Cache-Lookup in `buildHostVerifier`

Fallback-Chain: `lookupHostKey(entries) ?? inMemoryHostKeys.get(needle) ?? null`

## Testergebnisse

- 1168 Tests bestanden (48 in `knownHosts.test.ts`)
- Lint: 0 Errors
- TypeScript: 0 Errors
- Format: bestanden

## Review-Findings

| ID    | Schweregrad | Bereich       | Status        |
| ----- | ----------- | ------------- | ------------- |
| R-001 | Hinweis     | Memory        | ⏳ Akzeptiert |
| R-002 | Wichtig     | Concurrency   | ✅ Umgesetzt  |
| R-003 | Hinweis     | Security      | ⏳ Akzeptiert |
| R-004 | Hinweis     | API Design    | ⏳ Akzeptiert |
| R-005 | Hinweis     | Security      | ⏳ Akzeptiert |
| R-006 | Hinweis     | Test Coverage | ⏳ Akzeptiert |

- **R-002:** Cache-Lookup in hostVerifier-Callback verschoben für bessere Parallelitätsunterstützung. `inMemoryHostKeys.get()` wird jetzt im Callback zur Verifikationszeit aufgerufen statt einmalig bei `buildHostVerifier`.
