# 0065: Explizite Signal-Flush-Checkpoints

## Anforderung

Paratix soll neben dem bisherigen impliziten End-of-Scope-Signalverhalten ein explizites Checkpoint-Modell erhalten. Playbooks sollen gesammelte Signale bewusst an einer Stelle im Flow vorzeitig ausführen können, ohne das bestehende Default-Verhalten zu verlieren.

## Architekturentscheidungen

- Das Feature wird als Builtin `signals.flush(...)` im Core-API-Pfad umgesetzt.
- Das mentale Modell bleibt: Signale sind deferred side effects nach Changes.
- Scope-Ende bleibt der implizite Flush.
- `signals.flush(...)` ist ein expliziter vorgezogener Flush nur für den aktuellen Scope:
  - in einer Recipe die Recipe-Signale
  - auf Top-Level `server(...).signals`
- Es wird keine globale Signal-Queue eingeführt.
- Für die interne Orchestrierung wird `ModuleResult` und `OrchestrationStep` um den Marker `_flushSignals?: true` erweitert.
- Runner und Recipes verwalten dafür je ein lokales `signalsPending`-Flag.
- Ein erfolgreicher Flush setzt den Pending-Zustand zurück, damit Signale am Scope-Ende nicht doppelt ausgeführt werden.
- Spätere neue Änderungen im selben Scope können erneut `signalsPending` setzen und damit einen weiteren Flush auslösen.
- Dry-Run führt weiterhin keine echten Signale aus; `signals.flush(...)` bleibt dort ein Kontrollmodul ohne Signal-Ausführung.

## Betroffene Dateien

| Datei                                         | Beschreibung                                                                 |
| --------------------------------------------- | ---------------------------------------------------------------------------- |
| `packages/paratix/src/builtins.ts`            | Neues Builtin `signals.flush(...)`                                           |
| `packages/paratix/src/index.ts`               | Exportiert `signals` im Public API Entry Point                               |
| `packages/paratix/src/types.ts`               | Interner `_flushSignals`-Marker in `ModuleResult` und `OrchestrationStep`    |
| `packages/paratix/src/runner.ts`              | Top-Level-Pending-State und expliziter Flush von `server(...).signals`       |
| `packages/paratix/src/recipe.ts`              | Recipe-lokaler Pending-State und expliziter Flush von Recipe-Signalen        |
| `packages/paratix/src/signalOrchestration.ts` | Weiterverwendete Signal-Ausführung ohne zusätzliche Queue-Logik              |
| `packages/paratix/test/builtins.test.ts`      | Tests für `signals.flush(...)`                                               |
| `packages/paratix/test/recipe.test.ts`        | Regressionen für Recipe-Flush, Duplicate-Prevention und Mehrfach-Flush       |
| `packages/paratix/test/runner.test.ts`        | Regressionen für Top-Level-Flush, Duplicate-Prevention und Dry-Run-Verhalten |
| `packages/paratix/llm-guide.md`               | API- und Modell-Dokumentation für explizite Signal-Checkpoints               |

## Implementierungsdetails

- `signals.flush(...)` ist `local: true` und `_dryRunBlocker: true`.
- Das Modul liefert bei `apply()`:
  - `status: "ok"`
  - `_flushSignals: true`
  - `_dryRunDetail: "(dry-run, pending signals not executed)"`
- Top-Level-Runner:
  - setzt `signalsPending = true`, sobald ein Modul `"changed"` liefert
  - führt bei `_flushSignals` und vorhandenem Pending-State sofort `definition.signals` aus
  - setzt `signalsPending` danach zurück
  - führt am Run-Ende nur dann noch Signale aus, wenn nach dem letzten Flush erneut Änderungen passiert sind
- Recipes:
  - verwalten ein eigenes `signalsPending`
  - führen bei `signals.flush(...)` ihre Recipe-Signale sofort aus
  - setzen den Pending-State danach zurück
  - flushen verbleibende Signale weiterhin implizit am Recipe-Ende
- Signal-Fehler verhalten sich weiterhin wie normale Signal-Fehler:
  - der aktuelle Scope schlägt fehl
  - spätere Module werden nicht weiter ausgeführt

## Testergebnisse

- `pnpm --filter paratix exec vitest run test/builtins.test.ts test/recipe.test.ts test/runner.test.ts`
- `pnpm --filter paratix exec tsc --noEmit`
- `pnpm agent:check`

## Review-Findings und Behebung

- Keine offenen internen Review-Findings nach der Umsetzung.
