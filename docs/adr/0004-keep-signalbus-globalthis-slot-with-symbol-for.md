# 0004 — signalBus.ts: globalThis-Slot via Symbol.for bleibt

## Status

Nicht umgesetzt

## Kontext

Review-Report: review-report-2026-05-09.md, Finding R-0000260
Workflow: /apply-review

## Entscheidung

Der `Symbol.for("paratix.signalBus.activeBus")`-Slot auf `globalThis` bleibt erhalten.

## Begründung

Der Slot ist Voraussetzung dafür, dass die `vi.resetModules()`-basierten Test-Patterns in `packages/paratix/test/runner-lifecycle.test.ts` und weiteren Runner-Tests funktionieren:

1. `beforeEach` (`installRunnerTestHooks` in `helpers/runnerMocks.ts`) registriert per `setSignalBus(testBus)` einen `TestSignalBus` im globalen Slot.
2. Der Test ruft anschließend `vi.resetModules()` auf und importiert `runner.ts` dynamisch neu.
3. Der frisch geladene `runner.ts` zieht eine neue `signalBus.ts`-Instanz mit eigenem `let activeBus`-Slot.
4. Nur weil beide Modul-Instanzen über `Symbol.for(...)` denselben `globalThis`-Slot teilen, sehen sie dieselbe Test-Bus-Referenz.

Ein lokaler `Symbol("...")` würde diese Sichtbarkeit aufheben — der Runner sähe nach `resetModules()` wieder den `defaultProcessSignalBus` und würde echte SIGINT/SIGTERM-Handler an `process` registrieren. Das brächte Test-Determinismus aus dem Gleichgewicht.

Die in R-0000260 beschriebene Kollisions-Gefahr ist real, aber stark begrenzt:

- Die `paratix.signalBus.activeBus`-Konvention ist projektspezifisch und nicht in einer öffentlich indizierten Library standardisiert.
- Ein Vendor-Library-Conflict müsste dieselben drei Methoden (`on`/`off`/`listenerCount`) mit kompatiblen Signaturen liefern, sonst greift `isSignalBus` und das System fällt auf den Default-Bus zurück.
- Ein bewusster Eindringling im selben Prozess hat ohnehin Zugriff auf `process.on`/`process.removeListener` und braucht keinen Umweg über den Bus.

Eine echte Dependency-Injection von `SignalBus` in den Runner-Konstruktor wäre eine API-Änderung, die mehrere Public-API-Touchpoints verändert und ist außerhalb des Scopes dieses Fixes.

## Quell-Finding

R-0000260 aus review-report-2026-05-09.md: `Symbol.for("paratix.signalBus.activeBus")` ist im globalen Symbol-Registry abgelegt — jeder Code mit demselben String-Argument kann den Slot lesen/überschreiben. Empfehlung war: lokales Symbol verwenden.
