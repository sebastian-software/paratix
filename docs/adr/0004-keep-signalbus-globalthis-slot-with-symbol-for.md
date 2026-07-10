# 0004 - Keep the signalBus.ts globalThis Slot via Symbol.for

## Status

Not implemented

## Context

Review report: review-report-2026-05-09.md, finding R-0000260
Workflow: /apply-review

## Decision

Keep the `Symbol.for("paratix.signalBus.activeBus")` slot on `globalThis`.

## Rationale

The slot is required for the `vi.resetModules()`-based test patterns in
`packages/paratix/test/runner-lifecycle.test.ts` and other runner tests to work:

1. `beforeEach` (`installRunnerTestHooks` in `helpers/runnerMocks.ts`) registers a `TestSignalBus`
   in the global slot via `setSignalBus(testBus)`.
2. The test then calls `vi.resetModules()` and dynamically imports `runner.ts` again.
3. The newly loaded `runner.ts` obtains a new `signalBus.ts` instance with its own local
   `let activeBus` slot.
4. Only because both module instances share the same `globalThis` slot through `Symbol.for(...)`
   do they see the same test-bus reference.

A local `Symbol("...")` would remove this visibility. After `resetModules()`, the runner would see
the `defaultProcessSignalBus` again and register real SIGINT/SIGTERM handlers on `process`, which
would disrupt test determinism.

The collision risk described in R-0000260 is real but tightly constrained:

- The `paratix.signalBus.activeBus` convention is project-specific and is not standardized by a
  publicly indexed library.
- A conflicting vendor library would have to provide the same three methods
  (`on`/`off`/`listenerCount`) with compatible signatures; otherwise, `isSignalBus` rejects it and
  the system falls back to the default bus.
- A deliberate attacker in the same process already has access to
  `process.on`/`process.removeListener` and does not need to go through the bus.

True dependency injection of `SignalBus` into the runner constructor would be an API change that
affects several public API touchpoints and is outside the scope of this fix.

## Source Finding

R-0000260 from review-report-2026-05-09.md: `Symbol.for("paratix.signalBus.activeBus")` is stored in
the global symbol registry; any code using the same string argument can read or overwrite the slot.
The recommendation was to use a local symbol.
