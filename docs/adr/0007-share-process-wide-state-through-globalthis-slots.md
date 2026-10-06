# 0007 - Share Process-Wide State Through globalThis Slots

## Status

Accepted

## Context

Issue: sebastian-software/paratix#193
Follow-up to: [0004 - Keep the signalBus.ts globalThis Slot via Symbol.for](0004-keep-signalbus-globalthis-slot-with-symbol-for.md)

`paratix` ships its module code twice. `dist/cli.js` is a self-contained CLI bundle (splitting has
been off deliberately since R-0000729). The library entries, `dist/index.js` among them, share a
separate chunk. The CLI loads a playbook with `import()`, and the playbook's
`import … from "paratix"` resolves to the library bundle. The runner and the library code therefore
reach different copies of the same module, each with its own module-level state.

The duplicated state that matters:

- **`secretSink`:** the secret reference counts and the run-scope `AsyncLocalStorage`. A run scope
  opened by the runner (CLI copy) is not seen by `op` (library copy), so op secrets were released
  when `op` finished and later printed unmasked by runner and CLI diagnostics. Sudo passwords
  registered by the CLI copy were not masked by library-side writers.
- **`runnerAbortSignal`:** its `AsyncLocalStorage`. Ctrl-C did not reach library-side waits such as
  `pause`, `net.waitFor`, the `op` and `rsync` spawns, or user recipes.
- **Error classes `CommandError`, `InvalidUtf8OutputError`, `SudoInputUnsupportedError`:**
  `instanceof` fails across copies. Under `--verbose`, `printCommandFailure` could throw a
  `TypeError` on a masked clone that lacked `fullStdout`/`fullStderr`.

## Decision

Keep the bundle layout and give each piece of state one process-wide identity through a `Symbol.for`
slot on `globalThis`, the same pattern already used in `output.ts`, `secretPrewarm.ts`,
`firstRunContext.ts` and `signalBus.ts` (ADR 0004).

- `Symbol.for("paratix.runnerAbortSignal.storage")` holds the `AsyncLocalStorage`.
- `Symbol.for("paratix.secretSink.state")` holds one object:
  `{ version: 1, counts: Map<string, number>, scopeStorage: AsyncLocalStorage<Map<string, number>> }`.
  The whole object is shared rather than only the `Map`, so a run scope opened by one copy is
  recognized as re-entrant by the other.
- Each slot is created eagerly at module evaluation. An existing value of the wrong shape fails the
  import closed with an error that names the slot key. It is never overwritten, and there is no
  fallback to private per-copy state.
- The three error classes get a non-enumerable prototype brand,
  `Symbol.for("paratix.<module>.<ClassName>")`, and internal type guards (`isCommandError`,
  `isInvalidUtf8OutputError`, `isSudoInputUnsupportedError`) replace `instanceof`. The brand lives
  on the prototype, so it survives the `Object.create` clone path in `secretSink`.

## Versioning Rule

`MINIMUM_SECRET_LENGTH`, the redaction placeholder and the state layout are constants of each copy.
Copies that share `version: 1` must treat them identically. Changing any of them, or the layout,
must raise `version`. A copy with a different version then fails closed at import instead of
silently leaving a secret unmasked.

## Accepted Trade-off: Data Protection

Any code in the process can read, clear and pre-seed the registered secret values through the
`secretSink` slot. This is accepted under same-process trust: playbooks and modules run in the same
process as the runner and can already read every secret they use. As argued in ADR 0004, an attacker
in the same process does not need the slot.

## Alternatives Rejected

- **Merge the bundles or re-enable splitting for the CLI:** out of scope; the R-0000729 split stays.
- **Share only the counts `Map`:** two scope `AsyncLocalStorage` instances would remain, and nested
  scopes across copies would still not be recognized.
- **`Symbol.hasInstance` overrides on the error classes:** unnecessary, because the classes are not
  public API; internal guards cover every call site.

## Source

- **Issue:** https://github.com/sebastian-software/paratix/issues/193
- **Files:** packages/paratix/src/secretSink.ts, packages/paratix/src/runnerAbortSignal.ts,
  packages/paratix/src/sshHelpers.ts, packages/paratix/src/ssh.ts, packages/paratix/tsup.config.ts
