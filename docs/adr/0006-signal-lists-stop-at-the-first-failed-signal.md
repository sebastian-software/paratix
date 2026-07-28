# ADR-0006: Signal lists stop at the first failed signal

**Status:** Accepted
**Date:** 2026-07-28
**Context:** Issue #149 - a failed image update left a container stack split across two networks

## Context

`runSignalModules` (`packages/paratix/src/signalOrchestration.ts`) used to run every signal in a
list even after one of them failed. It only latched a `failed` flag and let the enclosing recipe or
run convert that flag into a break _after_ the whole list had run.

That made signal lists the one place in Paratix where a failure did not stop the work in progress.
Regular recipe children abort immediately (`packages/paratix/src/recipe.ts:391`), and the design
documentation states the same contract for the run as a whole: "Bei `status: "failed"` bricht der
gesamte Run sofort ab. … Es gibt kein `continueOnError`" (`docs/initialbeschreibung.md`), and
"Modules run in order; execution stops on first `failed` status" (`packages/paratix/llm-guide.md`).
Neither document mentioned that signals behaved differently, so the divergence read as an
oversight rather than a decision.

Issue #149 showed the concrete cost. A three-container Quadlet stack was rolled out with one
`quadlet.updateImage` signal per container. The first container could not be replaced because
Podman refused while dependent containers still existed. The remaining two signals kept running and
recreated their containers on the new network, which left the stack split across the old and the
new network. The application was broken (`UnknownHostException` for the database host) while the
HTTP frontend still answered `200`, so the run looked partially healthy. A second `apply` reproduced
the identical state, because the blocking condition was host state rather than configuration.
Recovery had to be done by hand.

## Decision

A failed signal aborts the remaining signals of its own list. The abort is scoped to that list:
whether the enclosing recipe or run also stops is still decided by their existing post-list
handling (`packages/paratix/src/recipe.ts:487`), so a separate signal list is not suppressed.

There is no opt-out. No `continueOnError`-style flag is introduced for signals.

This is a breaking behavior change for playbooks that relied on later signals still running after a
failure.

## Rationale

- **Restores the documented contract.** Both the design description and the agent-facing API guide
  already promised that execution stops on the first failure. The previous signal behavior
  contradicted them silently.
- **Consistency with recipe children.** A signal is an ordinary module in a different position. Two
  different failure semantics for the same module type is a trap for playbook authors, who have no
  reason to expect the position to change the semantics.
- **The failure mode is worse than the lost work.** Continuing after a failure does not merely skip
  a step; it actively builds new state on top of a known-broken prerequisite. The resulting mixed
  state is not self-healing, which makes it more expensive than the aborted signals would have been.
- **Fail-fast keeps the old state intact.** Stopping at the first failure leaves the previous,
  working state in place, which is the outcome an operator can reason about and roll forward from.
- **An opt-out would re-import the rejected concept.** `continueOnError` was deliberately excluded
  from the design. Adding it for signals only, to preserve behavior that was never specified, would
  trade a clear contract for a configurable one whose safe default is the same abort anyway.

## Consequences

- Playbooks whose signal lists contain genuinely independent restarts now stop at the first
  failure instead of attempting the rest. Independent work that must all be attempted belongs in
  separate signal lists or separate runs.
- Two tests that asserted the previous continue-on-failure behavior were inverted:
  `packages/paratix/test/runner-signals.test.ts` and `packages/paratix/test/recipe.test.ts`.
- The change ships as a Conventional Commit breaking change so release-please classifies the
  release accordingly.

## Source

- **Issue:** https://github.com/sebastian-software/paratix/issues/149
- **Files:** packages/paratix/src/signalOrchestration.ts,
  packages/paratix/src/recipe.ts:391, packages/paratix/src/recipe.ts:487
