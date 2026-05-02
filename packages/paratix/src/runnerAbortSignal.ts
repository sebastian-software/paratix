/**
 * Process-scoped holder for the runner's prompt/poll abort signal.
 *
 * The {@link import("./runner.js").runPlaybook} entry installs the signal at
 * the start of a run via {@link setRunnerAbortSignal} and clears it during
 * teardown. Modules that perform interactive waits (e.g. the `pause` builtin)
 * or polling loops (e.g. `net.waitFor`) read the signal via
 * {@link getRunnerAbortSignal} so a SIGINT/SIGTERM observed mid-run can
 * unblock the wait promptly instead of running to its configured timeout.
 *
 * The holder is intentionally process-scoped — analogous to
 * {@link "./secretSink".registerSecret} — so that helpers deep in the module
 * tree can observe the abort signal without threading it through every
 * `Module.apply` signature. Lifting it into a dedicated module (rather than
 * leaving it inside `builtins.ts`) keeps `pause` and `waitFor` on the same
 * plumbing without forcing module files to import from `builtins.ts`.
 *
 * R-0000027 introduced the `pause` use case; R-0000052 generalized the helper
 * for `net.waitFor` so its polling loop aborts on shutdown.
 */
let runnerAbortSignal: AbortSignal | undefined

/**
 * Register or clear the abort signal that the runner exposes to long-running
 * modules. Pass `undefined` to clear.
 *
 * Intended for the runner's lifecycle only — playbooks must never call this
 * directly.
 *
 * @param signal - The abort signal whose `abort` event cancels active waits
 *   and polling loops in modules that observe it.
 */
export function setRunnerAbortSignal(signal: AbortSignal | undefined): void {
  runnerAbortSignal = signal
}

/**
 * Retrieve the currently registered runner abort signal, if any.
 *
 * @returns The active abort signal, or `undefined` when no run is in flight.
 */
export function getRunnerAbortSignal(): AbortSignal | undefined {
  return runnerAbortSignal
}
