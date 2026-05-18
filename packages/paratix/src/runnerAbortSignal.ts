import { AsyncLocalStorage } from "node:async_hooks"

/**
 * Async-context-scoped holder for the runner's prompt/poll abort signal.
 *
 * The {@link import("./runner.js").runPlaybook} entry installs the signal at
 * the start of a run via {@link withRunnerAbortSignal} so the entire playbook
 * lifecycle runs inside an {@link AsyncLocalStorage} scope that owns the
 * signal. Modules that perform interactive waits (e.g. the `pause` builtin)
 * or polling loops (e.g. `net.waitFor`) read the signal via
 * {@link getRunnerAbortSignal} so a SIGINT/SIGTERM observed mid-run can
 * unblock the wait promptly instead of running to its configured timeout.
 *
 * R-0000743: the holder is now async-context-scoped instead of module-global
 * so two concurrent `runPlaybook` invocations sharing the same Node process
 * never observe each other's signals. The previous module-global slot let a
 * parallel run overwrite the in-flight signal of an earlier run; with
 * {@link AsyncLocalStorage} every async chain rooted in `withRunnerAbortSignal`
 * sees its own value and other chains stay isolated.
 *
 * R-0000027 introduced the `pause` use case; R-0000052 generalized the helper
 * for `net.waitFor` so its polling loop aborts on shutdown.
 */
const runnerAbortSignalStorage = new AsyncLocalStorage<AbortSignal | undefined>()

/**
 * Runs `body` while {@link getRunnerAbortSignal} resolves to `signal` for the
 * duration of the entire async sub-tree rooted in this call.
 *
 * Intended for the runner's lifecycle only — playbooks must never call this
 * directly.
 *
 * @param signal - The abort signal whose `abort` event cancels active waits
 *   and polling loops in modules that observe it. Pass `undefined` to scope
 *   a body that has no abort signal (e.g. tests that need to clear an outer
 *   scope without disturbing it).
 * @param body - Async work that observes the scoped signal.
 * @returns The value resolved by `body`.
 */
export function withRunnerAbortSignal<T>(
  signal: AbortSignal | undefined,
  body: () => Promise<T>
): Promise<T> {
  return runnerAbortSignalStorage.run(signal, body)
}

/**
 * Imperatively register or clear the abort signal observable through
 * {@link getRunnerAbortSignal} for the current async context and every
 * task that branches off it.
 *
 * R-0000743: this helper is the imperative escape hatch over the new
 * {@link AsyncLocalStorage}-backed implementation. Tests that exercise
 * abort-aware modules (`recipe.check`, `op.apply`, `net.waitFor`, …) can
 * still call this to seed the scope without wrapping their bodies in a
 * dedicated `withRunnerAbortSignal` block. Production code in the runner
 * uses {@link withRunnerAbortSignal} instead so the entire playbook run
 * is bounded by a single async-local scope.
 *
 * Pass `undefined` to clear the registration in the current async context.
 *
 * @param signal - The abort signal to install, or `undefined` to clear.
 */
export function setRunnerAbortSignal(signal: AbortSignal | undefined): void {
  // R-0000743: `enterWith` updates the ALS store for the current async
  // chain and every descendant task without requiring a wrapper callback.
  // This preserves the imperative `setRunnerAbortSignal(...)` API used by
  // existing tests while ensuring sibling async chains (e.g. a parallel
  // `runPlaybook` running on its own `withRunnerAbortSignal` scope) keep
  // observing their own scoped value.
  runnerAbortSignalStorage.enterWith(signal)
}

/**
 * Retrieve the abort signal scoped to the current async context, if any.
 *
 * @returns The active abort signal, or `undefined` when no run is in flight
 *   in the current async chain.
 */
export function getRunnerAbortSignal(): AbortSignal | undefined {
  return runnerAbortSignalStorage.getStore()
}
