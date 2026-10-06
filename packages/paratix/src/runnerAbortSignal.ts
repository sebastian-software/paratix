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
 *
 * #193: the storage itself MUST be a single process-wide singleton. paratix
 * ships this module in two separate bundles — the CLI (`cli.js`, whose runner
 * installs the signal) and the library (`index.js` plus its shared chunk,
 * imported by the user's playbook, whose `pause`, `net.waitFor`, `op` and
 * recipes read it). Without sharing, each bundle would build its own
 * {@link AsyncLocalStorage}: the runner would install the signal in one
 * instance, every library-side wait would read `undefined` from the other and
 * Ctrl-C would no longer unblock it. A `Symbol.for`-keyed slot on `globalThis`
 * collapses every copy of this module onto one storage, mirroring the slots
 * in `output.ts`, `secretPrewarm.ts` and `firstRunContext.ts`. The slot is
 * created eagerly at module evaluation. A slot that already holds anything
 * other than an {@link AsyncLocalStorage} belongs to an incompatible paratix
 * copy or version: the import fails closed instead of overwriting the foreign
 * value or falling back to private per-copy state.
 */
const RUNNER_ABORT_SIGNAL_STORAGE_KEY_NAME = "paratix.runnerAbortSignal.storage"
const RUNNER_ABORT_SIGNAL_STORAGE_KEY = Symbol.for(RUNNER_ABORT_SIGNAL_STORAGE_KEY_NAME)

// The store type is erased at runtime; every paratix copy writes only
// `AbortSignal | undefined` into this storage.
function isRunnerAbortSignalStorage(
  value: unknown
): value is AsyncLocalStorage<AbortSignal | undefined> {
  return value instanceof AsyncLocalStorage
}

function getSharedRunnerAbortSignalStorage(): AsyncLocalStorage<AbortSignal | undefined> {
  const registry = globalThis as Record<symbol, unknown>
  const existing = registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY]
  if (existing === undefined) {
    const created = new AsyncLocalStorage<AbortSignal | undefined>()
    registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY] = created
    return created
  }
  if (isRunnerAbortSignalStorage(existing)) return existing
  throw new Error(
    `globalThis[Symbol.for("${RUNNER_ABORT_SIGNAL_STORAGE_KEY_NAME}")] holds a value that is not an ` +
      "AsyncLocalStorage; another, incompatible paratix copy or version is loaded in this process. " +
      "Make sure the CLI and the playbook resolve the same paratix installation."
  )
}

const runnerAbortSignalStorage = getSharedRunnerAbortSignalStorage()

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
export async function withRunnerAbortSignal<T>(
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
