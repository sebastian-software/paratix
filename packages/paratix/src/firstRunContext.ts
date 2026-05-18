import { AsyncLocalStorage } from "node:async_hooks"

/**
 * R-0000695: the first-run flag propagates through an
 * {@link AsyncLocalStorage} context instead of mutating `process.env`.
 *
 * The flag tells a freshly bootstrapped playbook whether the CLI was
 * invoked with `--first-run`. Two real-world hazards motivated lifting it
 * out of `process.env`:
 *
 * - Every other code path running in the same Node process — vitest
 *   worker-pool fixtures, embedded runners, unrelated tooling — observed
 *   the synthetic value too. Tests had to manually clean up
 *   `process.env.PARATIX_FIRST_RUN` to avoid cross-test contamination.
 * - The mutation/restore dance trusted every caller to wire up
 *   try/finally semantics correctly. A missed restore in any code path
 *   left the flag stuck on the process for the rest of its lifetime.
 *
 * The AsyncLocalStorage-based variant solves both problems: the value is
 * scoped to the async chain that owns the wrapped body and is automatically
 * released when that chain finishes, regardless of how it resolves.
 * Playbooks now read the flag via the {@link isFirstRun} helper (exported
 * as public API) which queries the same async-local store.
 *
 * R-0000729: the helper lives in its own module so the package entry
 * `dist/index.js` can re-export `isFirstRun` without dragging `cli.ts` into
 * the library bundle. `cli.ts` uses `import.meta.url` for its direct-run
 * detection, which interferes with esbuild chunk splitting when the
 * library entries pull the CLI module transitively.
 */
const firstRunContext = new AsyncLocalStorage<boolean>()

/**
 * Public API helper that returns the current first-run flag.
 *
 * Returns `true` only when called from inside a
 * `withCliProcessEnvironment` body whose `firstRun` option was `true`.
 * Outside of a CLI invocation, or when the flag was not set, the helper
 * returns `false`. The helper is async-context aware: a playbook that
 * schedules its own microtasks/timers within the CLI body keeps observing
 * the same flag, while concurrent work outside that body sees `false`.
 *
 * @returns `true` when the current async context is a first-run CLI body.
 */
export function isFirstRun(): boolean {
  return firstRunContext.getStore() === true
}

/**
 * Runs `body` while the CLI-derived first-run flag is observable through
 * {@link isFirstRun}. The flag is cleared automatically when the wrapped
 * body settles, regardless of whether `body` resolves or rejects.
 *
 * @param body - Async work to run while the flag is installed. Its
 *   resolved value is forwarded; rejections propagate normally.
 * @returns The value resolved by `body`.
 */
export async function runWithFirstRunFlag<T>(body: () => Promise<T>): Promise<T> {
  return firstRunContext.run(true, body)
}

/**
 * R-0000796: open a dedicated clear-scope where {@link isFirstRun} observes
 * `false` for the duration of `body`. Required when a nested CLI invocation
 * sets `firstRun: false` while running inside an outer scope that had set
 * it to `true`: without this helper the nested body would inherit the
 * outer-context flag and silently observe `true` even though the operator
 * explicitly disabled it. Mirrors the success-path of {@link runWithFirstRunFlag}
 * but installs `false` instead of `true`.
 *
 * @param body - Async work to run while the flag is forced to `false`.
 * @returns The value resolved by `body`.
 */
export async function runWithoutFirstRunFlag<T>(body: () => Promise<T>): Promise<T> {
  return firstRunContext.run(false, body)
}
