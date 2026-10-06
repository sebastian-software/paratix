import { AsyncLocalStorage } from "node:async_hooks"

/**
 * R-0000695: the first-run flag propagates through an
 * {@link AsyncLocalStorage} context instead of mutating `process.env`.
 *
 * The flag tells a playbook whether the CLI was invoked with `--first-run`.
 * `paratix apply --first-run` opens two scopes: one while the CLI imports and
 * evaluates the playbook, and one that the runner opens for the entire run
 * lifecycle (validation, connect, every module `check` and `apply` including
 * recipe children and `when` predicates, and teardown). The CLI glue between
 * import and run calls no user code and may observe `false`.
 *
 * Mutating `process.env.PARATIX_FIRST_RUN` was abandoned because every other
 * code path in the same Node process (test workers, embedded runners) observed
 * the synthetic value, and a missed restore left the flag stuck on the process.
 * An async-local value is scoped to the async chain that owns the wrapped body
 * and is released automatically when that chain settles. The
 * `PARATIX_FIRST_RUN` entry in the threaded `Environment` is a separate,
 * unchanged channel.
 *
 * R-0000729: the helper lives in its own module so the package entry
 * `dist/index.js` can re-export `isFirstRun` without dragging `cli.ts` (with
 * its `import.meta.url` direct-run guard) into the library bundle.
 *
 * The storage itself is a process-wide singleton. The CLI bundle (`cli.js`,
 * which opens the scopes) and the library bundle (`index.js`, from which
 * playbooks import {@link isFirstRun}) each contain a copy of this module;
 * without sharing, the playbook would read a different store than the one the
 * CLI and runner write and observe `false` even under `--first-run`. A
 * `Symbol.for`-keyed slot on `globalThis` collapses every copy onto one
 * storage, mirroring `secretPrewarm.ts`. The key name and the plain `boolean`
 * store value are a cross-bundle and cross-version contract and must not
 * change.
 */
const FIRST_RUN_STORAGE_KEY = Symbol.for("paratix.firstRunContext.storage")

function getSharedFirstRunStorage(): AsyncLocalStorage<boolean> {
  const registry = globalThis as Record<symbol, AsyncLocalStorage<boolean> | undefined>
  const existing = registry[FIRST_RUN_STORAGE_KEY]
  if (existing != null) return existing
  const created = new AsyncLocalStorage<boolean>()
  registry[FIRST_RUN_STORAGE_KEY] = created
  return created
}

const firstRunContext = getSharedFirstRunStorage()

/**
 * Public API helper that returns the current first-run flag.
 *
 * Returns `true` during a `paratix apply --first-run` invocation: while the
 * CLI imports and evaluates the playbook (including construction of the
 * exported server definition) and for the entire run lifecycle — validation,
 * connect, every module `check` and `apply` (including recipe children and
 * `when` predicates) and teardown.
 *
 * Returns `false` everywhere else: in ordinary runs, after a run settles, and
 * in any run started without the first-run option, even when nested inside a
 * first-run scope. The flag is stored in an async-local context and never
 * mutates `process.env.PARATIX_FIRST_RUN`.
 *
 * @returns `true` while a `--first-run` playbook is being loaded or run.
 */
export function isFirstRun(): boolean {
  return firstRunContext.getStore() === true
}

/**
 * Runs `body` in a scope where {@link isFirstRun} observes `true`. The CLI
 * uses it for the playbook import of a `--first-run` invocation; the runner
 * opens its own scope via {@link runWithFirstRunValue}. The outer value is
 * restored automatically when `body` settles, whether it resolves or rejects.
 *
 * @param body - Async work to run while the flag is installed. Its
 *   resolved value is forwarded; rejections propagate normally.
 * @returns The value resolved by `body`.
 */
export async function runWithFirstRunFlag<T>(body: () => Promise<T>): Promise<T> {
  return firstRunContext.run(true, body)
}

/**
 * R-0000796: opens a dedicated scope where {@link isFirstRun} observes `false`
 * for the duration of `body`. The CLI uses it for a playbook import without
 * `--first-run` so that a nested import inside an outer `true` scope does not
 * inherit the outer flag. Counterpart of {@link runWithFirstRunFlag}.
 *
 * @param body - Async work to run while the flag is forced to `false`.
 * @returns The value resolved by `body`.
 */
export async function runWithoutFirstRunFlag<T>(body: () => Promise<T>): Promise<T> {
  return firstRunContext.run(false, body)
}

/**
 * Runs `body` in a dedicated scope where {@link isFirstRun} observes exactly
 * `value`, regardless of any outer scope. The previous value is restored
 * automatically when `body` settles, whether it resolves or rejects. Used by
 * the runner so it can install the per-run flag without branching between
 * {@link runWithFirstRunFlag} and {@link runWithoutFirstRunFlag}.
 *
 * @param value - The first-run flag to expose for the duration of `body`.
 * @param body - Async work to run inside the scope. Its resolved value is
 *   forwarded; rejections propagate normally.
 * @returns The value resolved by `body`.
 */
export async function runWithFirstRunValue<T>(value: boolean, body: () => Promise<T>): Promise<T> {
  return firstRunContext.run(value, body)
}
