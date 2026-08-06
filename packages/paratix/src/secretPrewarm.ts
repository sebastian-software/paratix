/**
 * Run-scoped secret cache and module-tree walk for the prewarm phase.
 *
 * A run resolves every secret it needs *before* it connects over SSH, so an
 * interactive secret provider prompts once — right after the command was
 * started — instead of somewhere in the middle of the run, possibly long after
 * the operator left the terminal. Modules that read secrets expose the internal
 * {@link Module._prewarmSecrets} hook; the runner walks the tree once, awaits
 * every hook it finds, and keeps the cache open for the remainder of the run so
 * the modules themselves reuse the already-resolved values instead of invoking
 * the provider a second time.
 *
 * This file stays provider-neutral: it knows nothing about 1Password or `op://`
 * references and only owns the walk, the async-context scope, and a generic
 * memoization keyed by an opaque reference string. A future secret provider
 * (Vault, SOPS, …) can reuse it without a runner change.
 */

import { AsyncLocalStorage } from "node:async_hooks"

import type { Module } from "./types.js"

import { isRecipe } from "./recipeGuard.js"

/**
 * Cache of resolved secrets, keyed by the opaque provider reference. The stored
 * value is the **post-processed** secret — the exact string a module hands on
 * and that the secret sink masks — never the raw provider output.
 */
type SecretCache = Map<string, Promise<string>>

/**
 * The cache is async-context-scoped, the same construction as
 * `runScopedSecretCounts` (`secretSink.ts`) and `runnerAbortSignalStorage`
 * (`runnerAbortSignal.ts`) and for the same reason (R-0000743): two
 * `runPlaybook` invocations sharing one Node process must never observe each
 * other's cache. The cache ends with the run; there is deliberately no
 * persistence across runs.
 *
 * The storage itself, on the other hand, MUST be a single process-wide
 * singleton. paratix ships this module in two separate bundles — the CLI
 * (`cli.js`, which owns the runner and opens the scope) and the library
 * (`index.js`, imported by the user's server definition and therefore by every
 * module that reads a secret). Without sharing, each bundle would build its own
 * {@link AsyncLocalStorage}: the runner would open the scope in one instance and
 * the module would look for it in the other, find nothing, and call the provider
 * a second time at its own position in the run — exactly the extra prompt this
 * phase exists to prevent. A `Symbol.for`-keyed slot on `globalThis` collapses
 * every copy of this module onto one storage, mirroring the live output state
 * in `output.ts`.
 */
const SECRET_CACHE_STORAGE_KEY = Symbol.for("paratix.secretPrewarm.cacheStorage")

function getSharedSecretCacheStorage(): AsyncLocalStorage<SecretCache> {
  const registry = globalThis as Record<symbol, AsyncLocalStorage<SecretCache> | undefined>
  const existing = registry[SECRET_CACHE_STORAGE_KEY]
  if (existing != null) return existing
  const created = new AsyncLocalStorage<SecretCache>()
  registry[SECRET_CACHE_STORAGE_KEY] = created
  return created
}

const secretCacheStorage = getSharedSecretCacheStorage()

/** Options for {@link prewarmSecrets}. */
export type PrewarmSecretsOptions = {
  /**
   * Invoked exactly once, immediately before the first hook runs, and only when
   * the walked tree actually carries a hook. The runner uses it to print the
   * status line that explains why the terminal is waiting on a provider prompt;
   * a tree without a single secret module stays silent.
   */
  onBeforeFirstPrewarm?: () => void
}

/**
 * Open the run-scoped secret cache for `body`.
 *
 * The scope has to span the whole run, not just the prewarm phase: the modules
 * run later at their own position in `run` and resolve the same references
 * again, and only an open cache turns those calls into cache hits instead of
 * fresh provider invocations.
 *
 * Nested calls reuse the enclosing cache instead of opening a second one, so an
 * inner scope can never split the "exactly one provider call per reference and
 * run" guarantee. Mirrors the re-entrant shape of `withRunScopedSecrets`.
 *
 * Invariant: a caller opens this scope **inside** a `withRunScopedSecrets`
 * bracket that lives at least as long. A cached value is resolved once but read
 * many times, and only a sink scope that outlives the cache keeps the value
 * redacted for every later reader. Providers are expected to re-register on
 * every read so a violation degrades instead of silently unmasking, but the
 * ordering is what the design relies on.
 *
 * @param body - The async unit of work that runs with the cache open.
 * @returns Whatever `body` resolves to.
 */
export async function withSecretPrewarmScope<T>(body: () => Promise<T>): Promise<T> {
  if (secretCacheStorage.getStore() != null) return body()
  return secretCacheStorage.run(new Map(), body)
}

/**
 * Collect every node of the tree that carries a {@link Module._prewarmSecrets}
 * hook, in run order.
 *
 * The walk descends into both child lists a recipe can hold — `_modules` **and**
 * `_signals`. It is deliberately wider than `collectModuleNames`
 * (`moduleFilter.ts`), which only looks at `_modules`: a secret module inside a
 * recipe's signal handlers would otherwise stay unreachable and prompt in the
 * middle of the run — exactly the case the top-level `definition.signals` walk
 * already covers, only one level deeper.
 *
 * A node that carries the hook is collected as-is and never descended into: a
 * composite that keeps its children private (`when(...)`) owns the delegation
 * to them through its own hook. The walk therefore has exactly two descent
 * paths — `isRecipe` and the hook itself.
 *
 * @param modules - The module list to walk.
 * @returns The hook-carrying nodes in the order the walk reached them.
 */
function collectPrewarmCarriers(modules: Module[]): Module[] {
  const carriers: Module[] = []
  const visit = (module: Module): void => {
    if (module._prewarmSecrets != null) {
      carriers.push(module)
      return
    }
    if (!isRecipe(module)) return
    for (const child of module._modules) visit(child)
    for (const child of module._signals ?? []) visit(child)
  }
  for (const module of modules) visit(module)
  return carriers
}

/**
 * Report whether `modules` contains a node that resolves secrets ahead of the
 * run.
 *
 * A composite that keeps its children private decides at construction time
 * whether it can contribute a secret at all, and only then exposes the hook.
 * Exposing it unconditionally would make every such block look like a secret
 * carrier: a run without a single secret would print the "resolving secrets"
 * status line, and `--filter` would warn about lost secrets that never existed.
 *
 * @param modules - The module list to walk.
 * @returns `true` when at least one node in the tree carries the hook.
 */
export function hasSecretPrewarmCarriers(modules: Module[]): boolean {
  return collectPrewarmCarriers(modules).length > 0
}

/**
 * Collect the names of every node that resolves secrets ahead of the run.
 *
 * Used by the CLI to compare the unfiltered tree against the `--filter`ed one:
 * a carrier that no longer exists after filtering was replaced by a skip module
 * and resolves nothing, which silently leaves the modules that depend on its
 * values without an environment entry.
 *
 * @param modules - The module list to walk.
 * @returns The display names of all hook-carrying nodes.
 */
export function collectSecretPrewarmCarrierNames(modules: Module[]): Set<string> {
  return new Set(collectPrewarmCarriers(modules).map((module) => module.name))
}

/**
 * Resolve every secret the tree needs, before the run connects.
 *
 * Hooks are awaited strictly one after another. Parallel provider calls would
 * stack several interactive unlock prompts on top of each other and defeat the
 * purpose of the phase, so the sequential shape is a requirement, not an
 * oversight.
 *
 * A failing hook propagates: the run must abort before the SSH connect when a
 * secret cannot be resolved.
 *
 * @param modules - The module list to walk (top-level run plus signals).
 * @param options - Optional notification hook, see {@link PrewarmSecretsOptions}.
 */
export async function prewarmSecrets(
  modules: Module[],
  options: PrewarmSecretsOptions = {}
): Promise<void> {
  const carriers = collectPrewarmCarriers(modules)
  if (carriers.length === 0) return
  options.onBeforeFirstPrewarm?.()
  for (const carrier of carriers) {
    // eslint-disable-next-line no-await-in-loop -- sequential by design: see the doc comment above
    await carrier._prewarmSecrets?.()
  }
}

/**
 * Resolve `reference` through the run-scoped cache, loading it at most once per
 * run.
 *
 * Without an active scope — a direct library call, a unit test, any use outside
 * `runPlaybook` — the loader is passed through unchanged, so a caller behaves
 * exactly as it did before the cache existed. The cache is an accelerator, not
 * a precondition.
 *
 * A rejected load is evicted so a later attempt starts a fresh one instead of
 * being stuck on the first failure permanently; same policy as the memoized
 * environment resolver in `meta.ts` (R-0000206).
 *
 * @param reference - Opaque provider reference used as the cache key.
 * @param load - Loader that performs the actual provider call and returns the
 *   post-processed value. It must also perform whatever secret registration the
 *   value needs, because it runs exactly once per reference and run — at the
 *   moment the value is first observed.
 * @returns The resolved value, from cache on every call after the first.
 */
export async function resolveCachedSecret(
  reference: string,
  load: () => Promise<string>
): Promise<string> {
  const cache = secretCacheStorage.getStore()
  if (cache == null) return load()

  const cached = cache.get(reference)
  if (cached != null) return cached

  const pending: Promise<string> = load().catch((error: unknown) => {
    // Only evict our own entry: a retry may already have installed a newer
    // load for the same reference by the time this rejection is observed.
    if (cache.get(reference) === pending) cache.delete(reference)
    throw error
  })
  cache.set(reference, pending)
  return pending
}
