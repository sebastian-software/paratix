/* eslint-disable max-lines -- CLI entrypoint co-locates parsers, validators, and command wiring */
import { Command } from "commander"
import { AsyncLocalStorage } from "node:async_hooks"
import { realpathSync } from "node:fs"
import { extname, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import pc from "picocolors"

import type { Environment, ServerDefinition } from "./types.js"

import { isMissingTsxDependencyError } from "./cliTsxHelpers.js"
import { ENVIRONMENT_FORBIDDEN_KEYS } from "./environment.js"
import { inspectRedactedBinaryValue } from "./errorRedaction.js"
import { runWithFirstRunFlag, runWithoutFirstRunFlag } from "./firstRunContext.js"
import { printCliHeader } from "./output.js"
import { type RunOptions, runPlaybook } from "./runner.js"
import { maskRegisteredSecrets } from "./secretSink.js"
import { collectSshConfigErrors } from "./serverDefinitionValidation.js"

declare const PACKAGE_DISPLAY_VERSION: string

const SECONDS_TO_MS = 1000
const ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_]\w*$/v
const FIRST_RUN_ENV_NAME = "PARATIX_FIRST_RUN"
const TYPESCRIPT_ENTRY_EXTENSIONS = new Set([".cts", ".mts", ".ts"])

/**
 * Upper bound for second-based CLI timeouts (24h).
 *
 * Avoids overflow when the parsed value is later multiplied by
 * `SECONDS_TO_MS` and added to `Date.now()` for deadline checks.
 */
const RECONNECT_TIMEOUT_MAX_SECONDS = 86_400

function resolveRealPath(path: string): null | string {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is either import.meta-derived or process argv entrypoint; direct file resolution is the intended check
    return realpathSync(path)
  } catch {
    // Symlink loops, EACCES, ENOENT, or unusual pnpm shim layouts can throw
    // before any try/catch in apply() can intercept the failure. Returning
    // null lets callers fall back safely (e.g. treat as "not direct CLI
    // execution") instead of producing an uncaught Node-internal error.
    return null
  }
}

/**
 * Type guard that checks whether `value` has the shape of a
 * {@link ServerDefinition} — an object with a non-empty string `name`,
 * a non-empty string `host`, a valid `ssh` config, and a non-empty `run` array.
 *
 * @param value - The value to inspect.
 * @returns `true` when `value` satisfies the structural requirements of `ServerDefinition`.
 */
export function isServerDefinitionLike(value: unknown): value is ServerDefinition {
  return collectDefinitionErrors(value).length === 0
}

/** Descriptor for a property validation check. */
type PropertyCheck = {
  /** The key to look up in the object. */
  key: string
  /** The label to use in error messages (defaults to `key`). */
  label?: string
}

/**
 * Validates that a required string property exists, has the correct type, and
 * is not empty.  Pushes a human-readable error into `errors` when any check
 * fails.
 *
 * @param object - The object to inspect.
 * @param check - Property key and optional display label.
 * @param errors - Accumulator for error messages.
 */
function collectStringErrors(
  object: Record<string, unknown>,
  check: PropertyCheck,
  errors: string[]
): void {
  const name = check.label ?? check.key
  if (!(check.key in object)) {
    errors.push(`Missing property '${name}' (expected string)`)
  } else if (typeof object[check.key] !== "string") {
    errors.push(`Invalid property '${name}' (expected string, got ${typeof object[check.key]})`)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by typeof check above
  } else if ((object[check.key] as string).length === 0) {
    errors.push(`Property '${name}' must not be empty`)
  }
}

/**
 * Validates that a required array property exists, has the correct type, and
 * is not empty.  Pushes a human-readable error into `errors` when any check
 * fails.
 *
 * @param object - The object to inspect.
 * @param check - Property key and optional display label.
 * @param errors - Accumulator for error messages.
 */
function collectArrayErrors(
  object: Record<string, unknown>,
  check: PropertyCheck,
  errors: string[]
): void {
  const name = check.label ?? check.key
  if (!(check.key in object)) {
    errors.push(`Missing property '${name}' (expected array)`)
  } else if (!Array.isArray(object[check.key])) {
    errors.push(`Invalid property '${name}' (expected array, got ${typeof object[check.key]})`)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by Array.isArray check above
  } else if ((object[check.key] as unknown[]).length === 0) {
    errors.push(`Property '${name}' must not be empty`)
  }
}

function collectSshErrors(value: Record<string, unknown>, errors: string[]): void {
  if (!("ssh" in value)) {
    errors.push("Missing property 'ssh' (expected object)")
    return
  }
  errors.push(...collectSshConfigErrors(value.ssh))
}

/**
 * Collects human-readable error messages for every property of `value` that
 * does not conform to the `ServerDefinition` shape.
 *
 * @param value - The value to validate.
 * @returns An array of error strings, empty when `value` is structurally valid.
 */
export function collectDefinitionErrors(value: unknown): string[] {
  const errors: string[] = []
  if (typeof value !== "object" || value === null) {
    errors.push("Export is not an object")
    return errors
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by typeof/null checks above
  const object = value as Record<string, unknown>
  collectStringErrors(object, { key: "name" }, errors)
  collectStringErrors(object, { key: "host" }, errors)
  collectSshErrors(object, errors)
  collectArrayErrors(object, { key: "run" }, errors)
  return errors
}

/**
 * Assertion function that ensures `value` is a valid {@link ServerDefinition}.
 *
 * When validation fails, all collected errors are printed to stderr and the
 * process exits with code `2`, so callers can treat the function as a
 * narrowing assertion without additional error handling.
 *
 * @param value - The value to validate.
 * @param file - Path of the file that exported `value`, used in the error message.
 */
function validateServerDefinition(value: unknown, file: string): asserts value is ServerDefinition {
  if (isServerDefinitionLike(value)) {
    return
  }
  const errors = collectDefinitionErrors(value)
  const details = errors.map((entry) => `  - ${entry}`).join("\n")
  console.error(
    `Error: ${file} does not export a valid ServerDefinition.\n${details}\n  Use the server() helper to create a valid definition.`
  )
  // eslint-disable-next-line node/no-process-exit
  process.exit(2)
}

/**
 * Inspect bounds used by {@link errorToString} when rendering plain
 * (non-Error) caught values. The bounds keep error rendering cheap and
 * prevent leaking sensitive Buffer contents (private keys) or huge
 * ssh2-internal arrays into stderr; subsequent maskRegisteredSecrets passes
 * also stay linear in the bounded output size.
 *
 * R-0000262: previously a JSON.stringify branch ran first and only fell back
 * to `inspect` on a thrown error. JSON.stringify(Buffer) produces
 * `{"type":"Buffer","data":[…]}` — the entire byte array. If a caught error
 * carried a private-key Buffer in its context, those bytes would land in
 * stderr unbounded. Routing every plain object through `inspect` with these
 * bounds removes that path; `compact: true` keeps the rendering similar to
 * the previous JSON output for small, well-behaved objects.
 */
const ERROR_INSPECT_DEPTH = 2
const ERROR_INSPECT_MAX_ARRAY_LENGTH = 32
const ERROR_INSPECT_MAX_STRING_LENGTH = 1024

/**
 * R-0000691: maximum recursion depth applied to the pre-inspect redaction
 * walk. Stays one level beyond `ERROR_INSPECT_DEPTH` so a Buffer that
 * `inspect` would still render is still elided. A bounded depth is
 * mandatory: an attacker-controlled error graph could otherwise hang the
 * walk on a cyclic reference.
 */
const REDACT_BUFFER_MAX_DEPTH = ERROR_INSPECT_DEPTH + 1

/**
 * Returns a human-readable string for any caught value.
 * Uses `.message` for `Error` instances and falls back to the string
 * representation for primitives. For plain objects, `util.inspect` with
 * bounded array/string lengths is used instead of `[object Object]` (and
 * instead of `JSON.stringify`, which would unfold full Buffer byte arrays
 * — see R-0000262).
 *
 * @param value - The value to convert to a string.
 * @returns A human-readable string representation of `value`.
 */
function errorToString(value: unknown): string {
  if (value instanceof Error) return maskRegisteredSecrets(value.message)
  if (typeof value === "object" && value !== null) {
    // R-0000691: pre-redact every nested Buffer to a static placeholder
    // before `inspect` runs. `util.inspect` would otherwise render the
    // Buffer bytes (subject to `maxArrayLength`) and a sensitive
    // payload — private key, session secret, password ciphertext — could
    // leak into stderr through any caught value with a Buffer-shaped
    // cause / data field. The pre-pass clones the graph defensively so
    // the original error object stays untouched for downstream consumers.
    return maskRegisteredSecrets(
      inspectRedactedBinaryValue(value, {
        breakLength: Infinity,
        compact: true,
        depth: ERROR_INSPECT_DEPTH,
        maxArrayLength: ERROR_INSPECT_MAX_ARRAY_LENGTH,
        maxStringLength: ERROR_INSPECT_MAX_STRING_LENGTH,
        redactMaxDepth: REDACT_BUFFER_MAX_DEPTH,
      })
    )
  }
  return maskRegisteredSecrets(String(value))
}

/**
 * Walks the cause chain of `error` and prints each cause to stderr.
 *
 * Uses a WeakSet to detect cyclic `cause` references (e.g. produced by
 * third-party libraries that wrap the same Error twice) so the loop always
 * terminates instead of hanging the CLI before `process.exit` is reached.
 *
 * @param error - The root `Error` whose `.cause` chain should be printed.
 */
/**
 * R-0000795: follow `.cause` on both Error instances and plain wrapper
 * objects (e.g. `{ message, cause: realError }`) so a non-Error wrapper
 * inserted in the middle of the chain does not silently truncate the walk.
 *
 * @param cause - The current node of the cause chain.
 * @returns The next cause value, or `undefined` when the chain ends.
 */
function nextCauseValue(cause: unknown): unknown {
  if (cause instanceof Error) return cause.cause
  if (typeof cause === "object" && cause !== null && "cause" in cause) {
    return (cause as { cause?: unknown }).cause
  }
  return undefined
}

function printCauseChain(error: Error): void {
  // R-0000795: track every object-typed cause — both `Error` instances and
  // plain objects — in the same WeakSet so a chain that mixes them cannot
  // cycle past the cycle-detection guard. A plain `{ cause }` wrapper that
  // points back to an Error already visited (or to another plain object that
  // ultimately points back) would previously have been re-printed each pass
  // because only Error references were tracked.
  const visitedCauses = new WeakSet<object>()
  visitedCauses.add(error)
  let cause: unknown = error.cause
  while (cause != null) {
    if (typeof cause === "object") {
      if (visitedCauses.has(cause)) {
        console.error("  Caused by: <cycle detected>")
        return
      }
      visitedCauses.add(cause)
    }
    console.error(`  Caused by: ${errorToString(cause)}`)
    cause = nextCauseValue(cause)
  }
}

/**
 * Prints a structured error message to stderr, including the cause chain and
 * optionally the full stack trace when `verbose` is `true`.
 *
 * @param error - The caught value (may be any type).
 * @param verbose - When `true`, the stack trace of `error` is printed.
 */
export function printExceptionError(error: unknown, verbose: boolean): void {
  console.error(`Error: ${errorToString(error)}`)

  if (error instanceof Error) {
    printCauseChain(error)

    if (verbose && error.stack != null) {
      console.error(`\n${maskRegisteredSecrets(error.stack)}`)
    }
  }
}

/**
 * Handles a failed attempt to load the `tsx` runtime.
 *
 * When the failed import is for a TypeScript file (`.ts`, `.mts`, `.cts`), a
 * clear error message is printed to stderr and the process exits with code 2.
 * For JavaScript files the failure is silently ignored because `tsx` is not
 * required there.
 *
 * @param filePath - The resolved path of the playbook file being loaded.
 */
export function handleTsxLoadFailure(filePath: string): void {
  if (/\.[cm]?ts$/v.test(filePath)) {
    console.error(
      `${pc.red("Error:")} tsx is required to run TypeScript playbooks but could not be loaded.\n` +
        `  Install it with: ${pc.bold("npm install -g tsx")} or add it as a devDependency.`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
}

/**
 * Returns whether the current CLI module is the direct process entrypoint.
 *
 * This resolves symlinks on both sides so pnpm-style executable shims and
 * symlinked `node_modules` entries still count as direct execution.
 *
 * @param moduleUrl - The current module URL, usually `import.meta.url`.
 * @param candidateEntryScript - The process entry script path, usually `process.argv[1]`.
 * @returns `true` when both paths resolve to the same file on disk.
 */
export function isDirectCliExecution(moduleUrl: string, candidateEntryScript?: string): boolean {
  if (candidateEntryScript == null) {
    return false
  }

  const moduleRealPath = resolveRealPath(fileURLToPath(moduleUrl))
  const entryRealPath = resolveRealPath(candidateEntryScript)
  if (moduleRealPath == null || entryRealPath == null) {
    return false
  }

  return moduleRealPath === entryRealPath
}

/**
 * Returns a copy of `environment` augmented with the runtime override flags
 * derived from CLI options.
 *
 * This function is pure: it does not mutate `environment`, the global
 * `process.env`, or any shared state. The augmented Environment is consumed
 * by the runner and threaded into module execution; runner code never reads
 * {@link FIRST_RUN_ENV_NAME} from `process.env` directly.
 *
 * The companion {@link withCliProcessEnvironment} mutates the global
 * `process.env` only for the duration of the serialized playbook
 * `import()` so playbooks can read `process.env.PARATIX_FIRST_RUN` at module
 * scope without contaminating another concurrent playbook import.
 *
 * @param environment - The base environment supplied by the caller.
 * @param options - Overrides derived from CLI flags.
 * @param options.firstRun - When `true`, sets `PARATIX_FIRST_RUN=true` in the
 *   returned copy.
 * @returns A new Environment with the overrides applied.
 */
export function applyCliEnvironmentOverrides(
  environment: Environment,
  options: { firstRun: boolean }
): Environment {
  if (!options.firstRun) return environment
  return { ...environment, [FIRST_RUN_ENV_NAME]: "true" }
}

/**
 * R-0000695 / R-0000729: the first-run AsyncLocalStorage now lives in
 * `firstRunContext.ts` so the library entry `index.ts` can re-export
 * `isFirstRun` without dragging `cli.ts` (with its `import.meta.url`
 * direct-run guard) into the library bundle. The runtime semantics are
 * unchanged: `isFirstRun()` reads the scoped flag, and
 * {@link withCliProcessEnvironment} below installs it via
 * {@link runWithFirstRunFlag}.
 */
export { isFirstRun } from "./firstRunContext.js"

/**
 * Runs `body` while the CLI-derived first-run flag is observable through
 * `isFirstRun` and guarantees the flag is cleared before returning,
 * regardless of whether `body` resolves or rejects.
 *
 * R-0000265: this helper replaces the previous `applyCliProcessEnvironment`
 * which returned a manual restore callback. That API trusted every caller
 * to wire up its own try/finally; a missed restore in any code path left
 * the flag stuck on the process for the rest of its lifetime. Wrapping the
 * body internally removes the discipline burden.
 *
 * R-0000695: the flag no longer touches `process.env`. The runner already
 * consumes the value through the typed Environment returned by
 * {@link applyCliEnvironmentOverrides}, so business logic stays free of
 * implicit globals. Playbooks that previously read
 * `process.env.PARATIX_FIRST_RUN` at module scope should call
 * `isFirstRun` inside their async surface area
 * (`init`/`apply`/`check`) instead — the flag is async-local, not global.
 *
 * Reentrant CLI calls are supported: a nested invocation that sets
 * `firstRun: true` extends the inner async context but does not leak the
 * value into the surrounding caller. After every nested call returns, the
 * outer context's flag remains visible until its own `body` completes.
 *
 * @param options - CLI flags that determine which mutations to apply.
 * @param options.firstRun - When `true`, marks the current async context
 *   as a first-run invocation for the duration of `body`.
 * @param body - Async work to run while the flag is installed. Its
 *   resolved value is forwarded; rejections propagate normally.
 * @returns The value resolved by `body`.
 */
export async function withCliProcessEnvironment<T>(
  options: { firstRun: boolean },
  body: () => Promise<T>
): Promise<T> {
  if (!options.firstRun) {
    // R-0000796: a nested invocation that explicitly disables firstRun must
    // observe `false` even when the outer scope set the flag to `true`.
    // Without a dedicated clear-scope the nested body would inherit the
    // outer AsyncLocalStorage value and silently see `true`, contradicting
    // the option the operator just passed. `runWithoutFirstRunFlag` opens
    // a fresh `firstRunContext.run(false, body)` so `isFirstRun()` returns
    // `false` for the entire async surface of `body` and reverts to the
    // outer state when the scope exits.
    return runWithoutFirstRunFlag(body)
  }
  return runWithFirstRunFlag(body)
}

/**
 * Cached registration promise so repeated calls share the result.
 *
 * The tsx ESM loader registers globally and is safe to install only once:
 * every additional `register()` call adds another loader entry that stays
 * alive for the rest of the process. Repeated calls happen in practice when
 * multiple TypeScript playbooks are imported sequentially (CLI batch),
 * inside vitest worker pools, or from embedded runners. Memoizing the
 * promise makes the helper idempotent and concurrency-safe so callers can
 * invoke it freely without leaking loader registrations or racing on a
 * boolean flag.
 *
 * On failure the cached promise is dropped so a later invocation can retry
 * (e.g. after the operator installs tsx).
 */
let tsxRegistrationPromise: null | Promise<void> = null
/**
 * R-0000846: per-fileUrl serialization queues. The previous design used a
 * single process-global queue, which meant two independent playbooks A and
 * B serialized against each other unnecessarily — even though A and B
 * cannot interfere with each other's module-record. By keying the queue on
 * the resolved `fileUrl`, parallel imports of distinct playbooks proceed
 * concurrently while repeated imports of the same `fileUrl` (e.g. tests
 * loading the same playbook back-to-back) still observe the prior import's
 * completion.
 *
 * Entries are removed when their settling task is the queue head, so the
 * map does not grow without bound in long-running processes.
 */
const playbookImportLocks = new Map<string, Promise<void>>()
const playbookImportContext = new AsyncLocalStorage<boolean>()

/**
 * R-0000787: serialize playbook imports across the process so a TypeScript
 * playbook's top-level `await import("./other-playbook.ts")` cannot deadlock
 * against an outer `withSerializedPlaybookImport` that is still holding the
 * lock. The AsyncLocalStorage-based reentrancy check below intentionally
 * uses a boolean flag — every nested import inside the same async context
 * bypasses the queue.
 *
 * WARNING for future maintainers: this reentrancy bypass is safe ONLY for
 * playbook-to-playbook imports. The tsx ESM loader registration
 * (`tsx.register()` in `registerTsxLoader`) and any other host-side
 * machinery that runs underneath `withSerializedPlaybookImport` MUST NOT
 * trigger a nested call into `withSerializedPlaybookImport`. If the loader
 * ever needs to load a playbook itself, the boolean flag would cause that
 * nested import to skip the queue and race with the outer lock, defeating
 * the serialization contract that downstream callers rely on. Keep the tsx
 * registration body free of `withSerializedPlaybookImport` calls or convert
 * this guard into a fileUrl-keyed map of in-flight imports instead.
 *
 * @param body - The async unit of work whose playbook import must be
 *   serialized against every other playbook import in the process.
 * @param fileUrl - Optional resolved `pathToFileURL(...).href` of the playbook
 *   being imported. Supplied by production callers so the lock is scoped per
 *   playbook (R-0000846); omitted by ad-hoc invocations and tests, in which
 *   case the legacy single-queue behaviour is used.
 * @returns Whatever `body` resolves to.
 */
export async function withSerializedPlaybookImport<T>(
  body: () => Promise<T>,
  fileUrl?: string
): Promise<T> {
  if (playbookImportContext.getStore() === true) {
    return body()
  }

  // R-0000846: callers without a known fileUrl fall back to a sentinel key
  // so the legacy single-queue behaviour stays available for tests and any
  // ad-hoc invocation that cannot supply a stable identifier. Production
  // callers should always pass a resolved `pathToFileURL(...).href`.
  const lockKey = fileUrl ?? "__paratix_default_playbook_lock__"
  const previousImport = playbookImportLocks.get(lockKey) ?? Promise.resolve()
  let releaseCurrentImport!: () => void
  const currentImport = new Promise<void>((resolveQueue) => {
    releaseCurrentImport = resolveQueue
  })
  playbookImportLocks.set(lockKey, currentImport)

  // R-0000746: swallow rejections from the previous queue head. A
  // playbook import that fails (tsx registration error, dynamic import
  // syntax error, runtime throw at module scope) currently produces a
  // rejected promise here; without the catch a single failed import
  // would freeze the lock for every subsequent caller because the
  // `await previousImport` below would re-throw and skip the
  // `releaseCurrentImport()` in `finally`. Analogous to the
  // catch-and-ignore pattern in knownHosts.ts:31-38.
  try {
    await previousImport
  } catch {
    // The previous import already surfaced its failure to its own
    // caller. The lock only cares that the prior holder is settled, so
    // its outcome is intentionally discarded here.
  }

  try {
    return await playbookImportContext.run(true, body)
  } finally {
    releaseCurrentImport()
    // R-0000846: prune the map entry when we are still the head of the
    // queue. If another caller has already enqueued behind us (the map
    // value differs from `currentImport`), they own the cleanup once they
    // settle. This keeps the map bounded in long-running processes.
    if (playbookImportLocks.get(lockKey) === currentImport) {
      playbookImportLocks.delete(lockKey)
    }
  }
}

/**
 * Resets the cached tsx registration promise. Exported so tests can
 * exercise the registration path in isolation; production code never needs
 * to clear the cache.
 */
export function resetTsxRegistrationForTests(): void {
  tsxRegistrationPromise = null
}

async function performTsxRegistration(filePath: string): Promise<void> {
  try {
    const tsx = (await import("tsx/esm/api")) as { register: () => void }
    tsx.register()
  } catch (error) {
    if (isMissingTsxDependencyError(error)) {
      handleTsxLoadFailure(filePath)
      return
    }
    throw new Error(
      `Failed to load tsx/esm/api: ${error instanceof Error ? error.message : String(error)}`,
      {
        cause: error,
      }
    )
  }
}

/**
 * R-0000692: tracks how many concurrent awaiters are still observing the
 * cached registration promise. The promise can only be cleared after every
 * waiter has settled — otherwise a parallel call would see `null` while
 * the in-flight `.catch` handler is still propagating a rejection, race
 * a fresh `performTsxRegistration`, and end up with the second registration
 * out of sync with the first one's failure semantics.
 */
let tsxRegistrationWaiterCount = 0

/**
 * R-0000840: marks that the cached registration promise should be discarded
 * as soon as the last waiter releases. Replaces the prior microtask
 * busy-loop that re-queued `Promise.resolve().then(clearWhenQuiet)` until
 * `tsxRegistrationWaiterCount` reached zero — under heavy contention that
 * loop could spin the microtask queue indefinitely. With this sentinel the
 * waiter `finally` block performs the clear deterministically as part of
 * its own settlement.
 */
let tsxRegistrationClearPending = false

function clearTsxRegistrationIfQuiet(): void {
  if (!tsxRegistrationClearPending) return
  if (tsxRegistrationWaiterCount !== 0) return
  tsxRegistrationClearPending = false
  tsxRegistrationPromise = null
}

async function registerTsxForTypeScriptEntry(filePath: string): Promise<void> {
  // R-0000692: when a cached promise exists, every parallel waiter must
  // observe the same (success or rejection) terminal value before we drop
  // the cache. Increment the waiter counter so a rejection cannot race a
  // fresh registration while a sibling caller is still in `await`. The
  // counter is decremented in the `finally` below regardless of the
  // outcome.
  if (tsxRegistrationPromise != null) {
    tsxRegistrationWaiterCount += 1
    try {
      await tsxRegistrationPromise
    } finally {
      tsxRegistrationWaiterCount -= 1
      // R-0000840: the last sibling awaiter performs the deferred cache
      // clear as part of its own `finally`, so the microtask loop the
      // originating catch used to spin is no longer required.
      clearTsxRegistrationIfQuiet()
    }
    return
  }
  // Wrap the registration so a rejection also clears the cache — but only
  // once every concurrent awaiter has observed the rejection. Holding the
  // catch promise in the cache until the waiter count drops to zero means
  // every parallel `await tsxRegistrationPromise` resolves against the
  // same terminal state. After the cache clears, a later call can retry
  // (e.g. once the operator installs tsx) by entering this branch and
  // creating a fresh registration.
  const registration = performTsxRegistration(filePath).catch((error: unknown) => {
    if (tsxRegistrationWaiterCount === 0) {
      tsxRegistrationPromise = null
    } else {
      // R-0000840: arm the clear sentinel and let the last waiter perform
      // the actual reset from its own `finally` block. No microtask loop
      // is queued — the sentinel is checked once per waiter release.
      tsxRegistrationClearPending = true
    }
    throw error
  })
  tsxRegistrationPromise = registration
  await registration
}

export async function loadServerDefinitionFromFile(
  file: string,
  options: { firstRun: boolean }
): Promise<ServerDefinition> {
  const filePath = resolve(file)
  const fileUrl = pathToFileURL(filePath).href
  const isTypeScriptEntry = TYPESCRIPT_ENTRY_EXTENSIONS.has(extname(filePath).toLowerCase())

  return withSerializedPlaybookImport(
    async () =>
      withCliProcessEnvironment(options, async () => {
        // Register tsx for TypeScript imports.
        // R-0000071: narrow the catch so only a genuine missing-tsx error is
        // routed through handleTsxLoadFailure. Any other error from the dynamic
        // import (incompatible Node, broken install, OOM, transitive dep
        // missing) is rethrown with the original cause so the CLI exit handler
        // surfaces the real loader failure instead of falsely reporting that
        // tsx is not installed.
        if (isTypeScriptEntry) await registerTsxForTypeScriptEntry(filePath)

        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- Dynamic import has unknown shape
        const imported = await import(fileUrl)
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-type-assertion -- Accessing .default on dynamic import
        const definition = (imported.default ?? imported) as ServerDefinition

        validateServerDefinition(definition, filePath)
        return definition
      }),
    fileUrl
  )
}

type ApplyCommandOptions = {
  dryRun: boolean
  env: Environment
  envFile?: string
  firstRun: boolean
  reconnectTimeout?: number
  verbose: boolean
}

type RunPlaybookFunction = (definition: ServerDefinition, options: RunOptions) => Promise<void>

export async function runApplyCommand(
  file: string,
  options: ApplyCommandOptions,
  run: RunPlaybookFunction = runPlaybook
): Promise<void> {
  printCliHeader(PACKAGE_DISPLAY_VERSION)
  const environmentOverrides = applyCliEnvironmentOverrides(options.env, {
    firstRun: options.firstRun,
  })
  const definition = await loadServerDefinitionFromFile(file, {
    firstRun: options.firstRun,
  })

  const runOptions: RunOptions = {
    dryRun: options.dryRun,
    envFile: options.envFile,
    envOverrides: environmentOverrides,
    verbose: options.verbose,
  }
  if (options.reconnectTimeout !== undefined) {
    runOptions.reconnectTimeout = options.reconnectTimeout * SECONDS_TO_MS
  }

  await run(definition, runOptions)
}

export function exitAfterApplyError(error: unknown, verbose: boolean): never {
  printExceptionError(error, verbose)
  const exitCode = process.exitCode === undefined || process.exitCode === 0 ? 2 : process.exitCode
  // eslint-disable-next-line node/no-process-exit
  process.exit(exitCode)
}

const program = new Command()

program
  .name("paratix")
  .description("Idempotent VPS setup tool in TypeScript")
  .version(PACKAGE_DISPLAY_VERSION)

program
  .command("apply <file>")
  .description("Apply a server definition")
  .option(
    "--dry-run",
    "Only check, do not apply. Some modules validate prospective config but cannot verify runtime restarts.",
    false
  )
  .option("--env <key=value...>", "Set env values", collectEnvironment, {})
  .option("--env-file <path>", "Load dotenv file")
  .option("--first-run", "Set PARATIX_FIRST_RUN=true before loading the playbook", false)
  .option(
    "--reconnect-timeout <seconds>",
    "SSH reconnect timeout (seconds, max 86400)",
    parseReconnectTimeoutSeconds
  )
  .option("--verbose", "Show full stack traces on error", false)
  .action(async (file: string, options: Record<string, unknown>) => {
    try {
      await runApplyCommand(file, {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        dryRun: options.dryRun as boolean,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        env: options.env as Environment,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        envFile: options.envFile as string | undefined,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        firstRun: options.firstRun as boolean,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        reconnectTimeout: options.reconnectTimeout as number,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        verbose: options.verbose as boolean,
      })
    } catch (error) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
      exitAfterApplyError(error, options.verbose as boolean)
    }
  })

export function parsePositiveNumber(value: string, options: { max?: number } = {}): number {
  const parsed = Number(value)
  // R-0000839: require a positive integer. Floats like `30.5` would survive
  // the previous `Number.isFinite` check and then silently round when later
  // multiplied to milliseconds, while values like `"3e9"` produced numbers
  // far beyond any sane bound. Pin the type so misuse fails fast at CLI
  // parse time with a clear exit code.
  if (!Number.isInteger(parsed) || parsed <= 0) {
    console.error(
      `Invalid --reconnect-timeout value: ${value} (expected a positive integer number of seconds)`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  // Enforce an explicit upper bound to prevent later overflow when the value
  // is converted to milliseconds and added to `Date.now()`.
  if (options.max !== undefined && parsed > options.max) {
    console.error(
      `Invalid --reconnect-timeout value: ${value} (must be at most ${options.max} seconds)`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  return parsed
}

/**
 * Commander option parser for `--reconnect-timeout` (seconds).
 *
 * Wraps {@link parsePositiveNumber} with a hard upper bound of
 * {@link RECONNECT_TIMEOUT_MAX_SECONDS} so values such as `1e10` are rejected
 * with a clear error message instead of silently producing a deadline that
 * overflows `Number.MAX_SAFE_INTEGER` after the seconds-to-ms multiplication.
 *
 * @param value - The raw CLI string (in seconds) to parse.
 * @returns The validated numeric value.
 */
export function parseReconnectTimeoutSeconds(value: string): number {
  return parsePositiveNumber(value, { max: RECONNECT_TIMEOUT_MAX_SECONDS })
}

export function collectEnvironment(
  value: string,
  previous: Record<string, string>
): Record<string, string> {
  const eqIndex = value.indexOf("=")
  if (eqIndex === -1) {
    console.error(`Invalid --env format: ${value} (expected key=value)`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  const key = value.slice(0, eqIndex)
  const value_ = value.slice(eqIndex + 1)
  if (!ENVIRONMENT_KEY_PATTERN.test(key)) {
    console.error(
      `Invalid --env name: ${key === "" ? "(empty)" : key} (expected [A-Za-z_][A-Za-z0-9_]*)`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  if (ENVIRONMENT_FORBIDDEN_KEYS.has(key)) {
    console.error(`Forbidden --env name: ${key} (reserved JavaScript identifier)`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  // R-0000478: use a null-prototype accumulator so the merged environment
  // never inherits keys like `__proto__` or `toString` from Object.prototype.
  // Mirrors the shape produced by `loadDotEnvironment` / `mergeEnvironment`.
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- intentional: Object.create(null) is the prototype-pollution defense
  const accumulator = Object.create(null) as Record<string, string>
  return Object.assign(accumulator, previous, { [key]: value_ })
}

// Only parse when executed directly, not when imported (e.g. in tests)
const entryScript = process.argv[1]
if (isDirectCliExecution(import.meta.url, entryScript)) {
  await program.parseAsync()
}
