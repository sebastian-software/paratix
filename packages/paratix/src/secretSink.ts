/**
 * Process-scoped registry of sensitive material that must be redacted before
 * any failure diagnostic, stack trace, or verbose output is written to
 * stderr. Modules register secrets just before they pass them to a remote
 * tool (op resolved values, sudo passwords, user password hashes, download
 * URL tokens, signed URLs) and unregister them when the work completes.
 *
 * The sink is intentionally process-scoped — analogous to
 * {@link "./runnerAbortSignal".setRunnerAbortSignal} — so that
 * {@link "./output"} can observe the registered secrets without having to
 * thread them through every caller. The runner ensures secrets are cleared
 * on shutdown.
 *
 * R-0000041: `printCommandFailure` and `printVerboseGenericError` consult
 * this sink so a thrown {@link Error} whose message or stack trace contains
 * registered secret material is masked before it reaches stderr.
 */

import { AsyncLocalStorage } from "node:async_hooks"

import type { ModuleResult } from "./types.js"

import { isSecretDiagnosticField, REDACTED_SECRET_FIELD_PLACEHOLDER } from "./errorRedaction.js"
import { CommandError, maskSecrets } from "./sshHelpers.js"

/**
 * Reference-counted registry: a single secret may be registered concurrently
 * by multiple modules. The counter ensures `unregisterSecret` only forgets
 * the value once the last registration goes out of scope.
 */
const secretCounts = new Map<string, number>()
const runScopedSecretCounts = new AsyncLocalStorage<Map<string, number>>()
const REDACTED_PLACEHOLDER = REDACTED_SECRET_FIELD_PLACEHOLDER
const CIRCULAR_PLACEHOLDER = "[Circular]"

function assertRegistrableSecret(secret: string): void {
  if (secret.includes(REDACTED_PLACEHOLDER)) {
    throw new Error("Secret registrations must not contain the redaction placeholder")
  }
}

/**
 * Minimum length of a secret string that will be accepted by
 * {@link registerSecret}. Values shorter than this are silently ignored so a
 * stray one- or two-character token (a single TOTP digit, a partially
 * extracted PIN, …) cannot turn every byte of diagnostic output into the
 * redaction marker via `replaceAll`.
 *
 * R-0000583: kept at 8 so a 6-digit TOTP code cannot collide with arbitrary
 * 6-digit substrings in diagnostic text, and so reference-counting via plain
 * string identity does not get confused by short 4-character fragments that
 * appear in many unrelated values.
 */
const MINIMUM_SECRET_LENGTH = 8

/**
 * Register a secret string for redaction in subsequent diagnostic output.
 *
 * Values shorter than {@link MINIMUM_SECRET_LENGTH} characters are silently
 * ignored to keep `replaceAll(value, REDACTED)` from accidentally turning
 * every byte of the diagnostic output into the redaction marker. The
 * registration is optimistic — callers do not learn that a short secret was
 * dropped because the sink is shared process-wide and an error here would
 * abort the workload that produced the value.
 *
 * @param secret - The sensitive value to mask in stderr output. Ignored when
 *   shorter than {@link MINIMUM_SECRET_LENGTH} characters.
 */
export function registerSecret(secret: string): void {
  if (secret.length < MINIMUM_SECRET_LENGTH) return
  assertRegistrableSecret(secret)
  secretCounts.set(secret, (secretCounts.get(secret) ?? 0) + 1)
}

/**
 * Register a secret and attach that registration to the active run scope.
 *
 * This is intentionally separate from {@link registerSecret}: most callers
 * already balance their own registration with {@link unregisterSecret}. Values
 * produced by `op.resolve` must stay redacted for the whole playbook run, then
 * be released when that run finishes.
 *
 * @param secret - The sensitive value to mask for the active run.
 */
export function registerRunScopedSecret(secret: string): void {
  registerSecret(secret)
  if (secret.length < MINIMUM_SECRET_LENGTH) return
  const scopedSecrets = runScopedSecretCounts.getStore()
  if (scopedSecrets == null) return
  scopedSecrets.set(secret, (scopedSecrets.get(secret) ?? 0) + 1)
}

/**
 * Check whether long-lived secret registrations can currently be tied to a
 * run-scoped cleanup boundary.
 *
 * @returns `true` when {@link registerRunScopedSecret} can attach cleanup to
 *   the active playbook or direct-apply run scope.
 */
export function hasActiveRunScopedSecretScope(): boolean {
  return runScopedSecretCounts.getStore() != null
}

/**
 * Decrement the registration count for a previously registered secret. When
 * the counter reaches zero the value is forgotten so the sink does not grow
 * unboundedly across long-running CLI sessions.
 *
 * Calling this with an unknown secret is a no-op so callers can use it from
 * `try`/`finally` blocks without worrying about double-frees.
 *
 * @param secret - The previously registered value.
 */
export function unregisterSecret(secret: string): void {
  if (secret.length < MINIMUM_SECRET_LENGTH) return
  const current = secretCounts.get(secret)
  if (current == null) return
  if (current <= 1) {
    secretCounts.delete(secret)
    return
  }
  secretCounts.set(secret, current - 1)
}

/**
 * Run `body` with `secrets` registered for redaction. Any subsequent failure
 * diagnostic that surfaces through {@link "./output".printCommandFailure} or
 * {@link "./output".printVerboseGenericError} will mask the registered
 * values. The registrations are released on both success and failure paths.
 *
 * Use this helper when secret material flows through synchronous-or-async
 * code that may throw — it keeps the sink balanced even when the caller
 * does not own the error.
 *
 * @param secrets - The values to register process-wide and mask inside this
 *   scope. Values shorter than {@link MINIMUM_SECRET_LENGTH} characters are
 *   only ignored for process-wide registration; scoped result/error masking
 *   still redacts them.
 * @param body - The async unit of work whose failures must be redacted.
 * @returns Whatever `body` resolves to.
 */
export async function withRegisteredSecrets<T>(
  secrets: readonly string[],
  body: () => Promise<T>
): Promise<T> {
  const registered: string[] = []
  const registerableSecrets = secrets.filter((secret) => secret.length >= MINIMUM_SECRET_LENGTH)
  // R-0000195: Validate up-front so the register loop only runs on inputs
  // that are guaranteed registrable. The register loop and the body are then
  // both protected by the same try/finally — if a future API extension
  // causes `registerSecret` to throw mid-iteration, already-registered
  // values are still released.
  for (const secret of secrets) {
    assertRegistrableSecret(secret)
  }
  try {
    for (const secret of registerableSecrets) {
      registerSecret(secret)
      registered.push(secret)
    }
    const result = await body()
    return maskScopedResult(result, secrets)
  } catch (error) {
    throw maskScopedError(error, secrets)
  } finally {
    for (const secret of registered) {
      unregisterSecret(secret)
    }
  }
}

/**
 * Execute a playbook run with a cleanup scope for long-lived secret
 * registrations. Each scoped secret is released exactly as often as it was
 * registered in this run, preserving reference counts for concurrent runs.
 *
 * @param body - The async run body.
 * @returns Whatever `body` resolves to.
 */
export async function withRunScopedSecrets<T>(body: () => Promise<T>): Promise<T> {
  if (runScopedSecretCounts.getStore() != null) {
    return body()
  }

  const scopedSecrets = new Map<string, number>()
  try {
    return await runScopedSecretCounts.run(scopedSecrets, body)
  } finally {
    for (const [secret, count] of scopedSecrets) {
      for (let index = 0; index < count; index += 1) {
        unregisterSecret(secret)
      }
    }
  }
}

function maskScopedResult<T>(result: T, secrets: readonly string[]): T {
  if (secrets.length === 0 || !isModuleResult(result)) return result
  // R-0000477: mask `detail` for every status — a module that returns
  // `status: "ok"` (or "changed" / "skipped") with secrets embedded in the
  // detail string would otherwise leak the registered material through the
  // module summary line. The `error` mask remains conditional on the failed
  // status because that field is only populated on failure.
  const secretList = [...secrets]
  let next: ModuleResult | T = result
  if (result.detail != null) {
    const maskedDetail = maskSecrets(result.detail, secretList)
    if (maskedDetail !== result.detail) {
      next = { ...result, detail: maskedDetail }
    }
  }
  if (isModuleResult(next) && next.status === "failed" && next.error != null) {
    next = { ...next, error: maskScopedError(next.error, secrets) }
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- preserved at runtime: we only ever clone the same ModuleResult shape that the type guard already verified.
  return next as T
}

function isModuleResult(value: unknown): value is ModuleResult {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value &&
    typeof (value as { status?: unknown }).status === "string"
  )
}

function maskCauseValue(cause: unknown, secrets: readonly string[], secretList: string[]): unknown {
  if (cause === undefined) return undefined
  if (cause instanceof Error) return maskScopedError(cause, secrets)
  return maskSecrets(stringifyCause(cause, secretList), secretList)
}

function buildMaskedErrorClone(error: Error, maskedMessage: string, secretList: string[]): Error {
  if (error instanceof CommandError) {
    return new CommandError(
      maskedMessage,
      maskSecrets(error.fullStdout, secretList),
      maskSecrets(error.fullStderr, secretList)
    )
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- preserving Error subclass prototype without re-running its constructor; Object.create is the standard pattern.
  const clone: Error = Object.create(Object.getPrototypeOf(error) as object) as Error
  Object.defineProperty(clone, "message", {
    configurable: true,
    value: maskedMessage,
    writable: true,
  })
  return clone
}

// R-0000259: return a masked clone instead of mutating the original Error.
// Mutating the original made the redaction irreversible — consumers outside
// the scope (test frameworks, parallel loggers) still saw the masked values
// after `withRegisteredSecrets` returned. Cloning leaves the caller's Error
// untouched and keeps the scope-local masking semantics intact.
function maskScopedError(error: unknown, secrets: readonly string[]): Error {
  if (!(error instanceof Error) || secrets.length === 0) {
    return error instanceof Error ? error : new Error(maskSecrets(String(error), [...secrets]))
  }

  const secretList = [...secrets]
  const maskedMessage = maskSecrets(error.message, secretList)
  const maskedStack = error.stack == null ? undefined : maskSecrets(error.stack, secretList)
  const maskedCause = maskCauseValue(error.cause, secrets, secretList)

  const clone = buildMaskedErrorClone(error, maskedMessage, secretList)
  clone.name = error.name
  if (maskedStack != null) {
    Object.defineProperty(clone, "stack", {
      configurable: true,
      value: maskedStack,
      writable: true,
    })
  }
  if (maskedCause !== undefined) {
    Object.defineProperty(clone, "cause", {
      configurable: true,
      value: maskedCause,
      writable: true,
    })
  }
  return clone
}

function stringifyCause(cause: unknown, secretList: string[]): string {
  if (typeof cause === "string") return cause
  if (typeof cause === "function")
    return cause.name.length > 0 ? `[Function: ${cause.name}]` : "[Function]"
  if (typeof cause === "number") return String(cause)
  if (typeof cause === "boolean") return String(cause)
  if (typeof cause === "bigint") return String(cause)
  if (typeof cause === "symbol") return String(cause)
  if (cause === undefined) return String(cause)
  if (cause === null) return "null"
  return stringifyObjectCause(cause, secretList)
}

function stringifyObjectCause(cause: object, secretList: string[]): string {
  try {
    const serialized = JSON.stringify(normalizeObjectCause(cause, secretList, new WeakSet())) as
      | string
      | undefined
    return serialized ?? Object.prototype.toString.call(cause)
  } catch {
    return Object.prototype.toString.call(cause)
  }
}

function normalizeObjectCause(cause: object, secretList: string[], seen: WeakSet<object>): unknown {
  if (isBinaryCauseValue(cause)) return REDACTED_PLACEHOLDER
  if (cause instanceof Date) return cause.toJSON()
  if (seen.has(cause)) return CIRCULAR_PLACEHOLDER
  seen.add(cause)
  try {
    if (Array.isArray(cause)) {
      return cause.map((value) => normalizeCausePropertyValue(value, secretList, seen))
    }

    const normalized: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(cause)) {
      if (isSecretDiagnosticField(key)) {
        normalized[key] = REDACTED_PLACEHOLDER
        continue
      }
      normalized[key] = normalizeCausePropertyValue(value, secretList, seen)
    }
    return normalized
  } finally {
    seen.delete(cause)
  }
}

function normalizeCausePropertyValue(
  value: unknown,
  secretList: string[],
  seen: WeakSet<object>
): unknown {
  if (value === null) return null
  if (typeof value === "bigint") return String(value)
  if (typeof value !== "object") return value
  return normalizeObjectCause(value, secretList, seen)
}

function isBinaryCauseValue(value: object): boolean {
  return value instanceof ArrayBuffer || ArrayBuffer.isView(value)
}

/**
 * Return a snapshot of currently registered secrets for masking. Used
 * internally by {@link "./output"} — modules should not call this directly.
 *
 * @returns A new array of registered secret values.
 */
export function getRegisteredSecrets(): string[] {
  return [...secretCounts.keys()]
}

/**
 * Clear the entire sink. Used by the runner during a hard-exit shutdown
 * (second SIGINT/SIGTERM) and by tests.
 *
 * R-0000518: do NOT call this on normal per-run teardown. The sink is
 * reference-counted via {@link registerSecret} / {@link unregisterSecret},
 * so balanced scopes (in particular {@link withRegisteredSecrets}) drain it
 * automatically. Wiping the sink unconditionally between concurrent
 * `runPlaybook` invocations sharing the same Node process would strip the
 * redaction context of every still-running scope.
 *
 * Intentionally NOT exported through the public package surface so playbooks
 * cannot accidentally drop the redaction context for the rest of the run.
 */
export function clearRegisteredSecrets(): void {
  secretCounts.clear()
}

/**
 * Apply the registered secrets to `text`. When the sink is empty the input
 * is returned unchanged. Convenience wrapper around {@link maskSecrets} that
 * keeps the variant-resolution overhead out of the caller.
 *
 * @param text - The string to redact.
 * @returns The redacted text, or `text` itself when no secrets are registered.
 */
export function maskRegisteredSecrets(text: string): string {
  if (secretCounts.size === 0) return text
  return maskSecrets(text, getRegisteredSecrets())
}
