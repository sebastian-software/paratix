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

import type { ModuleResult } from "./types.js"

import { CommandError, maskSecrets } from "./sshHelpers.js"

/**
 * Reference-counted registry: a single secret may be registered concurrently
 * by multiple modules. The counter ensures `unregisterSecret` only forgets
 * the value once the last registration goes out of scope.
 */
const secretCounts = new Map<string, number>()
const REDACTED_PLACEHOLDER = "[REDACTED]"

function assertRegistrableSecret(secret: string): void {
  if (secret.includes(REDACTED_PLACEHOLDER)) {
    throw new Error("Secret registrations must not contain the redaction placeholder")
  }
}

/**
 * Register a secret string for redaction in subsequent diagnostic output.
 *
 * Empty strings are ignored to keep `replaceAll(value, REDACTED)` from
 * accidentally turning every byte into the redaction marker.
 *
 * @param secret - The sensitive value to mask in stderr output. Ignored when
 *   empty.
 */
export function registerSecret(secret: string): void {
  if (secret.length === 0) return
  assertRegistrableSecret(secret)
  secretCounts.set(secret, (secretCounts.get(secret) ?? 0) + 1)
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
  if (secret.length === 0) return
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
 * @param secrets - The values to register. Empty strings are ignored.
 * @param body - The async unit of work whose failures must be redacted.
 * @returns Whatever `body` resolves to.
 */
export async function withRegisteredSecrets<T>(
  secrets: readonly string[],
  body: () => Promise<T>
): Promise<T> {
  const registered: string[] = []
  const registerableSecrets = secrets.filter((secret) => secret.length > 0)
  // R-0000195: Validate up-front so the register loop only runs on inputs
  // that are guaranteed registrable. The register loop and the body are then
  // both protected by the same try/finally — if a future API extension
  // causes `registerSecret` to throw mid-iteration, already-registered
  // values are still released.
  for (const secret of registerableSecrets) {
    assertRegistrableSecret(secret)
  }
  try {
    for (const secret of registerableSecrets) {
      registerSecret(secret)
      registered.push(secret)
    }
    const result = await body()
    return maskScopedResult(result, registered)
  } catch (error) {
    throw maskScopedError(error, registered)
  } finally {
    for (const secret of registered) {
      unregisterSecret(secret)
    }
  }
}

function maskScopedResult<T>(result: T, secrets: readonly string[]): T {
  if (secrets.length === 0 || !isModuleResult(result) || result.status !== "failed") return result
  if (result.error == null) return result
  return { ...result, error: maskScopedError(result.error, secrets) }
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
  return maskSecrets(stringifyCause(cause), secretList)
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

function stringifyCause(cause: unknown): string {
  if (typeof cause === "string") return cause
  if (typeof cause === "function")
    return cause.name.length > 0 ? `[Function: ${cause.name}]` : "[Function]"
  if (typeof cause === "number") return String(cause)
  if (typeof cause === "boolean") return String(cause)
  if (typeof cause === "bigint") return String(cause)
  if (typeof cause === "symbol") return String(cause)
  if (cause === undefined) return String(cause)
  if (cause === null) return "null"
  return stringifyObjectCause(cause)
}

function stringifyObjectCause(cause: object): string {
  try {
    const serialized = JSON.stringify(cause) as string | undefined
    return serialized ?? Object.prototype.toString.call(cause)
  } catch {
    return Object.prototype.toString.call(cause)
  }
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
 * Clear the entire sink. Used by the runner during shutdown and by tests.
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
