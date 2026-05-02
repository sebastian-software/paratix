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

import { maskSecrets } from "./sshHelpers.js"

/**
 * Reference-counted registry: a single secret may be registered concurrently
 * by multiple modules. The counter ensures `unregisterSecret` only forgets
 * the value once the last registration goes out of scope.
 */
const secretCounts = new Map<string, number>()

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
  for (const secret of secrets) {
    if (secret.length === 0) continue
    registerSecret(secret)
    registered.push(secret)
  }
  try {
    return await body()
  } finally {
    for (const secret of registered) {
      unregisterSecret(secret)
    }
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
