/**
 * Redaction helpers for the failure paths of the `op` module.
 *
 * Two paths need them, with different guarantees:
 *
 * - `apply()` renders a failed {@link "../types".ModuleResult} and only has to
 *   redact the detail string it builds.
 * - the up-front secret phase *throws*, and its error has to be completely
 *   redacted at throw time — message, `cause`, and `stack`. It cannot fall back
 *   on the run-scoped secret sink: `withRunScopedSecrets` awaits its body inside
 *   the `try`, so its `finally` releases every scoped registration *before* the
 *   rejection propagates. By the time the CLI renders the failure,
 *   `maskRegisteredSecrets` sees an empty sink and returns the text unchanged.
 *   And unlike `withRegisteredSecrets`, `withRunScopedSecrets` does not mask the
 *   escaping error itself either.
 *
 * Extracted from `op.ts` — like `opSpawnError.ts` and `opOutputCapture.ts` —
 * to keep that module within the project max-lines cap.
 */

import { inspectRedactedDiagnosticValue } from "../errorRedaction.js"
import { maskSecrets } from "../sshHelpers.js"
import { maskKnownSecretPrefixes } from "./opOutputCapture.js"
import { OpSpawnError } from "./opSpawnError.js"

/** Marker used in place of a cause chain that references itself. */
const CIRCULAR_CAUSE_PLACEHOLDER = "[Circular]"

/**
 * Bounds for `util.inspect` when a non-Error `cause` is rendered, so a runaway
 * plain object cannot dump unbounded text into the redacted message. Mirrors
 * the bounds `output.ts` applies to the same kind of value.
 */
const CAUSE_INSPECT_DEPTH = 2
const CAUSE_INSPECT_MAX_STRING_LENGTH = 1024
const CAUSE_REDACT_BINARY_MAX_DEPTH = CAUSE_INSPECT_DEPTH + 1

/**
 * Build a single-string failure detail from a caught error so a later
 * {@link maskOpText} pass can redact any resolved values that happened to leak
 * into the error message (typically via captured stderr from the op CLI).
 *
 * @param error - The thrown error caught from the op CLI invocation.
 * @returns The detail string (message or `String(value)` fallback) to mask and surface.
 */
export function buildOpFailureDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Apply both redaction layers this module relies on: exact-match masking plus
 * the prefix matcher that catches a partially printed value.
 *
 * @param text - The diagnostic text to redact.
 * @param secrets - Masking candidates (resolved values, references, captured op output).
 * @returns The redacted text.
 */
export function maskOpText(text: string, secrets: string[]): string {
  return maskKnownSecretPrefixes(maskSecrets(text, secrets), secrets)
}

/**
 * Build a masked clone of `error` that preserves its prototype without
 * re-running the constructor. Mirrors `maskScopedError` in `secretSink.ts`
 * (R-0000259): the caught error itself is never mutated, so consumers outside
 * this scope keep an untouched value.
 *
 * @param error - The error to clone.
 * @param maskedMessage - The already-redacted message for the clone.
 * @returns A clone carrying the masked message.
 */
function createMaskedErrorClone(error: Error, maskedMessage: string): Error {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- preserving the Error subclass prototype without re-running its constructor; Object.create is the standard pattern, identical to `maskScopedError` in secretSink.ts.
  const clone: Error = Object.create(Object.getPrototypeOf(error) as object) as Error
  Object.defineProperty(clone, "message", {
    configurable: true,
    value: maskedMessage,
    writable: true,
  })
  return clone
}

/**
 * Redact a `cause` value of any shape. A non-Error cause goes through the
 * bounded diagnostic inspector, so a plain object keeps useful context instead
 * of collapsing into `[object Object]`.
 *
 * @param cause - The cause-chain value to redact.
 * @param secrets - Masking candidates.
 * @param visited - Errors already cloned, so a self-referencing chain terminates.
 * @returns The redacted cause, or `undefined` when there was none.
 */
function maskOpErrorCause(cause: unknown, secrets: string[], visited: WeakSet<Error>): unknown {
  if (cause === undefined) return undefined
  if (!(cause instanceof Error)) {
    const rendered = inspectRedactedDiagnosticValue(cause, {
      depth: CAUSE_INSPECT_DEPTH,
      maxStringLength: CAUSE_INSPECT_MAX_STRING_LENGTH,
      redactMaxDepth: CAUSE_REDACT_BINARY_MAX_DEPTH,
    })
    return maskOpText(rendered, secrets)
  }
  if (visited.has(cause)) return CIRCULAR_CAUSE_PLACEHOLDER
  return maskOpError(cause, secrets, visited)
}

/**
 * Clone `error` with its message, stack, and whole cause chain redacted.
 *
 * An {@link OpSpawnError} is rebuilt through its constructor so the captured
 * stdout/stderr it carries are redacted too and stay structurally intact — the
 * same special case `maskScopedError` makes for `CommandError`.
 *
 * @param error - The error to redact.
 * @param secrets - Masking candidates.
 * @param visited - Errors already cloned, so a self-referencing chain terminates.
 * @returns The fully redacted clone.
 */
function maskOpError(error: Error, secrets: string[], visited: WeakSet<Error>): Error {
  visited.add(error)
  const maskedMessage = maskOpText(error.message, secrets)
  const clone =
    error instanceof OpSpawnError
      ? new OpSpawnError(maskedMessage, {
          stderr: maskOpText(error.opStderr, secrets),
          stdout: maskOpText(error.opStdout, secrets),
        })
      : createMaskedErrorClone(error, maskedMessage)
  clone.name = error.name
  if (error.stack != null) {
    Object.defineProperty(clone, "stack", {
      configurable: true,
      value: maskOpText(error.stack, secrets),
      writable: true,
    })
  }
  const maskedCause = maskOpErrorCause(error.cause, secrets, visited)
  if (maskedCause !== undefined) {
    Object.defineProperty(clone, "cause", {
      configurable: true,
      value: maskedCause,
      writable: true,
    })
  }
  return clone
}

/**
 * Build the error that the up-front secret phase throws — fully redacted at
 * throw time, see the module comment for why nothing downstream can do it.
 *
 * The outer error is constructed from the already-redacted detail, so its own
 * freshly captured stack carries nothing sensitive; the caught error survives
 * as a redacted `cause` so the diagnostic chain is not lost.
 *
 * @param error - The caught failure of the up-front phase.
 * @param secrets - Masking candidates (references, resolved values, op output).
 * @returns The error to throw.
 */
export function buildPrewarmFailure(error: unknown, secrets: string[]): Error {
  const detail = maskOpText(buildOpFailureDetail(error), secrets)
  return new Error(`Failed to resolve 1Password references: ${detail}`, {
    cause: maskOpErrorCause(error, secrets, new WeakSet()),
  })
}
