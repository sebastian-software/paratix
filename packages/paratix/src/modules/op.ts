import type { Environment, Module, ModuleResult } from "../types.js"

import { environmentToMetaEntries } from "../meta.js"
import { failed } from "../moduleFailure.js"
import {
  hasActiveRunScopedSecretScope,
  registerRunScopedSecret,
  withRunScopedSecrets,
} from "../secretSink.js"
import { generateTotpCode } from "../totp.js"
import { buildOpFailureDetail, buildPrewarmFailure, maskOpText } from "./opFailureMasking.js"
import {
  readOtpauthUri,
  readSecretValue,
  splitReferences,
  validateReferences,
} from "./opReferenceResolution.js"
import { collectOpFailureOutputs } from "./opSpawnError.js"

/**
 * Resolve regular (non-OTP) 1Password references via `op read`.
 *
 * @param entries - Map of logical names to 1Password references.
 * @param leakedValues - Mutable sink that captures every resolved value. The
 *   caller uses it to feed `maskSecrets` on failure paths so any value that
 *   leaks into stderr or a stack trace is still redacted.
 * @returns Resolved key-value pairs.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveRegularReferences(
  entries: Record<string, string>,
  leakedValues: string[]
): Promise<Record<string, string>> {
  const result: Record<string, string> = {}

  for (const [name, reference] of Object.entries(entries)) {
    // eslint-disable-next-line no-await-in-loop
    const value = await readSecretValue(reference)
    if (value.length > 0) {
      leakedValues.push(value)
    }
    result[name] = value
  }

  return result
}

/**
 * Resolve OTP 1Password references into lazy TOTP code generators.
 *
 * Each reference is resolved exactly once via `op read` to obtain the
 * `otpauth://totp/...` URI, then wrapped in a lazy function so the
 * time-based TOTP **code** is recomputed on every access.
 *
 * Note: only the TOTP code rotates per call — the underlying seed (the
 * `secret=` parameter of the otpauth URI) is captured by the returned
 * closure and is NOT refetched. A seed rotation in 1Password during a
 * running playbook is therefore not observable until the next `runPlaybook`
 * invocation re-resolves the reference. This is a deliberate design
 * decision: resolving the seed on every access would invoke `op read`
 * (and potentially a 1Password authentication pop-up / biometric prompt)
 * for every module evaluation, which is unacceptable for both performance
 * and interactive UX. Use a fresh playbook run when a seed has been
 * rotated.
 *
 * @param entries - Map of logical names to OTP 1Password references.
 * @param leakedValues - Mutable sink that captures every resolved otpauth URI.
 *   The caller uses it to feed `maskSecrets` on failure paths so the
 *   `secret=` parameter in the URI is redacted from any user-visible output.
 * @returns Map of logical names to lazy functions that compute a fresh TOTP
 *   code (from the captured seed) on every call.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function resolveOtpReferences(
  entries: Record<string, string>,
  leakedValues: string[]
): Promise<Environment> {
  const result: Environment = {}

  for (const [name, reference] of Object.entries(entries)) {
    // R-0000165: the otpauth URI is registered in the secret sink the moment it
    // is first observed — inside `readReference` — so an exception thrown later
    // (e.g. from a follow-up op invocation or from generateTotpCode) cannot
    // leak the URI's `secret=` parameter through stack traces or shared error
    // renderers.
    //
    // R-0000576: that registration still happens BEFORE the closure below is
    // defined, because the awaited read completes first. A third-party catch
    // site that stringifies the thrown error therefore never sees the raw URI
    // before the sink masks it.
    // eslint-disable-next-line no-await-in-loop
    const otpauthUri = await readOtpauthUri(reference)
    if (otpauthUri.length > 0) {
      leakedValues.push(otpauthUri)
    }
    result[name] = () => {
      // R-0000576: the captured `otpauthUri` is closed over and would show
      // up in V8 stack traces if `generateTotpCode` throws synchronously.
      // Rethrow a sanitized Error whose message contains only the logical
      // reference name; the original error is kept in `cause` so callers
      // who carefully render `cause` keep diagnostic detail, while the
      // top-level message stays free of the secret.
      try {
        const code = generateTotpCode(otpauthUri)
        if (hasActiveRunScopedSecretScope()) {
          registerRunScopedSecret(code)
        }
        return code
      } catch (error) {
        throw new Error(`Failed to generate TOTP code for ${JSON.stringify(name)}`, {
          cause: error,
        })
      }
    }
  }

  return result
}

/**
 * Resolve every reference of one `op.resolve` module into the run-scoped cache,
 * before the run connects.
 *
 * Resolution is sequential (as it is in `apply()`): parallel `op read` calls
 * would stack several biometric prompts on top of each other. The resolved
 * values are only warmed here — the lazy TOTP closure belongs to the module and
 * is built in `apply()`, not in the cache.
 *
 * @param references - Map of logical names to 1Password references.
 * @throws {Error} A fully redacted error when a reference cannot be resolved.
 */
async function prewarmReferences(references: Record<string, string>): Promise<void> {
  // Mirrors the `leakedValues` list of `apply()`: every value observed here
  // feeds the masking of a failure raised later in this phase. The list that
  // `apply()` builds locally is not reachable from here.
  const resolvedValues: string[] = []
  try {
    const [regularEntries, otpEntries] = splitReferences(references)
    for (const reference of Object.values(regularEntries)) {
      // eslint-disable-next-line no-await-in-loop -- sequential by design, see the doc comment above
      const value = await readSecretValue(reference)
      if (value.length > 0) resolvedValues.push(value)
    }
    for (const reference of Object.values(otpEntries)) {
      // eslint-disable-next-line no-await-in-loop -- sequential by design, see the doc comment above
      const otpauthUri = await readOtpauthUri(reference)
      if (otpauthUri.length > 0) resolvedValues.push(otpauthUri)
    }
  } catch (error) {
    throw buildPrewarmFailure(error, [
      ...Object.values(references),
      ...resolvedValues,
      // R-0000589: fold the per-line captured stdout/stderr of the failing op
      // invocation into the masking candidates, exactly as the apply() path does.
      ...collectOpFailureOutputs(error),
    ])
  }
}

/**
 * Modules for resolving secrets from 1Password on the local controller.
 */
export const op = {
  /**
   * Resolve 1Password secret references into environment values.
   *
   * Regular references are resolved via `op read`.
   * References ending in `/one-time-password` or `/otp` are resolved individually
   * via `op read` and returned as lazy functions that compute a fresh TOTP code
   * on each call.
   *
   * This module runs locally (`local: true`) and never touches the remote host.
   * `check` always returns `"needs-apply"` so the runner executes `apply`
   * unconditionally and propagates the resolved meta values.
   * If any CLI call fails the module returns `{ status: "failed", error }`.
   *
   * Inside a `runPlaybook` run every reference is already read at the very
   * start of the run, before the SSH connect, so the 1Password interaction
   * (biometric unlock, `op signin`) happens immediately and only once. `apply`
   * then runs at its own position in `run`, serves its values from the
   * run-scoped cache without another CLI call, and emits the same meta as
   * before. A failure during that up-front phase aborts the run before any
   * connection is opened, instead of surfacing as a failed module later on.
   * Outside a run — a direct `op.resolve(...).apply(...)` call — there is no
   * cache and the references are resolved on the spot, exactly as before.
   *
   * @param references - A map of logical names to 1Password secret references
   *   (e.g. `op://vault/item/field`). References ending in `/one-time-password`
   *   or `/otp` are treated as TOTP sources.
   * @returns A Module that resolves the references and emits them as meta values.
   *
   * @example
   * ```ts
   * op.resolve({
   *   DB_PASSWORD: "op://prod/database/password",
   *   API_TOKEN:   "op://prod/api/credential",
   *   MFA_CODE:    "op://prod/authenticator/one-time-password",
   * })
   * ```
   */
  resolve(references: Record<string, string>): Module {
    validateReferences(references)

    return {
      _dryRunMetaProducer: true,
      async _prewarmSecrets(): Promise<void> {
        // The hook opens its own run-scoped secret bracket, just like `apply()`
        // does. Inside the runner the helper is re-entrant and this costs
        // nothing, but it makes the hook self-supporting: on a direct call
        // without a surrounding run scope, `registerRunScopedSecret` increments
        // the process-wide count unconditionally and only *then* returns when
        // there is no store (`secretSink.ts`), and no regular path ever releases
        // it again (R-0000518). Without this bracket a direct call would leak
        // its registrations process-wide.
        await withRunScopedSecrets(async () => {
          await prewarmReferences(references)
        })
      },
      async apply(): Promise<ModuleResult> {
        return withRunScopedSecrets(async () => {
          // Track every secret we observe locally (resolved values + otpauth
          // URIs) so the failure path can mask them from stderr and stack
          // traces, not just the op:// reference strings the caller supplied.
          const leakedValues: string[] = []
          try {
            const [regularEntries, otpEntries] = splitReferences(references)
            // R-0000041 / R-0000850: `resolveRegularReferences` and
            // `resolveOtpReferences` read through `readReference`, which
            // registers every resolved value with the process-scoped secret
            // sink as soon as it observes it — in this run that may already
            // have happened during the prewarm phase. We deliberately do not
            // re-register here — keeping that single loader as the source of
            // truth for secret registration avoids the risk of the sites
            // drifting apart (e.g. when a future helper learns to register a
            // derived value but the post-loop block is overlooked).
            const resolvedRegular = await resolveRegularReferences(regularEntries, leakedValues)
            const resolvedOtp = await resolveOtpReferences(otpEntries, leakedValues)

            return {
              meta: environmentToMetaEntries({ ...resolvedRegular, ...resolvedOtp }),
              status: "ok",
            }
          } catch (error) {
            const rawDetail = buildOpFailureDetail(error)
            // R-0000589: also feed the per-line captured stdout/stderr of the
            // failing op invocation into the secret list. A partial stdout
            // buffer (e.g. half a secret value) that ended up embedded in the
            // error message is then redacted as defense-in-depth.
            const secrets = [
              ...Object.values(references),
              ...leakedValues,
              ...collectOpFailureOutputs(error),
            ]
            const detail = maskOpText(rawDetail, secrets)
            // R-0000850: every value that ended up in `leakedValues` was already
            // registered with the secret sink by the helpers above (see
            // `resolveRegularReferences` / `resolveOtpReferences`). We rely on
            // that single registration site so the resolve flow has one — and
            // only one — canonical place that owns secret registration.
            return failed(`Failed to resolve 1Password references: ${detail}`)
          }
        })
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return "needs-apply"
      },
      local: true,
      name: `op.resolve: ${Object.keys(references).join(", ")}`,
    }
  },
}
