/**
 * Reference handling for the `op` module: validate `op://` references, split
 * them by kind, and read a single reference through the run-scoped prewarm
 * cache with the normalization that kind requires.
 *
 * Extracted from `op.ts` — like `opSpawnRunner.ts`, `opSpawnError.ts`,
 * `opOutputCapture.ts` and `opFailureMasking.ts` — to keep that module within
 * the project max-lines cap. `op.ts` keeps the resolution loops and the module
 * definition that drive these helpers.
 */

import { resolveCachedSecret } from "../secretPrewarm.js"
import { hasActiveRunScopedSecretScope, registerRunScopedSecret } from "../secretSink.js"
import { spawnWithInput } from "./opSpawnRunner.js"

const OTP_SUFFIX_PATTERN = /\/(?:one-time-password|otp)$/iv

const REFERENCE_PREFIX = "op://"

/**
 * Validate that all reference values start with `op://`.
 *
 * @param references - Map of logical names to 1Password references.
 * @throws {Error} If any reference does not start with `op://`.
 */
export function validateReferences(references: Record<string, string>): void {
  for (const [name, reference] of Object.entries(references)) {
    if (!reference.startsWith(REFERENCE_PREFIX)) {
      throw new Error(
        `Invalid 1Password reference for "${name}": must start with "${REFERENCE_PREFIX}"`
      )
    }
  }
}

/**
 * Split references into regular secrets and OTP references.
 *
 * @param references - Map of logical names to 1Password references.
 * @returns A tuple of [regularEntries, otpEntries].
 */
export function splitReferences(
  references: Record<string, string>
): [Record<string, string>, Record<string, string>] {
  const regularEntries: Record<string, string> = {}
  const otpEntries: Record<string, string> = {}

  for (const [name, reference] of Object.entries(references)) {
    if (OTP_SUFFIX_PATTERN.test(reference)) {
      otpEntries[name] = reference
    } else {
      regularEntries[name] = reference
    }
  }

  return [regularEntries, otpEntries]
}

function stripTrailingCliNewline(value: string): string {
  return value.replace(/\r?\n$/v, "")
}

/**
 * Read a single 1Password reference, routed through the run-scoped prewarm
 * cache so each reference costs exactly one `op read` per run — no matter how
 * many `op.resolve` modules name it, and no matter whether the prewarm phase or
 * the module's own `apply()` asks first.
 *
 * `normalize` post-processes the raw CLI stdout, and the **normalized** value —
 * not the raw stdout — is what gets cached and registered. That distinction is
 * load-bearing: the secret sink masks exactly the string it was handed, so a
 * raw value registered with its trailing newline would leave the trimmed value
 * that actually reaches the output unmasked.
 *
 * R-0000165 / R-0000850: the loader registers the value with the secret sink at
 * the moment it is first observed, so the window between the up-front phase and
 * the module's own execution is covered too. An empty value is cached and passed
 * on like any other but never registered.
 *
 * Every *observation* registers as well, not just the load. The loader runs once
 * per reference and run, so its registration is only as long-lived as whichever
 * `withRunScopedSecrets` bracket happened to be active back then. A cache hit
 * that re-registers inside the caller's own bracket makes each consumer
 * self-supporting again — exactly the property `apply()` had before the cache
 * existed — instead of depending on an ordering of scopes that nothing enforces.
 * The registration is reference-counted, so the extra registration is released
 * exactly as often as it was taken; the scope guard follows the precedent of the
 * TOTP closure in `resolveOtpReferences` (`op.ts`) and keeps a registration
 * without a scope (which nothing would ever release) from happening.
 *
 * @param reference - The `op://` reference to read.
 * @param normalize - Post-processing applied to the raw CLI stdout.
 * @returns The normalized value, served from cache once the reference was read.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
async function readReference(
  reference: string,
  normalize: (stdout: string) => string
): Promise<string> {
  const value = await resolveCachedSecret(reference, async () => {
    const stdout = await spawnWithInput("op", ["read", "--", reference], { input: "" })
    const loaded = normalize(stdout)
    if (loaded.length > 0) registerRunScopedSecret(loaded)
    return loaded
  })
  if (value.length > 0 && hasActiveRunScopedSecretScope()) registerRunScopedSecret(value)
  return value
}

/**
 * Read a regular (non-OTP) reference: the secret value with the trailing
 * newline the CLI appends removed.
 *
 * @param reference - The `op://` reference to read.
 * @returns The resolved secret value.
 */
export async function readSecretValue(reference: string): Promise<string> {
  return readReference(reference, stripTrailingCliNewline)
}

/**
 * Read an OTP reference: the `otpauth://` seed URI, trimmed. Only the seed is
 * read here — the TOTP code itself stays lazy, see `resolveOtpReferences` in
 * `op.ts`.
 *
 * `splitReferences` assigns every reference to exactly one of the two branches
 * by its suffix, so a single reference can never be cached under both
 * normalizations.
 *
 * @param reference - The `op://` reference to read.
 * @returns The resolved `otpauth://` URI.
 */
export async function readOtpauthUri(reference: string): Promise<string> {
  return readReference(reference, (stdout) => stripTrailingCliNewline(stdout).trim())
}
