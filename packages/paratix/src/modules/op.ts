import { execFileSync } from "node:child_process"

import type { Environment, Module, ModuleResult } from "../types.js"

import { generateTotpCode } from "../totp.js"

const OTP_SUFFIX_PATTERN = /\/(?:one-time-password|otp)$/iv

const REFERENCE_PREFIX = "op://"

/**
 * Validate that all reference values start with `op://`.
 *
 * @param references - Map of logical names to 1Password references.
 * @throws {Error} If any reference does not start with `op://`.
 */
function validateReferences(references: Record<string, string>): void {
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
function splitReferences(
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

/**
 * Resolve regular (non-OTP) 1Password references in bulk via `op inject`.
 *
 * @param entries - Map of logical names to 1Password references.
 * @returns Resolved key-value pairs.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
function resolveRegularReferences(entries: Record<string, string>): Record<string, string> {
  if (Object.keys(entries).length === 0) return {}

  const injected = execFileSync("op", ["inject"], {
    encoding: "utf8",
    input: JSON.stringify(entries),
  })

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- op inject returns a JSON object matching the input shape
  const parsed: Record<string, string> = JSON.parse(injected)
  return parsed
}

/**
 * Resolve OTP 1Password references into lazy TOTP code generators.
 *
 * Each reference is resolved immediately via `op read` to obtain the
 * `otpauth://totp/...` URI, then wrapped in a lazy function so the TOTP
 * code is computed fresh on every access.
 *
 * @param entries - Map of logical names to OTP 1Password references.
 * @returns Map of logical names to lazy functions that compute fresh TOTP codes.
 * @throws {Error} If the `op` CLI is not available or the session is not authenticated.
 */
function resolveOtpReferences(entries: Record<string, string>): Environment {
  const result: Environment = {}

  for (const [name, reference] of Object.entries(entries)) {
    const otpauthUri = execFileSync("op", ["read", reference], {
      encoding: "utf8",
    }).trim()

    result[name] = () => generateTotpCode(otpauthUri)
  }

  return result
}

/**
 * Modules for resolving secrets from 1Password on the local controller.
 */
export const op = {
  /**
   * Resolve 1Password secret references into environment values.
   *
   * Regular references are resolved in bulk via `op inject`.
   * References ending in `/one-time-password` or `/otp` are resolved individually
   * via `op read` and returned as lazy functions that compute a fresh TOTP code
   * on each call.
   *
   * This module runs locally (`local: true`) and never touches the remote host.
   * `check` always returns `"ok"` — secrets are resolved unconditionally in `apply`.
   * If any CLI call fails the module returns `{ status: "failed" }`.
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
      // eslint-disable-next-line @typescript-eslint/require-await
      async apply(): Promise<ModuleResult> {
        try {
          const [regularEntries, otpEntries] = splitReferences(references)
          const resolvedRegular = resolveRegularReferences(regularEntries)
          const resolvedOtp = resolveOtpReferences(otpEntries)

          return { meta: { ...resolvedRegular, ...resolvedOtp }, status: "ok" }
        } catch {
          return { status: "failed" }
        }
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return "ok"
      },
      local: true,
      name: `op.resolve: ${Object.keys(references).join(", ")}`,
    }
  },
}
