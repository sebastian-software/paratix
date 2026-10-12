import type { SecretRequest } from "./secretResolution.js"

/** 1Password reference validation and preparation for the shared lifecycle. */
import { assertValidTotpSeed, generateTotpCode } from "../totp.js"
import { spawnWithInput } from "./opSpawnRunner.js"

const OTP_SUFFIX_PATTERN = /\/(?:one-time-password|otp)$/iv
const REFERENCE_PREFIX = "op://"

/**
 * Preserve the legacy entry point's reference validation boundary.
 * @param references - Logical names and unchanged provider references.
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
 * Classify legacy unmarked references without interpreting a query string.
 * @param references - Logical names and unchanged provider references.
 * @returns Ordinary fields followed by legacy OTP fields.
 */
export function splitReferences(
  references: Record<string, string>
): [Record<string, string>, Record<string, string>] {
  const regularEntries: Record<string, string> = {}
  const otpEntries: Record<string, string> = {}
  for (const [name, reference] of Object.entries(references)) {
    if (OTP_SUFFIX_PATTERN.test(reference)) otpEntries[name] = reference
    else regularEntries[name] = reference
  }
  return [regularEntries, otpEntries]
}

async function readField(reference: string): Promise<string> {
  const stdout = await spawnWithInput("op", ["read", "--", reference], { input: "" })
  return stdout.replace(/\r?\n$/v, "")
}

/**
 * Only query selection chooses the marked loader; the reference stays opaque.
 * @param reference - Unchanged provider reference.
 * @returns Whether the reference requests a stored seed or a current code.
 */
function markedSourceKind(reference: string): "code" | "seed" {
  const queryStart = reference.indexOf("?")
  const query = queryStart === -1 ? "" : reference.slice(queryStart + 1)
  const selectors = [...new URLSearchParams(query)].filter(
    ([name]) => name === "attribute" || name === "attr"
  )
  if (selectors.length > 1) {
    throw new Error("Marked 1Password TOTP reference has conflicting attribute selectors")
  }
  const attribute = selectors.length === 0 ? undefined : selectors[0][1]
  if (attribute == null || attribute === "value") return "seed"
  if (attribute === "otp") return "code"
  throw new Error("Marked 1Password TOTP reference requires a value or otp attribute")
}

/**
 * Prepare a reference without reading a secret or rewriting the CLI argument.
 * @param name - Logical environment name.
 * @param reference - Unchanged provider reference.
 * @param markedTotp - Whether the caller explicitly requested per-access TOTP.
 * @returns A provider request for the shared module lifecycle.
 */
export function prepareOpRequest(
  name: string,
  reference: string,
  markedTotp = false
): SecretRequest {
  validateReferences({ [name]: reference })
  if (markedTotp && markedSourceKind(reference) === "code") {
    return {
      name,
      reference,
      resolution: "per-access",
      resolve: async () => readField(reference),
    }
  }
  const request: SecretRequest = {
    early: { cacheKey: reference, load: async () => readField(reference) },
    name,
    reference,
  }
  if (!markedTotp && !OTP_SUFFIX_PATTERN.test(reference)) return request
  return {
    ...request,
    prepare: (value) => value.trim(),
    ...(markedTotp ? ({ resolution: "per-access", validate: assertValidTotpSeed } as const) : {}),
    resolve(value = "") {
      // The seed is observed and registered before the shared core creates
      // this lazy resolver. Preserve the legacy diagnostic and safe cause.
      try {
        return generateTotpCode(value)
      } catch (error) {
        throw new Error(`Failed to generate TOTP code for ${JSON.stringify(name)}`, {
          cause: error,
        })
      }
    },
  }
}

/**
 * Keep ordinary fields before all legacy or marked TOTP requests.
 * @param requests - Prepared requests in binding order.
 * @returns A stable ordinary-before-TOTP ordering.
 */
export function orderOpRequests(requests: SecretRequest[]): SecretRequest[] {
  return [
    ...requests.filter((request) => request.resolve == null),
    ...requests.filter((request) => request.resolve != null),
  ]
}
