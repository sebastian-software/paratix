import { inspect, type InspectOptions } from "node:util"

/**
 * Token placed in the redacted graph wherever a binary value used to live.
 * Mirrors the masking style used elsewhere in the CLI so operators can grep
 * for "[REDACTED" and find every sensitive payload that was elided.
 */
export const REDACTED_BINARY_PLACEHOLDER = "[REDACTED Buffer]"
export const REDACTED_SECRET_FIELD_PLACEHOLDER = "[REDACTED]"

/**
 * Keys we must skip even if they appear as own properties so an
 * attacker-controlled error graph cannot mutate the freshly created clone's
 * prototype chain. `Object.create(null)` already removes Object.prototype,
 * but explicit skip is cheap defence-in-depth for the rare case the clone
 * gets re-rooted onto a non-null prototype downstream.
 */
const REDACT_FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"])
// Cover common credential-bearing field names that may appear in plain object
// diagnostics from SDKs, HTTP clients, and module wrappers.
const SECRET_FIELD_NAMES = new Set([
  "apikey",
  "auth",
  "authorization",
  "bearer",
  "cookie",
  "cred",
  "credential",
  "credentials",
  "jwt",
  "key",
  "mfa",
  "otp",
  "pass",
  "passphrase",
  "passwd",
  "password",
  "pin",
  "privatekey",
  "pwd",
  "secret",
  "sessionkey",
  "signature",
  "token",
])

const SECRET_FIELD_SUFFIXES = [
  "token",
  "password",
  "secret",
  "privatekey",
  "sessionkey",
  "signature",
  "jwt",
  "pin",
  "mfa",
  "otp",
  "cookie",
]

function isBufferLikeView(value: unknown): boolean {
  if (Buffer.isBuffer(value)) return true
  if (value instanceof ArrayBuffer) return true
  return ArrayBuffer.isView(value)
}

function isAsciiAlphaNumeric(character: string): boolean {
  return (character >= "0" && character <= "9") || (character >= "a" && character <= "z")
}

export function isSecretDiagnosticField(key: string): boolean {
  let normalized = ""
  for (const character of key.toLowerCase()) {
    if (isAsciiAlphaNumeric(character)) normalized += character
  }
  if (SECRET_FIELD_NAMES.has(normalized)) return true
  return SECRET_FIELD_SUFFIXES.some((suffix) => normalized.endsWith(suffix))
}

function copyRedactedProperty(parameters: {
  depth: number
  destinationKey: string
  maxDepth: number
  redacted: Record<string, unknown>
  seen: WeakSet<object>
  source: Record<string, unknown>
  sourceKey: PropertyKey
}): void {
  const { depth, destinationKey, maxDepth, redacted, seen, source, sourceKey } = parameters
  const descriptor = Object.getOwnPropertyDescriptor(source, sourceKey)
  if (descriptor == null) return
  if (!("value" in descriptor)) {
    redacted[destinationKey] = "[Accessor]"
    return
  }
  const descriptorValue: unknown = descriptor.value
  if (isSecretDiagnosticField(destinationKey) && !isBufferLikeView(descriptorValue)) {
    redacted[destinationKey] = REDACTED_SECRET_FIELD_PLACEHOLDER
    return
  }
  redacted[destinationKey] = redactBinaryValues(descriptorValue, {
    depth: depth + 1,
    maxDepth,
    seen,
  })
}

function redactObjectProperties(parameters: {
  depth: number
  maxDepth: number
  seen: WeakSet<object>
  sourceRecord: Record<string, unknown>
}): Record<string, unknown> {
  const { depth, maxDepth, seen, sourceRecord } = parameters
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- intentional: Object.create(null) is the prototype-pollution defense
  const redacted: Record<string, unknown> = Object.create(null) as Record<string, unknown>
  for (const key of Object.keys(sourceRecord)) {
    if (REDACT_FORBIDDEN_KEYS.has(key)) continue
    copyRedactedProperty({
      depth,
      destinationKey: key,
      maxDepth,
      redacted,
      seen,
      source: sourceRecord,
      sourceKey: key,
    })
  }
  for (const symbolKey of Object.getOwnPropertySymbols(sourceRecord)) {
    copyRedactedProperty({
      depth,
      destinationKey: `@@symbol:${symbolKey.toString()}`,
      maxDepth,
      redacted,
      seen,
      source: sourceRecord,
      sourceKey: symbolKey,
    })
  }
  return redacted
}

export function redactBinaryValues(
  value: unknown,
  options: { depth?: number; maxDepth: number; seen?: WeakSet<object> }
): unknown {
  const { depth = 0, maxDepth, seen = new WeakSet<object>() } = options
  if (isBufferLikeView(value)) return REDACTED_BINARY_PLACEHOLDER
  if (value === null || typeof value !== "object") return value
  if (depth > maxDepth) return value
  if (seen.has(value)) return "[Circular]"
  seen.add(value)
  if (Array.isArray(value)) {
    return value.map((entry) => redactBinaryValues(entry, { depth: depth + 1, maxDepth, seen }))
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- the prior object/array guards prove that keys can be enumerated safely
  const sourceRecord = value as Record<string, unknown>
  return redactObjectProperties({ depth, maxDepth, seen, sourceRecord })
}

export function inspectRedactedDiagnosticValue(
  value: unknown,
  options: { redactMaxDepth: number } & InspectOptions
): string {
  const { redactMaxDepth, ...inspectOptions } = options
  const sanitized = redactBinaryValues(value, { maxDepth: redactMaxDepth })
  return inspect(sanitized, inspectOptions)
}
