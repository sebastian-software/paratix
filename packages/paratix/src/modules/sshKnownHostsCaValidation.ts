import { isIP } from "node:net"

import { assertValidUserName } from "./posixNames.js"
import { assertAuthorizedKeyValue } from "./sshPublicKeyValidation.js"

const SSH_STRING_LENGTH_BYTES = 4
const IPV6_VERSION = 6
const MAX_TCP_PORT = 65_535
const MIN_CA_LINE_FIELDS = 4

/** Options for managing one user's `@cert-authority` entry in `known_hosts`. */
export type KnownHostsCertAuthorityOptions =
  | { hosts: string[]; publicKey: string; state?: "present" }
  | { hosts?: string[]; publicKey: string; state: "absent" }

export type KnownHostsCaParameters = {
  key: string
  patterns: string[]
  state: "absent" | "present"
  user: string
}

/**
 * Validate the blob with the existing raw-key contract, then compare canonical bytes.
 *
 * @param value - The full public key, optionally followed by a comment.
 * @param strict - Whether the input must already use canonical base64.
 * @returns The validated algorithm and canonical base64, without a comment.
 */
export function canonicalKnownHostsCaKey(value: string, strict: boolean): string {
  assertTextValue(value, "publicKey")
  const trimmed = value.trim()
  assertAuthorizedKeyValue(trimmed)
  const [algorithm, encoded] = trimmed.split(/\s+/v)
  const bytes = Buffer.from(encoded, "base64")
  const algorithmLength = bytes.readUInt32BE(0)
  const encodedAlgorithm = bytes.subarray(
    SSH_STRING_LENGTH_BYTES,
    SSH_STRING_LENGTH_BYTES + algorithmLength
  )
  if (!encodedAlgorithm.equals(Buffer.from(algorithm, "utf8"))) {
    throw new Error(
      "ssh.knownHostsCertAuthority: publicKey algorithm must match its encoded bytes exactly"
    )
  }
  const canonical = bytes.toString("base64")
  if (strict && canonical !== encoded) {
    throw new Error("ssh.knownHostsCertAuthority: publicKey must use canonical base64")
  }
  return `${algorithm} ${canonical}`
}

function assertTextValue(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string") {
    throw new TypeError(`ssh.knownHostsCertAuthority: ${field} must be a string`)
  }
}

function assertHostPattern(pattern: unknown): asserts pattern is string {
  assertTextValue(pattern, "host pattern")
  if (
    pattern.length === 0 ||
    /[\s\p{Cc}\p{Cf}\p{Cs},!@#\|\\]/v.test(pattern) ||
    pattern.startsWith("-")
  ) {
    throw new Error(`ssh.knownHostsCertAuthority: invalid host pattern: ${JSON.stringify(pattern)}`)
  }
  if (!pattern.includes("[") && !pattern.includes("]")) {
    if (pattern.includes(":") && isIP(pattern) !== IPV6_VERSION) {
      throw new Error(`ssh.knownHostsCertAuthority: invalid IPv6 pattern: ${pattern}`)
    }
    return
  }
  assertPortQualifiedPattern(pattern)
}

function assertPortQualifiedPattern(pattern: string): void {
  const qualified = /^\[(?<host>[^\[\]]+)\]:(?<port>\d+)$/v.exec(pattern)
  if (qualified === null) {
    throw new Error(`ssh.knownHostsCertAuthority: invalid port-qualified pattern: ${pattern}`)
  }
  const host = qualified.groups?.host ?? ""
  const port = Number(qualified.groups?.port)
  if (port < 1 || port > MAX_TCP_PORT || (host.includes(":") && isIP(host) !== IPV6_VERSION)) {
    throw new Error(`ssh.knownHostsCertAuthority: invalid host or port: ${pattern}`)
  }
}

function caState(value: unknown): "absent" | "present" {
  const state = value === undefined ? "present" : value
  if (state !== "present" && state !== "absent") {
    throw new Error('ssh.knownHostsCertAuthority state must be "present" or "absent"')
  }
  return state
}

function hostPatterns(value: unknown): string[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    throw new TypeError("ssh.knownHostsCertAuthority: hosts must be an array")
  }
  const patterns: string[] = []
  for (const pattern of value) {
    assertHostPattern(pattern)
    patterns.push(pattern)
  }
  return patterns
}

export function knownHostsCaParameters(
  user: string,
  options: KnownHostsCertAuthorityOptions
): KnownHostsCaParameters {
  assertTextValue(user, "user")
  assertValidUserName(user)
  const state = caState(options.state)
  const key = canonicalKnownHostsCaKey(options.publicKey, true)
  const patterns = hostPatterns(options.hosts)
  if (state === "present" && patterns.length === 0) {
    throw new Error("ssh.knownHostsCertAuthority: hosts must not be empty for present")
  }
  return { key, patterns: [...new Set(patterns)].sort(), state, user }
}

function lineHasCaIdentity(line: string, key: string): boolean {
  // OpenSSH separators are ASCII; UTF-8 continuation bytes must remain inside host patterns.
  const parts = line.replace(/^[ \t]+/v, "").split(/[ \t\r\n]+/v)
  if (parts[0] !== "@cert-authority" || parts.length < MIN_CA_LINE_FIELDS) return false
  try {
    return canonicalKnownHostsCaKey(`${parts[2]} ${parts[3]}`, false) === key
  } catch {
    return false
  }
}

/**
 * Preserve every unrelated byte, including blank lines and a missing final LF.
 *
 * @param content - Original bytes represented as a Latin-1 string.
 * @param parameters - The validated CA identity and desired patterns and state.
 * @returns Reconciled bytes represented as a Latin-1 string.
 */
export function reconcileKnownHostsCa(content: string, parameters: KnownHostsCaParameters): string {
  // Snapshots store raw bytes as Latin-1; encode authored text as UTF-8 before joining it.
  const canonical = Buffer.from(
    `@cert-authority ${parameters.patterns.join(",")} ${parameters.key}\n`,
    "utf8"
  ).toString("latin1")
  const lines = content.split("\n")
  const records = lines.map((line, index) => (index === lines.length - 1 ? line : `${line}\n`))
  let inserted = false
  const preserved: string[] = []
  for (const record of records) {
    if (!lineHasCaIdentity(record, parameters.key)) {
      preserved.push(record)
      continue
    }
    if (parameters.state === "present" && !inserted) {
      preserved.push(canonical)
      inserted = true
    }
  }
  const result = preserved.join("")
  if (parameters.state === "absent" || inserted) return result
  return `${result}${result.length > 0 && !result.endsWith("\n") ? "\n" : ""}${canonical}`
}
