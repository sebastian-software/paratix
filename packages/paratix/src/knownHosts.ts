import { createHash, createHmac, timingSafeEqual } from "node:crypto"
import { readFileSync } from "node:fs"
import { appendFile, mkdir } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"

import { shellQuote } from "./sshHelpers.js"

type HostVerifierOptions = {
  expectedHostFingerprint?: string
  expectedHostPublicKey?: string
}

export type HostVerifierResult = {
  hostVerifier?: (key: Buffer) => boolean
  pendingPersist?: Promise<void>
}

type HostLocation = {
  host: string
  port: number
}

/** Thrown when a remote host key does not match the expected key in known_hosts. */
export class HostKeyVerificationError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = "HostKeyVerificationError"
    Error.captureStackTrace(this, HostKeyVerificationError)
  }
}

/** A parsed entry from a known_hosts file. */
export type KnownHostEntry = {
  /** Algorithm name as stored in the file (e.g. `"ssh-ed25519"`). */
  algo: string
  /** Host pattern as stored in the file (plain hostname or `[host]:port` notation). */
  host: string
  /** Raw public key bytes decoded from the Base64 field. */
  key: Buffer
  /** Optional OpenSSH marker such as `@revoked`. */
  marker?: string
}

/** Minimum number of whitespace-separated fields in a valid known_hosts line. */
const MIN_KNOWN_HOSTS_FIELDS = 3

/** The default SSH port used by OpenSSH. */
const DEFAULT_SSH_PORT = 22

/** Byte size of the uint32 length prefix in SSH wire format. */
const UINT32_SIZE = 4
const HASHED_HOST_PARTS = 4

/**
 * In-memory cache for accepted host keys that could not be persisted to disk.
 * Keyed by the formatted host needle (e.g. `"example.com"` or `"[example.com]:2222"`).
 */
const inMemoryHostKeys = new Map<string, Buffer>()

/**
 * Clear the in-memory host key cache. Intended for use in tests.
 */
export function clearHostKeyCache(): void {
  inMemoryHostKeys.clear()
}

function parseKnownHostsLine(line: string): KnownHostEntry[] {
  const parts = line.split(/\s+/v)
  const offset = parts[0]?.startsWith("@") ? 1 : 0
  if (parts.length < MIN_KNOWN_HOSTS_FIELDS + offset) return []

  const marker = offset === 1 ? parts[0] : undefined
  const hostsPart = parts[offset]
  const algo = parts[offset + 1]
  const base64Key = parts[offset + 2]

  const key = Buffer.from(base64Key, "base64")
  return hostsPart.split(",").map((host) => ({ algo, host, key, marker }))
}

/**
 * Parse the contents of an OpenSSH `known_hosts` file into structured entries.
 *
 * - Blank lines and comment lines (starting with `#`) are skipped.
 * - Hosts separated by commas produce one entry per hostname.
 *
 * @param content - The raw file content.
 * @returns An array of parsed entries.
 */
export function parseKnownHosts(content: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = []
  for (const raw of content.split("\n")) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith("#")) continue
    entries.push(...parseKnownHostsLine(line))
  }
  return entries
}

/**
 * Format the host lookup needle for known_hosts matching.
 *
 * For port 22 the plain hostname is returned. For non-standard ports the
 * bracketed `[host]:port` notation is used, matching OpenSSH behavior.
 *
 * @param host - The hostname or IP.
 * @param port - The SSH port.
 * @returns The formatted needle string.
 */
function formatHostNeedle(host: string, port: number): string {
  return port === DEFAULT_SSH_PORT ? host : `[${host}]:${port}`
}

/**
 * Look up a host key in the parsed known_hosts entries.
 *
 * @param pattern - The stored OpenSSH hashed host pattern.
 * @param needle - The formatted host lookup needle.
 * @returns Whether the hashed entry matches the target host.
 */
function matchesHashedHost(pattern: string, needle: string): boolean {
  if (!pattern.startsWith("|1|")) return false

  const parts = pattern.split("|")
  if (parts.length !== HASHED_HOST_PARTS || parts[1] !== "1") return false

  const salt = Buffer.from(parts[2] ?? "", "base64")
  const expectedHash = Buffer.from(parts[3] ?? "", "base64")
  if (salt.length === 0 || expectedHash.length === 0) return false

  const actualHash = createHmac("sha1", salt).update(needle).digest()
  return actualHash.length === expectedHash.length && timingSafeEqual(actualHash, expectedHash)
}

function findMatchingEntries(
  entries: KnownHostEntry[],
  host: string,
  port: number
): KnownHostEntry[] {
  const needle = formatHostNeedle(host, port)
  return entries.filter((entry) => entry.host === needle || matchesHashedHost(entry.host, needle))
}

function lookupHostEntry(
  entries: KnownHostEntry[],
  host: string,
  port: number
): KnownHostEntry | null {
  const match = findMatchingEntries(entries, host, port).find(
    (entry) => entry.marker !== "@revoked"
  )
  return match ?? null
}

function findRevokedEntry(entries: KnownHostEntry[], key: Buffer): KnownHostEntry | undefined {
  return entries.find(
    (entry) =>
      entry.marker === "@revoked" &&
      entry.key.length === key.length &&
      timingSafeEqual(entry.key, key)
  )
}

function throwHostKeyMismatch(host: string, presentedKey: Buffer, existingKey?: Buffer): never {
  const presentedAlgo = extractAlgoFromKey(presentedKey)
  const knownHostsDetails =
    existingKey == null
      ? "remote host key does not match the key in known_hosts. "
      : `remote host key (${presentedAlgo}) does not match the key in known_hosts (${extractAlgoFromKey(existingKey)}). `
  throw new HostKeyVerificationError(
    `HOST KEY VERIFICATION FAILED for ${host}: ${knownHostsDetails}` +
      "This could indicate a man-in-the-middle attack."
  )
}

function verifyHostKeyAgainstKnownEntries(parameters: {
  cachedKey: Buffer | null
  fileEntries: KnownHostEntry[]
  host: string
  key: Buffer
}): boolean {
  const { cachedKey, fileEntries, host, key } = parameters
  const revokedKey = findRevokedEntry(fileEntries, key)
  if (revokedKey != null) {
    throw new HostKeyVerificationError(
      `HOST KEY VERIFICATION FAILED for ${host}: remote host key (${extractAlgoFromKey(revokedKey.key)}) is marked as revoked in known_hosts.`
    )
  }

  const existingKey = fileEntries.find((entry) => entry.marker !== "@revoked")?.key ?? cachedKey
  if (existingKey != null) {
    if (existingKey.length === key.length && timingSafeEqual(existingKey, key)) return true
    throwHostKeyMismatch(host, key, existingKey)
  }
  if (fileEntries.length > 0) throwHostKeyMismatch(host, key)
  return false
}

export function lookupHostKey(
  entries: KnownHostEntry[],
  host: string,
  port: number
): Buffer | null {
  return lookupHostEntry(entries, host, port)?.key ?? null
}

/**
 * Extract the algorithm name from an SSH public key in wire format.
 *
 * The SSH wire format starts with a `uint32` length prefix followed by the
 * algorithm name as an ASCII string.
 *
 * @param keyBuffer - The raw public key buffer.
 * @returns The algorithm name (e.g. `"ssh-ed25519"`).
 */
export function extractAlgoFromKey(keyBuffer: Buffer): string {
  if (keyBuffer.length < UINT32_SIZE) {
    throw new Error("Invalid SSH key buffer: too short to contain algorithm length")
  }
  const algoLength = keyBuffer.readUInt32BE(0)
  if (algoLength === 0 || UINT32_SIZE + algoLength > keyBuffer.length) {
    throw new Error("Invalid SSH key buffer: algorithm length exceeds buffer size")
  }
  return keyBuffer.subarray(UINT32_SIZE, UINT32_SIZE + algoLength).toString("ascii")
}

/**
 * Compute the SHA256 fingerprint of an SSH public key in OpenSSH format.
 *
 * The result matches the fingerprint shown by `ssh-keygen -l`, e.g.
 * `SHA256:AbCdEf...`. Trailing `=` padding characters are stripped from the
 * base64 digest to conform to the OpenSSH fingerprint representation.
 *
 * @param key - The raw public key buffer (SSH wire format).
 * @returns The fingerprint string prefixed with `SHA256:`.
 */
export function computeFingerprint(key: Buffer): string {
  const hash = createHash("sha256").update(key).digest("base64")
  // Remove trailing '=' padding to match OpenSSH format
  return `SHA256:${hash.replaceAll("=", "")}`
}

/**
 * Append a new host key entry to `~/.ssh/known_hosts`.
 *
 * Creates the `~/.ssh` directory (mode `0o700`) and the file itself if they
 * do not exist yet.
 *
 * @param host - The hostname or IP.
 * @param port - The SSH port.
 * @param keyBuffer - The raw public key buffer.
 */
export async function appendHostKey(host: string, port: number, keyBuffer: Buffer): Promise<void> {
  const hostLabel = formatHostNeedle(host, port)
  const algo = extractAlgoFromKey(keyBuffer)
  const base64Key = keyBuffer.toString("base64")
  const line = `${hostLabel} ${algo} ${base64Key}\n`

  const sshDirectory = join(homedir(), ".ssh")
  const filePath = join(sshDirectory, "known_hosts")

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  await mkdir(sshDirectory, { mode: 0o700, recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  await appendFile(filePath, line, { mode: 0o644 })
}

/**
 * Read and parse `~/.ssh/known_hosts`, returning an empty array on failure.
 *
 * @returns The parsed entries.
 */
function loadKnownHostEntries(): KnownHostEntry[] {
  const filePath = join(homedir(), ".ssh", "known_hosts")
  let content = ""
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    content = readFileSync(filePath, "utf8")
  } catch {
    // File may not exist yet — treat as empty
  }
  return parseKnownHosts(content)
}

/**
 * Accept an unknown host key, warn to stderr, and persist it to `~/.ssh/known_hosts`.
 *
 * The key is immediately stored in the in-memory cache so subsequent connections
 * within the same process succeed even if the disk write fails. If writing to
 * disk fails, a recovery hint with the equivalent `ssh-keyscan` command is
 * printed to stderr.
 *
 * @param host - The hostname or IP of the remote host.
 * @param port - The SSH port of the remote host.
 * @param key - The raw public key buffer presented by the remote host.
 * @returns A promise that resolves once the key has been written to disk (or the write error has been handled).
 */
async function acceptAndPersistHostKey(host: string, port: number, key: Buffer): Promise<void> {
  try {
    const algo = extractAlgoFromKey(key)
    const fingerprint = computeFingerprint(key)
    process.stderr.write(
      `WARNING: Permanently added '${host}' (${algo}) to the list of known hosts. ` +
        `Fingerprint: ${fingerprint}\n`
    )
  } catch {
    process.stderr.write(`WARNING: Permanently added '${host}' to the list of known hosts.\n`)
  }
  inMemoryHostKeys.set(formatHostNeedle(host, port), key)
  try {
    await appendHostKey(host, port, key)
  } catch (error: unknown) {
    const keyscanArguments =
      port === DEFAULT_SSH_PORT ? shellQuote(host) : `-p ${port} ${shellQuote(host)}`
    process.stderr.write(
      `WARNING: Could not persist host key for ${host} — ` +
        `the key is cached in memory for this session. ` +
        `To persist it, ensure ~/.ssh/ is writable or run: ` +
        `ssh-keyscan ${keyscanArguments} >> ~/.ssh/known_hosts. ` +
        `${String(error)}\n`
    )
  }
}

function normalizePinnedPublicKey(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/v)
  if (parts.length < 2) {
    throw new Error("Expected host public key must use the format '<algorithm> <base64>'")
  }
  const [algorithm, key] = parts
  return `${algorithm} ${key}`
}

function formatPresentedPublicKey(key: Buffer): string {
  return `${extractAlgoFromKey(key)} ${key.toString("base64")}`
}

function hasPinnedHostTrustAnchor(options?: HostVerifierOptions): boolean {
  return options?.expectedHostFingerprint != null || options?.expectedHostPublicKey != null
}

function verifyPinnedHostKey(host: string, key: Buffer, options: HostVerifierOptions): void {
  const normalizedExpectedPublicKey =
    options.expectedHostPublicKey == null
      ? null
      : normalizePinnedPublicKey(options.expectedHostPublicKey)
  const expectedFingerprint = options.expectedHostFingerprint ?? null
  const presentedPublicKey = formatPresentedPublicKey(key)
  const presentedFingerprint = computeFingerprint(key)

  if (
    normalizedExpectedPublicKey === presentedPublicKey ||
    expectedFingerprint === presentedFingerprint
  ) {
    return
  }

  throw new HostKeyVerificationError(
    `HOST KEY VERIFICATION FAILED for ${host}: the remote host key does not match the configured trust anchor.`
  )
}

/**
 * Build the `hostVerifier` callback for an ssh2 `ConnectConfig`.
 *
 * Behavior by mode:
 * - `"no"` — returns an empty object (no verification, ssh2 default).
 * - `"accept-new"` — accepts unknown keys and appends them to `~/.ssh/known_hosts`;
 *   throws if a known key does not match.
 * - `"yes"` — throws for both unknown keys and mismatched keys.
 *
 * @param mode - The host key verification strategy.
 * @param location - The target host and SSH port.
 * @param options - Optional pinned trust anchors for the remote host.
 * @returns An object with `hostVerifier` set (or empty for mode `"no"`).
 * @throws {Error} When a known host key does not match the presented key (all modes except `"no"`).
 * @throws {Error} When no known_hosts entry exists for the host and mode is `"yes"`.
 */
export function buildHostVerifier(
  mode: "accept-new" | "no" | "yes",
  location: HostLocation,
  options: HostVerifierOptions = {}
): HostVerifierResult {
  const { host, port } = location
  if (mode === "no" && !hasPinnedHostTrustAnchor(options)) return {}

  const entries = loadKnownHostEntries()
  const fileEntries = findMatchingEntries(entries, host, port)
  const cachedKey = inMemoryHostKeys.get(formatHostNeedle(host, port)) ?? null

  const result: { hostVerifier: (key: Buffer) => boolean } & HostVerifierResult = {
    hostVerifier(key: Buffer): boolean {
      if (
        mode !== "no" &&
        verifyHostKeyAgainstKnownEntries({ cachedKey, fileEntries, host, key })
      ) {
        if (hasPinnedHostTrustAnchor(options)) verifyPinnedHostKey(host, key, options)
        return true
      }
      if (hasPinnedHostTrustAnchor(options)) {
        verifyPinnedHostKey(host, key, options)
        return true
      }
      if (mode === "yes") {
        throw new HostKeyVerificationError(
          `Host key for ${host} not found in known_hosts. ` +
            'Set strictHostKeyChecking to "accept-new" for explicit TOFU or configure ssh.expectedHostFingerprint / ssh.expectedHostPublicKey.'
        )
      }
      if (mode === "no") return true
      // mode === "accept-new": accept and persist
      result.pendingPersist = acceptAndPersistHostKey(host, port, key)
      return true
    },
  }
  return result
}
