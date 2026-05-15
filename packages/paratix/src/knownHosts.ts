/* eslint-disable max-lines -- known_hosts lock, parser, verifier, and persist helpers stay co-located */
import { createHash, timingSafeEqual } from "node:crypto"
import { readFileSync } from "node:fs"
import { appendFile, mkdir } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"

import { matchesKnownHostPatternList } from "./knownHostPatterns.js"
import { shellQuote } from "./sshHelpers.js"

/**
 * R-0000151 / R-0000194: serialize every read and write against
 * `~/.ssh/known_hosts` through a single in-process mutex. `appendHostKey`
 * runs writes via `appendFile` and `buildHostVerifier` reads the file via
 * `readFileSync`. Both paths must share the same queue, otherwise a
 * synchronous read from a parallel handshake could observe a partially
 * written line that `parseKnownHostsLine` would discard, leaking a valid
 * trust anchor.
 */
let knownHostsLock: Promise<unknown> = Promise.resolve()

/**
 * Run `operation` while holding the known_hosts mutex. Both writes
 * (`appendHostKey`) and reads (`buildHostVerifier` -> `loadKnownHostEntries`)
 * funnel through this helper so they observe each other in FIFO order and a
 * synchronous read never overlaps with an async append in flight.
 *
 * @param operation - The read or write to perform while the lock is held.
 * @returns The value returned by `operation` once the lock has been acquired.
 */
async function withKnownHostsLock<T>(operation: () => Promise<T> | T): Promise<T> {
  const previous = knownHostsLock
  const next = previous.then(async () => operation())
  // Suppress unhandled-rejection bookkeeping on the chained sentinel; callers
  // observe the real settlement through the returned `next` promise.
  knownHostsLock = next.catch(() => null)
  return next
}

type HostVerifierOptions = {
  cache?: HostKeyCache
  expectedHostFingerprint?: string
  expectedHostPublicKey?: string
}

export type HostVerifierResult = {
  commitAcceptedHostKey?: () => Promise<void>
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
  /** OpenSSH comma-separated host pattern list from the original line. */
  hostPatterns?: string[]
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

/**
 * Strict base64 alphabet used to validate the key field of a known_hosts line.
 *
 * `Buffer.from(value, "base64")` silently ignores invalid characters which would
 * truncate corrupt or tampered entries instead of rejecting them. We therefore
 * reject anything that contains whitespace, padding inside the body, or any
 * character outside the standard base64 alphabet before decoding.
 */
const STRICT_BASE64_PATTERN = /^[A-Za-z0-9+\/]+=*$/v

/**
 * R-0000204: human-readable hint surfaced when a `@cert-authority` entry is
 * encountered. paratix does not validate OpenSSH certificates and refuses to
 * silently fall through to accept-new.
 */
const CERT_AUTHORITY_MESSAGE =
  "HOST KEY VERIFICATION FAILED — known_hosts contains a @cert-authority entry, " +
  "but paratix does not validate certificate-authority host keys. " +
  "Remove the @cert-authority marker or pin the host with ssh.expectedHostFingerprint / " +
  "ssh.expectedHostPublicKey instead."

/**
 * In-memory cache for accepted host keys that could not be persisted to disk.
 * Keyed by the formatted host needle (e.g. `"example.com"` or `"[example.com]:2222"`).
 *
 * R-0000479: the cache is no longer a hidden module-level singleton. Each
 * `SshConnectionImpl` instance owns its own {@link HostKeyCache} so that two
 * parallel SSH connections to the same `[host]:port` cannot overwrite each
 * other's pinned host keys. The exported {@link createHostKeyCache} factory
 * builds a fresh per-instance cache; callers that omit the argument (only the
 * legacy test helpers do this) fall back to the module-level
 * {@link defaultHostKeyCache} so existing fixtures keep working.
 */
export type HostKeyCache = Map<string, Buffer>

const defaultHostKeyCache: HostKeyCache = new Map<string, Buffer>()

/**
 * Build a fresh per-connection host key cache. Each `SshConnectionImpl`
 * allocates one and passes it to {@link buildHostVerifier} for every connect
 * / reconnect attempt; that keeps the in-memory trust state scoped to the
 * owning connection while preserving process-lifetime caching across
 * reconnects of the same instance.
 *
 * @returns A fresh, empty per-connection host key cache.
 */
export function createHostKeyCache(): HostKeyCache {
  return new Map<string, Buffer>()
}

/**
 * Clear the module-level default host key cache. Intended for use in tests
 * that do not allocate their own {@link HostKeyCache}; tests with explicit
 * caches simply discard them between cases.
 */
export function clearHostKeyCache(): void {
  defaultHostKeyCache.clear()
}

/**
 * Wait until every queued known_hosts read or write has finished.
 *
 * R-0000151 / R-0000194: callers that need a synchronous read to observe the
 * result of concurrent persists can `await` this helper first; this drains
 * the known_hosts mutex so subsequent `readFileSync` calls see a consistent
 * file with no partially-written lines in flight. `buildHostVerifier` already
 * routes its read through the lock, so this helper is mainly intended for
 * tests and out-of-band callers.
 */
export async function waitForKnownHostsWrites(): Promise<void> {
  await knownHostsLock.catch(() => null)
}

function parseKnownHostsLine(line: string): KnownHostEntry[] {
  const parts = line.split(/\s+/v)
  const offset = parts[0]?.startsWith("@") ? 1 : 0
  if (parts.length < MIN_KNOWN_HOSTS_FIELDS + offset) return []

  const marker = offset === 1 ? parts[0] : undefined
  const hostsPart = parts[offset]
  const algo = parts[offset + 1]
  const base64Key = parts[offset + 2]

  // Reject entries whose key field is not strict base64. `Buffer.from` would
  // otherwise drop unknown characters and produce a truncated buffer, which
  // could let corrupt or tampered known_hosts entries influence later lookups
  // such as findRevokedEntry.
  if (!STRICT_BASE64_PATTERN.test(base64Key)) return []

  const key = Buffer.from(base64Key, "base64")
  const hostPatterns = hostsPart.split(",")
  return hostPatterns.map((host) => ({ algo, host, hostPatterns, key, marker }))
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

function matchesKnownHostEntry(entry: KnownHostEntry, needle: string): boolean {
  return matchesKnownHostPatternList(entry.hostPatterns ?? [entry.host], needle)
}

function findMatchingEntries(
  entries: KnownHostEntry[],
  host: string,
  port: number
): KnownHostEntry[] {
  const needle = formatHostNeedle(host, port)
  return entries.filter((entry) => matchesKnownHostEntry(entry, needle))
}

function lookupHostEntry(
  entries: KnownHostEntry[],
  host: string,
  port: number
): KnownHostEntry | null {
  const match = findMatchingEntries(entries, host, port).find((entry) => entry.marker == null)
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
  // R-0000210: both buffers can be untrusted (presented key from a remote
  // peer, existing key from a possibly-tampered known_hosts entry). Use the
  // non-throwing variant so a malformed wire format surfaces as a clean
  // HostKeyVerificationError instead of a RangeError.
  const presentedAlgo = describeAlgoForDiagnostics(presentedKey)
  const knownHostsDetails =
    existingKey == null
      ? "remote host key does not match the key in known_hosts. "
      : `remote host key (${presentedAlgo}) does not match the key in known_hosts (${describeAlgoForDiagnostics(existingKey)}). `
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
    // R-0000210: the matched entry came from disk and may have a malformed
    // wire-format buffer; fall back to "<unknown>" rather than letting a
    // RangeError escape past HostKeyVerificationError.
    throw new HostKeyVerificationError(
      `HOST KEY VERIFICATION FAILED for ${host}: remote host key (${describeAlgoForDiagnostics(revokedKey.key)}) is marked as revoked in known_hosts.`
    )
  }
  // R-0000204: paratix does not implement `@cert-authority` validation.
  // Refuse rather than silently append a duplicate raw-key entry next to
  // the CA line via accept-new.
  if (fileEntries.some((entry) => entry.marker === "@cert-authority"))
    throw new HostKeyVerificationError(`${host}: ${CERT_AUTHORITY_MESSAGE}`)

  const rawHostKeyEntries = fileEntries.filter((entry) => entry.marker == null)
  const matchingEntry = rawHostKeyEntries.find(
    (entry) => entry.key.length === key.length && timingSafeEqual(entry.key, key)
  )
  if (matchingEntry != null) return true
  if (cachedKey?.length === key.length && timingSafeEqual(cachedKey, key)) {
    return true
  }

  const firstRawHostKey = rawHostKeyEntries.at(0)?.key
  if (firstRawHostKey != null) throwHostKeyMismatch(host, key, firstRawHostKey)
  if (cachedKey != null) throwHostKeyMismatch(host, key, cachedKey)
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
 * R-0000210: non-throwing variant of {@link extractAlgoFromKey} for
 * untrusted input (corrupt revoked entries, presented host keys from a
 * malicious peer). Callers that only want the algorithm for diagnostics
 * use this and fall back to a placeholder so a malformed buffer surfaces
 * as a {@link HostKeyVerificationError} rather than a generic `RangeError`.
 *
 * @param keyBuffer - The raw public key buffer (possibly malformed).
 * @returns The algorithm name, or `"<unknown>"` when the buffer cannot be parsed.
 */
function describeAlgoForDiagnostics(keyBuffer: Buffer): string {
  try {
    return extractAlgoFromKey(keyBuffer)
  } catch {
    return "<unknown>"
  }
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
 * R-0000151 / R-0000194: the append is serialized through
 * {@link withKnownHostsLock} so concurrent invocations cannot interleave
 * partial writes. The same lock also fences the read path inside
 * {@link buildHostVerifier}, so a verifier scheduled after this call always
 * sees the appended line in full.
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

  await withKnownHostsLock(async () => {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    await mkdir(sshDirectory, { mode: 0o700, recursive: true })
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    await appendFile(filePath, line, { mode: 0o644 })
  })
}

function getFileSystemErrorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : undefined
}

/**
 * Read and parse `~/.ssh/known_hosts`.
 *
 * A missing file is treated as an empty trust store. Other read failures fail
 * closed so `accept-new` cannot bypass an unreadable existing trust anchor.
 *
 * @returns The parsed entries.
 */
function loadKnownHostEntries(): KnownHostEntry[] {
  const filePath = join(homedir(), ".ssh", "known_hosts")
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    return parseKnownHosts(readFileSync(filePath, "utf8"))
  } catch (error) {
    if (getFileSystemErrorCode(error) === "ENOENT") {
      return []
    }
    throw new HostKeyVerificationError(
      `Could not read known_hosts at ${filePath}: ${String(error)}`
    )
  }
}

/**
 * Accept an unknown host key, warn to stderr, and persist it to `~/.ssh/known_hosts`.
 *
 * The key is immediately stored in the in-memory cache so subsequent connections
 * within the same process succeed even if the disk write fails. If writing to
 * disk fails, a recovery hint with the equivalent `ssh-keyscan` command is
 * printed to stderr.
 *
 * @param location - The target host and SSH port to persist the key for.
 * @param key - The raw public key buffer presented by the remote host.
 * @param cache - The per-connection in-memory host key cache to update.
 * @returns A promise that resolves once the key has been written to disk (or the write error has been handled).
 */
async function acceptAndPersistHostKey(
  location: HostLocation,
  key: Buffer,
  cache: HostKeyCache
): Promise<void> {
  const { host, port } = location
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
  cache.set(formatHostNeedle(host, port), key)
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

/**
 * R-0000205: allowlist of SSH host-key algorithms paratix recognises in
 * pinned public keys. `ecdsa-sha2-*` covers the three OpenSSH curves
 * (nistp256, nistp384, nistp521); anything outside this set is almost
 * certainly a typo (`ed25519` vs `ssh-ed25519`) or an unsupported algorithm
 * and is rejected up front instead of failing later with an opaque mismatch.
 */
const PINNED_HOST_KEY_ALGORITHM_PATTERN =
  /^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-(?:nistp256|nistp384|nistp521))$/v

function normalizePinnedPublicKey(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/v)
  if (parts.length < 2) {
    throw new Error("Expected host public key must use the format '<algorithm> <base64>'")
  }
  const [algorithm, key] = parts
  // R-0000205: validate algorithm against the allowlist so typos like
  // `ed25519` (missing `ssh-` prefix) fail with an actionable error instead
  // of a misleading "remote key does not match" later.
  if (!PINNED_HOST_KEY_ALGORITHM_PATTERN.test(algorithm)) {
    throw new Error(
      `Expected host public key uses unsupported algorithm '${algorithm}'. ` +
        "Supported algorithms: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521."
    )
  }
  // R-0000205: validate base64 with the same strict alphabet used for
  // known_hosts entries so silent truncation by `Buffer.from(value, "base64")`
  // cannot mask a tampered or copy-pasted key.
  if (!STRICT_BASE64_PATTERN.test(key)) {
    throw new Error(
      "Expected host public key contains invalid base64 in the key field. " +
        "Use the exact value from `ssh-keygen -y` or the second field of an OpenSSH known_hosts line."
    )
  }
  return `${algorithm} ${key}`
}

export function validateExpectedHostPublicKey(publicKey: string): null | string {
  try {
    normalizePinnedPublicKey(publicKey)
    return null
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}

function formatPresentedPublicKey(key: Buffer): null | string {
  // R-0000210: the presented key comes from the remote peer (untrusted).
  // Return null on a malformed wire format so verifyPinnedHostKey can fail
  // closed with a HostKeyVerificationError instead of a RangeError.
  try {
    return `${extractAlgoFromKey(key)} ${key.toString("base64")}`
  } catch {
    return null
  }
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

  // R-0000210: treat null (malformed wire format) as "does not match".
  if (
    (presentedPublicKey != null && normalizedExpectedPublicKey === presentedPublicKey) ||
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
 * R-0000194: the synchronous read of `~/.ssh/known_hosts` is funneled through
 * the same in-process mutex as writes, so a verifier built right after a
 * concurrent `appendHostKey` always observes the freshly persisted line and
 * cannot race with a partial write.
 *
 * @param mode - The host key verification strategy.
 * @param location - The target host and SSH port.
 * @param options - Optional pinned trust anchors and per-connection cache override.
 * @returns An object with `hostVerifier` set (or empty for mode `"no"`).
 * @throws {Error} When a known host key does not match the presented key (all modes except `"no"`).
 * @throws {Error} When no known_hosts entry exists for the host and mode is `"yes"`.
 */
export async function buildHostVerifier(
  mode: "accept-new" | "no" | "yes",
  location: HostLocation,
  options: HostVerifierOptions = {}
): Promise<HostVerifierResult> {
  const cache = options.cache ?? defaultHostKeyCache
  const { host, port } = location
  if (mode === "no" && !hasPinnedHostTrustAnchor(options)) return {}

  const entries = await withKnownHostsLock(loadKnownHostEntries)
  const fileEntries = findMatchingEntries(entries, host, port)
  const cachedKey = cache.get(formatHostNeedle(host, port)) ?? null
  let acceptedHostKey: Buffer | null = null

  const result: { hostVerifier: (key: Buffer) => boolean } & HostVerifierResult = {
    async commitAcceptedHostKey(): Promise<void> {
      if (acceptedHostKey != null) await acceptAndPersistHostKey(location, acceptedHostKey, cache)
    },
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
      // mode === "accept-new": accept this key for this handshake, but only
      // commit TOFU trust after ssh2 reports the connection as ready.
      acceptedHostKey = Buffer.from(key)
      return true
    },
  }
  return result
}
