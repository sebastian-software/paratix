import { readFileSync } from "node:fs"
import { appendFile, mkdir } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"

/** A parsed entry from a known_hosts file. */
export type KnownHostEntry = {
  /** Algorithm name as stored in the file (e.g. `"ssh-ed25519"`). */
  algo: string
  /** Host pattern as stored in the file (plain hostname or `[host]:port` notation). */
  host: string
  /** Raw public key bytes decoded from the Base64 field. */
  key: Buffer
}

/** Minimum number of whitespace-separated fields in a valid known_hosts line. */
const MIN_KNOWN_HOSTS_FIELDS = 3

/** The default SSH port used by OpenSSH. */
const DEFAULT_SSH_PORT = 22

/** Byte size of the uint32 length prefix in SSH wire format. */
const UINT32_SIZE = 4

/**
 * Parse the contents of an OpenSSH `known_hosts` file into structured entries.
 *
 * - Blank lines and comment lines (starting with `#`) are skipped.
 * - Hashed hostnames (starting with `|1|`) are skipped because they cannot be
 *   matched without the original hostname.
 * - Hosts separated by commas produce one entry per hostname.
 *
 * @param content - The raw file content.
 * @returns An array of parsed entries.
 */
export function parseKnownHosts(content: string): KnownHostEntry[] {
  const entries: KnownHostEntry[] = []
  for (const raw of content.split("\n")) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith("#") || line.startsWith("|1|") || line.startsWith("@"))
      continue

    const parts = line.split(/\s+/v)
    if (parts.length < MIN_KNOWN_HOSTS_FIELDS) continue

    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- length checked above
    const [hostsPart, algo, base64Key] = parts as [string, string, string]
    const key = Buffer.from(base64Key, "base64")

    for (const host of hostsPart.split(",")) {
      entries.push({ algo, host, key })
    }
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
 * @param entries - Parsed known_hosts entries.
 * @param host - The hostname or IP to look up.
 * @param port - The SSH port.
 * @returns The key buffer if found, otherwise `null`.
 */
export function lookupHostKey(
  entries: KnownHostEntry[],
  host: string,
  port: number
): Buffer | null {
  const needle = formatHostNeedle(host, port)
  for (const entry of entries) {
    if (entry.host === needle) return entry.key
  }
  return null
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
 * Build the `hostVerifier` callback for an ssh2 `ConnectConfig`.
 *
 * Behaviour by mode:
 * - `"no"` — returns an empty object (no verification, ssh2 default).
 * - `"accept-new"` — accepts unknown keys and appends them to `~/.ssh/known_hosts`;
 *   throws if a known key does not match.
 * - `"yes"` — throws for both unknown keys and mismatched keys.
 *
 * @param mode - The host key verification strategy.
 * @param host - The target hostname or IP.
 * @param port - The target SSH port.
 * @returns An object with `hostVerifier` set (or empty for mode `"no"`).
 * @throws {Error} When a known host key does not match the presented key (all modes except `"no"`).
 * @throws {Error} When no known_hosts entry exists for the host and mode is `"yes"`.
 */
export function buildHostVerifier(
  mode: "accept-new" | "no" | "yes",
  host: string,
  port: number
): { hostVerifier?: (key: Buffer) => boolean } {
  if (mode === "no") return {}

  const entries = loadKnownHostEntries()
  const existingKey = lookupHostKey(entries, host, port)

  return {
    hostVerifier(key: Buffer): boolean {
      if (existingKey != null) {
        if (existingKey.equals(key)) return true
        const presentedAlgo = extractAlgoFromKey(key)
        const existingAlgo = extractAlgoFromKey(existingKey)
        throw new Error(
          `HOST KEY VERIFICATION FAILED for ${host}: ` +
            `remote host key (${presentedAlgo}) does not match the key in known_hosts (${existingAlgo}). ` +
            "This could indicate a man-in-the-middle attack."
        )
      }
      if (mode === "yes") {
        throw new Error(
          `Host key for ${host} not found in known_hosts. ` +
            'Set strictHostKeyChecking to "accept-new" to auto-accept new keys.'
        )
      }
      // mode === "accept-new": accept and persist
      appendHostKey(host, port, key).catch((error: unknown) => {
        process.stderr.write(
          `WARNING: Could not persist host key for ${host} — ` +
            `future connections to this host cannot be verified. ${String(error)}\n`
        )
      })
      return true
    },
  }
}
