import type { HostKeyInfo, ScanOptions } from "@paratix/ssh-native"

import { createHash } from "node:crypto"

import { validateHostKeyBlob } from "./hostKeyBlobValidation.js"

export type HostKeyScanner = (options: ScanOptions) => Promise<HostKeyInfo>

type HostFingerprintBootstrapOptions = {
  allowHostKeyScan?: boolean
  port?: number
  scanner?: HostKeyScanner
  signal?: AbortSignal
  timeoutMs?: number
}

let pendingScanner: Promise<HostKeyScanner> | undefined

export async function loadHostKeyScanner(): Promise<HostKeyScanner> {
  // The native package is CommonJS. Loading is deferred until a live scan
  // is offered, so importing the generator also works without a binary.
  pendingScanner ??= import("@paratix/ssh-native").then((module) => module.default.scan)
  return pendingScanner
}

// R-0000123: callers need both the algorithm and the fingerprint so an
// operator can spot a downgrade attack (for example a sudden switch from
// ssh-ed25519 to a weaker key) before pinning the fingerprint into server.ts.
export type HostFingerprintScanResult = {
  algorithm: string
  fingerprint: string
}

const DEFAULT_HOST_FINGERPRINT_PORT = 22
const DEFAULT_SCAN_TIMEOUT_MS = 10_000
const SSH_KEY_ALGO_LENGTH_FIELD_BYTES = 4

// R-0000128: ssh-rsa is intentionally absent from this allowlist. The wire
// blob alone does not let us cheaply enforce a 2048-bit modulus floor in a
// host-key scan while keeping the validation logic
// minimal, and modern Linux distributions ship ed25519 host keys by default.
// Operators who must pin an RSA host key should pass --expected-host-fingerprint
// with an out-of-band verified value instead. This is a breaking change for
// hosts that present only ssh-rsa host keys during the scan.
const ACCEPTED_HOST_KEY_ALGORITHMS = new Set([
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "ssh-ed25519",
])

// R-0000232: validate the algorithm field as printable ASCII (0x20-0x7E)
// before decoding. `Buffer.toString("ascii")` masks the upper bit (byte &
// 0x7F), so manipulated bytes in the range 0x80-0xFF would silently map onto
// printable ASCII characters. A buffer with high-bit bytes that decodes to
// "ssh-ed25519" would then pass the allowlist check while the raw wire bytes
// were anything else. We reject any non-printable byte up front so the
// allowlist comparison operates on the bytes the wire actually contains.
const PRINTABLE_ASCII_MIN = 0x20
const PRINTABLE_ASCII_MAX = 0x7e

function isPrintableAsciiByte(byte: number): boolean {
  return byte >= PRINTABLE_ASCII_MIN && byte <= PRINTABLE_ASCII_MAX
}

// R-0000733: extractHostKeyAlgorithm now returns both the parsed
// algorithm string and the wire offset that follows the algorithm
// field. Threading that nextOffset through to validateHostKeyBlob keeps
// the wire-position computation in a single place — the consumer no
// longer has to recompute `4 + Buffer.byteLength(algorithm, "ascii")`
// and risk drifting from the bytes the wire actually contains.
type HostKeyAlgorithmExtractionResult = {
  algorithm: string
  nextOffset: number
}

function extractHostKeyAlgorithm(keyBuffer: Buffer): HostKeyAlgorithmExtractionResult {
  if (keyBuffer.length < SSH_KEY_ALGO_LENGTH_FIELD_BYTES) {
    throw new Error("Invalid SSH host key buffer: too short to contain an algorithm length field")
  }
  const algoLength = keyBuffer.readUInt32BE(0)
  if (algoLength === 0 || SSH_KEY_ALGO_LENGTH_FIELD_BYTES + algoLength > keyBuffer.length) {
    throw new Error("Invalid SSH host key buffer: algorithm length exceeds buffer size")
  }
  const algorithmBytes = keyBuffer.subarray(
    SSH_KEY_ALGO_LENGTH_FIELD_BYTES,
    SSH_KEY_ALGO_LENGTH_FIELD_BYTES + algoLength
  )
  for (const byte of algorithmBytes) {
    if (!isPrintableAsciiByte(byte)) {
      throw new Error("Invalid SSH host key buffer: algorithm field contains non-printable bytes")
    }
  }
  return {
    algorithm: algorithmBytes.toString("ascii"),
    nextOffset: SSH_KEY_ALGO_LENGTH_FIELD_BYTES + algoLength,
  }
}

function assertSupportedHostKeyAlgorithm(keyBuffer: Buffer): HostKeyAlgorithmExtractionResult {
  const extraction = extractHostKeyAlgorithm(keyBuffer)
  if (!ACCEPTED_HOST_KEY_ALGORITHMS.has(extraction.algorithm)) {
    throw new Error(
      `Refusing to capture host fingerprint: unsupported SSH host key algorithm "${extraction.algorithm}". ` +
        `This may indicate a man-in-the-middle attack. ` +
        `Expected one of: ${[...ACCEPTED_HOST_KEY_ALGORITHMS].sort().join(", ")}.`
    )
  }
  return extraction
}

function computeFingerprint(key: Buffer): string {
  const hash = createHash("sha256").update(key).digest("base64")
  return `SHA256:${hash.replaceAll("=", "")}`
}

function toError(error: unknown, host: string, port: number): Error {
  const message = error instanceof Error ? error.message : String(error)
  return new Error(`Failed to read the host key from ${host}:${port}: ${message}`, { cause: error })
}

function validateScanResult(info: HostKeyInfo): HostFingerprintScanResult {
  if (info.kind !== "key") {
    throw new Error("Refusing to capture host fingerprint: SSH host certificates are unsupported.")
  }
  const buffer = Buffer.from(info.keyBase64, "base64")
  const { algorithm, nextOffset } = assertSupportedHostKeyAlgorithm(buffer)
  // R-0000128: an algorithm label alone proves nothing. Validate the raw
  // wire blob before trusting either the label or its fingerprint.
  validateHostKeyBlob(buffer, algorithm, nextOffset)
  if (algorithm !== info.algorithm) {
    throw new Error("SSH host key algorithm does not match the scanned key blob.")
  }
  const fingerprint = computeFingerprint(buffer)
  if (fingerprint !== info.fingerprintSha256) {
    throw new Error("SSH host key fingerprint does not match the scanned key blob.")
  }
  return { algorithm, fingerprint }
}

export async function readHostFingerprint(
  host: string,
  options: HostFingerprintBootstrapOptions = {}
): Promise<HostFingerprintScanResult> {
  if (options.allowHostKeyScan !== true) {
    throw new Error(
      "Refusing to start host-key scan without explicit opt-in. " +
        "Pass allowHostKeyScan: true only after the operator requested a live SSH scan."
    )
  }
  const port = options.port ?? DEFAULT_HOST_FINGERPRINT_PORT
  try {
    const scanner = options.scanner ?? (await loadHostKeyScanner())
    // R-0000127, R-0000188: the native deadline covers both TCP and the
    // handshake, and cancellation belongs to the native operation itself.
    const info = await scanner({
      host,
      port,
      signal: options.signal,
      timeoutMs: options.timeoutMs ?? DEFAULT_SCAN_TIMEOUT_MS,
    })
    return validateScanResult(info)
  } catch (error) {
    throw toError(error, host, port)
  }
}
