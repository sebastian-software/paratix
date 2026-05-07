import { createHash } from "node:crypto"
import { Client, type ConnectConfig } from "ssh2"

import { validateHostKeyBlob } from "./hostKeyBlobValidation.js"

type HostKeyClient = Pick<Client, "connect" | "end" | "on" | "removeAllListeners">
type HostKeyClientFactory = () => HostKeyClient

type HostFingerprintBootstrapOptions = {
  clientFactory?: HostKeyClientFactory
  port?: number
  readyTimeoutMs?: number
}

// R-0000123: callers need both the algorithm and the fingerprint so an
// operator can spot a downgrade attack (for example a sudden switch from
// ssh-ed25519 to a weaker key) before pinning the fingerprint into server.ts.
export type HostFingerprintScanResult = {
  algorithm: string
  fingerprint: string
}

const DEFAULT_HOST_FINGERPRINT_PORT = 22
const DEFAULT_READY_TIMEOUT_MS = 10_000
const SSH_KEY_ALGO_LENGTH_FIELD_BYTES = 4

// R-0000128: ssh-rsa is intentionally absent from this allowlist. The wire
// blob alone does not let us cheaply enforce a 2048-bit modulus floor in a
// pre-handshake host-verifier callback while keeping the validation logic
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

function extractHostKeyAlgorithm(keyBuffer: Buffer): string {
  if (keyBuffer.length < SSH_KEY_ALGO_LENGTH_FIELD_BYTES) {
    throw new Error("Invalid SSH host key buffer: too short to contain an algorithm length field")
  }
  const algoLength = keyBuffer.readUInt32BE(0)
  if (algoLength === 0 || SSH_KEY_ALGO_LENGTH_FIELD_BYTES + algoLength > keyBuffer.length) {
    throw new Error("Invalid SSH host key buffer: algorithm length exceeds buffer size")
  }
  return keyBuffer
    .subarray(SSH_KEY_ALGO_LENGTH_FIELD_BYTES, SSH_KEY_ALGO_LENGTH_FIELD_BYTES + algoLength)
    .toString("ascii")
}

function assertSupportedHostKeyAlgorithm(keyBuffer: Buffer): string {
  const algorithm = extractHostKeyAlgorithm(keyBuffer)
  if (!ACCEPTED_HOST_KEY_ALGORITHMS.has(algorithm)) {
    throw new Error(
      `Refusing to capture host fingerprint: unsupported SSH host key algorithm "${algorithm}". ` +
        `This may indicate a man-in-the-middle attack. ` +
        `Expected one of: ${[...ACCEPTED_HOST_KEY_ALGORITHMS].sort().join(", ")}.`
    )
  }
  return algorithm
}

function computeFingerprint(key: Buffer): string {
  const hash = createHash("sha256").update(key).digest("base64")
  return `SHA256:${hash.replaceAll("=", "")}`
}

function toError(error: unknown, host: string, port: number): Error {
  const message = error instanceof Error ? error.message : String(error)
  return new Error(`Failed to read the host key from ${host}:${port}: ${message}`)
}

function createConnectionConfig(parameters: {
  captureHostVerifierError: (error: unknown) => void
  captureScanResult: (result: HostFingerprintScanResult) => void
  host: string
  port: number
  readyTimeoutMs: number
}): ConnectConfig {
  const { captureHostVerifierError, captureScanResult, host, port, readyTimeoutMs } = parameters
  return {
    host,
    hostVerifier(key: Buffer): boolean {
      const buffer = Buffer.from(key)
      try {
        // R-0000123: capture the algorithm name alongside the fingerprint so
        // the interactive prompt can show both values to the operator.
        const algorithm = assertSupportedHostKeyAlgorithm(buffer)
        // R-0000128: an algorithm label alone proves nothing — a MITM can
        // ship arbitrary bytes after the label. Reject malformed wire
        // payloads (truncated, wrong curve, point off-curve) before we
        // pin a fingerprint computed over them.
        validateHostKeyBlob(buffer, algorithm)
        captureScanResult({ algorithm, fingerprint: computeFingerprint(buffer) })
      } catch (error) {
        captureHostVerifierError(error)
      }
      return false
    },
    port,
    readyTimeout: readyTimeoutMs,
    username: "paratix-hostkey-scan",
  }
}

function resolveBootstrapOptions(options: HostFingerprintBootstrapOptions): {
  client: HostKeyClient
  port: number
  readyTimeoutMs: number
} {
  const clientFactory = options.clientFactory ?? (() => new Client())
  return {
    client: clientFactory(),
    port: options.port ?? DEFAULT_HOST_FINGERPRINT_PORT,
    readyTimeoutMs: options.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS,
  }
}

function cleanupClient(client: HostKeyClient): void {
  // R-0000187: removeAllListeners drops the original error listener. If
  // client.end() then synchronously or asynchronously emits an error event
  // (half-closed socket, ssh2-layer throw), Node treats it as an uncaught
  // error and crashes the process. Install a no-op error listener first so
  // the cleanup path always has a sink for late error events.
  client.removeAllListeners()
  client.on("error", () => {
    // Swallow late errors emitted while shutting the connection down — at
    // this point the fingerprint promise has already settled.
  })
  try {
    client.end()
  } catch {
    // best-effort cleanup
  }
}

function createSettlementHandlers(parameters: {
  cleanup: () => void
  host: string
  port: number
  reject: (reason: Error) => void
  resolve: (result: HostFingerprintScanResult) => void
}): {
  rejectOnce: (error: unknown) => void
  resolveOnce: (result: HostFingerprintScanResult) => void
} {
  const { cleanup, host, port, reject, resolve } = parameters
  let settled = false

  return {
    rejectOnce(error: unknown): void {
      if (settled) return
      settled = true
      cleanup()
      reject(toError(error, host, port))
    },
    resolveOnce(result: HostFingerprintScanResult): void {
      if (settled) return
      settled = true
      cleanup()
      resolve(result)
    },
  }
}

function registerFingerprintListeners(parameters: {
  client: HostKeyClient
  onHostVerifierError: () => unknown
  onScanResult: () => HostFingerprintScanResult | null
  rejectOnce: (error: unknown) => void
  resolveOnce: (result: HostFingerprintScanResult) => void
}): void {
  const { client, onHostVerifierError, onScanResult, rejectOnce, resolveOnce } = parameters

  client.on("close", () => {
    const hostVerifierError = onHostVerifierError()
    if (hostVerifierError != null) {
      rejectOnce(hostVerifierError)
      return
    }

    const capturedResult = onScanResult()
    if (capturedResult != null) {
      resolveOnce(capturedResult)
    }
  })

  client.on("error", (error: unknown) => {
    const hostVerifierError = onHostVerifierError()
    if (hostVerifierError != null) {
      rejectOnce(hostVerifierError)
      return
    }

    const capturedResult = onScanResult()
    if (capturedResult != null) {
      resolveOnce(capturedResult)
      return
    }
    rejectOnce(error)
  })
}

/**
 * Arm the half-open watchdog that guarantees the fingerprint Promise always
 * settles. R-0000127: ssh2 does not emit `error`/`close` for a half-open
 * TCP socket, so we fall back to a timer at twice the readyTimeoutMs.
 *
 * @param parameters - Watchdog configuration.
 * @param parameters.readyTimeoutMs - The ssh2 ready timeout in milliseconds.
 * @param parameters.rejectOnce - Idempotent rejection callback.
 * @returns A cleanup function that disarms the watchdog.
 */
function armHalfOpenWatchdog(parameters: {
  readyTimeoutMs: number
  rejectOnce: (error: unknown) => void
}): () => void {
  const { readyTimeoutMs, rejectOnce } = parameters
  const watchdog: NodeJS.Timeout = setTimeout(() => {
    rejectOnce(
      new Error(`host key scan timed out after ${String(readyTimeoutMs * 2)}ms (TCP half-open?)`)
    )
  }, readyTimeoutMs * 2)
  // The watchdog must not keep the Node.js event loop alive after the
  // Promise has otherwise settled. unref is best-effort; on platforms
  // without it the explicit clearTimeout in cleanup still wins.
  watchdog.unref()
  return () => {
    clearTimeout(watchdog)
  }
}

async function readFingerprintFromClient(
  client: HostKeyClient,
  parameters: { host: string; port: number; readyTimeoutMs: number }
): Promise<HostFingerprintScanResult> {
  const { host, port, readyTimeoutMs } = parameters
  let capturedResult: HostFingerprintScanResult | null = null
  let hostVerifierError: unknown = null

  return new Promise((resolve, reject) => {
    let disarmWatchdog: (() => void) | null = null
    const cleanup = (): void => {
      disarmWatchdog?.()
      disarmWatchdog = null
      cleanupClient(client)
    }
    const { rejectOnce, resolveOnce } = createSettlementHandlers({
      cleanup,
      host,
      port,
      reject,
      resolve,
    })
    disarmWatchdog = armHalfOpenWatchdog({ readyTimeoutMs, rejectOnce })
    registerFingerprintListeners({
      client,
      onHostVerifierError: () => hostVerifierError,
      onScanResult: () => capturedResult,
      rejectOnce,
      resolveOnce,
    })

    try {
      client.connect(
        createConnectionConfig({
          captureHostVerifierError(error) {
            hostVerifierError = error
          },
          captureScanResult(result) {
            capturedResult = result
          },
          host,
          port,
          readyTimeoutMs,
        })
      )
    } catch (error) {
      rejectOnce(error)
    }
  })
}

export async function readHostFingerprintViaSsh2(
  host: string,
  options: HostFingerprintBootstrapOptions = {}
): Promise<HostFingerprintScanResult> {
  const { client, port, readyTimeoutMs } = resolveBootstrapOptions(options)
  return readFingerprintFromClient(client, { host, port, readyTimeoutMs })
}
