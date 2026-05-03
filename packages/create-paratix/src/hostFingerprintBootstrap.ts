import { createHash } from "node:crypto"
import { Client, type ConnectConfig } from "ssh2"

type HostKeyClient = Pick<Client, "connect" | "end" | "on" | "removeAllListeners">
type HostKeyClientFactory = () => HostKeyClient

type HostFingerprintBootstrapOptions = {
  clientFactory?: HostKeyClientFactory
  port?: number
  readyTimeoutMs?: number
}

// R-0000123: callers need both the algorithm and the fingerprint so an
// operator can spot a downgrade attack (for example a sudden switch from
// ssh-ed25519 to ssh-rsa) before pinning the fingerprint into server.ts.
export type HostFingerprintScanResult = {
  algorithm: string
  fingerprint: string
}

const DEFAULT_HOST_FINGERPRINT_PORT = 22
const DEFAULT_READY_TIMEOUT_MS = 10_000
const SSH_KEY_ALGO_LENGTH_FIELD_BYTES = 4

const ACCEPTED_HOST_KEY_ALGORITHMS = new Set([
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "ssh-ed25519",
  "ssh-rsa",
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
  captureScanResult: (result: HostFingerprintScanResult) => void
  host: string
  port: number
  readyTimeoutMs: number
}): ConnectConfig {
  const { captureScanResult, host, port, readyTimeoutMs } = parameters
  return {
    host,
    hostVerifier: (key: Buffer): boolean => {
      const buffer = Buffer.from(key)
      // R-0000123: capture the algorithm name alongside the fingerprint so
      // the interactive prompt can show both values to the operator.
      const algorithm = assertSupportedHostKeyAlgorithm(buffer)
      captureScanResult({ algorithm, fingerprint: computeFingerprint(buffer) })
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
  client.removeAllListeners()
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
    rejectOnce: (error: unknown): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(toError(error, host, port))
    },
    resolveOnce: (result: HostFingerprintScanResult): void => {
      if (settled) return
      settled = true
      cleanup()
      resolve(result)
    },
  }
}

function registerFingerprintListeners(parameters: {
  client: HostKeyClient
  onScanResult: () => HostFingerprintScanResult | null
  rejectOnce: (error: unknown) => void
  resolveOnce: (result: HostFingerprintScanResult) => void
}): void {
  const { client, onScanResult, rejectOnce, resolveOnce } = parameters

  client.on("close", () => {
    const capturedResult = onScanResult()
    if (capturedResult != null) {
      resolveOnce(capturedResult)
    }
  })

  client.on("error", (error: unknown) => {
    const capturedResult = onScanResult()
    if (capturedResult != null) {
      resolveOnce(capturedResult)
      return
    }
    rejectOnce(error)
  })
}

async function readFingerprintFromClient(
  client: HostKeyClient,
  parameters: { host: string; port: number; readyTimeoutMs: number }
): Promise<HostFingerprintScanResult> {
  const { host, port, readyTimeoutMs } = parameters
  let capturedResult: HostFingerprintScanResult | null = null

  return new Promise((resolve, reject) => {
    // R-0000127: ssh2 only emits "ready"/"close"/"error" through Client. If
    // the TCP socket goes into a half-open state (peer firewall blackholes
    // packets after the handshake started, NAT entry expires, …) neither
    // event fires and the Promise hangs forever. We arm a fallback watchdog
    // at twice the readyTimeoutMs to guarantee that the Promise always
    // settles. The handler runs through rejectOnce so a real error/close
    // event that arrives later is still ignored.
    let watchdog: NodeJS.Timeout | null = null
    const cleanup = (): void => {
      if (watchdog != null) {
        clearTimeout(watchdog)
        watchdog = null
      }
      cleanupClient(client)
    }
    const { rejectOnce, resolveOnce } = createSettlementHandlers({
      cleanup,
      host,
      port,
      reject,
      resolve,
    })
    watchdog = setTimeout(() => {
      rejectOnce(
        new Error(
          `host key scan timed out after ${String(readyTimeoutMs * 2)}ms (TCP half-open?)`
        )
      )
    }, readyTimeoutMs * 2)
    // The watchdog must not keep the Node.js event loop alive after the
    // Promise has otherwise settled. unref is best-effort; on platforms
    // without it the explicit clearTimeout in cleanup still wins.
    watchdog.unref?.()
    registerFingerprintListeners({
      client,
      onScanResult: () => capturedResult,
      rejectOnce,
      resolveOnce,
    })

    try {
      client.connect(
        createConnectionConfig({
          captureScanResult: (result) => {
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
