import { createHash } from "node:crypto"
import { Client, type ConnectConfig } from "ssh2"

type HostKeyClient = Pick<Client, "connect" | "end" | "on" | "removeAllListeners">
type HostKeyClientFactory = () => HostKeyClient

type HostFingerprintBootstrapOptions = {
  clientFactory?: HostKeyClientFactory
  port?: number
  readyTimeoutMs?: number
}

const DEFAULT_HOST_FINGERPRINT_PORT = 22
const DEFAULT_READY_TIMEOUT_MS = 10_000

function computeFingerprint(key: Buffer): string {
  const hash = createHash("sha256").update(key).digest("base64")
  return `SHA256:${hash.replaceAll("=", "")}`
}

function toError(error: unknown, host: string, port: number): Error {
  const message = error instanceof Error ? error.message : String(error)
  return new Error(`Failed to read the host key from ${host}:${port}: ${message}`)
}

function createConnectionConfig(parameters: {
  captureFingerprint: (fingerprint: string) => void
  host: string
  port: number
  readyTimeoutMs: number
}): ConnectConfig {
  const { captureFingerprint, host, port, readyTimeoutMs } = parameters
  return {
    host,
    hostVerifier: (key: Buffer): boolean => {
      captureFingerprint(computeFingerprint(Buffer.from(key)))
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
  resolve: (fingerprint: string) => void
}): {
  rejectOnce: (error: unknown) => void
  resolveOnce: (fingerprint: string) => void
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
    resolveOnce: (fingerprint: string): void => {
      if (settled) return
      settled = true
      cleanup()
      resolve(fingerprint)
    },
  }
}

function registerFingerprintListeners(parameters: {
  client: HostKeyClient
  onFingerprint: () => null | string
  rejectOnce: (error: unknown) => void
  resolveOnce: (fingerprint: string) => void
}): void {
  const { client, onFingerprint, rejectOnce, resolveOnce } = parameters

  client.on("close", () => {
    const capturedFingerprint = onFingerprint()
    if (capturedFingerprint != null) {
      resolveOnce(capturedFingerprint)
    }
  })

  client.on("error", (error: unknown) => {
    const capturedFingerprint = onFingerprint()
    if (capturedFingerprint != null) {
      resolveOnce(capturedFingerprint)
      return
    }
    rejectOnce(error)
  })
}

async function readFingerprintFromClient(
  client: HostKeyClient,
  parameters: { host: string; port: number; readyTimeoutMs: number }
): Promise<string> {
  const { host, port, readyTimeoutMs } = parameters
  let capturedFingerprint: null | string = null

  return new Promise((resolve, reject) => {
    const cleanup = (): void => {
      cleanupClient(client)
    }
    const { rejectOnce, resolveOnce } = createSettlementHandlers({
      cleanup,
      host,
      port,
      reject,
      resolve,
    })
    registerFingerprintListeners({
      client,
      onFingerprint: () => capturedFingerprint,
      rejectOnce,
      resolveOnce,
    })

    try {
      client.connect(
        createConnectionConfig({
          captureFingerprint: (fingerprint) => {
            capturedFingerprint = fingerprint
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
): Promise<string> {
  const { client, port, readyTimeoutMs } = resolveBootstrapOptions(options)
  return readFingerprintFromClient(client, { host, port, readyTimeoutMs })
}
