import { spawnSync } from "node:child_process"
import { readFile } from "node:fs/promises"
import { resolve } from "node:path"
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest"

import type { Transport, TransportConnection, TransportExit } from "../../src/transport.js"

import { extractAlgoFromKey } from "../../src/knownHosts.js"
import { createNativeTransport } from "../../src/transportNative.js"
import { createIntegrationEnvironment, type IntegrationEnvironment } from "./harness.js"

const READY_TIMEOUT_MS = 20_000
const dockerAvailable =
  spawnSync("docker", ["info"], {
    stdio: "ignore",
    timeout: 30_000,
  }).status === 0

const HOST_KEY_PROFILES = [
  { port: "ed25519Port", type: "ed25519" },
  { port: "rsaPort", type: "rsa" },
  { port: "ecdsaPort", type: "ecdsa" },
] as const

let environment: IntegrationEnvironment
let cleanupEnvironment: (() => Promise<void>) | undefined
let clientPrivateKey: Buffer | undefined
const openConnections: TransportConnection[] = []

function knownHostKey(type: keyof IntegrationEnvironment["hostPublicKeys"]): string {
  return environment.hostPublicKeys[type].split(/\s+/v).slice(0, 2).join(" ")
}

async function runTrue(connection: TransportConnection): Promise<TransportExit> {
  const channel = await connection.exec("true")
  channel.stdout.resume()
  channel.stderr.resume()
  return new Promise((resolveExit) => {
    channel.onExit(resolveExit)
  })
}

/**
 * Connect through one adapter, run a command and return the presented host key
 * in the `verifiedHostPublicKey` format of ssh.ts.
 * @param transport - A fresh adapter for this connection attempt.
 * @param port - The published port of the sshd profile.
 * @returns `<algorithm> <base64 key blob>` as the verifier received it.
 */
async function presentedHostKey(transport: Transport, port: number): Promise<string> {
  if (clientPrivateKey === undefined) throw new Error("Client key has not been loaded")
  const presented: Buffer[] = []
  const connection = await transport.connect({
    host: environment.host,
    port,
    // A fresh buffer per attempt: the caller's buffer must stay usable.
    privateKey: Buffer.from(clientPrivateKey),
    readyTimeout: READY_TIMEOUT_MS,
    username: "paratix",
    verifyHostKey(hostKey) {
      presented.push(Buffer.from(hostKey))
      return true
    },
  })
  openConnections.push(connection)
  expect(await runTrue(connection)).toStrictEqual({ code: 0, signal: null })
  expect(presented).toHaveLength(1)
  const [key] = presented
  return `${extractAlgoFromKey(key)} ${key.toString("base64")}`
}

// Sequential execution keeps at most one session per adapter open at a time.
describe.skipIf(!dockerAvailable)("native transport host keys", { concurrent: false }, () => {
  beforeAll(async () => {
    environment = await createIntegrationEnvironment(resolve(import.meta.dirname, "../.."))
    cleanupEnvironment = environment.cleanup
    clientPrivateKey = await readFile(environment.clientPrivateKeyPath)
  })

  afterEach(async () => {
    await Promise.all(openConnections.splice(0).map(async (connection) => connection.close()))
  })

  afterAll(async () => {
    clientPrivateKey?.fill(0)
    await cleanupEnvironment?.()
  })

  for (const profile of HOST_KEY_PROFILES) {
    it(`receives the server's ${profile.type} host key byte-equal to the known key`, async () => {
      const port = environment[profile.port]
      const native = await presentedHostKey(createNativeTransport(), port)
      expect(native).toBe(knownHostKey(profile.type))
    })
  }
})
