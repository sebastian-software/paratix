import { spawnSync } from "node:child_process"
import { randomUUID } from "node:crypto"
import { resolve } from "node:path"
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import type * as Terminal from "../../src/terminal.js"
import type { SshConfig } from "../../src/types.js"

import { SshConnectionImpl } from "../../src/ssh.js"
import { promptTerminal } from "../../src/terminal.js"
import {
  createIntegrationAgent,
  createIntegrationEnvironment,
  disconnectIntegrationSessions,
  type IntegrationAgent,
  type IntegrationEnvironment,
  restoreHomeEnvironmentVariable,
  waitForIntegrationMarker,
} from "./harness.js"

vi.mock("../../src/terminal.js", async (importOriginal) => ({
  ...(await importOriginal<typeof Terminal>()),
  promptTerminal: vi.fn(),
}))

const MINIMUM_KEYBOARD_TIMEOUT_MS = 9000
const dockerAvailable =
  spawnSync("docker", ["info"], {
    stdio: "ignore",
    timeout: 30_000,
  }).status === 0

let environment: IntegrationEnvironment
let cleanupEnvironment: (() => Promise<void>) | undefined
let agent: IntegrationAgent | undefined
let connection: SshConnectionImpl | undefined
let originalHome: string | undefined
let originalAgentSocket: string | undefined

function setTestHome(): void {
  process.env.HOME = environment.workspaceHome
}

function clearConnection(): void {
  connection = undefined
}

function restoreAgentSocket(): void {
  if (originalAgentSocket === undefined) delete process.env.SSH_AUTH_SOCK
  else process.env.SSH_AUTH_SOCK = originalAgentSocket
}

function createConnection(overrides: Partial<SshConfig> = {}): SshConnectionImpl {
  connection = new SshConnectionImpl(environment.host, {
    expectedHostPublicKey: environment.hostPublicKey,
    ports: [environment.primaryPort],
    privateKey: environment.clientPrivateKeyPath,
    strictHostKeyChecking: "yes",
    user: "paratix",
    ...overrides,
  })
  return connection
}

function useTestAgent(): IntegrationAgent {
  if (agent == null) throw new Error("Test SSH agent has not been initialized")
  process.env.SSH_AUTH_SOCK = agent.socket
  return agent
}

async function connectHostKey(
  type: keyof IntegrationEnvironment["hostPublicKeys"],
  port: number
): Promise<string | undefined> {
  const expected = environment.hostPublicKeys[type].split(/\s+/v).slice(0, 2).join(" ")
  const ssh = createConnection({ expectedHostPublicKey: expected, ports: [port] })
  await ssh.connect()
  const result = await ssh.exec("true")
  expect(result.code).toBe(0)
  return ssh.getConnectionInfo().verifiedHostPublicKey
}

// Sequential execution ensures the disconnect cell owns the only paratix session.
describe.skipIf(!dockerAvailable)("SSH transport parity", { concurrent: false }, () => {
  beforeAll(async () => {
    originalHome = process.env.HOME
    originalAgentSocket = process.env.SSH_AUTH_SOCK
    environment = await createIntegrationEnvironment(resolve(import.meta.dirname, "../.."))
    cleanupEnvironment = environment.cleanup
    setTestHome()
    agent = await createIntegrationAgent(environment.clientPrivateKeyPath)
  })

  beforeEach(() => {
    delete process.env.SSH_AUTH_SOCK
    vi.mocked(promptTerminal).mockReset()
    process.exitCode = 0
  })

  afterEach(() => {
    try {
      connection?.disconnect()
    } finally {
      clearConnection()
      restoreAgentSocket()
      process.exitCode = 0
    }
  })

  afterAll(async () => {
    restoreHomeEnvironmentVariable(originalHome)
    restoreAgentSocket()
    try {
      await agent?.cleanup()
    } finally {
      await cleanupEnvironment?.()
    }
  })

  it("authenticates with a key file and reports privateKey authentication", async () => {
    const ssh = createConnection()
    await ssh.connect()
    const result = await ssh.exec("true")
    expect(result.code).toBe(0)
    expect(ssh.getConnectionInfo().authMethod).toBe("privateKey")
  })

  it("authenticates with the isolated test agent and reports its socket", async () => {
    const testAgent = useTestAgent()
    const ssh = createConnection({ privateKey: undefined })
    await ssh.connect()
    const result = await ssh.exec("true")
    expect(result.code).toBe(0)
    expect(ssh.getConnectionInfo().authMethod).toBe("agent")
    expect(ssh.getConnectionInfo().agentSocket).toBe(testAgent.socket)
  })

  it("authenticates with the prompted runtime password", async () => {
    vi.mocked(promptTerminal).mockResolvedValue(environment.password)
    const ssh = createConnection({
      passwordFallback: true,
      ports: [environment.passwordPort],
      privateKey: undefined,
    })
    await ssh.connect()
    const result = await ssh.exec("true")
    expect(result.code).toBe(0)
    expect(ssh.getConnectionInfo().authMethod).toBe("password")
    expect(promptTerminal).toHaveBeenCalledOnce()
  })

  /* oxlint-disable vitest/no-conditional-in-test -- only the documented timeout may satisfy this expected-failure cell. */
  it.fails(
    "authenticates with keyboard-interactive after the ready-timeout gap is closed",
    async () => {
      let connecting = false
      let started = 0
      try {
        vi.mocked(promptTerminal).mockResolvedValue(environment.password)
        const ssh = createConnection({
          passwordFallback: true,
          ports: [environment.keyboardInteractivePort],
        })
        started = performance.now()
        connecting = true
        await ssh.connect()
        connecting = false
        const result = await ssh.exec("true")
        expect(result.code).toBe(0)
      } catch (error) {
        // Only the documented connect timeout may validate the known gap.
        if (
          !connecting ||
          !(error instanceof Error) ||
          performance.now() - started < MINIMUM_KEYBOARD_TIMEOUT_MS ||
          !/^Failed to connect to .+ on ports:/v.test(error.message)
        )
          return
        throw error
      }
    }
  )

  /* oxlint-enable vitest/no-conditional-in-test */

  it("forwards only the test agent to a root session when enabled", async () => {
    const testAgent = useTestAgent()
    const ssh = createConnection({
      agentForward: true,
      ports: [environment.forwardingPort],
      privateKey: undefined,
      user: "root",
    })
    await ssh.connect()
    const result = await ssh.exec("ssh-add -l", { ignoreExitCode: true })
    expect(result.code).toBe(0)
    expect(result.stdout).toContain(testAgent.fingerprint)
  })

  it("does not forward the test agent to a root session by default", async () => {
    useTestAgent()
    const ssh = createConnection({
      ports: [environment.forwardingPort],
      privateKey: undefined,
      user: "root",
    })
    await ssh.connect()
    const result = await ssh.exec("ssh-add -l", { ignoreExitCode: true })
    expect(result.code).toBe(2)
  })

  it("rejects a running exec after server disconnect and reconnects successfully", async () => {
    const ssh = createConnection()
    await ssh.connect()
    const marker = `/tmp/paratix-parity-${randomUUID()}`
    const running = ssh.exec(`touch ${marker}; sleep 30`)
    // Observe rejection immediately so server-side termination cannot leave an unhandled promise.
    const settled = Promise.allSettled([running])
    await waitForIntegrationMarker(environment, marker)
    await disconnectIntegrationSessions(environment)
    const results = await settled
    expect(results[0].status).toBe("rejected")
    await ssh.reconnect()
    const result = await ssh.exec("true")
    expect(result.code).toBe(0)
  })

  it("reports SIGTERM when the remote command terminates itself", async () => {
    const ssh = createConnection()
    await ssh.connect()
    await expect(ssh.exec("kill -TERM $$")).rejects.toThrow("signal SIGTERM")
  })

  it("reports exactly one channel refusal with MaxSessions 1", async () => {
    // Root avoids sudo-probe channels before the measured concurrent commands.
    const ssh = createConnection({ ports: [environment.maxSessionsPort], user: "root" })
    await ssh.connect()
    const results = await Promise.allSettled([ssh.exec("sleep 2"), ssh.exec("true")])
    const rejected = results.filter((result) => result.status === "rejected")
    expect(rejected).toHaveLength(1)
    expect(rejected[0].reason).toBeInstanceOf(Error)
    expect((rejected[0].reason as Error).message).toContain(
      "the SSH server refused a new session channel"
    )
    const fulfilled = results.filter((result) => result.status === "fulfilled")
    expect(fulfilled).toHaveLength(1)
    expect(fulfilled[0].value.code).toBe(0)
  })

  it("verifies the isolated ed25519 host key type and base64", async () => {
    expect(await connectHostKey("ed25519", environment.ed25519Port)).toBe(
      environment.hostPublicKeys.ed25519.split(/\s+/v).slice(0, 2).join(" ")
    )
  })

  it("verifies the isolated RSA host key type and base64", async () => {
    expect(await connectHostKey("rsa", environment.rsaPort)).toBe(
      environment.hostPublicKeys.rsa.split(/\s+/v).slice(0, 2).join(" ")
    )
  })

  it("verifies the isolated ECDSA host key type and base64", async () => {
    expect(await connectHostKey("ecdsa", environment.ecdsaPort)).toBe(
      environment.hostPublicKeys.ecdsa.split(/\s+/v).slice(0, 2).join(" ")
    )
  })
})
