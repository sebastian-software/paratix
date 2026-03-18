import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import { stat } from "node:fs/promises"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type * as KnownHosts from "../src/knownHosts.js"
import type * as SshHelpers from "../src/sshHelpers.js"

import { sftpDownload } from "../src/sftp.js"
import { SshConnectionImpl } from "../src/ssh.js"
import { collectStreamOutput, tryConnectOnPort } from "../src/sshHelpers.js"
import { promptTerminal } from "../src/terminal.js"

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("node:fs", () => ({
  readFileSync: vi.fn().mockReturnValue(""),
  unlinkSync: vi.fn(),
  writeFileSync: vi.fn(),
}))

vi.mock("node:fs/promises", () => ({
  appendFile: vi.fn().mockResolvedValue(null),
  mkdir: vi.fn().mockResolvedValue(null),
  readFile: vi.fn().mockResolvedValue("fake-private-key"),
  stat: vi.fn().mockResolvedValue({}),
}))

vi.mock("../src/knownHosts.js", async () => {
  const actual = await vi.importActual<typeof KnownHosts>("../src/knownHosts.js")
  return {
    appendHostKey: vi.fn().mockResolvedValue(null),
    // Default: return empty object (no hostVerifier) so ssh.ts can safely destructure after resetAllMocks.
    buildHostVerifier: vi.fn().mockReturnValue({}),
    extractAlgoFromKey: actual.extractAlgoFromKey,
    lookupHostKey: actual.lookupHostKey,
    parseKnownHosts: actual.parseKnownHosts,
  }
})

vi.mock("../src/sftp.js", () => ({
  sftpDownload: vi.fn().mockResolvedValue(null),
  sftpUpload: vi.fn(),
}))

vi.mock("../src/sshHelpers.js", async () => {
  const actual = await vi.importActual<typeof SshHelpers>("../src/sshHelpers.js")
  return {
    collectStreamOutput: vi.fn(actual.collectStreamOutput),
    maskSecrets: actual.maskSecrets,
    shellQuote: actual.shellQuote,
    tryConnectOnPort: vi.fn(),
    validateMode: actual.validateMode,
  }
})

vi.mock("../src/terminal.js", () => ({
  promptTerminal: vi.fn().mockResolvedValue("mock-password"),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type StreamWithStderr = {
  close: () => void
  stderr: EventEmitter
  write: ReturnType<typeof vi.fn>
} & EventEmitter

type ExecCallback = (error: Error | undefined, stream: StreamWithStderr) => void

function makeStream(): StreamWithStderr {
  const stream = new EventEmitter() as StreamWithStderr
  stream.stderr = new EventEmitter()
  // Define methods on the object so vi.spyOn can find them
  stream.write = (() => true) as unknown as ReturnType<typeof vi.fn>
  stream.close = () => {
    /* noop */
  }
  vi.spyOn(stream, "write" as never).mockImplementation((() => true) as never)
  vi.spyOn(stream, "close" as never).mockImplementation((() => {
    /* noop */
  }) as never)
  return stream
}

function makeClientWithEnd(endSpy: ReturnType<typeof vi.fn>): Client {
  return {
    end: endSpy,
    exec: vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
      const stream = makeStream()
      callback(undefined, stream)
      stream.emit("close", 0)
    }),
    sftp: vi.fn().mockImplementation((callback: Parameters<Client["sftp"]>[0]) => {
      callback(undefined, {} as SFTPWrapper)
    }),
  } as unknown as Client
}

function makeClientWithExecSpy(execSpy: ReturnType<typeof vi.fn>): Client {
  return {
    end: vi.fn(),
    exec: execSpy,
    sftp: vi.fn().mockImplementation((callback: Parameters<Client["sftp"]>[0]) => {
      callback(undefined, {} as SFTPWrapper)
    }),
  } as unknown as Client
}

function makeConnectedSsh(
  client: Client,
  options: { sudoPassword?: string; user?: string } = {}
): SshConnectionImpl {
  const config = {
    ports: [22],
    privateKey: "/dev/null",
    sudoPassword: options.sudoPassword,
    user: options.user ?? "root",
  }
  const ssh = new SshConnectionImpl("1.2.3.4", config)
  ;(ssh as unknown as Record<string, unknown>).client = client
  return ssh
}

/**
 * Creates an SSH instance with a mock client that also has the 'close' listener
 * registered — exactly as tryConnectOnPorts() would do it. This allows tests to
 * simulate an unexpected connection drop by emitting 'close' on the client.
 *
 * @param client - Mock SSH2 Client that also extends EventEmitter so 'close' can be emitted.
 * @param options - Optional connection options.
 * @param options.sudoPassword - Optional sudo password for the connection.
 * @param options.user - Optional SSH user (defaults to "root").
 * @returns A connected SshConnectionImpl with the 'close' listener attached.
 */
function makeConnectedSshWithCloseListener(
  client: Client & EventEmitter,
  options: { sudoPassword?: string; user?: string } = {}
): SshConnectionImpl {
  const ssh = makeConnectedSsh(client, options)
  const pendingRejects = (ssh as unknown as Record<string, unknown>).pendingRejects as Set<
    (reason: Error) => void
  >
  client.on("close", () => {
    const error = new Error("SSH connection closed unexpectedly")
    for (const rejectFunction of pendingRejects) {
      rejectFunction(error)
    }
    pendingRejects.clear()
  })
  return ssh
}

function makeSshInstance(
  overrides: {
    host?: string
    maxReconnectAttempts?: number
    ports?: number[]
    reconnectTimeout?: number
    user?: string
  } = {}
): SshConnectionImpl {
  const config = {
    maxReconnectAttempts: overrides.maxReconnectAttempts,
    ports: overrides.ports ?? [22],
    privateKey: "/dev/null",
    reconnectTimeout: overrides.reconnectTimeout,
    user: overrides.user ?? "root",
  }
  return new SshConnectionImpl(overrides.host ?? "1.2.3.4", config)
}

function makeSshInstanceWithAgent(
  overrides: {
    agentForward?: boolean
    host?: string
    passwordFallback?: boolean
    ports?: number[]
    reconnectTimeout?: number
    user?: string
  } = {}
): SshConnectionImpl {
  const config = {
    agentForward: overrides.agentForward,
    passwordFallback: overrides.passwordFallback,
    ports: overrides.ports ?? [22],
    reconnectTimeout: overrides.reconnectTimeout,
    user: overrides.user ?? "root",
    // privateKey intentionally omitted to trigger agent-auth path
  }
  return new SshConnectionImpl(overrides.host ?? "1.2.3.4", config)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SshConnectionImpl", () => {
  beforeEach(async () => {
    // Re-establish buildHostVerifier mock after vi.resetAllMocks() wipes it.
    // Without this, the destructuring `const { hostVerifier } = buildHostVerifier(...)` in
    // tryConnectOnPorts() would throw a TypeError because the mock returns undefined.
    const knownHosts = await import("../src/knownHosts.js")
    vi.mocked(knownHosts.buildHostVerifier).mockReturnValue({})
  })

  afterEach(() => {
    vi.resetAllMocks()
    vi.useRealTimers()
  })

  // -------------------------------------------------------------------------
  // ensureClient
  // -------------------------------------------------------------------------

  describe("ensureClient (via exec)", () => {
    it("throws 'SSH not connected' when client is null", async () => {
      const ssh = makeSshInstance()

      await expect(ssh.exec("whoami")).rejects.toThrow("SSH not connected")
    })
  })

  // -------------------------------------------------------------------------
  // disconnect
  // -------------------------------------------------------------------------

  describe("disconnect", () => {
    it("calls client.end() when connected", () => {
      const endSpy = vi.fn()
      const client = makeClientWithEnd(endSpy)
      const ssh = makeConnectedSsh(client)

      ssh.disconnect()

      expect(endSpy).toHaveBeenCalledOnce()
    })

    it("is idempotent — calling twice does not throw", () => {
      const endSpy = vi.fn()
      const client = makeClientWithEnd(endSpy)
      const ssh = makeConnectedSsh(client)

      ssh.disconnect()
      ssh.disconnect()

      expect(endSpy).toHaveBeenCalledOnce()
    })

    it("rejects pending exec() Promises when disconnect() is called while they are still pending", async () => {
      // BUG: disconnect() calls pendingRejects.clear() without iterating and
      // invoking the stored reject functions first. As a result, pending exec()
      // Promises are silently dropped and never settled, which causes callers to
      // hang indefinitely.
      //
      // The correct behavior (already implemented in the 'close' event handler
      // in tryConnectOnPorts) is to iterate over pendingRejects, call each
      // function with an Error, and then clear the set.
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // Stream intentionally never emits 'close' — the exec() Promise stays pending
      })

      const client = {
        end: vi.fn(),
        exec: execSpy,
        sftp: vi.fn(),
      } as unknown as Client

      const ssh = makeConnectedSsh(client)

      const execPromise = ssh.exec("sleep infinity")

      // Attach a no-op rejection handler so the unhandled-rejection detector
      // does not fire before we assert below.
      execPromise.catch(() => {
        /* handled below */
      })

      // Calling disconnect() while the exec Promise is pending should reject it.
      ssh.disconnect()

      await expect(execPromise).rejects.toThrow("SSH connection closed")
    })
  })

  // -------------------------------------------------------------------------
  // addPort
  // -------------------------------------------------------------------------

  describe("addPort", () => {
    it("adds a new port to the config", () => {
      const ssh = makeSshInstance({ ports: [22] })

      ssh.addPort(2222)

      expect((ssh as unknown as Record<string, { ports: number[] }>).config.ports).toContain(2222)
    })

    it("does not add a duplicate port", () => {
      const ssh = makeSshInstance({ ports: [22] })

      ssh.addPort(22)

      expect((ssh as unknown as Record<string, { ports: number[] }>).config.ports).toHaveLength(1)
    })
  })

  // -------------------------------------------------------------------------
  // updateHost
  // -------------------------------------------------------------------------

  describe("updateHost", () => {
    it("updates the host used for connections", () => {
      const ssh = makeSshInstance({ host: "old-host" })

      ssh.updateHost("new-host")

      expect(ssh.getConnectionInfo().host).toBe("new-host")
    })
  })

  // -------------------------------------------------------------------------
  // reconnect
  // -------------------------------------------------------------------------

  describe("reconnect", () => {
    it("succeeds after N failed connect attempts", async () => {
      vi.useFakeTimers()

      vi.mocked(tryConnectOnPort)
        .mockRejectedValueOnce(new Error("Connection refused (attempt 1)"))
        .mockRejectedValueOnce(new Error("Connection refused (attempt 2)"))
        .mockResolvedValueOnce()

      const ssh = makeSshInstance({ reconnectTimeout: 300_000 })

      const reconnectPromise = ssh.reconnect()

      // Advance timers for first backoff delay
      await vi.advanceTimersByTimeAsync(2000)
      // Advance timers for second backoff delay
      await vi.advanceTimersByTimeAsync(4000)

      await reconnectPromise

      expect(tryConnectOnPort).toHaveBeenCalledTimes(3)
    })

    it("throws after deadline when all connect attempts fail", async () => {
      vi.useFakeTimers()

      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))

      const ssh = makeSshInstance({ reconnectTimeout: 5000 })

      const reconnectPromise = ssh.reconnect()

      // Register rejection handler before advancing timers to prevent unhandled rejection
      reconnectPromise.catch(() => {
        /* handled below */
      })

      // Advance time in steps to let pending microtasks settle between advances
      for (let elapsed = 0; elapsed < 12_000; elapsed += 1000) {
        // eslint-disable-next-line no-await-in-loop
        await vi.advanceTimersByTimeAsync(1000)
      }

      await expect(reconnectPromise).rejects.toThrow(
        /Failed to reconnect to 1\.2\.3\.4 after 5000ms/v
      )
    })

    it("throws after maxReconnectAttempts when all attempts fail before timeout", async () => {
      vi.useFakeTimers()

      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))

      // Use a high timeout so it never triggers — only the attempt limit should fire
      const ssh = makeSshInstance({ maxReconnectAttempts: 3, reconnectTimeout: 300_000 })

      const reconnectPromise = ssh.reconnect()

      // Register rejection handler before advancing timers to prevent unhandled rejection
      reconnectPromise.catch(() => {
        /* handled below */
      })

      // Advance timers so that all backoff delays between attempts can pass
      for (let elapsed = 0; elapsed < 60_000; elapsed += 1000) {
        // eslint-disable-next-line no-await-in-loop
        await vi.advanceTimersByTimeAsync(1000)
      }

      await expect(reconnectPromise).rejects.toThrow(
        /Failed to reconnect to 1\.2\.3\.4 after 3 attempts/v
      )
      expect(tryConnectOnPort).toHaveBeenCalledTimes(3)
    })

    it("uses default maxReconnectAttempts (10) when not specified", async () => {
      vi.useFakeTimers()

      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))

      // Use a high timeout so it never triggers — only the default attempt limit should fire
      const ssh = makeSshInstance({ reconnectTimeout: 600_000 })

      const reconnectPromise = ssh.reconnect()

      // Register rejection handler before advancing timers to prevent unhandled rejection
      reconnectPromise.catch(() => {
        /* handled below */
      })

      // Advance timers in large steps so all backoff delays (up to ~250 s total) pass.
      // Using 10 000 ms per step keeps microtask interleaving intact without exceeding
      // the default vitest test timeout.
      for (let elapsed = 0; elapsed < 300_000; elapsed += 10_000) {
        // eslint-disable-next-line no-await-in-loop
        await vi.advanceTimersByTimeAsync(10_000)
      }

      await expect(reconnectPromise).rejects.toThrow(
        /Failed to reconnect to 1\.2\.3\.4 after 10 attempts/v
      )
      expect(tryConnectOnPort).toHaveBeenCalledTimes(10)
    })
  })

  // -------------------------------------------------------------------------
  // connect — SSH agent auth
  // -------------------------------------------------------------------------

  describe("connect (agent auth)", () => {
    const AGENT_SOCKET = "/run/user/1000/ssh-agent.sock"

    afterEach(() => {
      delete process.env.SSH_AUTH_SOCK
    })

    it("connects via SSH agent when privateKey is omitted and SSH_AUTH_SOCK is set", async () => {
      vi.mocked(tryConnectOnPort).mockResolvedValueOnce()
      process.env.SSH_AUTH_SOCK = AGENT_SOCKET

      const ssh = makeSshInstanceWithAgent()
      await ssh.connect()

      expect(tryConnectOnPort).toHaveBeenCalledOnce()
      const [callArgs] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      expect(callArgs.agent).toBe(AGENT_SOCKET)
      expect(callArgs.privateKey).toBeUndefined()
    })

    it("throws when privateKey is omitted and SSH_AUTH_SOCK is not set", async () => {
      // SSH_AUTH_SOCK is absent (deleted in afterEach, not set here)
      const ssh = makeSshInstanceWithAgent()

      await expect(ssh.connect()).rejects.toThrow(
        "No privateKey configured and SSH_AUTH_SOCK is not set"
      )
      expect(tryConnectOnPort).not.toHaveBeenCalled()
    })

    it("throws when SSH_AUTH_SOCK is set to an empty string", async () => {
      process.env.SSH_AUTH_SOCK = ""

      const ssh = makeSshInstanceWithAgent()

      await expect(ssh.connect()).rejects.toThrow(
        "No privateKey configured and SSH_AUTH_SOCK is not set"
      )
      expect(tryConnectOnPort).not.toHaveBeenCalled()
    })

    it("throws when SSH_AUTH_SOCK points to a non-existent path", async () => {
      vi.mocked(stat).mockRejectedValueOnce(new Error("ENOENT"))
      process.env.SSH_AUTH_SOCK = "/no/such/socket"

      const ssh = makeSshInstanceWithAgent()

      await expect(ssh.connect()).rejects.toThrow(
        "SSH_AUTH_SOCK points to non-existent path: /no/such/socket"
      )
      expect(tryConnectOnPort).not.toHaveBeenCalled()
    })

    it("throws when SSH_AUTH_SOCK is set but all port connections fail", async () => {
      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))
      process.env.SSH_AUTH_SOCK = AGENT_SOCKET

      const ssh = makeSshInstanceWithAgent({ ports: [22, 2222] })

      await expect(ssh.connect()).rejects.toThrow(
        /Could not connect to 1\.2\.3\.4 via SSH agent on ports 22, 2222/v
      )
      // Must have tried each configured port
      expect(tryConnectOnPort).toHaveBeenCalledTimes(2)
    })

    it("passes agentForward: true to tryConnectOnPort when configured", async () => {
      vi.mocked(tryConnectOnPort).mockResolvedValueOnce()
      process.env.SSH_AUTH_SOCK = AGENT_SOCKET

      const ssh = makeSshInstanceWithAgent({ agentForward: true })
      await ssh.connect()

      const [callArgsForward] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      expect(callArgsForward.agentForward).toBe(true)
    })

    it("passes agentForward: undefined to tryConnectOnPort on key-auth path (backwards compatibility)", async () => {
      vi.mocked(tryConnectOnPort).mockResolvedValueOnce()

      const ssh = makeSshInstance()
      await ssh.connect()

      const [callArgsKeyAuth] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      expect(callArgsKeyAuth.agentForward).toBeUndefined()
    })

    it("connects on second attempt when agent-only fails and passwordFallback is true", async () => {
      // Arrange: first call (agent-only) rejects, second call (agent + password) resolves
      vi.mocked(tryConnectOnPort)
        .mockRejectedValueOnce(new Error("Agent auth failed"))
        .mockResolvedValueOnce()
      vi.mocked(promptTerminal).mockResolvedValueOnce("secret-password")
      process.env.SSH_AUTH_SOCK = AGENT_SOCKET

      const ssh = makeSshInstanceWithAgent({ passwordFallback: true })

      // Act
      await ssh.connect()

      // Assert: tryConnectOnPort called twice — once without password, once with
      expect(tryConnectOnPort).toHaveBeenCalledTimes(2)
      const [, secondCallArgs] = vi.mocked(tryConnectOnPort).mock.calls as [
        Parameters<typeof tryConnectOnPort>,
        Parameters<typeof tryConnectOnPort>,
      ]
      expect(secondCallArgs[0].password).toBe("secret-password")
      expect(secondCallArgs[0].agent).toBe(AGENT_SOCKET)
      expect(promptTerminal).toHaveBeenCalledOnce()
    })

    it("throws when agent-only fails and passwordFallback second attempt also fails", async () => {
      // Arrange: both attempts fail
      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))
      vi.mocked(promptTerminal).mockResolvedValueOnce("wrong-password")
      process.env.SSH_AUTH_SOCK = AGENT_SOCKET

      const ssh = makeSshInstanceWithAgent({ passwordFallback: true })

      // Act & Assert
      await expect(ssh.connect()).rejects.toThrow(
        /Could not connect to 1\.2\.3\.4 via SSH agent on ports 22/v
      )
      // Prompt must have been shown once (fallback was attempted)
      expect(promptTerminal).toHaveBeenCalledOnce()
      // Both agent-only and agent+password attempts must have been made
      expect(tryConnectOnPort).toHaveBeenCalledTimes(2)
    })

    it("throws immediately without prompting when agent-only fails and passwordFallback is disabled", async () => {
      // Arrange: agent-only attempt fails, passwordFallback not set
      vi.mocked(tryConnectOnPort).mockRejectedValueOnce(new Error("Permission denied"))
      process.env.SSH_AUTH_SOCK = AGENT_SOCKET

      const ssh = makeSshInstanceWithAgent({ passwordFallback: false })

      // Act & Assert
      await expect(ssh.connect()).rejects.toThrow(
        /Could not connect to 1\.2\.3\.4 via SSH agent on ports 22/v
      )
      // No prompt must have been shown
      expect(promptTerminal).not.toHaveBeenCalled()
      // Only one attempt (no fallback)
      expect(tryConnectOnPort).toHaveBeenCalledTimes(1)
    })
  })

  // -------------------------------------------------------------------------
  // exec
  // -------------------------------------------------------------------------

  describe("exec", () => {
    it("rejects with timeout error when stream never closes", async () => {
      vi.useFakeTimers()

      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // Stream never emits 'close' — simulates a hanging command
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      const execPromise = ssh.exec("sleep infinity", { timeout: 5000 })

      // Register rejection handler before advancing timers to prevent unhandled rejection
      execPromise.catch(() => {
        /* handled below */
      })

      await vi.advanceTimersByTimeAsync(5001)

      await expect(execPromise).rejects.toThrow(/Command timed out after 5000ms/v)
    })

    it("masks secrets in the timeout error message (regression: raw command was interpolated)", async () => {
      // Regression: before the fix, the timeout error interpolated `command`
      // directly without calling maskSecrets, leaking secrets into error messages.
      vi.useFakeTimers()

      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // Stream never emits 'close' — simulates a hanging command
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      const secret = "super-secret-token"
      const execPromise = ssh.exec(`echo ${secret}`, { secrets: [secret], timeout: 5000 })

      execPromise.catch(() => {
        /* handled below */
      })

      await vi.advanceTimersByTimeAsync(5001)

      const error = await execPromise.catch((error: unknown) => error as Error)
      expect(error.message).not.toContain(secret)
      expect(error.message).toContain("[REDACTED]")
    })

    it("prefixes sudo command with SUDO_PROMPT='' to suppress username disclosure in stderr", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { sudoPassword: "my-sudo-pass", user: "deploy" })

      await ssh.exec("whoami")

      const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
      expect(executedCommand).toContain("SUDO_PROMPT=''")
      expect(executedCommand).toMatch(/^SUDO_PROMPT='' sudo -S bash -c /v)
    })

    it("writes sudo password to stdin for non-root user with cachedSudoPassword", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // Verify write was called before close
        expect(stream.write).toHaveBeenCalledWith(Buffer.from("my-sudo-pass\n"))
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { sudoPassword: "my-sudo-pass", user: "deploy" })

      await ssh.exec("whoami")

      expect(execSpy).toHaveBeenCalledOnce()
    })

    it("registers stream listeners (collectStreamOutput) before writing sudo password to stdin (regression: race condition)", async () => {
      // Root cause: stream.write(sudoPassword) was called before collectStreamOutput,
      // so listeners were registered after the password was already written.
      // Fix: collectStreamOutput must be called first to register listeners,
      // then stream.write sends the password.
      let capturedStream: null | StreamWithStderr = null

      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        capturedStream = stream
        callback(undefined, stream)
        stream.emit("close", 0)
      })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { sudoPassword: "my-sudo-pass", user: "deploy" })

      await ssh.exec("whoami")

      expect(capturedStream).not.toBeNull()
      expect(vi.mocked(collectStreamOutput)).toHaveBeenCalledOnce()
      expect(vi.mocked(capturedStream!.write)).toHaveBeenCalledWith(Buffer.from("my-sudo-pass\n"))

      // collectStreamOutput must be invoked before stream.write so that all
      // stream event listeners are registered before the sudo password is sent
      const collectOrder = vi.mocked(collectStreamOutput).mock.invocationCallOrder[0]
      const writeOrder = vi.mocked(capturedStream?.write).mock.invocationCallOrder[0]
      expect(collectOrder).toBeDefined()
      expect(writeOrder).toBeDefined()
      expect(collectOrder).toBeLessThan(writeOrder)
    })

    it("rejects pending exec() immediately when client emits 'close'", async () => {
      let capturedStream: null | StreamWithStderr = null
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        capturedStream = stream
        callback(undefined, stream)
        // Stream intentionally never emits 'close' — the exec() Promise stays pending
      })

      const clientEmitter = new EventEmitter()
      const client = Object.assign(clientEmitter, {
        end: vi.fn(),
        exec: execSpy,
        sftp: vi.fn(),
      }) as unknown as Client & EventEmitter

      const ssh = makeConnectedSshWithCloseListener(client, {})

      const execPromise = ssh.exec("sleep infinity")

      // Ensure the stream was handed to exec() before we emit 'close'
      expect(capturedStream).not.toBeNull()

      // Simulate an unexpected connection drop
      clientEmitter.emit("close")

      await expect(execPromise).rejects.toThrow("SSH connection closed unexpectedly")
    })

    it("rejects when client.exec callback receives an error", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        callback(new Error("SSH channel open failed"), undefined as unknown as StreamWithStderr)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      await expect(ssh.exec("whoami")).rejects.toThrow("SSH channel open failed")
    })

    // -------------------------------------------------------------------------
    // env option — buildEnvPrefix validation
    // -------------------------------------------------------------------------

    describe("env option", () => {
      it("throws synchronously for an env key containing a semicolon (injection attempt)", async () => {
        const client = makeClientWithEnd(vi.fn())
        const ssh = makeConnectedSsh(client)

        await expect(ssh.exec("whoami", { env: { "FOO;rm -rf /": "val" } })).rejects.toThrow(
          "Invalid environment variable name: FOO;rm -rf /"
        )
      })

      it("throws for an env key that starts with a digit", async () => {
        const client = makeClientWithEnd(vi.fn())
        const ssh = makeConnectedSsh(client)

        await expect(ssh.exec("whoami", { env: { "1INVALID": "val" } })).rejects.toThrow(
          "Invalid environment variable name: 1INVALID"
        )
      })

      it("throws for an env key containing a space", async () => {
        const client = makeClientWithEnd(vi.fn())
        const ssh = makeConnectedSsh(client)

        await expect(ssh.exec("whoami", { env: { "MY VAR": "val" } })).rejects.toThrow(
          "Invalid environment variable name: MY VAR"
        )
      })

      it("throws for an env key containing a dollar sign", async () => {
        const client = makeClientWithEnd(vi.fn())
        const ssh = makeConnectedSsh(client)

        await expect(ssh.exec("whoami", { env: { $SECRET: "val" } })).rejects.toThrow(
          "Invalid environment variable name: $SECRET"
        )
      })

      it("accepts a simple uppercase key (MY_VAR)", async () => {
        const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        const client = makeClientWithExecSpy(execSpy)
        const ssh = makeConnectedSsh(client)

        await expect(ssh.exec("whoami", { env: { MY_VAR: "hello" } })).resolves.toBeDefined()

        const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
        expect(executedCommand).toContain("MY_VAR=")
      })

      it("accepts an underscore-prefixed key (_foo)", async () => {
        const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        const client = makeClientWithExecSpy(execSpy)
        const ssh = makeConnectedSsh(client)

        await expect(ssh.exec("whoami", { env: { _foo: "bar" } })).resolves.toBeDefined()

        const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
        expect(executedCommand).toContain("_foo=")
      })

      it("accepts the conventional PATH key", async () => {
        const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        const client = makeClientWithExecSpy(execSpy)
        const ssh = makeConnectedSsh(client)

        await expect(
          ssh.exec("whoami", { env: { PATH: "/usr/local/bin:/usr/bin" } })
        ).resolves.toBeDefined()

        const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
        expect(executedCommand).toContain("PATH=")
      })

      it("shell-quotes the env value to prevent injection", async () => {
        const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        const client = makeClientWithExecSpy(execSpy)
        const ssh = makeConnectedSsh(client)

        await ssh.exec("whoami", { env: { GREETING: "hello world; rm -rf /" } })

        const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
        // Value must be wrapped in single quotes, not interpolated raw
        expect(executedCommand).toContain("GREETING='hello world; rm -rf /'")
      })

      it("places env vars INSIDE the bash -c argument for non-root user with sudo (regression: env before sudo)", async () => {
        // Regression test: env vars must appear inside `bash -c '...'`, not before
        // the sudo call. Previously, the command was:
        //   MY_VAR='val' SUDO_PROMPT='' sudo -S bash -c 'whoami'
        // which is wrong because sudo strips env vars by default.
        // The correct form is:
        //   SUDO_PROMPT='' sudo -S bash -c 'MY_VAR='\''val'\'' whoami'
        const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        const client = makeClientWithExecSpy(execSpy)
        const ssh = makeConnectedSsh(client, { sudoPassword: "secret", user: "deploy" })

        await ssh.exec("whoami", { env: { MY_VAR: "val" } })

        const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]

        // The outer command must NOT start with env vars — sudo must come first
        expect(executedCommand).toMatch(/^SUDO_PROMPT='' sudo -S bash -c /v)

        // MY_VAR must appear inside the quoted bash -c argument (i.e. after `bash -c '`)
        const bashCArgument = executedCommand.replace(/^SUDO_PROMPT='' sudo -S bash -c /v, "")
        expect(bashCArgument).toContain("MY_VAR=")
      })

      it("places env vars INSIDE the bash -c argument for non-root user without sudo password (passwordless sudo)", async () => {
        // Same regression test for the passwordless-sudo branch (no cachedSudoPassword).
        // The correct form is:
        //   sudo bash -c 'MY_VAR='\''val'\'' whoami'
        const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        const client = makeClientWithExecSpy(execSpy)
        // No sudoPassword — triggers the `sudo bash -c` branch
        const ssh = makeConnectedSsh(client, { user: "deploy" })

        await ssh.exec("whoami", { env: { MY_VAR: "val" } })

        const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]

        // The outer command must NOT start with env vars — sudo must come first
        expect(executedCommand).toMatch(/^sudo bash -c /v)

        // MY_VAR must appear inside the quoted bash -c argument
        const bashCArgument = executedCommand.replace(/^sudo bash -c /v, "")
        expect(bashCArgument).toContain("MY_VAR=")
      })
    })
  })

  // -------------------------------------------------------------------------
  // sha256
  // -------------------------------------------------------------------------

  describe("sha256", () => {
    it("returns null when the file does not exist", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("close", 1) // file does not exist
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      const result = await ssh.sha256("/nonexistent")

      expect(result).toBeNull()
    })

    it("returns the hash when the file exists", async () => {
      const execSpy = vi
        .fn()
        // First call: test() — file exists, exit 0
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Second call: sha256sum output
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("data", Buffer.from("abc123def456  /etc/hosts\n"))
          stream.emit("close", 0)
        })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      const result = await ssh.sha256("/etc/hosts")

      expect(result).toBe("abc123def456")
    })
  })

  // -------------------------------------------------------------------------
  // lines
  // -------------------------------------------------------------------------

  describe("lines", () => {
    it("returns an empty array for empty output", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("data", Buffer.from("   \n"))
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      const result = await ssh.lines("echo ''")

      expect(result).toStrictEqual([])
    })
  })

  // -------------------------------------------------------------------------
  // readFile
  // -------------------------------------------------------------------------

  describe("readFile", () => {
    it("uses sudo prefix for non-root user", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("data", Buffer.from("file content"))
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.readFile("/etc/shadow")

      const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
      expect(executedCommand).toContain("sudo")
      expect(executedCommand).toContain("cat")
      expect(executedCommand).toContain("/etc/shadow")
    })

    it("does not use sudo prefix for root user", async () => {
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("data", Buffer.from("file content"))
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "root" })

      await ssh.readFile("/etc/hosts")

      const [executedCommand] = execSpy.mock.calls[0] as [string, ...unknown[]]
      expect(executedCommand).not.toContain("sudo")
      expect(executedCommand).toContain("cat")
    })
  })

  // -------------------------------------------------------------------------
  // uploadFile
  // -------------------------------------------------------------------------

  describe("uploadFile", () => {
    it("runs chmod on temp file before mv when mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/tmp/paratix-upload.ABCDEF"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        // First call: mktemp (via output())
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("data", Buffer.from(tempPath))
          stream.emit("close", 0)
        })
        // Second call: chmod (on temp file)
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Third call: mv
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Fourth call: rm -f (cleanup in finally)
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      await ssh.uploadFile("/local/file.txt", "/remote/path", { mode: "0644" })

      const chmodCommand = executedCommands.find((cmd) => cmd.includes("chmod"))
      expect(chmodCommand).toBeDefined()
      expect(chmodCommand).toContain("0644")
      expect(chmodCommand).toContain(tempPath)
      // chmod must come before mv
      const mvIndex = executedCommands.findIndex((cmd) => /(?:^| )mv /v.test(cmd))
      const chmodIndex = executedCommands.findIndex((cmd) => cmd.includes("chmod"))
      expect(chmodIndex).toBeLessThan(mvIndex)
    })

    it("does not run chmod when no mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/tmp/paratix-upload.ABCDEF"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        // First call: mktemp
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("data", Buffer.from(tempPath))
          stream.emit("close", 0)
        })
        // Second call: mv
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Third call: rm -f (cleanup in finally)
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      await ssh.uploadFile("/local/file.txt", "/remote/path")

      expect(executedCommands.some((cmd) => cmd.includes("chmod"))).toBe(false)
    })

    it("cleans up the temporary remote file when mv fails", async () => {
      // This test documents a bug: uploadFile has no try/finally, so the
      // temporary remote file created by mktemp is not removed when mv fails.
      // After the fix, exec must be called with `rm -f` on the temp path.
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/tmp/paratix-upload.ABCDEF"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        // First call: mktemp (via output()) — returns temp path
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("data", Buffer.from(tempPath))
          stream.emit("close", 0)
        })
        // Second call: mv — fails with non-zero exit code
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 1)
        })
        // Third call: rm -f — the cleanup that should happen in a fixed implementation
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      await expect(ssh.uploadFile("/local/file.txt", "/remote/file.txt")).rejects.toThrow(
        "Command failed"
      )

      // After the fix: rm -f must be called on the temporary path
      const cleanupCommand = executedCommands.find((cmd) => cmd.includes("rm -f"))
      expect(cleanupCommand).toBeDefined()
      expect(cleanupCommand).toContain(tempPath)
    })
  })

  // -------------------------------------------------------------------------
  // writeFile
  // -------------------------------------------------------------------------

  describe("writeFile", () => {
    it("always uses atomic SFTP path (write-to-temp + mv) for all content", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/tmp/paratix-write.ABCDEF"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("data", Buffer.from(tempPath))
          stream.emit("close", 0)
        })
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      await ssh.writeFile("/remote/plain.txt", "hello world")

      // SFTP upload must have been called — atomic path
      expect(vi.mocked(sftpUpload)).toHaveBeenCalledOnce()

      // printf must NOT have been used
      const usedPrintf = executedCommands.some((cmd) => cmd.includes("printf"))
      expect(usedPrintf).toBe(false)

      // mktemp and mv confirm atomic write path
      expect(executedCommands.some((cmd) => cmd.includes("mktemp"))).toBe(true)
      expect(executedCommands.some((cmd) => cmd.includes("mv"))).toBe(true)
    })

    it("runs chmod on temp file before mv when mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/tmp/paratix-write.ABCDEF"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("data", Buffer.from(tempPath))
          stream.emit("close", 0)
        })
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          executedCommands.push(_command)
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client)

      await ssh.writeFile("/remote/path", "hello world", { mode: "0755" })

      expect(vi.mocked(sftpUpload)).toHaveBeenCalledOnce()

      const chmodCommand = executedCommands.find((cmd) => cmd.includes("chmod"))
      expect(chmodCommand).toBeDefined()
      expect(chmodCommand).toContain("0755")
      expect(chmodCommand).toContain(tempPath)
      // chmod must come before mv
      const mvIndex = executedCommands.findIndex((cmd) => /(?:^| )mv /v.test(cmd))
      const chmodIndex = executedCommands.findIndex((cmd) => cmd.includes("chmod"))
      expect(chmodIndex).toBeLessThan(mvIndex)
    })
  })

  // -------------------------------------------------------------------------
  // downloadFile
  // -------------------------------------------------------------------------

  describe("downloadFile", () => {
    it("downloads directly via SFTP for root user", async () => {
      const execSpy = vi.fn()
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "root" })

      await ssh.downloadFile("/var/log/syslog", "/tmp/local-syslog")

      expect(vi.mocked(sftpDownload)).toHaveBeenCalledWith(
        client,
        "/var/log/syslog",
        "/tmp/local-syslog"
      )
      // No exec calls for cp/chmod/rm
      expect(execSpy).not.toHaveBeenCalled()
    })

    it("sets chmod 600 (owner-only) on the temporary copy for non-root user", async () => {
      const executedCommands: string[] = []
      const mktempOutput = "/tmp/paratix-download.ABCDEF"

      const execSpy = vi
        .fn()
        // First call: mktemp (via output())
        .mockImplementationOnce((cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("data", Buffer.from(mktempOutput))
          stream.emit("close", 0)
        })
        // Second call: cp
        .mockImplementationOnce((cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Third call: chmod
        .mockImplementationOnce((cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Fourth call: rm -f
        .mockImplementationOnce((cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.downloadFile("/var/log/secure", "/tmp/local-secure")

      const chmodCommand = executedCommands.find((cmd) => cmd.includes("chmod"))
      expect(chmodCommand).toBeDefined()
      // Temp copy must be owner-only (600), not world-readable (644)
      expect(chmodCommand).toContain("chmod 600")
    })

    it("uses mktemp, cp, chmod, sftp, rm for non-root user", async () => {
      const executedCommands: string[] = []
      const mktempOutput = "/tmp/paratix-download.ABCDEF"

      function makeExecHandler(output: string): (_command: string, callback: ExecCallback) => void {
        return (cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("data", Buffer.from(output))
          stream.emit("close", 0)
        }
      }

      const execSpy = vi
        .fn()
        // First call: mktemp (via output()) — returns temp path
        .mockImplementationOnce(makeExecHandler(mktempOutput))
        // Second call: cp
        .mockImplementationOnce(makeExecHandler(""))
        // Third call: chmod
        .mockImplementationOnce(makeExecHandler(""))
        // Fourth call: rm -f
        .mockImplementationOnce(makeExecHandler(""))

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.downloadFile("/var/log/secure", "/tmp/local-secure")

      // Verify the sequence: mktemp, cp, chmod, then sftpDownload, then rm
      expect(executedCommands.some((cmd) => cmd.includes("mktemp"))).toBe(true)
      expect(executedCommands.some((cmd) => cmd.includes("cp"))).toBe(true)
      expect(executedCommands.some((cmd) => cmd.includes("chmod 600"))).toBe(true)
      expect(vi.mocked(sftpDownload)).toHaveBeenCalledWith(
        client,
        mktempOutput,
        "/tmp/local-secure"
      )
      expect(executedCommands.some((cmd) => cmd.includes("rm -f"))).toBe(true)
    })
  })

  // -------------------------------------------------------------------------
  // constructor — sudoPassword newline validation
  // -------------------------------------------------------------------------

  describe("constructor sudoPassword newline validation", () => {
    it("throws when sudoPassword contains \\n", () => {
      // Arrange & Act & Assert
      expect(
        () =>
          new SshConnectionImpl("1.2.3.4", {
            ports: [22],
            privateKey: "/dev/null",
            sudoPassword: "pass\nword",
            user: "deploy",
          })
      ).toThrow("newline")
    })

    it("throws when sudoPassword contains \\r", () => {
      // Arrange & Act & Assert
      expect(
        () =>
          new SshConnectionImpl("1.2.3.4", {
            ports: [22],
            privateKey: "/dev/null",
            sudoPassword: "pass\rword",
            user: "deploy",
          })
      ).toThrow("newline")
    })

    it("does not throw when sudoPassword contains no newline characters", () => {
      // Arrange & Act & Assert
      expect(
        () =>
          new SshConnectionImpl("1.2.3.4", {
            ports: [22],
            privateKey: "/dev/null",
            sudoPassword: "s3cret-password!",
            user: "deploy",
          })
      ).not.toThrow()
    })

    it("does not throw when sudoPassword is undefined", () => {
      // Arrange & Act & Assert
      expect(
        () =>
          new SshConnectionImpl("1.2.3.4", {
            ports: [22],
            privateKey: "/dev/null",
            user: "deploy",
          })
      ).not.toThrow()
    })
  })

  // -------------------------------------------------------------------------
  // probeSudo
  // -------------------------------------------------------------------------

  describe("probeSudo", () => {
    it("masks the sudo password in the error message when authentication fails (regression)", async () => {
      // Arrange
      const password = "s3cret-pw"
      vi.mocked(promptTerminal).mockResolvedValueOnce(password)

      const execSpy = vi
        .fn()
        // First call: passwordless sudo probe — fails (sudo requires a password)
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 1)
        })
        // Second call: sudo with password — fails with the password in stderr
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.stderr.emit("data", Buffer.from(`Authentication failed: ${password} invalid`))
          stream.emit("close", 1)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act
      const error = await ssh.probeSudo().catch((error: unknown) => error as Error)

      // Assert: error is thrown
      expect(error).toBeInstanceOf(Error)
      // The error message must start with the expected prefix
      expect(error.message).toContain("Sudo authentication failed")
      // The plain-text password must NOT appear in the error message
      expect(error.message).not.toContain(password)
      // The password must be replaced with the mask token
      expect(error.message).toContain("[REDACTED]")
    })

    it("throws when the interactively entered sudo password contains \\n (regression)", async () => {
      // Arrange
      vi.mocked(promptTerminal).mockResolvedValueOnce("pass\nword")

      const execSpy = vi.fn().mockImplementationOnce((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // First exec call: passwordless sudo probe fails so probeSudo prompts for a password
        stream.emit("close", 1)
      })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act & Assert
      await expect(ssh.probeSudo()).rejects.toThrow("newline")
    })

    it("throws when the interactively entered sudo password contains \\r (regression)", async () => {
      // Arrange
      vi.mocked(promptTerminal).mockResolvedValueOnce("pass\rword")

      const execSpy = vi.fn().mockImplementationOnce((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("close", 1)
      })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act & Assert
      await expect(ssh.probeSudo()).rejects.toThrow("newline")
    })
  })

  // -------------------------------------------------------------------------
  // tryConnectOnPorts — hostVerifier and strictHostKeyChecking propagation
  // -------------------------------------------------------------------------

  describe("tryConnectOnPorts (hostVerifier + strictHostKeyChecking)", () => {
    // Re-establish the buildHostVerifier mock return value after each resetAllMocks() call.
    // vi.resetAllMocks() wipes mockReturnValue, causing destructuring of the result to throw.
    beforeEach(async () => {
      const knownHosts = await import("../src/knownHosts.js")
      vi.mocked(knownHosts.buildHostVerifier).mockReturnValue({})
      vi.mocked(tryConnectOnPort).mockResolvedValue()
    })

    it("calls buildHostVerifier with default mode 'accept-new' when strictHostKeyChecking is not set", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      const ssh = makeSshInstance({ host: "1.2.3.4", ports: [22] })

      await ssh.connect()

      expect(buildHostVerifier).toHaveBeenCalledWith("accept-new", "1.2.3.4", 22)
    })

    it("calls buildHostVerifier with mode 'no' when strictHostKeyChecking is 'no'", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      const config = {
        ports: [22],
        privateKey: "/dev/null",
        strictHostKeyChecking: "no" as const,
        user: "root",
      }
      const ssh = new SshConnectionImpl("1.2.3.4", config)

      await ssh.connect()

      expect(buildHostVerifier).toHaveBeenCalledWith("no", "1.2.3.4", 22)
    })

    it("calls buildHostVerifier with mode 'yes' when strictHostKeyChecking is 'yes'", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      const config = {
        ports: [22],
        privateKey: "/dev/null",
        strictHostKeyChecking: "yes" as const,
        user: "root",
      }
      const ssh = new SshConnectionImpl("1.2.3.4", config)

      await ssh.connect()

      expect(buildHostVerifier).toHaveBeenCalledWith("yes", "1.2.3.4", 22)
    })

    it("passes the hostVerifier from buildHostVerifier to tryConnectOnPort", async () => {
      const fakeVerifier = vi.fn().mockReturnValue(true)
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      vi.mocked(buildHostVerifier).mockReturnValue({ hostVerifier: fakeVerifier })

      const ssh = makeSshInstance({ host: "1.2.3.4", ports: [22] })

      await ssh.connect()

      const [callArgs] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      expect(callArgs.hostVerifier).toBe(fakeVerifier)
    })

    it("calls buildHostVerifier once per port when connecting across multiple ports", async () => {
      vi.mocked(tryConnectOnPort)
        .mockRejectedValueOnce(new Error("Connection refused on port 22"))
        .mockResolvedValueOnce()

      const { buildHostVerifier } = await import("../src/knownHosts.js")
      const ssh = makeSshInstance({ host: "1.2.3.4", ports: [22, 2222] })

      await ssh.connect()

      // One call per port attempted (22 failed, 2222 succeeded)
      expect(buildHostVerifier).toHaveBeenCalledTimes(2)
      expect(buildHostVerifier).toHaveBeenNthCalledWith(1, "accept-new", "1.2.3.4", 22)
      expect(buildHostVerifier).toHaveBeenNthCalledWith(2, "accept-new", "1.2.3.4", 2222)
    })

    it("passes undefined hostVerifier to tryConnectOnPort when mode is 'no'", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      // mode "no" returns empty object — no hostVerifier
      vi.mocked(buildHostVerifier).mockReturnValue({})

      const config = {
        ports: [22],
        privateKey: "/dev/null",
        strictHostKeyChecking: "no" as const,
        user: "root",
      }
      const ssh = new SshConnectionImpl("1.2.3.4", config)

      await ssh.connect()

      const [callArgs] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      expect(callArgs.hostVerifier).toBeUndefined()
    })
  })
})
