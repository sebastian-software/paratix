import type { Client, SFTPWrapper } from "ssh2"

import { EventEmitter } from "node:events"
import { stat } from "node:fs/promises"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type * as KnownHosts from "../src/knownHosts.js"
import type * as SshHelpers from "../src/sshHelpers.js"

import { HostKeyVerificationError } from "../src/knownHosts.js"
import { sftpDownload } from "../src/sftp.js"
import { SshConnectionImpl } from "../src/ssh.js"
import { collectStreamOutput, shellQuote, tryConnectOnPort } from "../src/sshHelpers.js"
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
  // readFile must return a Buffer (not a string) because connect() calls readFile(path)
  // without an encoding argument and then calls privateKey.fill(0) on the result.
  readFile: vi.fn().mockResolvedValue(Buffer.from("fake-private-key")),
  stat: vi.fn().mockResolvedValue({}),
}))

vi.mock("../src/knownHosts.js", async () => {
  const actual = await vi.importActual<typeof KnownHosts>("../src/knownHosts.js")
  return {
    appendHostKey: vi.fn().mockResolvedValue(null),
    // Default: return empty object (no hostVerifier) so ssh.ts can safely destructure after resetAllMocks.
    buildHostVerifier: vi.fn().mockReturnValue({}),
    extractAlgoFromKey: actual.extractAlgoFromKey,
    HostKeyVerificationError: actual.HostKeyVerificationError,
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

    // Re-establish readFile mock after vi.resetAllMocks() wipes it.
    // connect() calls readFile(path) without encoding — the result must be a Buffer
    // so that privateKey.fill(0) in the finally-block does not throw a TypeError.
    const fsp = await import("node:fs/promises")
    vi.mocked(fsp.readFile).mockResolvedValue(Buffer.from("fake-private-key") as never)
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
        /Failed to reconnect to 1\.2\.3\.4 after \d+ attempts \(timeout: 5000ms\)/v
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

    it("clears cached password and throws when host key changes on reconnect", async () => {
      const initialKey = Buffer.from("initial-host-key")
      const differentKey = Buffer.from("different-key!!")

      // Mock tryConnectOnPort to invoke hostVerifier with the provided key
      vi.mocked(tryConnectOnPort).mockImplementation(async (parameters) => {
        await Promise.resolve()
        parameters.hostVerifier?.(differentKey)
      })

      const ssh = makeSshInstance({ reconnectTimeout: 300_000 })

      // Simulate an already-pinned key from a previous connection
      ;(ssh as any).pinnedHostKey = initialKey
      ;(ssh as any).cachedSudoPassword = Buffer.from("secret")
      await expect(ssh.reconnect()).rejects.toThrow(HostKeyVerificationError)

      // Password should have been cleared before the error was thrown
      expect((ssh as any).cachedSudoPassword).toBeNull()
    })

    it("zeroes the password buffer before setting cachedSudoPassword to null — R-002 regression", async () => {
      // Arrange: capture a reference to the buffer before clearCachedPassword runs
      const passwordBuffer = Buffer.from("secret-password")
      const initialKey = Buffer.from("initial-host-key")
      const differentKey = Buffer.from("different-key!!")

      vi.mocked(tryConnectOnPort).mockImplementation(async (parameters) => {
        await Promise.resolve()
        parameters.hostVerifier?.(differentKey)
      })

      const ssh = makeSshInstance({ reconnectTimeout: 300_000 })
      ;(ssh as any).pinnedHostKey = initialKey
      ;(ssh as any).cachedSudoPassword = passwordBuffer

      await expect(ssh.reconnect()).rejects.toThrow(HostKeyVerificationError)

      // The buffer that was held by cachedSudoPassword must have been zeroed out
      expect(passwordBuffer.every((byte) => byte === 0)).toBe(true)
      // And the field must be null
      expect((ssh as any).cachedSudoPassword).toBeNull()
    })

    it("reconnects successfully when host key matches pinned key", async () => {
      const hostKey = Buffer.from("stable-host-key")

      vi.mocked(tryConnectOnPort).mockImplementation(async (parameters) => {
        await Promise.resolve()
        parameters.hostVerifier?.(hostKey)
      })

      const ssh = makeSshInstance({ reconnectTimeout: 300_000 })

      // Simulate an already-pinned key from a previous connection
      ;(ssh as any).pinnedHostKey = Buffer.from(hostKey)

      await ssh.reconnect()

      expect(tryConnectOnPort).toHaveBeenCalledTimes(1)
    })

    it("aborts immediately without retry when connect throws SSH connection closed — R-003 regression", async () => {
      const ssh = makeSshInstance({ reconnectTimeout: 300_000 })

      // Spy on the public connect() method so the error is thrown directly from
      // reconnect()'s `await this.connect()` call, bypassing tryConnectOnPorts().
      const connectSpy = vi
        .spyOn(ssh, "connect")
        .mockRejectedValue(new Error("SSH connection closed"))

      await expect(ssh.reconnect()).rejects.toThrow("SSH connection closed")

      // Must not retry — connect() is called exactly once
      expect(connectSpy).toHaveBeenCalledTimes(1)
    })

    it("pins host key on initial connection", async () => {
      const hostKey = Buffer.from("new-host-key")

      vi.mocked(tryConnectOnPort).mockImplementation(async (parameters) => {
        await Promise.resolve()
        parameters.hostVerifier?.(hostKey)
      })

      const ssh = makeSshInstance()

      await ssh.connect()

      expect((ssh as any).pinnedHostKey).toStrictEqual(hostKey)
    })

    it("backoff sleep does not exceed remaining time before deadline — R-004 regression", async () => {
      // Regression: without the fix, the last backoff sleep could be up to
      // RECONNECT_MAX_DELAY (30 000 ms) even when only a few milliseconds remain
      // before the deadline.  With the fix, the delay is capped to
      // `Math.max(0, deadline - Date.now())`, so the reconnect() promise must
      // reject very close to the reconnectTimeout, not at reconnectTimeout + 30 000.
      vi.useFakeTimers()

      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))

      const reconnectTimeout = 3000
      const ssh = makeSshInstance({ reconnectTimeout })

      const reconnectPromise = ssh.reconnect()

      // Register rejection handler early to prevent unhandled rejection warnings
      reconnectPromise.catch(() => {
        /* handled below */
      })

      // Advance time in 500 ms increments up to reconnectTimeout + a small
      // overhead (1 000 ms) that covers the cost of the connect() calls
      // themselves.  Without the fix this would need ~33 000 ms to settle.
      const tolerance = 1000
      for (let elapsed = 0; elapsed <= reconnectTimeout + tolerance; elapsed += 500) {
        // eslint-disable-next-line no-await-in-loop
        await vi.advanceTimersByTimeAsync(500)
      }

      // The promise must already be settled (rejected) within the deadline + tolerance
      await expect(reconnectPromise).rejects.toThrow(
        /Failed to reconnect to 1\.2\.3\.4 after \d+ attempts \(timeout: 3000ms\)/v
      )
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
  // connect — private key auth and memory sanitization
  // -------------------------------------------------------------------------

  describe("connect (private key auth)", () => {
    it("reads the private key as a Buffer (no utf8 encoding)", async () => {
      // Arrange: readFile mock returns a Buffer to simulate binary-safe read
      const { readFile } = await import("node:fs/promises")
      const fakeKeyBuffer = Buffer.from("fake-pem-key-content")
      vi.mocked(readFile).mockResolvedValueOnce(fakeKeyBuffer as never)
      vi.mocked(tryConnectOnPort).mockResolvedValueOnce()

      const ssh = makeSshInstance()

      // Act
      await ssh.connect()

      // Assert: readFile was called with just the path — no "utf8" encoding option
      expect(readFile).toHaveBeenCalledOnce()
      const [calledPath, calledOptions] = vi.mocked(readFile).mock.calls[0] as [string, unknown]
      expect(calledPath).toBe("/dev/null")
      // Must NOT pass an encoding so the result is a Buffer, not a string
      expect(calledOptions).toBeUndefined()
    })

    it("zeroes the private key Buffer after a successful connection (finally-block)", async () => {
      // Arrange
      const { readFile } = await import("node:fs/promises")
      const fakeKeyBuffer = Buffer.from("sensitive-private-key")
      vi.mocked(readFile).mockResolvedValueOnce(fakeKeyBuffer as never)
      vi.mocked(tryConnectOnPort).mockResolvedValueOnce()

      const ssh = makeSshInstance()

      // Act
      await ssh.connect()

      // Assert: every byte of the buffer must be 0 after connect() resolves
      expect(fakeKeyBuffer.every((byte) => byte === 0)).toBe(true)
    })

    it("zeroes the private key Buffer even when the connection fails (finally-block on error)", async () => {
      // Arrange
      const { readFile } = await import("node:fs/promises")
      const fakeKeyBuffer = Buffer.from("sensitive-private-key")
      vi.mocked(readFile).mockResolvedValueOnce(fakeKeyBuffer as never)
      // All ports fail — tryConnectOnPorts returns false, connect() throws
      vi.mocked(tryConnectOnPort).mockRejectedValue(new Error("Connection refused"))

      const ssh = makeSshInstance({ ports: [22] })

      // Act: expect the connect to fail
      await expect(ssh.connect()).rejects.toThrow(/Failed to connect/v)

      // Assert: buffer must still be zeroed despite the error
      expect(fakeKeyBuffer.every((byte) => byte === 0)).toBe(true)
    })

    it("passes the Buffer directly to tryConnectOnPort as privateKey", async () => {
      // Arrange
      const { readFile } = await import("node:fs/promises")
      const fakeKeyBuffer = Buffer.from("my-rsa-key")
      vi.mocked(readFile).mockResolvedValueOnce(fakeKeyBuffer as never)
      vi.mocked(tryConnectOnPort).mockResolvedValueOnce()

      const ssh = makeSshInstance()

      // Act
      await ssh.connect()

      // Assert: the Buffer was forwarded unchanged to tryConnectOnPort
      expect(tryConnectOnPort).toHaveBeenCalledOnce()
      const [callArgs] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      expect(callArgs.privateKey).toBe(fakeKeyBuffer)
      expect(Buffer.isBuffer(callArgs.privateKey)).toBe(true)
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
      const ssh = makeConnectedSsh(client, { user: "deploy" })

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
      const ssh = makeConnectedSsh(client, { user: "deploy" })

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

    it("masks shell-quoted secrets in timeout error messages", async () => {
      vi.useFakeTimers()

      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      const secret = "don't-print-this"
      const escapedSecret = shellQuote(secret)
      const execPromise = ssh.exec(`printf %s ${escapedSecret}`, {
        secrets: [secret],
        timeout: 5000,
      })

      execPromise.catch(() => {
        /* handled below */
      })

      await vi.advanceTimersByTimeAsync(5001)

      const error = await execPromise.catch((error: unknown) => error as Error)
      expect(error.message).not.toContain(secret)
      expect(error.message).not.toContain(escapedSecret)
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
        expect(stream.write).toHaveBeenCalledWith(Buffer.from("my-sudo-pass"))
        expect(stream.write).toHaveBeenCalledWith("\n")
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { sudoPassword: "my-sudo-pass", user: "deploy" })

      await ssh.exec("whoami")

      expect(execSpy).toHaveBeenCalledOnce()
    })

    it("does not materialize cached sudo passwords on successful exec calls without output", async () => {
      const passwordBuffer = Buffer.from("my-sudo-pass")
      const toStringSpy = vi.spyOn(passwordBuffer, "toString")

      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })
      ;(ssh as unknown as Record<string, unknown>).cachedSudoPassword = passwordBuffer

      await ssh.exec("whoami")

      expect(toStringSpy).not.toHaveBeenCalled()
    })

    it("materializes cached sudo passwords lazily on timeout masking paths only", async () => {
      vi.useFakeTimers()

      const passwordBuffer = Buffer.from("my-sudo-pass")
      const toStringSpy = vi.spyOn(passwordBuffer, "toString")

      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
      })
      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })
      ;(ssh as unknown as Record<string, unknown>).cachedSudoPassword = passwordBuffer

      const execPromise = ssh.exec("printf %s 'my-sudo-pass'", { timeout: 5000 })
      execPromise.catch(() => {
        /* handled below */
      })

      expect(toStringSpy).not.toHaveBeenCalled()

      await vi.advanceTimersByTimeAsync(5001)

      const error = await execPromise.catch((error: unknown) => error as Error)
      expect(error.message).toContain("[REDACTED]")
      expect(toStringSpy).toHaveBeenCalledOnce()
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
      expect(vi.mocked(capturedStream!.write)).toHaveBeenCalledWith(Buffer.from("my-sudo-pass"))
      expect(vi.mocked(capturedStream!.write)).toHaveBeenCalledWith("\n")

      // collectStreamOutput must be invoked before stream.write so that all
      // stream event listeners are registered before the sudo password is sent
      const collectOrder = vi.mocked(collectStreamOutput).mock.invocationCallOrder[0]
      const writeOrder = vi.mocked(capturedStream?.write).mock.invocationCallOrder[0]
      expect(collectOrder).toBeDefined()
      expect(writeOrder).toBeDefined()
      expect(collectOrder).toBeLessThan(writeOrder)
    })

    it("does not write sudo password to stdin when user is root (needsPassword: false)", async () => {
      // Arrange: root user with a sudoPassword set — sudoCommand() returns needsPassword: false
      let capturedStream: null | StreamWithStderr = null
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        capturedStream = stream
        callback(undefined, stream)
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      // sudoPassword is set but user is root → needsPassword must be false
      const ssh = makeConnectedSsh(client, { sudoPassword: "my-sudo-pass", user: "root" })

      // Act
      await ssh.exec("whoami")

      // Assert: stream.write must never have been called with the password
      expect(capturedStream).not.toBeNull()
      expect(capturedStream!.write).not.toHaveBeenCalled()
    })

    it("does not write sudo password to stdin when cachedSudoPassword is null (non-root, no password)", async () => {
      // Arrange: non-root user without a sudoPassword — cachedSudoPassword is null
      let capturedStream: null | StreamWithStderr = null
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        capturedStream = stream
        callback(undefined, stream)
        stream.emit("close", 0)
      })
      const client = makeClientWithExecSpy(execSpy)
      // No sudoPassword → cachedSudoPassword is null → needsPassword is false
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act
      await ssh.exec("whoami")

      // Assert: stream.write must never have been called
      expect(capturedStream).not.toBeNull()
      expect(capturedStream!.write).not.toHaveBeenCalled()
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
    it("creates and cleans up the temp file without sudo for non-root users", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-upload.ABCDEF"
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
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.uploadFile("/local/file.txt", "/remote/path")

      expect(executedCommands[0]).toBe("mktemp '/remote/paratix-upload.XXXXXX'")
      expect(executedCommands[1]).toBe(`chmod '0600' '${tempPath}'`)
      expect(executedCommands[2]).toMatch(/^sudo bash -c /v)
      expect(executedCommands[2]).toContain(tempPath)
      expect(executedCommands[2]).toContain("/remote/path")
      expect(executedCommands[3]).toBe(`rm -f '${tempPath}'`)
      expect(vi.mocked(sftpUpload)).toHaveBeenCalledWith(client, "/local/file.txt", tempPath)
    })

    it("applies restrictive mode 0600 to the temp file before mv when no mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-upload.ABCDEF"
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

      await ssh.uploadFile("/local/file.txt", "/remote/path")

      expect(executedCommands).toContain(`chmod '0600' '${tempPath}'`)
      const chmodIndex = executedCommands.indexOf(`chmod '0600' '${tempPath}'`)
      const mvIndex = executedCommands.indexOf(`mv '${tempPath}' '/remote/path'`)
      expect(chmodIndex).toBeGreaterThan(-1)
      expect(chmodIndex).toBeLessThan(mvIndex)
    })

    it("runs chmod on temp file before mv when mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-upload.ABCDEF"
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

    it("uses restrictive chmod 0600 when no mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-upload.ABCDEF"
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
        // Second call: default chmod 0600
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

      await ssh.uploadFile("/local/file.txt", "/remote/path")

      expect(executedCommands).toContain(`chmod '0600' '${tempPath}'`)
    })

    it("cleans up the temporary remote file when mv fails", async () => {
      // This test documents a bug: uploadFile has no try/finally, so the
      // temporary remote file created by mktemp is not removed when mv fails.
      // After the fix, exec must be called with `rm -f` on the temp path.
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-upload.ABCDEF"
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
    it("creates and cleans up the temp file without sudo for non-root users", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-write.ABCDEF"
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
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.writeFile("/remote/plain.txt", "hello world")

      expect(executedCommands[0]).toBe("mktemp '/remote/paratix-write.XXXXXX'")
      expect(executedCommands[1]).toBe(`chmod '0600' '${tempPath}'`)
      expect(executedCommands[2]).toMatch(/^sudo bash -c /v)
      expect(executedCommands[2]).toContain(tempPath)
      expect(executedCommands[2]).toContain("/remote/plain.txt")
      expect(executedCommands[3]).toBe(`rm -f '${tempPath}'`)
      expect(vi.mocked(sftpUpload)).toHaveBeenCalledOnce()
    })

    it("applies restrictive mode 0600 to the remote temp file before mv when no mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-write.ABCDEF"
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

      await ssh.writeFile("/remote/plain.txt", "hello world")

      expect(executedCommands).toContain(`chmod '0600' '${tempPath}'`)
      const chmodIndex = executedCommands.indexOf(`chmod '0600' '${tempPath}'`)
      const mvIndex = executedCommands.indexOf(`mv '${tempPath}' '/remote/plain.txt'`)
      expect(chmodIndex).toBeGreaterThan(-1)
      expect(chmodIndex).toBeLessThan(mvIndex)
    })

    it("always uses atomic SFTP path (write-to-temp + mv) for all content", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-write.ABCDEF"
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

      await ssh.writeFile("/remote/plain.txt", "hello world")

      // SFTP upload must have been called — atomic path
      expect(vi.mocked(sftpUpload)).toHaveBeenCalledOnce()

      // printf must NOT have been used
      const usedPrintf = executedCommands.some((cmd) => cmd.includes("printf"))
      expect(usedPrintf).toBe(false)

      // mktemp and mv confirm atomic write path
      expect(executedCommands.some((cmd) => cmd.includes("mktemp"))).toBe(true)
      expect(executedCommands.some((cmd) => cmd === `chmod '0600' '${tempPath}'`)).toBe(true)
      expect(executedCommands.some((cmd) => cmd.includes("mv"))).toBe(true)
    })

    it("runs chmod on temp file before mv when mode option is provided", async () => {
      const { sftpUpload } = await import("../src/sftp.js")
      vi.mocked(sftpUpload).mockResolvedValue()

      const tempPath = "/remote/paratix-write.ABCDEF"
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
    function makeExecHandler(
      executedCommands: string[],
      output: string
    ): (_command: string, callback: ExecCallback) => void {
      return (cmd: string, callback: ExecCallback) => {
        executedCommands.push(cmd)
        const stream = makeStream()
        callback(undefined, stream)
        stream.emit("data", Buffer.from(output))
        stream.emit("close", 0)
      }
    }

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

    it("creates the temporary copy without sudo and copies into it via sudo for non-root user", async () => {
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
        // Second call: sudo cat into the existing user-owned temp file
        .mockImplementationOnce((cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Third call: rm -f
        .mockImplementationOnce((cmd: string, callback: ExecCallback) => {
          executedCommands.push(cmd)
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.downloadFile("/var/log/secure", "/tmp/local-secure")

      expect(executedCommands[0]).toBe("mktemp /tmp/paratix-download.XXXXXX")
      expect(executedCommands[1]).toMatch(/^sudo bash -c /v)
      expect(executedCommands[1]).toContain("cat ")
      expect(executedCommands[1]).toContain("/var/log/secure")
      expect(executedCommands[1]).toContain(mktempOutput)
      expect(executedCommands[2]).toBe(`rm -f '${mktempOutput}'`)
    })

    it("uses user-owned temp file plus sudo copy, sftp, and user cleanup for non-root user", async () => {
      const executedCommands: string[] = []
      const mktempOutput = "/tmp/paratix-download.ABCDEF"

      const execSpy = vi
        .fn()
        // First call: mktemp (via output()) — returns temp path
        .mockImplementationOnce(makeExecHandler(executedCommands, mktempOutput))
        // Second call: sudo cat into temp file
        .mockImplementationOnce(makeExecHandler(executedCommands, ""))
        // Third call: rm -f
        .mockImplementationOnce(makeExecHandler(executedCommands, ""))

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      await ssh.downloadFile("/var/log/secure", "/tmp/local-secure")

      expect(executedCommands[0]).toBe("mktemp /tmp/paratix-download.XXXXXX")
      expect(executedCommands[1]).toMatch(/^sudo bash -c /v)
      expect(executedCommands[1]).toContain("cat ")
      expect(vi.mocked(sftpDownload)).toHaveBeenCalledWith(
        client,
        mktempOutput,
        "/tmp/local-secure"
      )
      expect(executedCommands[2]).toBe(`rm -f '${mktempOutput}'`)
    })

    it("cleans up the remote temp file even when sftpDownload rejects (regression)", async () => {
      // Arrange
      const mktempOutput = "/tmp/paratix-download.CLEANUP"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        // First call: mktemp (via output()) — returns temp path
        .mockImplementationOnce(makeExecHandler(executedCommands, mktempOutput))
        // Second call: sudo cat into temp file
        .mockImplementationOnce(makeExecHandler(executedCommands, ""))
        // Third call: rm -f (cleanup in finally)
        .mockImplementationOnce(makeExecHandler(executedCommands, ""))

      vi.mocked(sftpDownload).mockRejectedValueOnce(new Error("SFTP transfer failed"))

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "nonroot" })

      // Act
      await expect(ssh.downloadFile("/var/log/secure", "/tmp/local-secure")).rejects.toThrow(
        "SFTP transfer failed"
      )

      // Assert: rm -f must have been called for the temp file despite the SFTP error
      const rmCommand = executedCommands.find((cmd) => cmd.includes("rm -f"))
      expect(rmCommand).toBeDefined()
      expect(rmCommand).toContain(mktempOutput)
    })

    it("uses raw non-sudo cleanup for non-root download temp files", async () => {
      const mktempOutput = "/tmp/paratix-download.MASKSECRET"
      const executedCommands: string[] = []

      const execSpy = vi
        .fn()
        .mockImplementationOnce(makeExecHandler(executedCommands, mktempOutput))
        .mockImplementationOnce(makeExecHandler(executedCommands, ""))
        .mockImplementationOnce((_cmd: string, callback: ExecCallback) => {
          executedCommands.push(_cmd)
          callback(new Error(`permission denied: rm -f ${mktempOutput}`), makeStream())
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

      await ssh.downloadFile("/var/log/secure", "/tmp/local-secure")

      await vi.waitFor(() => {
        expect(stderrSpy).toHaveBeenCalled()
      })

      const stderrOutput = stderrSpy.mock.calls.map((args) => String(args[0])).join("")
      expect(executedCommands[2]).toBe(`rm -f '${mktempOutput}'`)
      expect(stderrOutput).toContain(`failed to remove temp file ${mktempOutput}`)
      expect(stderrOutput).not.toContain("sudo")

      stderrSpy.mockRestore()
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
        // First call: execRaw "command -v sudo" — sudo is installed
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Second call: passwordless sudo probe — fails (sudo requires a password)
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 1)
        })
        // Third call: sudo with password — fails with the password in stderr
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

      const execSpy = vi
        .fn()
        // First call: execRaw "command -v sudo" — sudo is installed
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Second call: passwordless sudo probe fails so probeSudo prompts for a password
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
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

      const execSpy = vi
        .fn()
        // First call: execRaw "command -v sudo" — sudo is installed
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 0)
        })
        // Second call: passwordless sudo probe fails so probeSudo prompts for a password
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 1)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act & Assert
      await expect(ssh.probeSudo()).rejects.toThrow("newline")
    })

    it("throws 'sudo is not installed' when command -v sudo exits with non-zero code (regression)", async () => {
      // Arrange: execRaw("command -v sudo") returns exit code 1 — sudo is absent
      const execSpy = vi
        .fn()
        // Only call: execRaw "command -v sudo" — sudo is NOT installed
        .mockImplementationOnce((_command: string, callback: ExecCallback) => {
          const stream = makeStream()
          callback(undefined, stream)
          stream.emit("close", 1)
        })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act & Assert
      await expect(ssh.probeSudo()).rejects.toThrow("sudo is not installed")
      // Verify exactly one exec call was made (command -v sudo only, no further probing)
      expect(execSpy).toHaveBeenCalledOnce()
    })

    it("rejects with timeout error when execRaw stream never closes (regression)", async () => {
      // Arrange
      vi.useFakeTimers()

      // The stream is created but close is never emitted — simulating a hanging command
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // Intentionally omit stream.emit("close", ...) to simulate a hang
      })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act
      const probePromise = ssh.probeSudo()

      // Register rejection handler before advancing timers to prevent unhandled rejection
      probePromise.catch(() => {
        /* handled below */
      })

      // Trigger the COMMAND_TIMEOUT (120 000 ms) in execRaw
      await vi.advanceTimersByTimeAsync(120_001)

      // Assert
      await expect(probePromise).rejects.toThrow(/Command timed out after 120000ms/v)
    })

    it("rejects immediately when disconnectTransport() is called while execRaw is pending — R-005 regression", async () => {
      // Regression: execRaw did not register its wrappedReject in pendingRejects,
      // so a disconnect during an ongoing execRaw call would never settle the
      // Promise. The caller (ensureSudoInstalled / probeSudo) would hang until the
      // 120-second COMMAND_TIMEOUT expired instead of failing fast.
      //
      // Fix: execRaw now registers wrappedReject in pendingRejects, exactly as
      // exec() does. disconnectTransport() iterates pendingRejects and rejects all
      // of them, so the Promise settles immediately.

      // Arrange: exec callback receives the stream but the stream never emits 'close'
      // — the execRaw Promise stays pending until something externally rejects it.
      const execSpy = vi.fn().mockImplementation((_command: string, callback: ExecCallback) => {
        const stream = makeStream()
        callback(undefined, stream)
        // Intentionally omit stream.emit("close", ...) to keep execRaw pending
      })

      const client = makeClientWithExecSpy(execSpy)
      const ssh = makeConnectedSsh(client, { user: "deploy" })

      // Act: start probeSudo (which internally calls ensureSudoInstalled → execRaw)
      const probePromise = ssh.probeSudo()

      // Attach rejection handler early so the unhandled-rejection detector does not
      // fire before the assertion below.
      probePromise.catch(() => {
        /* handled below */
      })

      // Assert precondition: execRaw must have been called and pendingRejects must
      // contain the registered wrappedReject — if the set is empty the bug is present.
      const pendingRejects = (ssh as unknown as Record<string, unknown>).pendingRejects as Set<
        (reason: Error) => void
      >
      expect(pendingRejects.size).toBe(1)

      // Simulate a disconnect while execRaw is waiting for the stream to close.
      // disconnectTransport() is private — call it via the public disconnect() API.
      ssh.disconnect()

      // The Promise must reject immediately with "SSH connection closed", not after
      // 120 000 ms (COMMAND_TIMEOUT).  No fake timers needed — if pendingRejects was
      // empty the Promise would never settle here and the test would time out.
      await expect(probePromise).rejects.toThrow("SSH connection closed")

      // After disconnect the pendingRejects set must have been cleared.
      expect(pendingRejects.size).toBe(0)
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
      const fsp = await import("node:fs/promises")
      vi.mocked(fsp.readFile).mockResolvedValue(Buffer.from("fake-private-key") as never)
    })

    it("calls buildHostVerifier with default mode 'yes' when strictHostKeyChecking is not set", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      const ssh = makeSshInstance({ host: "1.2.3.4", ports: [22] })

      await ssh.connect()

      expect(buildHostVerifier).toHaveBeenCalledWith(
        "yes",
        { host: "1.2.3.4", port: 22 },
        {
          expectedHostFingerprint: undefined,
          expectedHostPublicKey: undefined,
        }
      )
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

      expect(buildHostVerifier).toHaveBeenCalledWith(
        "no",
        { host: "1.2.3.4", port: 22 },
        {
          expectedHostFingerprint: undefined,
          expectedHostPublicKey: undefined,
        }
      )
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

      expect(buildHostVerifier).toHaveBeenCalledWith(
        "yes",
        { host: "1.2.3.4", port: 22 },
        {
          expectedHostFingerprint: undefined,
          expectedHostPublicKey: undefined,
        }
      )
    })

    it("passes expected host trust anchors to buildHostVerifier", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      const ssh = new SshConnectionImpl("1.2.3.4", {
        expectedHostFingerprint: "SHA256:trusted-fingerprint",
        expectedHostPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItrusted",
        ports: [22],
        privateKey: "/dev/null",
        user: "root",
      })

      await ssh.connect()

      expect(buildHostVerifier).toHaveBeenCalledWith(
        "yes",
        { host: "1.2.3.4", port: 22 },
        {
          expectedHostFingerprint: "SHA256:trusted-fingerprint",
          expectedHostPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItrusted",
        }
      )
    })

    it("passes a wrapped hostVerifier that delegates to buildHostVerifier's verifier", async () => {
      const fakeVerifier = vi.fn().mockReturnValue(true)
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      vi.mocked(buildHostVerifier).mockReturnValue({ hostVerifier: fakeVerifier })

      const ssh = makeSshInstance({ host: "1.2.3.4", ports: [22] })

      await ssh.connect()

      const [callArgs] = vi.mocked(tryConnectOnPort).mock.calls[0] as [
        Parameters<typeof tryConnectOnPort>[0],
      ]
      // The hostVerifier is now a wrapper that delegates to the original
      expect(callArgs.hostVerifier).not.toBe(fakeVerifier)
      expect(callArgs.hostVerifier).toBeTypeOf("function")
      // Calling the wrapper should invoke the original verifier
      const testKey = Buffer.from("test-key")
      callArgs.hostVerifier!(testKey)
      expect(fakeVerifier).toHaveBeenCalledWith(testKey)
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
      expect(buildHostVerifier).toHaveBeenNthCalledWith(
        1,
        "yes",
        { host: "1.2.3.4", port: 22 },
        {
          expectedHostFingerprint: undefined,
          expectedHostPublicKey: undefined,
        }
      )
      expect(buildHostVerifier).toHaveBeenNthCalledWith(
        2,
        "yes",
        { host: "1.2.3.4", port: 2222 },
        {
          expectedHostFingerprint: undefined,
          expectedHostPublicKey: undefined,
        }
      )
    })

    it("passes a wrapper hostVerifier even when mode is 'no' (for host-key pinning)", async () => {
      const { buildHostVerifier } = await import("../src/knownHosts.js")
      // mode "no" returns empty object — no hostVerifier from buildHostVerifier
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
      // The wrapper is always present for host-key pinning, even without an original verifier
      expect(callArgs.hostVerifier).toBeTypeOf("function")
    })
  })
})
