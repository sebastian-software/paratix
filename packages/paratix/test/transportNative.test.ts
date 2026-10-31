/* oxlint-disable vitest/no-conditional-in-test -- fakes mirror the binding's branching; every test asserts the same adapter contract */
import type {
  ConnectOptions,
  DisconnectEvent,
  ErrorCode,
  ExecChannel,
  ExecExit,
  HostKeyInfo,
  HostVerifier,
  Session,
  SftpSession,
} from "@paratix/ssh-native"

import { Readable, Writable } from "node:stream"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { NativeBinding } from "../src/nativeBinding.js"
import type {
  TransportConnectOptions,
  TransportExecChannel,
  TransportExit,
  TransportSftpSession,
} from "../src/transport.js"

import { HostKeyVerificationError } from "../src/knownHosts.js"
import { loadNativeBinding } from "../src/nativeBinding.js"
import { TransportError } from "../src/transport.js"
import { createNativeTransport, nativeErrorCode, toTransportError } from "../src/transportNative.js"

// Fake of the native module: no test loads the real binary.
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept
    reject = decline
  })
  return { promise, reject, resolve }
}

async function nextTurn(): Promise<void> {
  await new Promise<void>((resolve) => {
    setImmediate(resolve)
  })
}

/**
 * An error shaped like the binding's errors.
 * @param code - The binding error code.
 * @param message - The secret-free message.
 * @param fields - Extra diagnostic fields such as `sftpStatus`.
 * @returns The binding-style error.
 */
function nativeError(
  code: ErrorCode,
  message = `native ${code.toLowerCase()}`,
  fields: Record<string, unknown> = {}
): { code: ErrorCode } & Error {
  return Object.assign(new Error(message), { code, ...fields })
}

/** Native exec channel fake: like the binding, it zero-fills every stdin chunk after copying it. */
class FakeNativeChannel {
  public readonly cancel = vi.fn<() => void>()
  public readonly close = vi.fn<() => Promise<void>>(async () => {
    /* Close is requested. */
  })
  public readonly exit = deferred<ExecExit>()
  public readonly stderr = new Readable({
    read() {
      /* Pushed by the test. */
    },
  })
  public readonly stdin: Writable
  public stdinEnded = false
  public readonly stdinReceived: Buffer[] = []
  public readonly stdinSnapshots: Buffer[] = []
  public readonly stdout = new Readable({
    read() {
      /* Pushed by the test. */
    },
  })
  public constructor() {
    this.stdin = new Writable({
      final: (callback) => {
        this.stdinEnded = true
        callback()
      },
      write: (chunk: Buffer, _encoding, callback) => {
        this.stdinReceived.push(chunk)
        this.stdinSnapshots.push(Buffer.from(chunk))
        chunk.fill(0)
        callback()
      },
    })
    this.stdout.on("error", () => {
      /* The binding installs the same sink. */
    })
    this.stderr.on("error", () => {
      /* The binding installs the same sink. */
    })
  }
  public api(): ExecChannel {
    return {
      cancel: this.cancel,
      close: this.close,
      exit: this.exit.promise,
      stderr: this.stderr,
      stdin: this.stdin,
      stdout: this.stdout,
    }
  }
  public fail(error: Error): void {
    // The binding destroys both outputs with the error and rejects `exit`.
    this.stdout.destroy(error)
    this.stderr.destroy(error)
    this.exit.reject(error)
  }
  public finish(exit: Partial<ExecExit> = {}): void {
    this.stdout.push(null)
    this.stderr.push(null)
    this.exit.resolve({ code: 0, disconnected: false, signal: null, ...exit })
  }
}

class FakeNativeSftp {
  public readonly readStreams: Readable[] = []
  public readonly createReadStream = vi.fn((_path: string) => {
    const stream = new Readable({
      read() {
        /* Pushed by the test. */
      },
    })
    this.readStreams.push(stream)
    return stream
  })
  public readonly writeStreams: Array<{ mode: number | undefined; stream: Writable }> = []
  public readonly createWriteStream = vi.fn((_path: string, options?: { mode?: number }) => {
    const stream = new Writable({
      write(_chunk, _encoding, callback) {
        callback()
      },
    })
    this.writeStreams.push({ mode: options?.mode, stream })
    return stream
  })
  public readonly end = vi.fn<() => Promise<void>>(async () => {
    /* Ended. */
  })
  public get api(): SftpSession {
    return this
  }
}

class FakeNativeSession {
  public readonly close = vi.fn<() => Promise<void>>(async () => {
    /* Closed. */
  })
  public readonly destroy = vi.fn<() => void>()
  public readonly disconnectListeners = new Set<(event: DisconnectEvent) => void>()
  public readonly exec = vi.fn<(command: string, options?: unknown) => Promise<ExecChannel>>()
  public readonly onDisconnect = vi.fn((listener: (event: DisconnectEvent) => void) => {
    this.disconnectListeners.add(listener)
    return () => {
      this.disconnectListeners.delete(listener)
    }
  })
  public readonly sftp = vi.fn<() => Promise<SftpSession>>()
  public get api(): Session {
    return this as unknown as Session
  }
  public emitDisconnect(event: DisconnectEvent): void {
    for (const listener of this.disconnectListeners) listener(event)
  }
  public nextChannel(): FakeNativeChannel {
    const channel = new FakeNativeChannel()
    this.exec.mockResolvedValueOnce(channel.api())
    return channel
  }
}

function hostKeyInfo(overrides: Partial<HostKeyInfo> = {}): HostKeyInfo {
  return {
    algorithm: "ssh-ed25519",
    fingerprintSha256: "SHA256:fake",
    keyBase64: Buffer.from("fake-host-key-blob").toString("base64"),
    kind: "key",
    ...overrides,
  }
}

type FakeBinding = {
  api: NativeBinding
  connect: ReturnType<
    typeof vi.fn<(options: ConnectOptions, verify: HostVerifier) => Promise<Session>>
  >
}

function createFakeBinding(): FakeBinding {
  const connect = vi.fn<(options: ConnectOptions, verify: HostVerifier) => Promise<Session>>()
  return { api: { connect } as unknown as NativeBinding, connect }
}

/**
 * A binding `connect` that runs the verifier like the real one: only `true`
 * accepts, a thrown value is passed on, no answer ends with TIMEOUT.
 * @param session - The session to resolve with.
 * @param info - The presented host key.
 * @returns The fake native connect implementation.
 */
function verifyingConnect(
  session: FakeNativeSession,
  info: HostKeyInfo = hostKeyInfo()
): (options: ConnectOptions, verify: HostVerifier) => Promise<Session> {
  return async (options, verify) => {
    let timer: NodeJS.Timeout | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        reject(nativeError("TIMEOUT", "the SSH connection timed out"))
      }, options.readyTimeoutMs)
    })
    try {
      const verdict = await Promise.race([verify(info), timeout])
      if (!verdict) throw nativeError("HOST_KEY_REJECTED", "the host key was rejected")
      return session.api
    } finally {
      clearTimeout(timer)
    }
  }
}

vi.mock("../src/nativeBinding.js", () => ({ loadNativeBinding: vi.fn() }))

const ALL_NATIVE_CODES: ErrorCode[] = [
  "ABORTED",
  "AUTH_FAILED",
  "CHANNEL_OPEN_FAILED",
  "CONNECT_FAILED",
  "DISCONNECTED",
  "ENCRYPTED_KEY",
  "HOST_KEY_REJECTED",
  "INTERNAL",
  "PROTOCOL",
  "SFTP_STATUS",
  "TIMEOUT",
  "UNSUPPORTED_KEY",
]

const baseOptions: TransportConnectOptions = {
  host: "203.0.113.10",
  port: 2222,
  readyTimeout: 1000,
  username: "deploy",
  verifyHostKey: () => true,
}

let binding: FakeBinding

async function connected(session = new FakeNativeSession()) {
  binding.connect.mockResolvedValueOnce(session.api)
  const transport = createNativeTransport()
  await transport.connect({ ...baseOptions, privateKey: Buffer.from("key") })
  return { session, transport }
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error("expected a rejection")
}

function expectTransportError(error: unknown, code: string): TransportError {
  expect(error).toBeInstanceOf(TransportError)
  const transportError = error as TransportError
  expect(transportError.transportCode).toBe(code)
  return transportError
}

/**
 * Collect a bridged channel the way ssh.ts does: data listeners first, then the exit.
 * @param channel - The transport channel.
 * @param readStderr - Whether a stderr reader is attached.
 * @returns The collected events and a promise for the exit.
 */
function collect(channel: TransportExecChannel, readStderr = true) {
  const events: string[] = []
  channel.stdout.on("data", (data: Buffer) => {
    events.push(`stdout:${data.toString()}`)
  })
  if (readStderr) {
    channel.stderr.on("data", (data: Buffer) => {
      events.push(`stderr:${data.toString()}`)
    })
  }
  const exit = new Promise<TransportExit>((resolve) => {
    channel.onExit((result) => {
      events.push("exit")
      resolve(result)
    })
  })
  return { events, exit }
}

async function writeChunk(stream: Writable, chunk: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    stream.write(chunk, (error) => {
      if (error) reject(error)
      else resolve()
    })
  })
}

async function endWith(stream: Writable, chunk: Buffer): Promise<void> {
  await new Promise<void>((resolve) => {
    stream.end(chunk, resolve)
  })
}

async function neverAnsweringVerifier(): Promise<boolean> {
  return new Promise<boolean>(() => {
    /* Never settles. */
  })
}

/**
 * Capture errors the adapter rethrows on `process.nextTick` instead of letting
 * them reach Vitest's uncaught-exception handler; other callbacks run unchanged.
 * @param expected - The errors a test expects to be rethrown.
 * @returns The rethrown errors seen so far.
 */
function captureRethrown(expected: readonly unknown[]): unknown[] {
  const rethrown: unknown[] = []
  const nextTick = process.nextTick.bind(process)
  vi.spyOn(process, "nextTick").mockImplementation((callback, ...parameters) => {
    nextTick(() => {
      try {
        ;(callback as (...values: unknown[]) => void)(...parameters)
      } catch (error) {
        if (!expected.includes(error)) throw error
        rethrown.push(error)
      }
    })
  })
  return rethrown
}

function transportCodeOf(error: unknown): string | undefined {
  return error instanceof TransportError ? error.transportCode : undefined
}

async function openSftp() {
  const { session, transport } = await connected()
  const native = new FakeNativeSftp()
  session.sftp.mockResolvedValueOnce(native.api)
  const onSession = vi.fn<(session: TransportSftpSession) => void>()
  const sftp = await transport.sftp(onSession)
  expect(onSession).toHaveBeenCalledWith(sftp)
  return { native, session, sftp, transport }
}

describe("native transport", () => {
  beforeEach(() => {
    binding = createFakeBinding()
    vi.mocked(loadNativeBinding).mockResolvedValue(binding.api)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe("native transport: connect", () => {
    it("maps the transport options to the binding options", async () => {
      const session = new FakeNativeSession()
      binding.connect.mockResolvedValueOnce(session.api)
      const controller = new AbortController()
      const transport = createNativeTransport()
      const result = await transport.connect({
        ...baseOptions,
        agent: "/tmp/agent.sock",
        agentForward: true,
        signal: controller.signal,
      })
      expect(result).toBe(transport)
      const [options] = binding.connect.mock.calls[0]
      expect(options).toStrictEqual({
        agent: "/tmp/agent.sock",
        agentForward: true,
        host: "203.0.113.10",
        port: 2222,
        readyTimeoutMs: 1000,
        signal: controller.signal,
        user: "deploy",
      })
      expect(session.onDisconnect).toHaveBeenCalledOnce()
    })

    it("omits optional binding options that were not configured", async () => {
      const session = new FakeNativeSession()
      binding.connect.mockResolvedValueOnce(session.api)
      await createNativeTransport().connect({ ...baseOptions, agentForward: false, password: "pw" })
      const [options] = binding.connect.mock.calls[0]
      expect(Object.keys(options).toSorted()).toStrictEqual([
        "host",
        "password",
        "port",
        "readyTimeoutMs",
        "user",
      ])
    })

    it("rejects a second connect on the same object with INTERNAL", async () => {
      const { transport } = await connected()
      expectTransportError(await rejection(transport.connect(baseOptions)), "INTERNAL")
      expect(binding.connect).toHaveBeenCalledOnce()
    })

    it("reports a binding load failure as INTERNAL with the loader error as cause", async () => {
      const loaderError = new Error("no native binary for riscv64")
      vi.mocked(loadNativeBinding).mockRejectedValueOnce(loaderError)
      const error = expectTransportError(
        await rejection(createNativeTransport().connect(baseOptions)),
        "INTERNAL"
      )
      expect(error.cause).toBe(loaderError)
      expect(binding.connect).not.toHaveBeenCalled()
    })

    it.each(ALL_NATIVE_CODES.filter((code) => code !== "ABORTED"))(
      "maps a %s connect failure with the native message and code",
      async (code) => {
        const native = nativeError(code, "native failure")
        binding.connect.mockRejectedValueOnce(native)
        const error = expectTransportError(
          await rejection(createNativeTransport().connect(baseOptions)),
          code
        )
        expect(error.message).toBe(`native failure [${code}]`)
        expect((error.cause as Error).cause).toBe(native)
      }
    )

    it("maps a TypeError from the binding's validation to INTERNAL", async () => {
      binding.connect.mockRejectedValueOnce(new TypeError("agentForward requires an agent socket"))
      const error = expectTransportError(
        await rejection(createNativeTransport().connect({ ...baseOptions, agentForward: true })),
        "INTERNAL"
      )
      expect(error.message).toBe("agentForward requires an agent socket [INTERNAL]")
    })

    it("rejects with the abort reason itself when the connect is aborted", async () => {
      const controller = new AbortController()
      const reason = new Error("operator cancelled")
      controller.abort(reason)
      binding.connect.mockRejectedValueOnce(nativeError("ABORTED"))
      expect(
        await rejection(
          createNativeTransport().connect({ ...baseOptions, signal: controller.signal })
        )
      ).toBe(reason)
    })

    it("rejects with a plain abort error when the abort reason is not an Error", async () => {
      const controller = new AbortController()
      controller.abort("stop")
      binding.connect.mockRejectedValueOnce(nativeError("ABORTED"))
      const error = await rejection(
        createNativeTransport().connect({ ...baseOptions, signal: controller.signal })
      )
      expect(error).not.toBeInstanceOf(TransportError)
      expect((error as Error).message).toBe("SSH connect aborted")
    })
  })

  describe("native transport: secrets", () => {
    it("hands a copy of the key to the binding and leaves the caller's buffer unchanged", async () => {
      const session = new FakeNativeSession()
      const key = Buffer.from("-----BEGIN OPENSSH PRIVATE KEY-----")
      const original = Buffer.from(key)
      let handedOver: Buffer | undefined
      let contentAtCall = ""
      binding.connect.mockImplementationOnce(async (options) => {
        handedOver = options.privateKey
        contentAtCall = options.privateKey?.toString() ?? ""
        await nextTurn()
        return session.api
      })
      await createNativeTransport().connect({ ...baseOptions, privateKey: key })
      expect(handedOver).not.toBe(key)
      expect(contentAtCall).toBe(original.toString())
      expect(key.equals(original)).toBe(true)
      expect(handedOver?.every((byte) => byte === 0)).toBe(true)
    })

    it("passes a string key and the password as buffers", async () => {
      const session = new FakeNativeSession()
      const seen: Record<string, string | undefined> = {}
      binding.connect.mockImplementationOnce(async (options) => {
        seen.key = options.privateKey?.toString()
        seen.password = options.password?.toString()
        await nextTurn()
        return session.api
      })
      await createNativeTransport().connect({
        ...baseOptions,
        password: "pässword",
        privateKey: "PEM KEY",
      })
      expect(seen).toStrictEqual({ key: "PEM KEY", password: "pässword" })
    })

    it("zero-fills its copies when the native connect throws synchronously", async () => {
      const key = Buffer.from("private key bytes")
      const captured: Buffer[] = []
      binding.connect.mockImplementationOnce((options) => {
        if (options.privateKey) captured.push(options.privateKey)
        if (options.password) captured.push(options.password)
        throw new TypeError("invalid options")
      })
      expectTransportError(
        await rejection(
          createNativeTransport().connect({ ...baseOptions, password: "secret", privateKey: key })
        ),
        "INTERNAL"
      )
      expect(captured).toHaveLength(2)
      for (const copy of captured) expect(copy.every((byte) => byte === 0)).toBe(true)
      expect(key.toString()).toBe("private key bytes")
    })

    it("zero-fills its copies when the adapter fails before the native connect", async () => {
      const key = Buffer.from("private key bytes")
      const copies: Buffer[] = []
      const from = Buffer.from.bind(Buffer)
      vi.spyOn(Buffer, "from").mockImplementation((...parameters: Parameters<typeof from>) => {
        const result = from(...parameters)
        copies.push(result)
        return result
      })
      const options = {
        ...baseOptions,
        get password(): string {
          throw new Error("password unavailable")
        },
        privateKey: key,
      }
      const error = expectTransportError(
        await rejection(createNativeTransport().connect(options)),
        "INTERNAL"
      )
      expect(error.message).toBe("password unavailable [INTERNAL]")
      expect(binding.connect).not.toHaveBeenCalled()
      expect(copies).toHaveLength(1)
      expect(copies[0].every((byte) => byte === 0)).toBe(true)
      expect(key.toString()).toBe("private key bytes")
    })

    it("does not create copies when the binding cannot be loaded", async () => {
      const from = vi.spyOn(Buffer, "from")
      vi.mocked(loadNativeBinding).mockRejectedValueOnce(new Error("load failed"))
      await rejection(
        createNativeTransport().connect({ ...baseOptions, password: "pw", privateKey: "key" })
      )
      expect(from).not.toHaveBeenCalled()
    })
  })

  describe("native transport: host-key verification", () => {
    it("hands the raw key blob to the verifier and accepts an async true", async () => {
      const session = new FakeNativeSession()
      const info = hostKeyInfo()
      binding.connect.mockImplementationOnce(verifyingConnect(session, info))
      const verifyHostKey = vi.fn(async (_key: Buffer) => {
        await nextTurn()
        return true
      })
      await createNativeTransport().connect({ ...baseOptions, verifyHostKey })
      expect(verifyHostKey).toHaveBeenCalledWith(Buffer.from(info.keyBase64, "base64"))
    })

    it.each([false, 1, "yes", {}, undefined])(
      "rejects the verdict %j with HOST_KEY_REJECTED",
      async (verdict) => {
        binding.connect.mockImplementationOnce(verifyingConnect(new FakeNativeSession()))
        const verifyHostKey = (() => verdict) as unknown as TransportConnectOptions["verifyHostKey"]
        expect(
          transportCodeOf(
            await rejection(createNativeTransport().connect({ ...baseOptions, verifyHostKey }))
          )
        ).toBe("HOST_KEY_REJECTED")
      }
    )

    it("passes a thrown HostKeyVerificationError through as the same object", async () => {
      binding.connect.mockImplementationOnce(verifyingConnect(new FakeNativeSession()))
      const thrown = new HostKeyVerificationError("host key mismatch")
      const verifyHostKey = () => {
        throw thrown
      }
      expect(
        await rejection(createNativeTransport().connect({ ...baseOptions, verifyHostKey }))
      ).toBe(thrown)
    })

    it("passes a rejected verifier value through as the same object", async () => {
      binding.connect.mockImplementationOnce(verifyingConnect(new FakeNativeSession()))
      const reason = new Error("verifier failed")
      const verifyHostKey = async () => {
        await nextTurn()
        throw reason
      }
      expect(
        await rejection(createNativeTransport().connect({ ...baseOptions, verifyHostKey }))
      ).toBe(reason)
    })

    it("ends with TIMEOUT when the verifier never answers", async () => {
      binding.connect.mockImplementationOnce(verifyingConnect(new FakeNativeSession()))
      expect(
        transportCodeOf(
          await rejection(
            createNativeTransport().connect({
              ...baseOptions,
              readyTimeout: 20,
              verifyHostKey: neverAnsweringVerifier,
            })
          )
        )
      ).toBe("TIMEOUT")
    })

    it("rejects a host certificate without consulting the verifier", async () => {
      binding.connect.mockImplementationOnce(
        verifyingConnect(new FakeNativeSession(), hostKeyInfo({ kind: "certificate" }))
      )
      const verifyHostKey = vi.fn(() => true)
      expectTransportError(
        await rejection(createNativeTransport().connect({ ...baseOptions, verifyHostKey })),
        "HOST_KEY_REJECTED"
      )
      expect(verifyHostKey).not.toHaveBeenCalled()
    })
  })

  describe("native transport: error mapping", () => {
    it.each(ALL_NATIVE_CODES)("maps %s 1:1 with the native message and code", async (code) => {
      const { session, transport } = await connected()
      const native = nativeError(code, "channel failure", { detail: "exec-refused" })
      session.exec.mockRejectedValueOnce(native)
      const error = expectTransportError(await rejection(transport.exec("true")), code)
      expect(error.message).toBe(`channel failure [${code}]`)
      const cause = error.cause as Error & Record<string, unknown>
      expect(cause.message).toBe(`channel failure [${code}]`)
      expect(cause.cause).toBe(native)
      expect(cause.code).toBe(code)
      expect(cause.detail).toBe("exec-refused")
    })

    it("maps a TypeError to INTERNAL with the message and code", async () => {
      const { session, transport } = await connected()
      session.exec.mockRejectedValueOnce(new TypeError("command must be a string"))
      const error = expectTransportError(await rejection(transport.exec("true")), "INTERNAL")
      expect(error.message).toBe("command must be a string [INTERNAL]")
    })

    it("maps an unknown code, a non-Error value and keeps an existing TransportError", () => {
      expect(toTransportError(nativeError("NOPE" as ErrorCode)).transportCode).toBe("INTERNAL")
      const raw = toTransportError("raw")
      expect(raw.transportCode).toBe("INTERNAL")
      expect(raw.cause).toBe("raw")
      const existing = new TransportError("TIMEOUT", new Error("t"))
      expect(toTransportError(existing)).toBe(existing)
      expect(nativeErrorCode(null)).toBe("INTERNAL")
    })

    it("keeps sftpStatus, errno and syscallCode on the cause", () => {
      const sftp = toTransportError(nativeError("SFTP_STATUS", "no such file", { sftpStatus: 2 }))
      expect((sftp.cause as { sftpStatus?: number }).sftpStatus).toBe(2)
      const connect = toTransportError(
        nativeError("CONNECT_FAILED", "refused", { errno: 111, syscallCode: "ECONNREFUSED" })
      )
      expect(connect.cause).toMatchObject({ errno: 111, syscallCode: "ECONNREFUSED" })
    })
  })

  describe("native transport: connection lifecycle", () => {
    it("notifies early and late subscribers exactly once, late ones synchronously", async () => {
      const session = new FakeNativeSession()
      binding.connect.mockResolvedValueOnce(session.api)
      const transport = createNativeTransport()
      const early = vi.fn<(error: TransportError) => void>()
      const removed = vi.fn<(error: TransportError) => void>()
      transport.onDisconnect(early)
      transport.onDisconnect(removed)()
      await transport.connect(baseOptions)
      session.emitDisconnect({ reason: "remote" })
      session.emitDisconnect({ code: "PROTOCOL", reason: "error" })
      expect(early).toHaveBeenCalledOnce()
      expect(removed).not.toHaveBeenCalled()
      const error = expectTransportError(early.mock.calls[0][0], "DISCONNECTED")
      expect(error.message).toBe("SSH connection closed unexpectedly")
      const late = vi.fn<(error: TransportError) => void>()
      transport.onDisconnect(late)
      expect(late).toHaveBeenCalledOnce()
      expect(late.mock.calls[0][0]).toBe(error)
    })

    it("runs every disconnect listener and rethrows a listener failure asynchronously", async () => {
      const thrown = new Error("disconnect listener failed")
      const rethrown = captureRethrown([thrown])
      const { session, transport } = await connected()
      const second = vi.fn<(error: TransportError) => void>()
      transport.onDisconnect(() => {
        throw thrown
      })
      transport.onDisconnect(second)
      session.emitDisconnect({ reason: "remote" })
      expect(second).toHaveBeenCalledOnce()
      await nextTurn()
      expect(rethrown).toStrictEqual([thrown])
    })

    it("carries the event code and maps local teardown events to DISCONNECTED", async () => {
      const first = await connected()
      const errors: TransportError[] = []
      first.transport.onDisconnect((error) => {
        errors.push(error)
      })
      first.session.emitDisconnect({ code: "PROTOCOL", reason: "error" })
      const second = await connected()
      second.transport.onDisconnect((error) => {
        errors.push(error)
      })
      second.session.emitDisconnect({ reason: "local" })
      expect(errors.map((error) => error.transportCode)).toStrictEqual(["PROTOCOL", "DISCONNECTED"])
      expect(errors.map((error) => error.message)).toStrictEqual([
        "SSH connection closed unexpectedly",
        "SSH connection closed unexpectedly",
      ])
    })

    it("rejects exec and sftp before connect with INTERNAL", async () => {
      const transport = createNativeTransport()
      expect(transportCodeOf(await rejection(transport.exec("true")))).toBe("INTERNAL")
      expect(transportCodeOf(await rejection(transport.sftp()))).toBe("INTERNAL")
    })

    it("treats close and destroy before connect as no-ops", async () => {
      const transport = createNativeTransport()
      await expect(transport.close()).resolves.toBeUndefined()
      expect(() => {
        transport.destroy()
      }).not.toThrow()
    })

    it("never rejects close and never throws from destroy", async () => {
      const { session, transport } = await connected()
      session.close.mockRejectedValueOnce(nativeError("DISCONNECTED"))
      session.destroy.mockImplementationOnce(() => {
        throw nativeError("INTERNAL")
      })
      await expect(transport.close()).resolves.toBeUndefined()
      expect(() => {
        transport.destroy()
      }).not.toThrow()
      expect(session.close).toHaveBeenCalledOnce()
      expect(session.destroy).toHaveBeenCalledOnce()
    })
  })

  describe("native transport: exec", () => {
    it("hands the channel to onChannel and never uses native stdin, signal or cancel", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const onChannel = vi.fn<(channel: TransportExecChannel) => void>()
      const channel = await transport.exec("uptime", onChannel)
      expect(onChannel).toHaveBeenCalledWith(channel)
      expect(session.exec).toHaveBeenCalledWith("uptime")
      native.finish()
      await collect(channel).exit
      expect(native.cancel).not.toHaveBeenCalled()
      expect(native.stdinEnded).toBe(false)
    })

    it("reports the exit after all data without a stderr reader", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("cat")
      const { events, exit } = collect(channel, false)
      native.stdout.push("one")
      native.stderr.push("warning")
      native.stdout.push("two")
      native.finish({ code: 3 })
      expect(await exit).toStrictEqual({ code: 3, signal: null })
      expect(events).toStrictEqual(["stdout:one", "stdout:two", "exit"])
      const late: TransportExit[] = []
      channel.onExit((result) => {
        late.push(result)
      })
      expect(late).toStrictEqual([{ code: 3, signal: null }])
    })

    it("does not report the exit to an unsubscribed listener", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("true")
      const removed = vi.fn<(exit: TransportExit) => void>()
      channel.onExit(removed)()
      const { exit } = collect(channel)
      native.finish()
      await exit
      expect(removed).not.toHaveBeenCalled()
    })

    it("keeps buffered stderr for a late reader", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("cat")
      const { exit } = collect(channel, false)
      native.stderr.push("late stderr")
      native.finish()
      await exit
      const stderr: string[] = []
      channel.stderr.on("data", (data: Buffer) => {
        stderr.push(data.toString())
      })
      expect(stderr).toStrictEqual(["late stderr"])
    })

    it.each([
      [{ signal: "TERM" }, { code: null, signal: "SIGTERM" }],
      [{ signal: "SIGKILL" }, { code: null, signal: "SIGKILL" }],
      [{ signal: "" }, { code: null, signal: null }],
      [
        { code: null, signal: null },
        { code: null, signal: null },
      ],
    ])("normalizes the native exit %j to %j", async (nativeExit, expected) => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("kill")
      const { exit } = collect(channel)
      native.finish({ code: null, ...nativeExit })
      expect(await exit).toStrictEqual(expected)
    })

    it("reports a disconnected exit as 255 after onDisconnect", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("sleep 30")
      const order: string[] = []
      transport.onDisconnect(() => {
        order.push("disconnect")
      })
      const { exit } = collect(channel)
      channel.onExit(() => {
        order.push("exit")
      })
      session.emitDisconnect({ reason: "remote" })
      native.finish({ code: null, disconnected: true })
      expect(await exit).toStrictEqual({ code: 255, signal: null })
      expect(order).toStrictEqual(["disconnect", "exit"])
    })

    it("records the connection loss before a disconnected exit the session did not report", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("sleep 30")
      const order: string[] = []
      transport.onDisconnect((error) => {
        order.push(`disconnect:${error.transportCode}`)
      })
      const { exit } = collect(channel)
      channel.onExit(() => {
        order.push("exit")
      })
      native.finish({ code: 0, disconnected: true })
      expect(await exit).toStrictEqual({ code: 255, signal: null })
      expect(order).toStrictEqual(["disconnect:DISCONNECTED", "exit"])
    })

    it("reports a native stream error once as TransportError on stdout without an exit", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("cat")
      const onExit = vi.fn<(exit: TransportExit) => void>()
      channel.onExit(onExit)
      const failed = new Promise<unknown>((resolve) => {
        channel.stdout.on("error", resolve)
      })
      const errorListener = vi.fn<(error: unknown) => void>()
      channel.stdout.on("error", errorListener)
      native.fail(nativeError("PROTOCOL", "bad packet"))
      const error = expectTransportError(await failed, "PROTOCOL")
      expect(error.message).toBe("bad packet [PROTOCOL]")
      await nextTurn()
      expect(errorListener).toHaveBeenCalledOnce()
      expect(onExit).not.toHaveBeenCalled()
      channel.onExit(onExit)
      expect(onExit).not.toHaveBeenCalled()
    })

    it.each(["INTERNAL", "ABORTED"] as const)(
      "reports a rejected exit (%s) without stream error on stdout, also to a late listener",
      async (code) => {
        const { session, transport } = await connected()
        const native = session.nextChannel()
        const channel = await transport.exec("cat")
        const onExit = vi.fn<(exit: TransportExit) => void>()
        channel.onExit(onExit)
        native.exit.reject(nativeError(code))
        await nextTurn()
        const errors: unknown[] = []
        channel.stdout.on("error", (error) => {
          errors.push(error)
        })
        expect(errors).toHaveLength(1)
        expectTransportError(errors[0], code)
        expect(onExit).not.toHaveBeenCalled()
      }
    )

    it("drops native data that arrives after the failure was reported", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("cat")
      const events: string[] = []
      channel.stdout.on("data", (data: Buffer) => {
        events.push(`stdout:${data.toString()}`)
      })
      channel.stderr.on("data", (data: Buffer) => {
        events.push(`stderr:${data.toString()}`)
      })
      channel.stdout.on("error", () => {
        events.push("error")
      })
      // Buffered native data is delivered on the next tick, after the rejected exit.
      native.stdout.push("late stdout")
      native.stderr.push("late stderr")
      native.exit.reject(nativeError("INTERNAL"))
      await nextTurn()
      await nextTurn()
      expect(events).toStrictEqual(["error"])
    })

    it("runs every exit listener and rethrows a listener failure asynchronously", async () => {
      const thrown = new Error("exit listener failed")
      const rethrown = captureRethrown([thrown])
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("true")
      channel.onExit(() => {
        throw thrown
      })
      const { exit } = collect(channel)
      native.finish()
      expect(await exit).toStrictEqual({ code: 0, signal: null })
      await nextTurn()
      expect(rethrown).toStrictEqual([thrown])
    })

    it("closes the native channel and swallows its failure", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("cat")
      native.close.mockRejectedValueOnce(nativeError("DISCONNECTED"))
      channel.close()
      native.close.mockImplementationOnce(() => {
        throw nativeError("INTERNAL")
      })
      expect(() => {
        channel.close()
      }).not.toThrow()
      await nextTurn()
      expect(native.close).toHaveBeenCalledTimes(2)
    })
  })

  describe("native transport: stdin", () => {
    it("keeps a sudo password buffer written to two execs unchanged", async () => {
      const { session, transport } = await connected()
      const sudoPassword = Buffer.from("sudo-secret\n")
      const writeOnce = async () => {
        const native = session.nextChannel()
        const channel = await transport.exec("sudo -S true")
        await writeChunk(channel.stdin, sudoPassword)
        expect(sudoPassword.toString()).toBe("sudo-secret\n")
        expect(native.stdinSnapshots.map(String)).toStrictEqual(["sudo-secret\n"])
        expect(native.stdinReceived[0]).not.toBe(sudoPassword)
        expect(native.stdinEnded).toBe(false)
      }
      await writeOnce()
      await writeOnce()
    })

    it("keeps a buffer passed to stdin.end(input) unchanged and ends native stdin", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("cat > /tmp/file")
      const input = Buffer.from("file content")
      await endWith(channel.stdin, input)
      expect(input.toString()).toBe("file content")
      expect(native.stdinSnapshots.map(String)).toStrictEqual(["file content"])
      expect(native.stdinEnded).toBe(true)
    })

    it("swallows a write after the native stdin was closed", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("true")
      native.stdin.destroy()
      await expect(writeChunk(channel.stdin, Buffer.from("late"))).rejects.toThrow("destroyed")
      await nextTurn()
      expect(channel.stdin.destroyed).toBe(true)
    })

    it("settles stdin.end() when the native stdin is already closed", async () => {
      const { session, transport } = await connected()
      const native = session.nextChannel()
      const channel = await transport.exec("true")
      native.stdin.destroy()
      const closed = new Promise((resolve) => {
        channel.stdin.on("close", resolve)
      })
      channel.stdin.end()
      await closed
      expect(channel.stdin.closed).toBe(true)
    })
  })

  describe("native transport: sftp", () => {
    it("creates streams synchronously and passes the mode", async () => {
      const { native, sftp } = await openSftp()
      const read = sftp.createReadStream("/etc/hostname")
      const write = sftp.createWriteStream("/tmp/upload", { mode: 0o600 })
      expect(read).toBe(native.readStreams[0])
      expect(write).toBe(native.writeStreams[0].stream)
      expect(native.writeStreams[0].mode).toBe(0o600)
      expect(native.createReadStream).toHaveBeenCalledWith("/etc/hostname")
    })

    it("reports stream errors as TransportError with sftpStatus on the cause", async () => {
      const { native, sftp } = await openSftp()
      const read = sftp.createReadStream("/missing")
      const failed = new Promise<unknown>((resolve) => {
        read.on("error", resolve)
      })
      native.readStreams[0].destroy(nativeError("SFTP_STATUS", "no such file", { sftpStatus: 2 }))
      const error = expectTransportError(await failed, "SFTP_STATUS")
      expect(error.message).toBe("no such file [SFTP_STATUS]")
      expect((error.cause as { sftpStatus?: number }).sftpStatus).toBe(2)
    })

    it("keeps an unobserved stream error from crashing the process", async () => {
      const { native, sftp } = await openSftp()
      const write = sftp.createWriteStream("/tmp/upload", { mode: 0o644 })
      const closed = new Promise((resolve) => {
        write.on("close", resolve)
      })
      native.writeStreams[0].stream.destroy(nativeError("DISCONNECTED"))
      await closed
      expect(write.destroyed).toBe(true)
    })

    it("maps a synchronous stream creation failure", async () => {
      const { native, sftp } = await openSftp()
      native.createReadStream.mockImplementationOnce(() => {
        throw new TypeError("remote path must be a non-empty string")
      })
      native.createWriteStream.mockImplementationOnce(() => {
        throw new TypeError("mode must be an integer between 0 and 0o7777")
      })
      expect(() => sftp.createReadStream("")).toThrow(TransportError)
      expect(() => sftp.createWriteStream("/tmp/x", { mode: -1 })).toThrow(TransportError)
    })

    it("ends synchronously and swallows the native result", async () => {
      const { native, sftp } = await openSftp()
      native.end.mockRejectedValueOnce(nativeError("DISCONNECTED"))
      sftp.end()
      expect(native.end).toHaveBeenCalledOnce()
      native.end.mockImplementationOnce(() => {
        throw nativeError("INTERNAL")
      })
      expect(() => {
        sftp.end()
      }).not.toThrow()
      await nextTurn()
      expect(native.end).toHaveBeenCalledTimes(2)
    })

    it("maps a refused SFTP subsystem", async () => {
      const { session, transport } = await connected()
      session.sftp.mockRejectedValueOnce(
        nativeError("CHANNEL_OPEN_FAILED", "subsystem refused", { detail: "subsystem-refused" })
      )
      expect(transportCodeOf(await rejection(transport.sftp()))).toBe("CHANNEL_OPEN_FAILED")
    })
  })
})
