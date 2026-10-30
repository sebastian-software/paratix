/* oxlint-disable vitest/no-conditional-in-test -- parameterized rows choose termination or failure mechanisms and always assert the same contract */
import type { Client, ConnectConfig } from "ssh2"

import { generateKeyPairSync } from "node:crypto"
import { EventEmitter } from "node:events"
import { Writable } from "node:stream"
import { Server } from "ssh2"
import { afterEach, describe, expect, it, vi } from "vitest"

import type { TransportConnectOptions, TransportExecChannel } from "../src/transport.js"

import { HostKeyVerificationError } from "../src/knownHosts.js"
import { sftpUploadContent } from "../src/sftp.js"
import { TransportError } from "../src/transport.js"
import {
  cleanupSsh2Client,
  connectSsh2Client,
  createSsh2Transport,
  fromSsh2Client,
} from "../src/transportSsh2.js"

const options: TransportConnectOptions = {
  host: "127.0.0.1",
  password: "test-password",
  port: 22,
  readyTimeout: 1000,
  username: "root",
  verifyHostKey: () => true,
}
const testPrivateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
  format: "pem",
  type: "pkcs1",
})
const cleanups: Array<() => void> = []
function fakeClient() {
  const client = Object.assign(new EventEmitter(), {
    connect: vi.fn((_config: ConnectConfig) => client),
    destroy: vi.fn<() => void>(),
    end: vi.fn<() => void>(),
    exec: vi.fn<
      (
        command: string,
        callback: (error?: Error, stream?: ReturnType<typeof fakeChannel>) => void
      ) => void
    >(),
    sftp: vi.fn<(callback: (error?: Error, session?: unknown) => void) => void>(),
  })
  return client
}
function fakeChannel() {
  return Object.assign(new EventEmitter(), {
    close: vi.fn(),
    end: vi.fn(),
    stderr: new EventEmitter(),
    write: vi.fn(),
  })
}
function bridge(client: ReturnType<typeof fakeClient>) {
  return fromSsh2Client(client as unknown as Client)
}
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept
    reject = decline
  })
  return { promise, reject, resolve }
}

async function serverPort(): Promise<number> {
  const key = testPrivateKey
  const clients = new Set<{ end: () => void }>()
  const server = new Server({ hostKeys: [key] }, (client) => {
    clients.add(client)
    client.on("error", () => {
      /* Rejected handshakes are expected. */
    })
    client.on("authentication", (context) => {
      if (context.method === "password" && context.password === options.password) context.accept()
      else context.reject()
    })
  })
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve)
  })
  cleanups.push(() => {
    for (const client of clients) client.end()
    server.close()
  })
  const address = server.address()
  if (address === null || typeof address === "string") throw new Error("Missing test server port")
  return address.port
}
async function handshake(
  verifyHostKey: TransportConnectOptions["verifyHostKey"],
  overrides: Partial<TransportConnectOptions> = {}
) {
  const port = await serverPort()
  const transport = createSsh2Transport()
  cleanups.push(() => {
    transport.destroy()
  })
  return transport.connect({ ...options, port, verifyHostKey, ...overrides })
}

describe("ssh2 transport", () => {
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup()
    vi.useRealTimers()
  })

  describe("ssh2 verifier handshake", () => {
    it.each([true, Promise.resolve(true)])(
      "accepts only true, including a Promise (%s)",
      async (verdict) => {
        const connection = await handshake(async () => verdict)
        expect(connection).toHaveProperty("exec")
      }
    )
    it.each([false, 1, "yes", {}, undefined, null])(
      "rejects non-true verdict %s",
      async (verdict) => {
        await expect(handshake(() => verdict as boolean)).rejects.toMatchObject({
          transportCode: "HOST_KEY_REJECTED",
        })
      }
    )
    it("rejects a Promise resolving false", async () => {
      await expect(
        handshake((): boolean | Promise<boolean> => Promise.resolve(false))
      ).rejects.toMatchObject({
        transportCode: "HOST_KEY_REJECTED",
      })
    })
    it.each([false, true])(
      "preserves verifier failure identity (Promise: %s)",
      async (asPromise) => {
        const error = new HostKeyVerificationError("host key rejected by policy")
        await expect(
          handshake((): boolean | Promise<boolean> => {
            if (asPromise) return Promise.reject(error)
            throw error
          })
        ).rejects.toBe(error)
      }
    )
    it("preserves non-Error verifier rejection values", async () => {
      const raw = { refusal: "policy" }
      await expect(
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- prove arbitrary verifier rejection values are preserved
        handshake((): boolean | Promise<boolean> => Promise.reject(raw))
      ).rejects.toBe(raw)
    })
    it("times out a verifier that never answers", async () => {
      await expect(
        handshake(
          async () =>
            new Promise<boolean>(() => {
              /* Intentionally unanswered. */
            }),
          { readyTimeout: 50 }
        )
      ).rejects.toMatchObject({ transportCode: "TIMEOUT" })
    })
    it("preserves abort Error identity during a real handshake", async () => {
      const controller = new AbortController()
      const error = new Error("cancelled handshake")
      const entered = deferred<undefined>()
      const attempt = handshake(
        async () => {
          entered.resolve(undefined)
          return new Promise<boolean>(() => {
            /* Wait for abort. */
          })
        },
        { signal: controller.signal }
      )
      void attempt.catch(() => {
        /* The rejection is asserted below. */
      })
      await entered.promise
      controller.abort(error)
      await expect(attempt).rejects.toBe(error)
    })
    it("absorbs a verifier rejection after a real handshake timed out", async () => {
      const verdict = deferred<boolean>()
      const verifier = vi.fn((): boolean | Promise<boolean> => verdict.promise)
      const attempt = handshake(verifier, { readyTimeout: 100 })
      await expect(attempt).rejects.toMatchObject({ transportCode: "TIMEOUT" })
      expect(verifier).toHaveBeenCalledOnce()
      verdict.reject(new Error("late verifier rejection"))
      await verdict.promise.catch(() => {
        /* The adapter must independently absorb this rejection. */
      })
      await Promise.resolve()
    })
    it("ignores verifier fulfillment after a real handshake was aborted", async () => {
      const verdict = deferred<boolean>()
      const controller = new AbortController()
      const reason = new Error("abort during verifier")
      const verifier = vi.fn((): boolean | Promise<boolean> => verdict.promise)
      const failure = handshake(verifier, { signal: controller.signal }).catch(
        (error: unknown) => error
      )
      await vi.waitFor(() => {
        expect(verifier).toHaveBeenCalledOnce()
      })
      controller.abort(reason)
      expect(await failure).toBe(reason)
      verdict.resolve(true)
      await verdict.promise
      await Promise.resolve()
    })
    it("keeps agent forwarding with a key file as the existing INTERNAL failure", async () => {
      const privateKey = testPrivateKey
      await expect(handshake(() => true, { agentForward: true, privateKey })).rejects.toMatchObject(
        {
          message: /agent/iv,
          transportCode: "INTERNAL",
        }
      )
    })
  })

  describe("ssh2 connection lifecycle", () => {
    it.each([
      ["client-authentication", "AUTH_FAILED"],
      ["client-timeout", "TIMEOUT"],
      ["client-socket", "CONNECT_FAILED"],
      ["protocol", "PROTOCOL"],
      ["handshake", "PROTOCOL"],
      ["unknown", "INTERNAL"],
    ])("maps %s and preserves the raw cause", async (level, transportCode) => {
      const client = fakeClient()
      const error = Object.assign(new Error("raw connect error"), { code: "ECONNRESET", level })
      const attempt = connectSsh2Client(client, options)
      client.emit("error", error)
      await expect(attempt).rejects.toMatchObject({ cause: error, transportCode })
      await expect(attempt).rejects.toHaveProperty("cause", error)
      expect(error.code).toBe("ECONNRESET")
      expect(client.end).toHaveBeenCalledOnce()
      expect(() => client.emit("error", new Error("late error"))).not.toThrow()
    })
    it("preserves raw non-Error values in transport causes", async () => {
      const client = fakeClient()
      const raw = { code: 17 }
      const attempt = connectSsh2Client(client, options)
      client.emit("error", raw)
      const error = await attempt.catch((error: unknown) => error)
      expect(error).toBeInstanceOf(TransportError)
      expect((error as TransportError).cause).toBe(raw)
    })
    it("handles synchronous connect throws and duplicate late errors once", async () => {
      const client = fakeClient()
      const raw = new Error("synchronous connect failure")
      client.connect.mockImplementation(() => {
        throw raw
      })
      const attempt = connectSsh2Client(client, options)
      client.emit("error", new Error("late error"))
      await expect(attempt).rejects.toMatchObject({ cause: raw, transportCode: "INTERNAL" })
      expect(client.end).toHaveBeenCalledOnce()
    })
    it("fails closed without a verifier using the existing message", async () => {
      const client = fakeClient()
      await expect(
        connectSsh2Client(client, { ...options, verifyHostKey: undefined! })
      ).rejects.toThrow(
        "Refusing to start ssh2 without a host-key verifier. Use buildHostVerifier and pass the resulting hostVerifier, or explicitly configure a safe host-key policy."
      )
      expect(client.connect).not.toHaveBeenCalled()
    })
    it("owns its ready timer and removes connection-phase listeners at ready", async () => {
      vi.useFakeTimers()
      const client = fakeClient()
      const attempt = connectSsh2Client(client, options)
      client.emit("ready")
      const connection = await attempt
      expect(client.listenerCount("ready")).toBe(0)
      expect(vi.getTimerCount()).toBe(0)
      const disconnect = vi.fn<(error: TransportError) => void>()
      connection.onDisconnect(disconnect)
      client.emit("close")
      expect(disconnect).toHaveBeenCalledOnce()
      expect(disconnect.mock.calls[0][0]).toMatchObject({ transportCode: "DISCONNECTED" })
    })
    it("deduplicates error and close, supports unsubscribe and immediate late replay", () => {
      const client = fakeClient()
      const connection = bridge(client)
      const removed = vi.fn<(error: TransportError) => void>()
      connection.onDisconnect(removed)()
      const listener = vi.fn<(error: TransportError) => void>()
      connection.onDisconnect(listener)
      const raw = new Error("ECONNRESET")
      client.emit("error", raw)
      client.emit("close")
      client.emit("error", new Error("duplicate"))
      const late = vi.fn<(value: unknown) => void>()
      connection.onDisconnect(late)
      expect(removed).not.toHaveBeenCalled()
      expect(listener).toHaveBeenCalledOnce()
      expect(late).toHaveBeenCalledWith(listener.mock.calls[0][0])
      expect(listener.mock.calls[0][0].cause).toBe(raw)
    })
    it("notifies disconnect before a lost channel exit and never reports exit zero", async () => {
      const client = fakeClient()
      const raw = fakeChannel()
      client.exec.mockImplementation((_command, callback) => {
        callback(undefined, raw)
      })
      const connection = bridge(client)
      const order: string[] = []
      connection.onDisconnect(() => {
        order.push("disconnect")
      })
      const channel = await connection.exec("true")
      channel.onExit(({ code }) => {
        order.push(`exit:${String(code)}`)
      })
      client.emit("close")
      raw.emit("close")
      expect(order).toStrictEqual(["disconnect", "exit:255"])
    })
    it("destroys synchronously without throwing, including a throwing client", () => {
      const client = fakeClient()
      client.destroy.mockImplementation(() => {
        throw new Error("already destroyed")
      })
      const connection = bridge(client)
      client.emit("error", new Error("earlier failure"))
      expect(() => {
        connection.destroy()
      }).not.toThrow()
      expect(client.destroy).toHaveBeenCalledOnce()
    })
    it("closes cleanly and cancels the unreferenced destroy fallback", async () => {
      vi.useFakeTimers()
      const client = fakeClient()
      const close = bridge(client).close()
      expect(client.end).toHaveBeenCalledOnce()
      expect(vi.getTimerCount()).toBe(1)
      client.emit("close")
      await close
      await vi.advanceTimersByTimeAsync(5000)
      expect(client.destroy).not.toHaveBeenCalled()
    })
    it("resolves close after the fallback even when end and destroy throw", async () => {
      vi.useFakeTimers()
      const client = fakeClient()
      client.end.mockImplementation(() => {
        throw new Error("end failed")
      })
      client.destroy.mockImplementation(() => {
        throw new Error("destroy failed")
      })
      const close = bridge(client).close()
      await vi.advanceTimersByTimeAsync(5000)
      await expect(close).resolves.toBeUndefined()
      expect(client.destroy).toHaveBeenCalledOnce()
    })
    it("installs cleanup sinks before detaching listeners and tolerates teardown throws", () => {
      const client = fakeClient()
      client.on("ready", vi.fn<() => void>())
      client.end.mockImplementation(() => {
        client.emit("error", new Error("late cleanup"))
        throw new Error("end failed")
      })
      expect(() => {
        cleanupSsh2Client(client)
      }).not.toThrow()
      expect(client.listenerCount("ready")).toBe(0)
      expect(client.listenerCount("error")).toBe(1)
    })
  })

  describe("ssh2 verifier callback bridge", () => {
    it.each(
      ["timeout", "abort"].flatMap((ending) =>
        [false, true].map((rejectLate) => ({ ending, rejectLate }))
      )
    )(
      "ignores late verifier result after $ending (reject: $rejectLate)",
      async ({ ending, rejectLate }) => {
        vi.useFakeTimers()
        const client = fakeClient()
        const controller = new AbortController()
        const verdict = deferred<boolean>()
        const verify = vi.fn<(valid: boolean) => void>()
        const attempt = connectSsh2Client(client, {
          ...options,
          signal: controller.signal,
          verifyHostKey: async () => verdict.promise,
        })
        const failure = attempt.catch((error: unknown) => error)
        const config = client.connect.mock.calls[0][0]
        const hostVerifier = config.hostVerifier as (
          key: Buffer,
          verify: (valid: boolean) => void
        ) => unknown
        expect(hostVerifier(Buffer.from("key"), verify)).toBeUndefined()
        // eslint-disable-next-line vitest/no-conditional-in-test -- each row intentionally chooses one distinct termination mechanism
        if (ending === "timeout") await vi.advanceTimersByTimeAsync(1000)
        else controller.abort(new Error("abort"))
        await failure
        // eslint-disable-next-line vitest/no-conditional-in-test -- each row intentionally chooses fulfillment or rejection
        if (rejectLate) verdict.reject(new Error("late verifier failure"))
        else verdict.resolve(true)
        await Promise.resolve()
        expect(verify).not.toHaveBeenCalled()
      }
    )
    it("calls verify exactly once with strict true and always returns undefined", async () => {
      const client = fakeClient()
      const verdict = deferred<boolean>()
      const attempt = connectSsh2Client(client, {
        ...options,
        verifyHostKey: async () => verdict.promise,
      })
      const verify = vi.fn<(valid: boolean) => void>()
      const hostVerifier = client.connect.mock.calls[0][0].hostVerifier as (
        key: Buffer,
        verify: (valid: boolean) => void
      ) => unknown
      expect(hostVerifier(Buffer.from("key"), verify)).toBeUndefined()
      verdict.resolve(true)
      await vi.waitFor(() => {
        expect(verify).toHaveBeenCalledExactlyOnceWith(true)
      })
      client.emit("ready")
      await attempt
    })
    it("uses the existing generic error when abort reason is not an Error", async () => {
      const client = fakeClient()
      const controller = new AbortController()
      controller.abort("text reason")
      await expect(
        connectSsh2Client(client, { ...options, signal: controller.signal })
      ).rejects.toStrictEqual(new Error("SSH connect aborted"))
      expect(client.connect).not.toHaveBeenCalled()
    })
  })

  describe("ssh2 exec and SFTP channels", () => {
    it("invokes raw exec in the same tick and hands off only one buffered channel", async () => {
      const client = fakeClient()
      const raw = fakeChannel()
      client.exec.mockImplementation((_command, callback) => {
        callback(undefined, raw)
        raw.emit("data", Buffer.from("out"))
        raw.stderr.emit("data", Buffer.from("err"))
        raw.emit("close", 0, "TERM")
      })
      const handoff = vi.fn<(channel: unknown) => void>()
      const pending = bridge(client).exec("command", handoff)
      expect(client.exec).toHaveBeenCalledOnce()
      expect(handoff).toHaveBeenCalledOnce()
      const channel = await pending
      expect(channel).toBe(handoff.mock.calls[0][0])
      const order: string[] = []
      channel.stdout.on("data", (data: Buffer) => {
        order.push(data.toString())
      })
      channel.stderr.on("data", (data: Buffer) => {
        order.push(data.toString())
      })
      channel.onExit((exit) => {
        order.push(`${String(exit.code)}:${String(exit.signal)}`)
      })
      expect(order).toStrictEqual(["out", "err", "0:SIGTERM"])
      expect(raw.end).not.toHaveBeenCalled()
      expect(channel.stdin).toBe(raw)
    })
    it("drains unread stderr before synchronous exit and replays exit only once", async () => {
      const client = fakeClient()
      const raw = fakeChannel()
      client.exec.mockImplementation((_command, callback) => {
        callback(undefined, raw)
      })
      const channel = await bridge(client).exec("command")
      const exit = vi.fn<(exit: unknown) => void>()
      channel.onExit(exit)
      raw.stderr.emit("data", Buffer.alloc(128 * 1024))
      raw.emit("close", undefined, "")
      raw.emit("close", 7)
      expect(exit).toHaveBeenCalledExactlyOnceWith({ code: null, signal: null })
      const late = vi.fn<(value: unknown) => void>()
      channel.onExit(late)
      expect(late).toHaveBeenCalledExactlyOnceWith({ code: null, signal: null })
    })
    it("replays raw stream failures to a late Promise-only subscriber", async () => {
      const client = fakeClient()
      const raw = fakeChannel()
      const failure = new Error("early channel error")
      client.exec.mockImplementation((_command, callback) => {
        callback(undefined, raw)
        raw.emit("error", failure)
      })
      const channel = await bridge(client).exec("command")
      const errors: Error[] = []
      channel.stdout.on("error", (error: Error) => {
        errors.push(error)
      })
      expect(errors).toStrictEqual([failure])
    })
    it("supports exit unsubscribe and closes the raw channel", async () => {
      const client = fakeClient()
      const raw = fakeChannel()
      client.exec.mockImplementation((_command, callback) => {
        callback(undefined, raw)
      })
      const channel = await bridge(client).exec("command")
      const exit = vi.fn<(exit: unknown) => void>()
      channel.onExit(exit)()
      channel.close()
      raw.emit("close", 0)
      expect(exit).not.toHaveBeenCalled()
      expect(raw.close).toHaveBeenCalledOnce()
      expect(() => {
        raw.emit("error", new Error("late stdin"))
        raw.stderr.emit("error", new Error("late stderr"))
      }).not.toThrow()
    })
    it.each([false, true])(
      "rejects exec failures without synchronous throws (throw: %s)",
      async (syncThrow) => {
        const client = fakeClient()
        const raw = new Error(
          syncThrow ? "Not connected" : "(SSH) Channel open failure: open failed"
        )
        client.exec.mockImplementation((_command, callback) => {
          if (syncThrow) throw raw
          callback(raw)
        })
        let pending: Promise<TransportExecChannel> | undefined
        expect(() => {
          pending = bridge(client).exec("command")
        }).not.toThrow()
        await expect(pending).rejects.toMatchObject({
          cause: raw,
          transportCode: syncThrow ? "INTERNAL" : "CHANNEL_OPEN_FAILED",
        })
      }
    )
    it("maps SFTP open errors and preserves raw identity", async () => {
      const client = fakeClient()
      const raw = new Error("SFTP failed")
      client.sftp.mockImplementation((callback) => {
        callback(raw)
      })
      const error = await bridge(client)
        .sftp()
        .catch((error: unknown) => error)
      expect(error).toMatchObject({ transportCode: "INTERNAL" })
      expect((error as TransportError).cause).toBe(raw)
    })
    it("preserves synchronous SFTP stream creation and late error sinks", async () => {
      const client = fakeClient()
      const raw = new EventEmitter()
      const write = new EventEmitter()
      const failure = new Error("stream create failed")
      const sftp = Object.assign(new EventEmitter(), {
        createReadStream: vi.fn(() => raw),
        createWriteStream: vi.fn(() => write),
        end: vi.fn(),
      })
      client.sftp.mockImplementation((callback) => {
        callback(undefined, sftp)
      })
      const handoff = vi.fn<(channel: unknown) => void>()
      const pending = bridge(client).sftp(handoff)
      expect(handoff).toHaveBeenCalledOnce()
      const session = await pending
      expect(session).toBe(handoff.mock.calls[0][0])
      expect(session.createReadStream("/read")).toBe(raw)
      expect(session.createWriteStream("/write", { mode: 0o600 })).toBe(write)
      expect(sftp.createWriteStream).toHaveBeenCalledWith("/write", { mode: 0o600 })
      sftp.createReadStream.mockImplementation(() => {
        throw failure
      })
      expect(() => session.createReadStream("/bad")).toThrow(failure)
      session.end()
      expect(() => {
        sftp.emit("error", new Error("late session"))
        raw.emit("error", new Error("late read"))
        write.emit("error", new Error("late write"))
      }).not.toThrow()
      expect(sftp.end).toHaveBeenCalledOnce()
    })
    it("rejects missing SFTP sessions and synchronous open throws", async () => {
      const client = fakeClient()
      client.sftp
        .mockImplementationOnce((callback) => {
          callback(undefined, undefined)
        })
        .mockImplementationOnce(() => {
          throw new Error("open failed")
        })
      await expect(bridge(client).sftp()).rejects.toThrow("missing SFTP session")
      await expect(bridge(client).sftp()).rejects.toThrow("open failed")
    })
  })

  describe("Promise-only transport consumption", () => {
    it("opens and completes SFTP when a transport ignores the optional handoff", async () => {
      const client = fakeClient()
      const chunks: Buffer[] = []
      const writable = new Writable({
        write(chunk: Buffer, _encoding, callback) {
          chunks.push(chunk)
          callback()
        },
      })
      const sftp = Object.assign(new EventEmitter(), {
        createWriteStream: vi.fn(() => writable),
        end: vi.fn(),
      })
      client.sftp.mockImplementation((callback) => {
        callback(undefined, sftp)
      })
      const connection = bridge(client)
      const openSession = connection.sftp.bind(connection)
      connection.sftp = async () => openSession()
      await sftpUploadContent(connection, "payload", "/target")
      expect(Buffer.concat(chunks).toString()).toBe("payload")
      expect(sftp.createWriteStream).toHaveBeenCalledOnce()
      expect(sftp.end).toHaveBeenCalledOnce()
    })
  })
})
