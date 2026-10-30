import { Readable, Writable } from "node:stream"
import { vi } from "vitest"

import type {
  Transport,
  TransportConnection,
  TransportConnectOptions,
  TransportExecChannel,
  TransportExit,
  TransportSftpSession,
} from "../../src/transport.js"

import { TransportError } from "../../src/transport.js"

const DISCONNECTED_EXIT_CODE = 255

/** Readable with synchronous replay, as required before replaying a channel exit. */
class FakeOutput extends Readable {
  private readonly errors: Error[] = []
  public constructor() {
    super()
    this.on("error", () => {
      /* Errors remain available to a later consumer. */
    })
  }
  public override _read(): void {
    /* Output is explicitly driven by the test. */
  }
  public fail(error: Error): void {
    if (this.listenerCount("error") === 1) this.errors.push(error)
    this.emit("error", error)
  }
  public finish(): void {
    this.push(null)
  }
  public override on(event: string | symbol, listener: Parameters<Readable["on"]>[1]): this {
    super.on(event, listener)
    if (event === "data")
      while (this.read() !== null) {
        /* Drain before exit replay. */
      }
    if (event === "error" && this.listenerCount("error") > 1)
      for (const error of this.errors.splice(0)) this.emit("error", error)
    return this
  }
  public send(data: Buffer | string): void {
    this.push(data)
  }
}

export class FakeExecChannel implements TransportExecChannel {
  public closeRequested = false
  public readonly close = vi.fn(() => {
    this.closeRequested = true
  })
  public readonly stderr = new FakeOutput()
  public readonly stdin = new Writable({
    write(_chunk, _encoding, callback) {
      callback()
    },
  })
  public readonly stdout = new FakeOutput()
  private exit: TransportExit | undefined
  private readonly exits = new Set<(exit: TransportExit) => void>()
  public constructor() {
    this.stdin.on("error", () => {
      /* Late input failures cannot escape teardown. */
    })
    vi.spyOn(this.stdin, "write")
    vi.spyOn(this.stdin, "end")
  }
  public finish(code: null | number | undefined = null, signal: null | string = null): void {
    if (this.exit !== undefined) return
    this.stdout.finish()
    this.stderr.finish()
    this.exit = { code: code ?? null, signal }
    for (const listener of this.exits) listener(this.exit)
    this.exits.clear()
  }
  public onExit(listener: (exit: TransportExit) => void): () => void {
    if (this.exit === undefined) this.exits.add(listener)
    else listener(this.exit)
    return () => {
      this.exits.delete(listener)
    }
  }
}

/** Scenario delivery controls; the connection still exposes only the transport contract. */
export type ChannelDelivery = {
  (channel: FakeExecChannel): void
  fail: (error: unknown) => void
}
export type ExecScenario = (command: string, delivery: ChannelDelivery) => unknown
export type SessionDelivery = {
  (session: TransportSftpSession): void
  fail: (error: unknown) => void
}
export type FakeConnectionOptions = {
  execute?: ExecScenario
  onClose?: () => unknown
  onConnect?: (options: TransportConnectOptions) => Promise<void>
  onDestroy?: () => unknown
  openSftp?: (delivery: SessionDelivery) => unknown
  promiseOnly?: boolean
}

/** A transport connection with explicit operation delivery and lifecycle state. */
export class FakeTransportConnection implements Transport, TransportConnection {
  public closed = false
  public readonly close = vi.fn(async () => {
    this.closed = true
    await this.scenario.onClose?.()
  })
  public destroyed = false
  public readonly destroy = vi.fn(() => {
    this.destroyed = true
    this.scenario.onDestroy?.()
  })
  public readonly connect = vi.fn(async (options: TransportConnectOptions) => {
    try {
      await this.scenario.onConnect?.(options)
    } catch (error) {
      this.destroy()
      throw error
    }
    return this
  })
  public readonly exec: ReturnType<typeof vi.fn<TransportConnection["exec"]>>
  public readonly sftp: ReturnType<typeof vi.fn<TransportConnection["sftp"]>>
  private readonly channels = new Set<FakeExecChannel>()
  private disconnected: TransportError | undefined
  private readonly disconnects = new Set<(error: TransportError) => void>()
  public constructor(private readonly scenario: FakeConnectionOptions = {}) {
    this.exec = vi.fn(
      async (command, onChannel) =>
        new Promise((resolve, reject) => {
          const deliver: ChannelDelivery = Object.assign(
            (channel: FakeExecChannel) => {
              this.channels.add(channel)
              if (this.scenario.promiseOnly !== true) onChannel?.(channel)
              resolve(channel)
            },
            {
              fail(error: unknown) {
                reject(asTransportError(error))
              },
            }
          )
          try {
            this.scenario.execute?.(command, deliver)
          } catch (error) {
            deliver.fail(error)
          }
        })
    )
    this.sftp = vi.fn(
      async (onSession) =>
        new Promise((resolve, reject) => {
          const deliver: SessionDelivery = Object.assign(
            (session: TransportSftpSession) => {
              if (this.scenario.promiseOnly !== true) onSession?.(session)
              resolve(session)
            },
            {
              fail(error: unknown) {
                reject(asTransportError(error))
              },
            }
          )
          try {
            this.scenario.openSftp?.(deliver)
          } catch (error) {
            deliver.fail(error)
          }
        })
    )
  }
  public disconnect(
    error = new TransportError("DISCONNECTED", new Error("SSH connection closed unexpectedly"))
  ): void {
    if (this.disconnected !== undefined) return
    this.disconnected = error
    for (const listener of this.disconnects) listener(error)
    this.disconnects.clear()
    for (const channel of this.channels) channel.finish(DISCONNECTED_EXIT_CODE)
  }
  public disconnectListenerCount(): number {
    return this.disconnects.size
  }
  public onDisconnect(listener: (error: TransportError) => void): () => void {
    if (this.disconnected === undefined) this.disconnects.add(listener)
    else listener(this.disconnected)
    return () => {
      this.disconnects.delete(listener)
    }
  }
}

function asTransportError(error: unknown): TransportError {
  return error instanceof TransportError ? error : new TransportError("INTERNAL", error)
}

/** Typed SFTP session; callers control the actual Node streams used by each operation. */
export class FakeSftpSession implements TransportSftpSession {
  public readonly createReadStream: ReturnType<
    typeof vi.fn<TransportSftpSession["createReadStream"]>
  >
  public readonly createWriteStream: ReturnType<
    typeof vi.fn<TransportSftpSession["createWriteStream"]>
  >
  public ended = false
  public readonly end = vi.fn(() => {
    this.ended = true
  })
  public constructor(read: Readable, write: Writable) {
    this.createReadStream = vi.fn((_path) => read)
    this.createWriteStream = vi.fn((_path, _options) => write)
  }
}
