/* eslint-disable max-lines -- the temporary ssh2 adapter owns the complete ssh2 lifecycle and stream boundary */
// Temporary ssh2 adapter until C2 introduces the native transport.
import { Readable } from "node:stream"
import { Client, type ClientChannel, type ConnectConfig, type SFTPWrapper } from "ssh2"

import type {
  Transport,
  TransportConnection,
  TransportConnectOptions,
  TransportErrorCode,
  TransportExecChannel,
  TransportExit,
  TransportSftpSession,
} from "./transport.js"

import { TransportError } from "./transport.js"

// Legacy fixture bridges may omit EventEmitter methods; real ssh2 clients provide them.
type Ssh2Client = Omit<Client, "eventNames" | "on" | "once" | "removeListener"> &
  Partial<Pick<Client, "eventNames" | "on" | "once" | "removeListener">>
function rawClient(value: unknown): Ssh2Client {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- temporary boundary accepts existing ssh2 fixtures and real Client instances
  return value as Ssh2Client
}

type Ssh2ConnectOptions = Omit<TransportConnectOptions, "verifyHostKey"> &
  Partial<Pick<TransportConnectOptions, "verifyHostKey">>

const CHANNEL_OPEN_FAILURE_PATTERN = /channel open failure/iv
const DESTROY_FALLBACK_MS = 5000
const DISCONNECTED_EXIT_CODE = 255
const connections = new WeakMap<object, Ssh2Connection>()

function ignoreTeardownError(): void {
  /* Late errors never replace the settled result. */
}

function classify(error: unknown): TransportErrorCode {
  if (error instanceof Error && CHANNEL_OPEN_FAILURE_PATTERN.test(error.message))
    return "CHANNEL_OPEN_FAILED"
  const level: unknown =
    typeof error === "object" && error !== null ? Reflect.get(error, "level") : undefined
  switch (level) {
    case "client-authentication": {
      return "AUTH_FAILED"
    }
    case "client-socket": {
      return "CONNECT_FAILED"
    }
    case "client-timeout": {
      return "TIMEOUT"
    }
    case "handshake":
    case "protocol": {
      return "PROTOCOL"
    }
    default: {
      return "INTERNAL"
    }
  }
}
function wrap(error: unknown): TransportError {
  return new TransportError(classify(error), error)
}

/**
 * R-0000794: install the sink before removing any existing listener.
 * @param value - A real client, legacy fixture, or transport connection.
 */
export function cleanupSsh2Client(value: unknown): void {
  if (value instanceof Ssh2Connection) {
    value.cleanupFailed()
    return
  }
  const client = rawClient(value)
  try {
    client.removeListener?.("error", ignoreTeardownError)
    client.on?.("error", ignoreTeardownError)
    for (const event of client.eventNames?.() ?? []) {
      if (event !== "error") client.removeAllListeners(event)
    }
  } catch {
    /* Teardown must not throw. */
  }
  try {
    client.end()
  } catch {
    /* The socket may already be destroyed. */
  }
}

/** Drain raw streams immediately and replay data synchronously to the collector. */
class BufferedOutput extends Readable {
  private readonly pendingErrors: Error[] = []
  public constructor() {
    super()
    this.on("error", ignoreTeardownError)
  }
  public override _read(): void {
    /* Raw ssh2 data drives this readable. */
  }
  public append(data: Buffer): void {
    this.push(data)
  }
  public fail(error: Error): void {
    if (this.listenerCount("error") === 1) this.pendingErrors.push(error)
    this.emit("error", error)
  }
  public finish(): void {
    this.push(null)
  }
  // Node's overloaded EventEmitter contract accepts arbitrary event argument lists.
  public override on(event: string | symbol, listener: Parameters<Readable["on"]>[1]): this {
    super.on(event, listener)
    if (event === "data") {
      // Readable.on normally schedules buffered delivery for the next tick.
      // Drain now so the synchronous onExit replay follows every data event.
      while (this.read() !== null) {
        /* read() emits each buffered data chunk. */
      }
    }
    if (event === "error" && listener !== ignoreTeardownError) {
      for (const error of this.pendingErrors.splice(0)) this.emit("error", error)
    }
    return this
  }
}

function normalizeSignal(signal: null | string | undefined): null | string {
  if (signal == null || signal === "") return null
  return signal.startsWith("SIG") ? signal : `SIG${signal}`
}

/**
 * Temporary bridge for legacy channel test setup; removed with the C1 fake migration.
 * @param stream - The underlying ssh2 channel.
 * @param isDisconnected - Whether the parent connection has already ended.
 * @returns Buffered transport streams and the synchronous exit subscription.
 */
export function fromSsh2Channel(
  stream: ClientChannel,
  isDisconnected: () => boolean = () => false
): TransportExecChannel {
  const stdout = new BufferedOutput()
  const stderr = new BufferedOutput()
  const listeners = new Set<(exit: TransportExit) => void>()
  let exit: TransportExit | undefined
  stream.addListener("data", (data: Buffer) => {
    stdout.append(data)
  })
  stream.stderr.addListener("data", (data: Buffer) => {
    stderr.append(data)
  })
  stream.addListener("error", (error: Error) => {
    stdout.fail(error)
  })
  stream.stderr.addListener("error", (error: Error) => {
    stderr.fail(error)
  })
  stream.addListener("close", (code?: null | number, signal?: null | string) => {
    if (exit !== undefined) return
    stdout.finish()
    stderr.finish()
    exit = {
      code: isDisconnected() ? DISCONNECTED_EXIT_CODE : (code ?? null),
      signal: normalizeSignal(signal),
    }
    for (const listener of listeners) listener(exit)
    listeners.clear()
  })
  return {
    close() {
      stream.close()
    },
    onExit(listener) {
      if (exit === undefined) listeners.add(listener)
      else listener(exit)
      return () => {
        listeners.delete(listener)
      }
    },
    stderr,
    stdin: stream,
    stdout,
  }
}

function fromSftp(sftp: SFTPWrapper): TransportSftpSession {
  return {
    createReadStream(path) {
      const stream = sftp.createReadStream(path)
      stream.addListener("error", ignoreTeardownError)
      return stream
    },
    createWriteStream(path, options) {
      const stream = sftp.createWriteStream(path, options)
      stream.addListener("error", ignoreTeardownError)
      return stream
    },
    end() {
      // Lightweight legacy fixtures can omit the EventEmitter surface.
      const once: unknown = Reflect.get(sftp, "once")
      if (typeof once === "function") sftp.once("error", ignoreTeardownError)
      sftp.end()
    },
  }
}

function buildHostVerifierBridge(
  options: TransportConnectOptions,
  state: {
    fail: (error: unknown) => void
    isSettled: () => boolean
    onVerdict: (rejected: boolean) => void
  }
): NonNullable<ConnectConfig["hostVerifier"]> {
  return (key: Buffer, verify?: (valid: boolean) => void) => {
    let answered = false
    const answer = (verdict: unknown): void => {
      if (state.isSettled() || answered) return
      answered = true
      state.onVerdict(verdict !== true)
      verify?.(verdict === true)
    }
    const verifierFailed = (error: unknown): void => {
      if (state.isSettled() || answered) return
      // Settle first: verify(false) may synchronously emit a generic ssh2 error.
      state.fail(error)
      answered = true
      verify?.(false)
    }
    try {
      const verdict: unknown = options.verifyHostKey(key)
      if (typeof verdict === "object" && verdict !== null && "then" in verdict) {
        void Promise.resolve(verdict).then(answer, verifierFailed)
      } else answer(verdict)
    } catch (error) {
      verifierFailed(error)
    }
    // Returning no verdict keeps ssh2 in callback verification mode.
  }
}

function buildConnectConfig(
  options: Ssh2ConnectOptions,
  hostVerifier: ConnectConfig["hostVerifier"]
): ConnectConfig {
  const config: ConnectConfig = {
    host: options.host,
    hostVerifier,
    port: options.port,
    readyTimeout: options.readyTimeout,
    username: options.username,
  }
  if (options.privateKey != null) config.privateKey = options.privateKey
  if (options.agent != null) config.agent = options.agent
  if (options.agentForward === true) config.agentForward = true
  if (typeof options.password === "string") {
    config.password = options.password
    config.tryKeyboard = true
  }
  return config
}

class Ssh2Connection implements TransportConnection, Transport {
  private disconnected: TransportError | undefined
  private readonly listeners = new Set<(error: TransportError) => void>()
  private observing = false
  public constructor(private readonly client: Ssh2Client) {}
  public cleanupFailed(): void {
    cleanupSsh2Client(this.client)
  }
  public async close(): Promise<void> {
    return new Promise((resolve) => {
      const fallback = setTimeout(() => {
        this.destroy()
        resolve()
      }, DESTROY_FALLBACK_MS)
      fallback.unref()
      try {
        this.client.on?.("error", ignoreTeardownError)
        this.client.once?.("close", () => {
          clearTimeout(fallback)
          resolve()
        })
        this.client.end()
      } catch {
        /* The fallback owns hard teardown. */
      }
    })
  }
  public async connect(options: Ssh2ConnectOptions): Promise<TransportConnection> {
    const { client } = this
    // The timeout, abort and ready handlers share this single settlement closure.
    // eslint-disable-next-line max-statements -- keep listener ownership and settlement visibly together
    return new Promise((resolve, reject) => {
      let settled = false
      let verifierRejected = false
      const cleanup = (): void => {
        clearTimeout(timer)
        client.off("ready", handleReady)
        client.off("error", handleError)
        options.signal?.removeEventListener("abort", handleAbort)
      }
      const fail = (error: unknown): void => {
        if (settled) return
        settled = true
        cleanup()
        this.cleanupFailed()
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- verifier failures must preserve arbitrary raw values
        reject(error)
      }
      const handleReady = (): void => {
        if (settled) return
        settled = true
        cleanup()
        this.observe()
        resolve(this)
      }
      const handleError = (error: unknown): void => {
        fail(verifierRejected ? new TransportError("HOST_KEY_REJECTED", error) : wrap(error))
      }
      const handleAbort = (): void => {
        fail(
          options.signal?.reason instanceof Error
            ? options.signal.reason
            : new Error("SSH connect aborted")
        )
      }
      const timer = setTimeout(() => {
        fail(new TransportError("TIMEOUT", new Error(`Connection timeout on port ${options.port}`)))
      }, options.readyTimeout)
      const { verifyHostKey } = options
      if (verifyHostKey == null) {
        fail(
          new TransportError(
            "INTERNAL",
            new Error(
              "Refusing to start ssh2 without a host-key verifier. " +
                "Use buildHostVerifier and pass the resulting hostVerifier, or explicitly configure a safe host-key policy."
            )
          )
        )
        return
      }
      if (options.signal?.aborted === true) {
        handleAbort()
        return
      }
      const hostVerifier = buildHostVerifierBridge(
        { ...options, verifyHostKey },
        {
          fail,
          isSettled: () => settled,
          onVerdict(rejected) {
            verifierRejected = rejected
          },
        }
      )
      const config = buildConnectConfig(options, hostVerifier)
      client.on?.("ready", handleReady)
      client.on?.("error", handleError)
      options.signal?.addEventListener("abort", handleAbort, { once: true })
      try {
        client.connect(config)
      } catch (error) {
        handleError(error)
      }
    })
  }
  public destroy(): void {
    try {
      this.client.on?.("error", ignoreTeardownError)
      this.client.destroy()
    } catch {
      /* Synchronous hard-stop must never throw. */
    }
  }
  public async exec(
    command: string,
    onChannel?: (channel: TransportExecChannel) => void
  ): Promise<TransportExecChannel> {
    return new Promise((resolve, reject) => {
      try {
        this.client.exec(command, (error, stream) => {
          if (error) {
            reject(wrap(error))
            return
          }
          // Attach before returning to ssh2, including synchronous legacy fakes.
          const channel = fromSsh2Channel(stream, () => this.disconnected !== undefined)
          onChannel?.(channel)
          resolve(channel)
        })
      } catch (error) {
        reject(wrap(error))
      }
    })
  }
  public observe(): void {
    if (this.observing) return
    this.observing = true
    this.client.on?.("error", this.handleDisconnectError)
    this.client.once?.("close", this.handleDisconnectClose)
  }
  public onDisconnect(listener: (error: TransportError) => void): () => void {
    this.observe()
    if (this.disconnected === undefined) this.listeners.add(listener)
    else listener(this.disconnected)
    return () => {
      this.listeners.delete(listener)
    }
  }
  public async sftp(
    onSession?: (session: TransportSftpSession) => void
  ): Promise<TransportSftpSession> {
    return new Promise((resolve, reject) => {
      try {
        this.client.sftp((error, sftp) => {
          if (error) {
            reject(wrap(error))
            return
          }
          // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- legacy callbacks and malformed library responses can omit the session
          if (sftp === undefined) {
            reject(wrap(new Error("Failed to open SFTP session: missing SFTP session")))
            return
          }
          const session = fromSftp(sftp)
          onSession?.(session)
          resolve(session)
        })
      } catch (error) {
        reject(wrap(error))
      }
    })
  }
  private disconnect(error: TransportError): void {
    if (this.disconnected !== undefined) return
    this.disconnected = error
    for (const listener of this.listeners) listener(error)
    this.listeners.clear()
  }
  private readonly handleDisconnectClose = (): void => {
    this.disconnect(
      new TransportError("DISCONNECTED", new Error("SSH connection closed unexpectedly"))
    )
  }
  private readonly handleDisconnectError = (error: unknown): void => {
    this.disconnect(wrap(error))
  }
}

/**
 * Temporary bridge for existing ssh2 test fixtures, removed in PR 3.
 * @param client - An existing ssh2 client or legacy fixture.
 * @returns A transport connection sharing the client's lifecycle.
 */
export function fromSsh2Client(client: Client): TransportConnection {
  let connection = connections.get(client)
  if (connection === undefined) {
    connection = new Ssh2Connection(client)
    connections.set(client, connection)
  }
  connection.observe()
  return connection
}
export function createSsh2Transport(): Transport & TransportConnection {
  return new Ssh2Connection(new Client())
}
export async function connectSsh2Client(
  client: unknown,
  options: Ssh2ConnectOptions
): Promise<TransportConnection> {
  if (client instanceof Ssh2Connection) return client.connect(options)
  // Legacy fixtures supply the raw client until PR 3.
  return new Ssh2Connection(rawClient(client)).connect(options)
}
