/* eslint-disable max-lines -- the native adapter owns the complete binding lifecycle and stream boundary */
// Issue #257: transport adapter over the native binding @paratix/ssh-native.
import type {
  ConnectOptions,
  DisconnectEvent,
  ExecChannel,
  ExecExit,
  HostKeyInfo,
  Session,
  SftpSession,
} from "@paratix/ssh-native"

import { finished, Readable, Writable } from "node:stream"

import type {
  Transport,
  TransportConnection,
  TransportConnectOptions,
  TransportErrorCode,
  TransportExecChannel,
  TransportExit,
  TransportSftpSession,
} from "./transport.js"

import { loadNativeBinding, type NativeBinding } from "./nativeBinding.js"
import { TransportError } from "./transport.js"

const NATIVE_ERROR_CODES: ReadonlySet<string> = new Set<TransportErrorCode>([
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
])

/** Diagnostic fields of a binding error that the mapped cause keeps. */
const NATIVE_ERROR_FIELDS = ["code", "detail", "errno", "syscallCode", "sftpStatus"] as const

/**
 * Surface a consumer listener's failure like a throwing EventEmitter listener,
 * without stopping the remaining listeners or rejecting an internal promise.
 *
 * @param error - What the listener threw.
 */
function rethrowLater(error: unknown): void {
  process.nextTick(() => {
    throw error
  })
}

/**
 * Call every listener once; a throwing listener is rethrown asynchronously.
 *
 * @param listeners - The subscribed listeners, already detached from their set.
 * @param value - The value every listener receives.
 */
function notifyAll<T>(listeners: Iterable<(value: T) => void>, value: T): void {
  for (const listener of listeners) {
    try {
      listener(value)
    } catch (error) {
      rethrowLater(error)
    }
  }
}

function ignoreTeardownError(): void {
  /* Late errors never replace the settled result. */
}

/**
 * @param value - A candidate error code, for example from a binding error.
 * @returns Whether the value is one of the twelve codes the binding shares with Paratix.
 */
function isTransportErrorCode(value: unknown): value is TransportErrorCode {
  return typeof value === "string" && NATIVE_ERROR_CODES.has(value)
}

/**
 * @param error - A value the binding rejected, threw or emitted.
 * @returns The binding's error code; `INTERNAL` for a `TypeError` from argument
 *   validation and for anything without a known code.
 */
export function nativeErrorCode(error: unknown): TransportErrorCode {
  if (error instanceof TypeError || typeof error !== "object" || error === null) return "INTERNAL"
  const code: unknown = Reflect.get(error, "code")
  return isTransportErrorCode(code) ? code : "INTERNAL"
}

/**
 * Map a binding failure to a `TransportError` with the native code.
 *
 * The cause is a new `Error` whose message is `<native message> [<CODE>]`
 * (issue #257, decision 7). It keeps the binding error as its own `cause` and
 * copies the binding's diagnostic fields (`code`, `detail`, `errno`,
 * `syscallCode`, `sftpStatus`), so an `SFTP_STATUS` failure still carries
 * `sftpStatus` after `unwrapTransportError`. An existing `TransportError` is
 * returned unchanged; a non-Error value becomes `INTERNAL` and stays the raw
 * cause.
 *
 * @param error - What the binding rejected with, threw or emitted.
 * @returns The classified transport failure.
 */
export function toTransportError(error: unknown): TransportError {
  if (error instanceof TransportError) return error
  if (!(error instanceof Error)) return new TransportError("INTERNAL", error)
  const code = nativeErrorCode(error)
  const cause = new Error(`${error.message} [${code}]`, { cause: error })
  for (const field of NATIVE_ERROR_FIELDS) {
    if (Object.hasOwn(error, field)) Reflect.set(cause, field, Reflect.get(error, field))
  }
  return new TransportError(code, cause)
}

const DISCONNECTED_EXIT_CODE = 255

/** Drain native streams immediately and replay data synchronously to the collector. */
class BufferedOutput extends Readable {
  private readonly pendingErrors: Error[] = []
  public constructor() {
    super()
    this.on("error", ignoreTeardownError)
  }
  public override _read(): void {
    /* Native stream data drives this readable. */
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
 * The binding zero-fills every Buffer written to its stdin. Copy each chunk so
 * buffers the caller still owns (the cached sudo password, `stdin.end(input)`)
 * stay intact. The bridge never ends the native stdin on its own.
 *
 * @param target - The native stdin.
 * @returns The stdin handed to the caller.
 */
function createStdinBridge(target: Writable): Writable {
  const stdin = new Writable({
    final(callback) {
      // `end(callback)` never calls back on a destroyed stream; `finished` does.
      finished(target, (error) => {
        callback(error ?? undefined)
      })
      target.end()
    },
    write(chunk: Buffer, _encoding, callback) {
      target.write(Buffer.from(chunk), (error?: Error | null) => {
        callback(error ?? undefined)
      })
    },
  })
  // A write after the remote command ended fails; it never crashes the process.
  stdin.on("error", ignoreTeardownError)
  return stdin
}

/**
 * Call `listener` once the readable delivered all data (`end`) or went away (`close`).
 *
 * @param stream - A native output stream.
 * @param listener - Runs exactly once.
 */
function onDrained(stream: Readable, listener: () => void): void {
  let drained = false
  const done = (): void => {
    if (drained) return
    drained = true
    listener()
  }
  stream.once("end", done)
  stream.once("close", done)
}

/** Settlement of one exec channel: exactly one exit after all data, or one error. */
class NativeChannelBridge {
  public readonly stderr = new BufferedOutput()
  public readonly stdout = new BufferedOutput()
  private exit: TransportExit | undefined
  private failed = false
  private readonly listeners = new Set<(exit: TransportExit) => void>()
  private nativeExit: ExecExit | undefined
  private openStreams = 2
  private settled = false

  public constructor(private readonly beforeDisconnectedExit: () => void) {}

  /**
   * Buffer native output until the channel failed. The binding can still
   * deliver buffered chunks after the failure was reported; a consumer that
   * already settled on the stdout `error` must not receive them.
   *
   * @param output - The bridge stream for this native output.
   * @param data - One native chunk.
   */
  public append(output: BufferedOutput, data: Buffer): void {
    if (!this.failed) output.append(data)
  }

  public drained(): void {
    this.openStreams -= 1
    this.report()
  }

  public exited(result: ExecExit): void {
    this.nativeExit = result
    this.report()
  }

  public readonly fail = (error: unknown): void => {
    if (this.settled) return
    this.settled = true
    this.failed = true
    this.listeners.clear()
    this.stdout.fail(toTransportError(error))
  }

  public onExit(listener: (exit: TransportExit) => void): () => void {
    if (this.exit !== undefined) listener(this.exit)
    else if (!this.settled) this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  private report(): void {
    const result = this.nativeExit
    if (this.settled || result === undefined || this.openStreams > 0) return
    this.settled = true
    if (result.disconnected) this.beforeDisconnectedExit()
    this.stdout.finish()
    this.stderr.finish()
    const exit: TransportExit = {
      code: result.disconnected ? DISCONNECTED_EXIT_CODE : result.code,
      signal: normalizeSignal(result.signal),
    }
    this.exit = exit
    const listeners = [...this.listeners]
    this.listeners.clear()
    notifyAll(listeners, exit)
  }
}

/**
 * Adapt one native exec channel with buffered output and synchronous exit replay.
 *
 * Both native outputs are read at once, so native stdout never pauses and the
 * exit does not depend on stderr being read. The exit is reported exactly once,
 * after all data of both streams. A native stream error or a rejected `exit`
 * (including a defensive `ABORTED`) is reported as an `error` on the bridge
 * stdout, wrapped as `TransportError`; no exit follows.
 *
 * @param channel - The channel `Session.exec` resolved with; never cancelled.
 * @param beforeDisconnectedExit - Records the connection loss before a
 *   `disconnected` exit is reported.
 * @returns The transport channel.
 */
function fromNativeChannel(
  channel: ExecChannel,
  beforeDisconnectedExit: () => void
): TransportExecChannel {
  const bridge = new NativeChannelBridge(beforeDisconnectedExit)
  channel.stdout.on("data", (data: Buffer) => {
    bridge.append(bridge.stdout, data)
  })
  channel.stderr.on("data", (data: Buffer) => {
    bridge.append(bridge.stderr, data)
  })
  channel.stdout.on("error", bridge.fail)
  channel.stderr.on("error", bridge.fail)
  onDrained(channel.stdout, () => {
    bridge.drained()
  })
  onDrained(channel.stderr, () => {
    bridge.drained()
  })
  channel.exit.then((result) => {
    bridge.exited(result)
  }, bridge.fail)
  return {
    close() {
      try {
        channel.close().catch(ignoreTeardownError)
      } catch {
        /* Closing an ended channel must not throw. */
      }
    },
    onExit(listener) {
      return bridge.onExit(listener)
    },
    stderr: bridge.stderr,
    stdin: createStdinBridge(channel.stdin),
    stdout: bridge.stdout,
  }
}

/**
 * Report native stream errors as `TransportError` without replacing the stream.
 *
 * A wrapping Transform would decouple `finish`/`close` of the caller's stream
 * from the remote file, so the native stream keeps its identity and only the
 * value of its `error` events is mapped. The installed sink keeps an
 * unobserved stream error from crashing the process.
 *
 * @param stream - A native SFTP stream.
 * @returns The same stream.
 */
function mapStreamErrors<T extends Readable | Writable>(stream: T): T {
  const nativeEmit = stream.emit.bind(stream)
  Object.defineProperty(stream, "emit", {
    configurable: true,
    value(event: string | symbol, ...values: unknown[]): boolean {
      return event === "error"
        ? nativeEmit(event, toTransportError(values[0]))
        : nativeEmit(event, ...values)
    },
    writable: true,
  })
  stream.on("error", ignoreTeardownError)
  return stream
}

/**
 * @param sftp - The native SFTP session.
 * @returns The transport SFTP session; streams are created synchronously.
 */
function fromNativeSftp(sftp: SftpSession): TransportSftpSession {
  return {
    createReadStream(path) {
      try {
        return mapStreamErrors(sftp.createReadStream(path))
      } catch (error) {
        throw toTransportError(error)
      }
    },
    createWriteStream(path, options) {
      try {
        return mapStreamErrors(sftp.createWriteStream(path, { mode: options.mode }))
      } catch (error) {
        throw toTransportError(error)
      }
    },
    end() {
      try {
        sftp.end().catch(ignoreTeardownError)
      } catch {
        /* Ending a closed session must not throw. */
      }
    },
  }
}

function notConnected(operation: string): TransportError {
  return new TransportError(
    "INTERNAL",
    new Error(`Cannot ${operation} before the SSH connection is established`)
  )
}

/**
 * @param error - What the native connect rejected with.
 * @param verifierFailure - The value the host-key verifier threw, if it threw.
 * @param signal - The caller's abort signal.
 * @returns The value `connect()` rejects with: the verifier's own value, the
 *   unwrapped abort reason, or the classified `TransportError`.
 */
function connectFailure(
  error: unknown,
  verifierFailure: { error: unknown } | undefined,
  signal: AbortSignal | undefined
): unknown {
  if (verifierFailure !== undefined && verifierFailure.error === error) return error
  if (nativeErrorCode(error) === "ABORTED") {
    return signal?.reason instanceof Error ? signal.reason : new Error("SSH connect aborted")
  }
  return toTransportError(error)
}

/**
 * Bridge the transport verifier to the binding's verifier.
 *
 * Only a verdict of exactly `true` accepts. Host certificates are rejected
 * until #248/#258 add their verification. A value the verifier throws or
 * rejects with is recorded so `connect()` can pass that very object on; the
 * binding rejects with it for `HOST_KEY_REJECTED`.
 *
 * @param verifyHostKey - The transport verifier, called with the raw key blob.
 * @returns The binding verifier and the recorded verifier failure.
 */
function createHostVerifier(verifyHostKey: TransportConnectOptions["verifyHostKey"]): {
  failure: () => { error: unknown } | undefined
  verify: (info: HostKeyInfo) => Promise<boolean>
} {
  let failure: { error: unknown } | undefined
  return {
    failure: () => failure,
    async verify(info) {
      if (info.kind !== "key") return false
      try {
        const verdict: unknown = await verifyHostKey(Buffer.from(info.keyBase64, "base64"))
        return verdict === true
      } catch (error) {
        failure = { error }
        throw error
      }
    },
  }
}

/**
 * Start the native connect with per-attempt copies of the secrets.
 *
 * The binding zero-fills the buffers it receives in every path, so the caller's
 * key buffer is never handed over; the copies and the password buffer exist
 * only during this synchronous call. The binding has copied them before its
 * `connect` returns the promise, so they are zero-filled here in every path,
 * also when the adapter fails before the native call. Deliberately
 * synchronous: the `finally` must run before control returns to the event
 * loop, so the pending session is returned inside an object.
 *
 * @param binding - The loaded binding.
 * @param options - The transport options.
 * @param verify - The binding verifier.
 * @returns The pending native session.
 */
function startNativeConnect(
  binding: NativeBinding,
  options: TransportConnectOptions,
  verify: (info: HostKeyInfo) => Promise<boolean>
): { pending: Promise<Session> } {
  const secrets: Buffer[] = []
  try {
    const nativeOptions: ConnectOptions = {
      host: options.host,
      port: options.port,
      readyTimeoutMs: options.readyTimeout,
      user: options.username,
    }
    if (options.agent != null) nativeOptions.agent = options.agent
    if (options.agentForward === true) nativeOptions.agentForward = true
    if (options.signal !== undefined) nativeOptions.signal = options.signal
    if (options.privateKey != null) {
      nativeOptions.privateKey = Buffer.from(options.privateKey)
      secrets.push(nativeOptions.privateKey)
    }
    if (typeof options.password === "string") {
      nativeOptions.password = Buffer.from(options.password, "utf8")
      secrets.push(nativeOptions.password)
    }
    return { pending: binding.connect(nativeOptions, verify) }
  } finally {
    for (const secret of secrets) secret.fill(0)
  }
}

class NativeConnection implements TransportConnection, Transport {
  private connecting = false
  private disconnected: TransportError | undefined
  private readonly listeners = new Set<(error: TransportError) => void>()
  private session: Session | undefined

  public async close(): Promise<void> {
    try {
      await this.session?.close()
    } catch {
      /* The binding bounds close itself; teardown never rejects. */
    }
  }

  public async connect(options: TransportConnectOptions): Promise<TransportConnection> {
    if (this.connecting) {
      throw new TransportError("INTERNAL", new Error("connect() may be called only once"))
    }
    this.connecting = true
    let binding: NativeBinding
    try {
      binding = await loadNativeBinding()
    } catch (error) {
      throw new TransportError("INTERNAL", error)
    }
    const verifier = createHostVerifier(options.verifyHostKey)
    try {
      this.session = await startNativeConnect(binding, options, verifier.verify).pending
    } catch (error) {
      throw connectFailure(error, verifier.failure(), options.signal)
    }
    this.session.onDisconnect((event) => {
      this.disconnect(event)
    })
    return this
  }

  public destroy(): void {
    try {
      this.session?.destroy()
    } catch {
      /* Synchronous hard-stop must never throw. */
    }
  }

  public async exec(
    command: string,
    onChannel?: (channel: TransportExecChannel) => void
  ): Promise<TransportExecChannel> {
    const session = this.requireSession("exec")
    let nativeChannel
    try {
      nativeChannel = await session.exec(command)
    } catch (error) {
      throw toTransportError(error)
    }
    const channel = fromNativeChannel(nativeChannel, () => {
      this.disconnect({ reason: "error" })
    })
    onChannel?.(channel)
    return channel
  }

  public onDisconnect(listener: (error: TransportError) => void): () => void {
    if (this.disconnected === undefined) this.listeners.add(listener)
    else listener(this.disconnected)
    return () => {
      this.listeners.delete(listener)
    }
  }

  public async sftp(
    onSession?: (session: TransportSftpSession) => void
  ): Promise<TransportSftpSession> {
    const session = this.requireSession("open SFTP")
    let nativeSftp
    try {
      nativeSftp = await session.sftp()
    } catch (error) {
      throw toTransportError(error)
    }
    const sftp = fromNativeSftp(nativeSftp)
    onSession?.(sftp)
    return sftp
  }

  /**
   * Record the end of the connection once and notify every listener once.
   *
   * Every event maps to the same Paratix text (issue #257, decision 4),
   * including `reason: "local"` from our own `close()`/`destroy()`: the ssh2
   * adapter reports its own teardown as `DISCONNECTED` too, and `ssh.ts`
   * unsubscribes before it tears a connection down.
   *
   * @param event - The binding's disconnect event.
   */
  private disconnect(event: DisconnectEvent): void {
    if (this.disconnected !== undefined) return
    const code = isTransportErrorCode(event.code) ? event.code : "DISCONNECTED"
    const error = new TransportError(code, new Error("SSH connection closed unexpectedly"))
    this.disconnected = error
    const listeners = [...this.listeners]
    this.listeners.clear()
    notifyAll(listeners, error)
  }

  private requireSession(operation: string): Session {
    if (this.session === undefined) throw notConnected(operation)
    return this.session
  }
}

/**
 * Create the native transport for one connection attempt.
 *
 * Inactive in this release: nothing in Paratix selects it yet (issue #257, PR 1).
 *
 * @returns A stateful transport whose `connect` resolves with the object itself.
 */
export function createNativeTransport(): Transport & TransportConnection {
  return new NativeConnection()
}
