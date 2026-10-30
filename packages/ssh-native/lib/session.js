"use strict"

// `scan()` and the Session class; `connect()` lives in connect.js.

const {
  abortedError,
  callNative,
  callNativeSync,
  disconnectedError,
  toError,
} = require("./errors.js")
const { ExecChannelImpl } = require("./exec.js")
const native = require("./native.js")
const { SftpSession } = require("./sftp.js")
const { checkExecArguments, checkHostPort, checkSignal, checkTimeout } = require("./validate.js")

const DEFAULT_SCAN_TIMEOUT_MS = 10_000

/** @typedef {import("./exec.js").DisconnectInfo} DisconnectInfo */
/** @typedef {InstanceType<typeof ExecChannelImpl>} Channel */
/** @typedef {InstanceType<typeof SftpSession>} Sftp */

/**
 * A throwing listener surfaces like a throwing EventEmitter listener, without
 * breaking the binding's own bookkeeping.
 *
 * @param error what the listener threw
 */
function rethrowLater(error) {
  process.nextTick(() => {
    throw error
  })
}

/**
 * Wires an optional AbortSignal to a native abort handle.
 *
 * @param signal the caller's signal
 * @returns the handle and its cleanup
 */
function linkAbort(signal) {
  const handle = callNativeSync(() => native.abortHandleCreate())
  if (signal === undefined) return { handle, release() {} }
  const onAbort = () => {
    try {
      native.abortHandleFire(handle)
    } catch {
      // An abort listener must not throw; the operation ends on its own.
    }
  }
  signal.addEventListener("abort", onAbort, { once: true })
  return { handle, release: () => signal.removeEventListener("abort", onAbort) }
}

/**
 * Handshake without login.
 *
 * @param options target and deadline
 * @returns the presented host key
 */
async function scan(options) {
  const { host, port, signal, timeoutMs = DEFAULT_SCAN_TIMEOUT_MS } = options ?? {}
  checkHostPort(host, port)
  checkTimeout("timeoutMs", timeoutMs)
  checkSignal(signal)
  if (signal?.aborted) throw abortedError()
  const abort = linkAbort(signal)
  try {
    return await callNative(() => native.scan(host, port, timeoutMs, abort.handle))
  } finally {
    abort.release()
  }
}

/**
 * The public view of an exec channel.
 *
 * @param channel the internal channel object
 * @returns a frozen object with stdout, stderr, stdin, exit, cancel and close
 */
function publicChannel(channel) {
  return Object.freeze({
    cancel: () => channel.cancel(),
    close: () => channel.close(),
    exit: channel.exit,
    stderr: channel.stderr,
    stdin: channel.stdin,
    stdout: channel.stdout,
  })
}

/**
 * Cancels `channel` when `signal` aborts, until the channel ended.
 *
 * @param channel the running channel
 * @param signal the caller's signal
 */
function cancelOnAbort(channel, signal) {
  if (signal === undefined) return
  const onAbort = () => channel.cancel()
  signal.addEventListener("abort", onAbort, { once: true })
  channel.exit.finally(() => signal.removeEventListener("abort", onAbort)).catch(() => {})
  if (signal.aborted) channel.cancel()
}

const EXEC_API = Object.freeze({
  ack: (/** @type {unknown} */ channel, /** @type {number} */ bytes) =>
    native.execAckStdout(channel, bytes),
  cancel: (/** @type {unknown} */ channel) => native.execCancel(channel),
  close: (/** @type {unknown} */ channel) => native.execClose(channel),
  end: (/** @type {unknown} */ channel) => native.execEnd(channel),
  write: (/** @type {unknown} */ channel, /** @type {Buffer} */ chunk) =>
    native.execWrite(channel, chunk),
})

class Session {
  /** @type {unknown} */
  authInfo

  /** @returns whether the connection is gone */
  get closed() {
    return this.#disconnect !== null || callNativeSync(() => native.sessionClosed(this.#native))
  }
  /** @type {Set<Channel>} */
  #channels = new Set()
  /** @type {Readonly<DisconnectInfo> | null} */
  #disconnect = null
  /** @type {Set<(event: DisconnectInfo) => void>} */
  #listeners = new Set()

  #native

  /**
   * @param nativeSession the native handle
   * @param pendingDisconnect a disconnect that arrived before
   */
  constructor(nativeSession, pendingDisconnect) {
    this.#native = nativeSession
    this.authInfo = callNativeSync(() => native.sessionAuthInfo(nativeSession))
    if (pendingDisconnect) this.reportDisconnect(pendingDisconnect)
  }

  /**
   * Diagnostics: server-opened channels this client rejected or bridged.
   *
   * @returns the channel statistics
   */
  channelStats() {
    return callNativeSync(() => native.sessionChannelStats(this.#native))
  }

  /**
   * Graceful close. The native readers deliver each open channel's
   * remaining data and then its disconnected exit, in order, through the
   * channel's own event queue; ending channels here would race that queue.
   *
   * @returns resolves once the connection is gone
   */
  async close() {
    try {
      await callNative(() => native.sessionClose(this.#native))
    } finally {
      this.reportDisconnect({ reason: "local" })
    }
  }

  /**
   * Synchronous hard stop, safe right before `process.exit()`: shuts the
   * socket down and releases the event loop. Open exec channels end with a
   * disconnected exit right away; the remote command keeps running.
   */
  destroy() {
    try {
      native.sessionDestroy(this.#native)
    } catch (error) {
      throw toError(error)
    } finally {
      this.#endChannels()
    }
  }

  /**
   * Runs `command` without a PTY.
   *
   * @param command the command line
   * @param [options] initial stdin and cancellation
   * @returns the channel
   */
  async exec(command, options = {}) {
    const { signal, stdin } = options
    this.#checkExec(command, stdin, signal)
    const channel = this.#createChannel()
    const abort = linkAbort(signal)
    try {
      const nativeChannel = await this.#openChannel(channel, {
        abort: abort.handle,
        command,
        stdin,
      })
      channel.attach(nativeChannel)
    } catch (error) {
      this.#channels.delete(channel)
      throw error
    } finally {
      abort.release()
    }
    cancelOnAbort(channel, signal)
    return publicChannel(channel)
  }

  /**
   * Subscribes to the end of the connection; fires exactly once.
   *
   * @param listener called with the disconnect event
   * @returns unsubscribes
   */
  onDisconnect(listener) {
    if (typeof listener !== "function") throw new TypeError("listener must be a function")
    const event = this.#disconnect
    if (event !== null) {
      const late = setImmediate(() => {
        try {
          listener(event)
        } catch (error) {
          rethrowLater(error)
        }
      })
      // Unsubscribing before the late notification ran cancels it.
      return () => clearImmediate(late)
    }
    // A fresh wrapper per subscription, so unsubscribing removes exactly it.
    const entry = (info) => listener(info)
    this.#listeners.add(entry)
    return () => {
      this.#listeners.delete(entry)
    }
  }

  /**
   * Records the end of the connection (idempotent); internal.
   *
   * @param event `{ reason, code? }`; only the first call counts
   */
  reportDisconnect(event) {
    if (this.#disconnect !== null) return
    /** @type {DisconnectInfo} */
    const info = { reason: event.reason }
    if (typeof event.code === "string") info.code = event.code
    const frozen = Object.freeze(info)
    this.#disconnect = frozen
    const listeners = [...this.#listeners]
    this.#listeners.clear()
    for (const listener of listeners) {
      try {
        listener(frozen)
      } catch (error) {
        rethrowLater(error)
      }
    }
  }

  /**
   * Opens an SFTP subsystem channel.
   *
   * @returns streams over one SFTP subsystem channel
   */
  async sftp() {
    if (this.#disconnect !== null) throw disconnectedError()
    const handle = await callNative(() => native.sessionSftp(this.#native))
    return new SftpSession(handle)
  }

  /**
   * Validates `exec()` arguments; zero-fills `stdin` if they are rejected.
   *
   * @param command the command line
   * @param stdin optional initial stdin
   * @param signal optional AbortSignal
   */
  #checkExec(command, stdin, signal) {
    try {
      checkExecArguments(command, stdin, signal)
      if (signal?.aborted) throw abortedError()
      if (this.#disconnect !== null) throw disconnectedError()
    } catch (error) {
      if (Buffer.isBuffer(stdin)) stdin.fill(0)
      throw error
    }
  }

  /** @returns a channel registered with this session */
  #createChannel() {
    const channel = new ExecChannelImpl(EXEC_API, {
      onDisconnect: (event) => this.reportDisconnect(event),
      onFinish: () => this.#channels.delete(channel),
    })
    this.#channels.add(channel)
    return channel
  }

  /**
   * Reports the local disconnect and ends the channels that are still open
   * with a disconnected exit (the disconnect comes first).
   */
  #endChannels() {
    // Only for destroy(): the event loop may stop right after it.
    this.reportDisconnect({ reason: "local" })
    const event = /** @type {DisconnectInfo} */ (this.#disconnect)
    for (const channel of this.#channels) channel.finishDisconnected(event)
  }

  /**
   * @param channel receives the native events
   * @param request command line, initial stdin (zero-filled here) and native abort handle
   * @returns the native channel
   */
  async #openChannel(channel, request) {
    const { abort, command, stdin } = request
    let pending
    try {
      pending = callNativeSync(() =>
        native.sessionExec(this.#native, command, stdin ?? null, abort, channel.handleEvent)
      )
    } finally {
      // The native side copied stdin synchronously.
      stdin?.fill(0)
    }
    return callNative(() => pending)
  }
}

module.exports = { linkAbort, scan, Session }
