"use strict"

// JS side of an exec channel: stdout with backpressure, stderr, stdin and the
// exit promise. Native events arrive in channel order through one callback:
// stdout/stderr data, then exactly one exit (or one `internal` event after a
// panic in the native reader).

const { Readable, Writable } = require("node:stream")

const { abortedError, callNative, createError, internalError, toError } = require("./errors.js")

/** highWaterMark of the stdout Readable; part of the backpressure bound. */
const STDOUT_HIGH_WATER_MARK = 64 * 1024

/**
 * @typedef {object} ExecExit
 * @property {number | null} code exit status
 * @property {string | null} signal raw signal name, e.g. `TERM`
 * @property {boolean} disconnected whether the connection was lost
 */

/**
 * @typedef {object} DisconnectInfo
 * @property {string} reason `remote`, `local` or `error`
 * @property {string} [code] error code for `error`
 */

/**
 * Native functions of one channel; `channel` is the native handle.
 *
 * @typedef {object} ExecApi
 * @property {(channel: unknown, bytes: number) => void} ack acknowledges stdout
 * @property {(channel: unknown, chunk: Buffer) => Promise<void>} write writes stdin
 * @property {(channel: unknown) => Promise<void>} end sends EOF
 * @property {(channel: unknown) => Promise<void>} close sends CHANNEL_CLOSE
 * @property {(channel: unknown) => void} cancel stops the native reader
 */

/**
 * @typedef {object} ExecHooks
 * @property {(event: DisconnectInfo) => void} [onDisconnect] reports the session disconnect
 * @property {() => void} [onFinish] runs once when the channel ended
 */

/**
 * @typedef {object} NativeEvent
 * @property {string} [kind] `stdout`, `stderr`, `exit` or `internal`
 * @property {Buffer} [data] stdout/stderr data
 * @property {number} [code] exit status
 * @property {string} [signal] exit signal
 * @property {boolean} [disconnected] the channel ended with the connection
 * @property {string} [reason] disconnect reason
 * @property {string} [reasonCode] disconnect error code
 */

function ignore() {
  // Stream errors also reach the caller through `exit`; this sink keeps an
  // unobserved stream error from becoming an uncaught exception.
}

/**
 * A deferred whose rejection is pre-handled: a rejected exit never becomes
 * an unhandledRejection on its own; a caller awaiting it still sees it.
 *
 * @returns the promise with its resolve and reject functions
 */
function preHandledDeferred() {
  /** @type {PromiseWithResolvers<ExecExit>} */
  const deferred = Promise.withResolvers()
  deferred.promise.catch(ignore)
  return deferred
}

/**
 * Runs a native promise factory and reports the outcome to a stream callback.
 *
 * @param start starts the native call
 * @param callback the stream callback
 */
function settle(start, callback) {
  let pending
  try {
    pending = start()
  } catch (error) {
    callback(toError(error))
    return
  }
  Promise.resolve(pending).then(
    () => callback(),
    (error) => callback(toError(error))
  )
}

/**
 * stdin that zero-fills every Buffer written to it in every path: once the
 * binding copied it, immediately when the stream no longer accepts data,
 * and on destroy for chunks still queued.
 */
class StdinWritable extends Writable {
  /** @type {Set<Uint8Array>} */
  #pending = new Set()

  /**
   * @param options `write` and `final` for the underlying Writable
   */
  constructor(options) {
    super({
      ...options,
      destroy: (error, callback) => {
        for (const chunk of this.#pending) chunk.fill(0)
        this.#pending.clear()
        callback(error)
      },
    })
  }

  /**
   * @param chunk data to end with (optional)
   * @param args encoding and callback, as for Writable
   * @returns this stream
   */
  end(chunk, ...args) {
    this.#track(chunk)
    return super.end(chunk, ...args)
  }

  /**
   * Zero-fills a chunk and forgets it.
   *
   * @param chunk a chunk the binding has taken or refused
   */
  wipe(chunk) {
    if (chunk instanceof Uint8Array) chunk.fill(0)
    this.#pending.delete(chunk)
  }

  /**
   * @param chunk data to write
   * @param args encoding and callback, as for Writable
   * @returns whether more data may be written now
   */
  write(chunk, ...args) {
    this.#track(chunk)
    return super.write(chunk, ...args)
  }

  /** @param chunk a chunk handed to `write()` or `end()` */
  #track(chunk) {
    if (!(chunk instanceof Uint8Array)) return
    if (this.destroyed || this.writableEnded) chunk.fill(0)
    else this.#pending.add(chunk)
  }
}

class ExecChannelImpl {
  /** @type {Promise<ExecExit>} */
  exit
  /** @type {Readable} */
  stderr
  /** @type {StdinWritable} */
  stdin
  /** @type {Readable} */
  stdout

  #api
  #attached = false
  /** @type {unknown} */
  #channel = null
  #finished = false
  #hooks
  #preAttachAck = 0
  /** @type {(error: Error) => void} */
  #rejectExit = ignore
  /** @type {(exit: ExecExit) => void} */
  #resolveExit = ignore
  #unacked = 0

  /**
   * @param api native functions of the channel
   * @param [hooks] session callbacks
   */
  constructor(api, hooks = {}) {
    this.#api = api
    this.#hooks = hooks
    const exit = preHandledDeferred()
    this.exit = exit.promise
    this.#resolveExit = exit.resolve
    this.#rejectExit = exit.reject
    this.stdout = new Readable({
      // A destroyed stdout (early exit from an async iterator, a failed
      // pipeline, an explicit destroy) releases its outstanding credit;
      // later stdout is acknowledged on arrival. Otherwise the native reader
      // and the whole connection would stay stalled.
      destroy: (error, callback) => {
        this.#flushAck()
        callback(error)
      },
      highWaterMark: STDOUT_HIGH_WATER_MARK,
      read: () => this.#flushAck(),
    })
    // stderr is unbounded: data is always taken, so an unread stderr never
    // blocks stdout or the exit.
    this.stderr = new Readable({ read: ignore })
    this.stdin = new StdinWritable({
      final: (callback) => settle(() => this.#api.end(this.#channel), callback),
      write: (chunk, _encoding, callback) => this.#writeStdin(chunk, callback),
    })
    this.stdout.on("error", ignore)
    this.stderr.on("error", ignore)
    this.stdin.on("error", ignore)
  }

  /**
   * Attaches the native channel once `exec()` resolved.
   *
   * @param channel the native handle
   */
  attach(channel) {
    this.#channel = channel
    this.#attached = true
    if (this.#preAttachAck > 0) {
      const bytes = this.#preAttachAck
      this.#preAttachAck = 0
      this.#ack(bytes)
    }
  }

  /** Stops the channel: streams end with ABORTED and `exit` rejects. */
  cancel() {
    if (this.#finished) return
    if (this.#attached) this.#guard(() => this.#api.cancel(this.#channel))
    this.#fail(abortedError())
  }

  /**
   * Sends CHANNEL_CLOSE; the exit follows once the server confirms.
   *
   * @returns resolves once the request was sent
   */
  async close() {
    if (this.#finished || !this.#attached) return
    await callNative(() => this.#api.close(this.#channel))
  }

  /**
   * Ends the channel because the connection is gone (disconnect first).
   *
   * @param event the session disconnect
   */
  finishDisconnected(event) {
    if (this.#finished) return
    this.#hooks.onDisconnect?.(event)
    this.#complete({ code: null, disconnected: true, signal: null })
  }

  /**
   * The native listener; never throws (a throw would be fatal in Node).
   *
   * @param event one native event
   */
  handleEvent = (event) => {
    try {
      this.#dispatch(event)
    } catch {
      this.#fail(internalError())
    }
  }

  /** @param bytes stdout bytes the Readable took */
  #ack(bytes) {
    if (!this.#attached) {
      this.#preAttachAck += bytes
      return
    }
    this.#guard(() => this.#api.ack(this.#channel, bytes))
  }

  /** @param result the exit to report */
  #complete(result) {
    this.#finished = true
    this.stdout.push(null)
    this.stderr.push(null)
    this.stdin.destroy()
    this.#resolveExit(result)
    this.#hooks.onFinish?.()
  }

  /** @param event one native event */
  #dispatch(event) {
    if (this.#finished) {
      // Late stdout after a failure: keep the native reader going.
      if (event?.kind === "stdout" && event.data) this.#ack(event.data.length)
      return
    }
    switch (event?.kind) {
      case "exit": {
        this.#onExit(event)
        break
      }
      case "stderr": {
        this.stderr.push(event.data)
        break
      }
      case "stdout": {
        this.#onStdout(/** @type {Buffer} */ (event.data))
        break
      }
      default: {
        // `internal`, a malformed event or an unknown kind.
        this.#fail(internalError())
      }
    }
  }

  /** @param error why the channel failed */
  #fail(error) {
    if (this.#finished) return
    this.#finished = true
    // Stop the native reader too; it would otherwise wait for credit.
    if (this.#attached) {
      try {
        this.#api.cancel(this.#channel)
      } catch {
        // Already ended.
      }
    }
    this.stdout.destroy(error)
    this.stderr.destroy(error)
    this.stdin.destroy(error)
    this.#rejectExit(error)
    this.#hooks.onFinish?.()
  }

  #flushAck() {
    if (this.#unacked === 0) return
    const bytes = this.#unacked
    this.#unacked = 0
    this.#ack(bytes)
  }

  /** @param call a synchronous native call */
  #guard(call) {
    try {
      call()
    } catch {
      this.#fail(internalError())
    }
  }

  /** @param event the exit event */
  #onExit(event) {
    if (event.disconnected === true) {
      /** @type {DisconnectInfo} */
      const info = { reason: event.reason ?? "error" }
      if (typeof event.reasonCode === "string") info.code = event.reasonCode
      this.finishDisconnected(info)
      return
    }
    this.#complete({
      code: typeof event.code === "number" ? event.code : null,
      disconnected: false,
      signal: typeof event.signal === "string" ? event.signal : null,
    })
  }

  /** @param data stdout data */
  #onStdout(data) {
    if (this.stdout.destroyed) {
      // Nobody reads any more: keep the native reader going.
      this.#ack(data.length)
      return
    }
    if (this.stdout.push(data)) this.#ack(data.length)
    else this.#unacked += data.length
  }

  /**
   * @param chunk stdin data
   * @param callback the stream callback
   */
  #writeStdin(chunk, callback) {
    if (this.#finished || !this.#attached) {
      this.stdin.wipe(chunk)
      callback(createError("DISCONNECTED", "the exec channel is closed"))
      return
    }
    settle(() => {
      try {
        return this.#api.write(this.#channel, chunk)
      } finally {
        // The native side copied the chunk synchronously.
        this.stdin.wipe(chunk)
      }
    }, callback)
  }
}

module.exports = { ExecChannelImpl, STDOUT_HIGH_WATER_MARK }
