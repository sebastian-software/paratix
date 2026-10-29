"use strict"

// `connect()`: argument checks, secret zero-filling, the host-key verifier
// bridge and the mapping of the native result to a Session.

const { abortedError, callNative, callNativeSync } = require("./errors.js")
const native = require("./native.js")
const { linkAbort, Session } = require("./session.js")
const { checkConnectArguments } = require("./validate.js")

const DEFAULT_READY_TIMEOUT_MS = 20_000

/** @typedef {import("./exec.js").DisconnectInfo} DisconnectInfo */
/** @typedef {InstanceType<typeof Session>} SessionInstance */

/**
 * Per-connect state shared by the verifier, the disconnect listener and
 * `connect()` itself.
 */
class ConnectAttempt {
  /** @type {{ handle: unknown, release: () => void } | null} */
  abort = null
  /** @type {DisconnectInfo | null} */
  pendingDisconnect = null
  /**
   * Verdict promises handed to native code, held until they settle: napi
   * keeps no strong reference to them, and a collected pending verdict would
   * end the verification early.
   *
   * @type {Set<Promise<boolean>>}
   */
  pendingVerdicts = new Set()
  /** @type {SessionInstance | null} */
  session = null
  settled = false
  /** @type {{ error: unknown } | null} */
  thrown = null

  /** @param verifyHost the caller's verifier */
  constructor(verifyHost) {
    this.verifyHost = verifyHost
  }

  /** Marks the attempt settled; a late verdict is discarded from now on. */
  finish() {
    this.settled = true
    this.abort?.release()
  }

  /**
   * The native disconnect listener; never throws into native code.
   *
   * @param event `{ reason, code? }` from the native session task
   */
  onDisconnect = (event) => {
    try {
      if (this.session === null) this.pendingDisconnect ??= event
      else this.session.reportDisconnect(event)
    } catch {
      // Never throw into native code.
    }
  }

  /**
   * What `connect()` rejects with: the verifier's own thrown value if the
   * host key was rejected because the verifier threw.
   *
   * @param error the mapped native error
   * @returns the rejection value
   */
  rejection(error) {
    const code = /** @type {{ code?: string }} */ (error).code
    return code === "HOST_KEY_REJECTED" && this.thrown !== null ? this.thrown.error : error
  }

  /**
   * Validates the arguments and starts the native connect. Zero-fills the
   * caller's secrets in every path: the native side copied them synchronously.
   *
   * @param options the caller's options, validated here
   * @returns the pending native session
   */
  start(options) {
    const secrets = [options?.privateKey, options?.password].filter((value) =>
      Buffer.isBuffer(value)
    )
    try {
      checkConnectArguments(options, this.verifyHost, DEFAULT_READY_TIMEOUT_MS)
      if (options.signal?.aborted) throw abortedError()
      this.abort = linkAbort(options.signal)
      return callNativeSync(() => this.#nativeConnect(options))
    } catch (error) {
      this.finish()
      throw error
    } finally {
      for (const secret of secrets) secret.fill(0)
    }
  }

  /**
   * The host-key verifier handed to native code. Only a verdict of exactly
   * `true` accepts; a thrown or rejected value is remembered so `connect()`
   * can reject with that very object. Once `connect()` settled, a late
   * verdict is discarded.
   *
   * @param info the presented host key
   * @returns the verdict
   */
  verify = (info) => {
    const verdict = this.#decide(info)
    this.pendingVerdicts.add(verdict)
    verdict.then(() => this.pendingVerdicts.delete(verdict))
    return verdict
  }

  /**
   * @param info the presented host key
   * @returns resolves with the verdict; never rejects
   */
  async #decide(info) {
    if (this.settled) return false
    try {
      const verdict = await this.verifyHost(info)
      return !this.settled && verdict === true
    } catch (error) {
      if (!this.settled) this.thrown = { error }
      return false
    }
  }

  /**
   * @param options validated connect options
   * @returns the pending native session
   */
  #nativeConnect(options) {
    return native.connect(
      options.host,
      options.port,
      options.user,
      options.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS,
      options.agent ?? null,
      options.privateKey ?? null,
      options.password ?? null,
      options.agentForward === true,
      this.verify,
      this.onDisconnect,
      /** @type {{ handle: unknown }} */ (this.abort).handle
    )
  }
}

/**
 * Wraps the native session; if that fails, the native connection is
 * destroyed so it does not stay open without an owner.
 *
 * @param nativeSession the native handle
 * @param pendingDisconnect a disconnect that arrived before the wrapper existed
 * @returns the wrapper
 */
function createSession(nativeSession, pendingDisconnect) {
  try {
    return new Session(nativeSession, pendingDisconnect)
  } catch (error) {
    try {
      native.sessionDestroy(nativeSession)
    } catch {
      // Best effort: the original error is what matters.
    }
    throw error
  }
}

/**
 * Connects and authenticates.
 *
 * @param options host, port, user, credentials, timeout, signal
 * @param verifyHost host-key verifier; only `true` accepts
 * @returns the session
 */
async function connect(options, verifyHost) {
  const attempt = new ConnectAttempt(verifyHost)
  const pending = attempt.start(options)
  try {
    const nativeSession = await callNative(() => pending)
    const session = createSession(nativeSession, attempt.pendingDisconnect)
    attempt.session = session
    return session
  } catch (error) {
    throw attempt.rejection(error)
  } finally {
    attempt.finish()
  }
}

module.exports = { connect }
