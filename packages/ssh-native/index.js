// THROWAWAY SPIKE (issue #254): hand-written loader and thin JS wrapper over
// the napi-rs binding. Evidence for ADR 0008, not production code.
"use strict"

const { EventEmitter } = require("node:events")
const { existsSync, readFileSync } = require("node:fs")
const { constants: osConstants } = require("node:os")
const { join } = require("node:path")
const { PassThrough, Writable } = require("node:stream")

const SUPPORTED_TARGETS = [
  "linux-x64-gnu",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-arm64-musl",
  "darwin-x64",
  "darwin-arm64",
]

function isMusl() {
  if (process.platform !== "linux") return false
  try {
    const report = process.report.getReport()
    if (report.header && report.header.glibcVersionRuntime) return false
    const shared = report.sharedObjects || []
    if (shared.some((file) => file.includes("libc.musl-") || file.includes("ld-musl-"))) return true
  } catch {
    // fall through to the ldd probe
  }
  try {
    return readFileSync("/usr/bin/ldd", "utf8").includes("musl")
  } catch {
    return false
  }
}

function currentTarget() {
  const { arch, platform } = process
  if (platform === "linux") return `linux-${arch}-${isMusl() ? "musl" : "gnu"}`
  return `${platform}-${arch}`
}

function loadBinding() {
  const override = process.env.PARATIX_SSH_NATIVE_PATH
  if (override) return require(override)
  const target = currentTarget()
  if (!SUPPORTED_TARGETS.includes(target)) {
    const libc = process.platform === "linux" ? (isMusl() ? "musl" : "glibc") : "n/a"
    throw new Error(
      `@paratix/ssh-native: unsupported platform ${process.platform}/${process.arch} (libc: ${libc}). ` +
        `Supported targets: ${SUPPORTED_TARGETS.join(", ")}. If this platform is listed, the optional ` +
        `platform package may have been omitted (e.g. a lockfile from another platform, npm/cli#4828).`
    )
  }
  const file = join(__dirname, `ssh-native.${target}.node`)
  if (!existsSync(file)) {
    throw new Error(`@paratix/ssh-native: native binary for ${target} not found at ${file}`)
  }
  return require(file)
}

const native = loadBinding()

const ERRNO_NAMES = Object.fromEntries(
  Object.entries(osConstants.errno).map(([name, value]) => [value, name])
)

/** Turns a native `CODE|detail|message` rejection into an Error with `.code`. */
function toError(raw) {
  const text = raw && typeof raw.message === "string" ? raw.message : String(raw)
  const match = /^([A-Z_]+)\|([^|]*)\|(.*)$/s.exec(text)
  if (!match) {
    const error = new Error(`native SSH binding failed: ${text}`)
    error.code = "INTERNAL"
    return error
  }
  const [, code, detail, message] = match
  const error = new Error(message)
  error.code = code
  if (detail) error.detail = detail
  if (code === "CONNECT_FAILED" && /^\d+$/.test(detail)) {
    error.errno = Number(detail)
    error.syscallCode = ERRNO_NAMES[Number(detail)]
  }
  if (code === "SFTP_STATUS") error.sftpStatus = /^\d+$/.test(detail) ? Number(detail) : undefined
  return error
}

async function call(promiseFactory) {
  try {
    return await promiseFactory()
  } catch (error) {
    throw toError(error)
  }
}

/** Handshake without authentication. */
function scan({ host, port, timeoutMs = 10_000, hostCertificates = false }) {
  return call(() => native.scan({ host, port, timeoutMs, hostCertificates }))
}

class Session extends EventEmitter {
  constructor(nativeSession, state) {
    super()
    this._native = nativeSession
    this._state = state
    this.authInfo = nativeSession.authInfo
  }

  get closed() {
    return this._state.disconnected !== null || this._native.closed
  }

  /** Server-initiated channels this client rejected, plus bridged agent channels. */
  channelStats() {
    return this._native.channelStats()
  }

  /**
   * @param {string} command
   * @returns {Promise<{ stdout: PassThrough, stderr: PassThrough, stdin: Writable, done: Promise<{code: number|null, signal: string|null, execRefused: boolean}>, close(): Promise<void> }>}
   */
  async exec(command) {
    const stdout = new PassThrough()
    const stderr = new PassThrough()
    let execRefused = false
    let resolveDone
    const done = new Promise((resolve) => {
      resolveDone = resolve
    })
    const onEvent = (event) => {
      switch (event.kind) {
        case "stdout":
          stdout.write(event.data)
          break
        case "stderr":
          stderr.write(event.data)
          break
        case "failure":
          execRefused = true
          break
        case "exit":
          stdout.end()
          stderr.end()
          resolveDone({ code: event.code ?? null, signal: event.signal ?? null, execRefused })
          break
        default:
          break
      }
    }
    const channel = await call(() => this._native.exec(command, onEvent))
    const stdin = new Writable({
      write(chunk, _encoding, callback) {
        channel.write(chunk).then(
          () => callback(),
          (error) => callback(toError(error))
        )
      },
      final(callback) {
        channel.end().then(
          () => callback(),
          (error) => callback(toError(error))
        )
      },
    })
    return { stdout, stderr, stdin, done, close: () => call(() => channel.close()) }
  }

  /**
   * Opens a remote file for writing through SFTP.
   * @returns {Promise<Writable & { bytesWritten?: number }>}
   */
  async sftpWrite(remotePath, { mode, highWaterMark = 64 * 1024 } = {}) {
    const writer = await call(() => this._native.sftpOpenWrite(remotePath, mode ?? null))
    const stream = new Writable({
      highWaterMark,
      write(chunk, _encoding, callback) {
        writer.write(chunk).then(
          () => callback(),
          (error) => callback(toError(error))
        )
      },
      final(callback) {
        writer.end().then(
          (bytes) => {
            stream.bytesWritten = bytes
            callback()
          },
          (error) => callback(toError(error))
        )
      },
    })
    return stream
  }

  /** Graceful close; resolves once the connection is gone. */
  async close() {
    await call(() => this._native.close())
  }

  /** Synchronous hard stop; safe right before `process.exit()`. */
  destroy() {
    this._native.destroy()
  }
}

/**
 * Connects and authenticates. `verifyHost(info)` is awaited; if it throws or
 * rejects, `connect` rejects with that very error object.
 */
async function connect(options, verifyHost) {
  const state = { remembered: null, disconnected: null, session: null }
  const verify = async (info) => {
    try {
      const verdict = await verifyHost(info)
      return verdict !== false
    } catch (error) {
      state.remembered = { error }
      return false
    }
  }
  const onDisconnect = (reason) => {
    state.disconnected = reason
    if (state.session) state.session.emit("disconnect", reason)
  }
  const nativeOptions = {
    host: options.host,
    port: options.port,
    user: options.user,
    readyTimeoutMs: options.readyTimeoutMs ?? 20_000,
    agentForward: options.agentForward === true,
    hostCertificates: options.hostCertificates === true,
  }
  let passwordBuffer
  if (options.agent) nativeOptions.agent = options.agent
  else if (options.privateKey) nativeOptions.privateKey = options.privateKey
  else if (options.password !== undefined) {
    passwordBuffer = Buffer.from(options.password, "utf8")
    nativeOptions.password = passwordBuffer
  }
  let pending
  try {
    pending = native.connect(nativeOptions, verify, onDisconnect)
  } catch (error) {
    throw toError(error)
  } finally {
    // Rust copied the secrets synchronously; clear the JS copies in every path.
    if (options.privateKey) options.privateKey.fill(0)
    if (passwordBuffer) passwordBuffer.fill(0)
  }
  let nativeSession
  try {
    nativeSession = await pending
  } catch (raw) {
    const error = toError(raw)
    if (error.code === "HOST_KEY_REJECTED" && state.remembered) throw state.remembered.error
    throw error
  }
  const session = new Session(nativeSession, state)
  state.session = session
  return session
}

module.exports = {
  connect,
  scan,
  cryptoBackend: () => native.cryptoBackend(),
  internalPanicProbe: () => call(() => native.internalPanicProbe()),
  SUPPORTED_TARGETS,
  currentTarget,
}
