"use strict"

// Error mapping of the binding. Native errors arrive as `CODE|detail|message`;
// anything else (a panic text, an unknown code, a non-Error value) becomes
// INTERNAL with a fixed message and the original text is discarded.

const { constants: osConstants } = require("node:os")

/**
 * @typedef {Error & {
 *   code: string,
 *   detail?: string,
 *   errno?: number,
 *   syscallCode?: string,
 *   sftpStatus?: number,
 * }} BindingError
 */

const ERROR_CODES = Object.freeze([
  "AUTH_FAILED",
  "HOST_KEY_REJECTED",
  "TIMEOUT",
  "ABORTED",
  "CONNECT_FAILED",
  "PROTOCOL",
  "CHANNEL_OPEN_FAILED",
  "DISCONNECTED",
  "SFTP_STATUS",
  "UNSUPPORTED_KEY",
  "ENCRYPTED_KEY",
  "INTERNAL",
])

const KNOWN_CODES = new Set(ERROR_CODES)

const INTERNAL_MESSAGE = "internal error in the native SSH binding"

const NATIVE_REASON = /^(?<code>[A-Z_]+)\|(?<detail>[^\|]*)\|(?<message>.*)$/sv

const DIGITS = /^\d+$/v

/** @type {Map<number, string>} */
const ERRNO_NAMES = new Map(Object.entries(osConstants.errno).map(([name, value]) => [value, name]))

/**
 * Creates an Error with a code of the binding's set.
 *
 * @param code one of ERROR_CODES
 * @param message secret-free message
 * @param [detail] machine-readable detail
 * @returns an Error with `code` and the matching detail fields
 */
function createError(code, message, detail) {
  const error = /** @type {BindingError} */ (new Error(message))
  error.code = code
  if (detail) error.detail = detail
  const numeric = detail !== undefined && DIGITS.test(detail) ? Number(detail) : undefined
  if (code === "CONNECT_FAILED" && numeric !== undefined) {
    error.errno = numeric
    error.syscallCode = ERRNO_NAMES.get(numeric)
  }
  if (code === "SFTP_STATUS" && numeric !== undefined) error.sftpStatus = numeric
  return error
}

/**
 * @returns INTERNAL with the fixed message
 */
function internalError() {
  return createError("INTERNAL", INTERNAL_MESSAGE)
}

/**
 * Maps a native rejection to an Error with `.code`.
 *
 * @param raw what the native call threw or rejected with
 * @returns the mapped error
 */
function toError(raw) {
  const text = raw instanceof Error ? raw.message : undefined
  const groups = text === undefined ? undefined : NATIVE_REASON.exec(text)?.groups
  if (!groups || !KNOWN_CODES.has(groups.code) || groups.code === "INTERNAL") {
    return internalError()
  }
  return createError(groups.code, groups.message, groups.detail)
}

/**
 * Awaits a native promise factory, mapping both sync throws and rejections.
 *
 * @template T
 * @param factory starts the native call
 * @returns the native result
 */
async function callNative(factory) {
  try {
    return await factory()
  } catch (error) {
    throw toError(error)
  }
}

/**
 * Calls a synchronous native function, mapping a throw.
 *
 * @template T
 * @param call invokes one synchronous native function
 * @returns the native return value
 */
function callNativeSync(call) {
  try {
    return call()
  } catch (error) {
    throw toError(error)
  }
}

/**
 * @returns the error for an AbortSignal or cancel() (code ABORTED)
 */
function abortedError() {
  return createError("ABORTED", "the SSH operation was aborted")
}

/**
 * @returns the error for a call on a closed connection (code DISCONNECTED)
 */
function disconnectedError() {
  return createError("DISCONNECTED", "the SSH connection is closed")
}

module.exports = {
  abortedError,
  callNative,
  callNativeSync,
  createError,
  disconnectedError,
  ERROR_CODES,
  INTERNAL_MESSAGE,
  internalError,
  toError,
}
