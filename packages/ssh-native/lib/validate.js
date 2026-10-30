"use strict"

// Argument validation of the public API. Invalid arguments are programming
// errors and throw a TypeError (no binding error code).

const MAX_TIMEOUT_MS = 0xff_ff_ff_ff
const MAX_PORT = 65_535
const MAX_MODE = 0o7777

/**
 * @param value candidate
 * @returns whether it is a non-empty string
 */
function isNonEmptyString(value) {
  return typeof value === "string" && value !== ""
}

/**
 * @param value candidate
 * @param min smallest allowed value
 * @param max largest allowed value
 * @returns whether it is an integer in [min, max]
 */
function isIntegerBetween(value, min, max) {
  return Number.isInteger(value) && Number(value) >= min && Number(value) <= max
}

/**
 * @param host host name or address
 * @param port TCP port
 */
function checkHostPort(host, port) {
  if (!isNonEmptyString(host)) throw new TypeError("host must be a non-empty string")
  if (!isIntegerBetween(port, 1, MAX_PORT)) {
    throw new TypeError("port must be an integer between 1 and 65535")
  }
}

/**
 * @param name option name for the message
 * @param value timeout in milliseconds
 */
function checkTimeout(name, value) {
  if (!isIntegerBetween(value, 1, MAX_TIMEOUT_MS)) {
    throw new TypeError(`${name} must be a positive integer number of milliseconds`)
  }
}

/** @param signal optional AbortSignal */
function checkSignal(signal) {
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    throw new TypeError("signal must be an AbortSignal")
  }
}

/** @param path remote path */
function checkPath(path) {
  if (!isNonEmptyString(path)) throw new TypeError("remote path must be a non-empty string")
}

/** @param mode optional file mode */
function checkMode(mode) {
  if (mode !== undefined && !isIntegerBetween(mode, 0, MAX_MODE)) {
    throw new TypeError("mode must be an integer between 0 and 0o7777")
  }
}

/**
 * @param command the command line
 * @param stdin optional initial stdin
 * @param signal optional AbortSignal
 */
function checkExecArguments(command, stdin, signal) {
  if (typeof command !== "string") throw new TypeError("command must be a string")
  if (stdin !== undefined && !Buffer.isBuffer(stdin)) throw new TypeError("stdin must be a Buffer")
  checkSignal(signal)
}

/** @param options connect options */
function checkSecrets(options) {
  for (const name of ["privateKey", "password"]) {
    if (options[name] !== undefined && !Buffer.isBuffer(options[name])) {
      throw new TypeError(`${name} must be a Buffer`)
    }
  }
}

/** @param options connect options */
function checkAgent(options) {
  const { agent } = options
  if (agent !== undefined && !isNonEmptyString(agent)) {
    throw new TypeError("agent must be a non-empty socket path")
  }
  if (options.agentForward === true && agent === undefined) {
    throw new TypeError("agentForward requires an agent socket")
  }
  if (agent === undefined && options.privateKey === undefined && options.password === undefined) {
    throw new TypeError("one of agent, privateKey or password is required")
  }
}

/**
 * @param options must be an object with host, port, user and one credential
 * @param verifyHost must be a function
 * @param defaultReadyTimeoutMs used when `readyTimeoutMs` is absent
 */
function checkConnectArguments(options, verifyHost, defaultReadyTimeoutMs) {
  if (options === null || typeof options !== "object")
    throw new TypeError("options must be an object")
  const record = /** @type {Record<string, unknown>} */ (options)
  checkHostPort(record.host, record.port)
  if (!isNonEmptyString(record.user)) throw new TypeError("user must be a non-empty string")
  checkTimeout("readyTimeoutMs", record.readyTimeoutMs ?? defaultReadyTimeoutMs)
  checkSecrets(record)
  checkAgent(record)
  checkSignal(record.signal)
  if (typeof verifyHost !== "function") throw new TypeError("verifyHost must be a function")
}

module.exports = {
  checkConnectArguments,
  checkExecArguments,
  checkHostPort,
  checkMode,
  checkPath,
  checkSignal,
  checkTimeout,
}
