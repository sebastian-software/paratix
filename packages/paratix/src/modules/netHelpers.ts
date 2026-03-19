import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

/** Wait-for condition and timing options. */
export type WaitForOptions = {
  /** String that must appear in `file` for the condition to be satisfied. Requires `file`. */
  contains?: string
  /** Absolute path to a file whose existence (or content) is checked. */
  file?: string
  /** Host address used for port checks (default: `"127.0.0.1"`). */
  host?: string
  /** Poll interval in milliseconds between condition checks (default: `2000`). */
  interval?: number
  /** TCP port to probe with `nc -z`. */
  port?: number
  /** Maximum time in milliseconds to wait before failing (default: `60000`). */
  timeout?: number
}

/** Precomputed curl command parts for an HTTP request check. */
export type HttpCheckParameters = {
  /** Expected substring in the response body, or `undefined` to skip body verification. */
  expectedBody: string | undefined
  /** HTTP status code the response must return (e.g. `200`). */
  expectedStatus: number
  /** Pre-built `-H` curl flags string with trailing space, or empty string. */
  headerFlags: string
  /** Pre-built `-X METHOD ` curl flag string with trailing space, or empty string for GET. */
  methodFlag: string
  /** The URL to request. */
  url: string
}

/**
 * Build the shell command used to test a wait-for condition.
 *
 * @param options - The wait-for condition options.
 * @param host - The resolved host address for port checks.
 * @returns The shell test command string.
 */
export function buildWaitForTestCommand(options: WaitForOptions, host: string): string {
  if (options.port != null) {
    return `nc -z ${shellQuote(host)} ${shellQuote(String(options.port))}`
  }
  if (options.file != null && options.contains != null) {
    return `grep -q ${shellQuote(options.contains)} ${shellQuote(options.file)}`
  }
  if (options.file != null) {
    return `test -f ${shellQuote(options.file)}`
  }
  throw new Error("net.waitFor requires either port or file option")
}

/**
 * Build the display name for a wait-for module instance.
 *
 * @param options - The wait-for condition options.
 * @returns The formatted module display name.
 */
export function buildWaitForName(options: WaitForOptions): string {
  if (options.port != null) return `net.waitFor: port ${options.port}`
  if (options.file != null && options.contains != null) {
    return `net.waitFor: ${options.file} contains ${options.contains}`
  }
  if (options.file != null) return `net.waitFor: file ${options.file}`
  return "net.waitFor"
}

/** Last ASCII control character (U+001F). */
const LAST_CONTROL_CHAR = 0x1f
/** ASCII DEL character (U+007F). */
const DEL_CHAR = 0x7f

/**
 * Check whether a string is a valid HTTP header name per RFC 7230 (token chars).
 * Rejects control characters, DEL, colons, and any non-printable ASCII.
 *
 * @param name - The header name to validate.
 * @returns `true` if the name contains only valid token characters, `false` otherwise.
 */
export function isValidHeaderName(name: string): boolean {
  for (let index = 0; index < name.length; index++) {
    const code = name.charCodeAt(index)
    if (code <= LAST_CONTROL_CHAR || code >= DEL_CHAR || name[index] === ":") return false
  }
  return name.length > 0
}

/**
 * Check whether a string is safe to use as an HTTP header value.
 * Rejects values containing CR, LF, or null bytes to prevent HTTP header injection.
 *
 * @param value - The header value to validate.
 * @returns `true` if the value contains no newline characters, `false` otherwise.
 */
export function isValidHeaderValue(value: string): boolean {
  return !value.includes("\r") && !value.includes("\n") && !value.includes("\0")
}

/**
 * Build curl `-H` flags from a headers record for use in shell commands.
 * Validates header names and values to prevent HTTP header injection.
 *
 * @param headers - The HTTP headers to convert into curl flags.
 * @returns The formatted curl header flags string with trailing space, or empty string.
 */
export function buildCurlHeaderFlags(headers: Record<string, string>): string {
  const flags = Object.entries(headers)
    .map(([name, value]) => {
      if (!isValidHeaderName(name)) {
        throw new Error(`Invalid HTTP header name: ${name}`)
      }
      if (!isValidHeaderValue(value)) {
        throw new Error(`Invalid HTTP header value for ${name}: value contains newline characters`)
      }
      const header = `${name}: ${value}`
      return `-H ${shellQuote(header)}`
    })
    .join(" ")
  return flags.length > 0 ? `${flags} ` : ""
}

/**
 * Check whether an HTTP endpoint matches the expected status code and body content.
 *
 * @param conn - Active SSH connection to execute curl commands on.
 * @param parameters - Precomputed request parameters including URL and expectations.
 * @returns `true` if the endpoint matches all expectations.
 */
export async function checkHttpCondition(
  conn: SshConnection,
  parameters: HttpCheckParameters
): Promise<boolean> {
  try {
    const statusCommand = `curl -s -o /dev/null -w '%{http_code}' ${parameters.methodFlag}${parameters.headerFlags}${shellQuote(parameters.url)}`
    const statusOutput = await conn.output(statusCommand)
    if (statusOutput.trim() !== String(parameters.expectedStatus)) return false

    if (parameters.expectedBody != null) {
      const bodyCommand = `curl -s ${parameters.methodFlag}${parameters.headerFlags}${shellQuote(parameters.url)}`
      const bodyOutput = await conn.output(bodyCommand)
      if (!bodyOutput.includes(parameters.expectedBody)) return false
    }

    return true
  } catch {
    return false
  }
}

/**
 * Validate that a URL string is a well-formed HTTPS URL by default.
 * HTTP can be allowed explicitly via `allowHttp`.
 *
 * @param url - The URL string to validate.
 * @param options - Validation options.
 * @param options.allowHttp - When `true`, also allow `http://` URLs.
 * @throws {Error} If the URL is malformed or the scheme is not allowed.
 */
export function validateHttpUrl(url: string, options?: { allowHttp?: boolean }): void {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new Error(`Invalid URL '${url}': expected an http or https URL`)
  }
  if (parsed.protocol === "https:") return
  if (parsed.protocol === "http:" && options?.allowHttp === true) return
  if (parsed.protocol === "http:") {
    throw new Error(`Insecure URL scheme 'http' in '${url}': only https is allowed by default`)
  }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `Unsupported URL scheme '${parsed.protocol.replace(/:$/v, "")}' in '${url}': only http and https are allowed`
    )
  }
}

/**
 * Create a delay promise for use in polling loops.
 *
 * @param ms - The delay duration in milliseconds.
 * @returns A promise that resolves after the specified delay.
 */
export async function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}
