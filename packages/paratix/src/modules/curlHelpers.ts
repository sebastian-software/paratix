import { shellQuote } from "../ssh.js"

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
 * Check whether the given URL's query string carries sensitive material such
 * as presigned tokens, signatures, or credentials.
 *
 * @param url - The parsed URL to inspect.
 * @returns `true` when at least one query parameter name looks sensitive.
 */
export function hasSensitiveQueryParameters(url: URL): boolean {
  const sensitiveTokens = new Set([
    "auth",
    "credential",
    "key",
    "passwd",
    "password",
    "secret",
    "sig",
    "signature",
    "token",
  ])
  for (const [name] of url.searchParams) {
    const parts = name
      .toLowerCase()
      .replaceAll(".", " ")
      .replaceAll("_", " ")
      .replaceAll("-", " ")
      .split(" ")
    if (parts.some((part) => sensitiveTokens.has(part))) return true
  }
  return false
}

/**
 * Encode a string for use as a quoted value in a curl config file. Curl's
 * config grammar allows `\\` and `\"` inside double-quoted strings.
 *
 * @param value - The value to encode (URL or header value).
 * @returns The escaped value without surrounding quotes.
 */
export function escapeCurlConfigValue(value: string): string {
  return value.replaceAll("\\", String.raw`\\`).replaceAll('"', String.raw`\"`)
}

/**
 * Validate a header name/value pair and throw with a helpful message when the
 * name or value would inject newlines or invalid characters into the request.
 *
 * @param name - The HTTP header field name.
 * @param value - The HTTP header field value.
 */
export function validateHeaderPair(name: string, value: string): void {
  if (!isValidHeaderName(name)) {
    throw new Error(`Invalid HTTP header name: ${name}`)
  }
  if (!isValidHeaderValue(value)) {
    throw new Error(`Invalid HTTP header value for ${name}: value contains newline characters`)
  }
}

/**
 * Result of {@link buildCurlConfigPayload}: the stdin config payload and the
 * argv header list. Header values are always routed through stdin because
 * arbitrary custom headers may carry credentials.
 */
export type CurlConfigPayload = {
  /** Header pairs that may stay on argv. Currently empty by design. */
  argvHeaders: Array<[string, string]>
  /** Stdin config payload (terminated with a trailing newline). */
  configInput: string
}

/**
 * Build the stdin config payload for `curl --config -`.
 *
 * The URL is passed through stdin when `parameters.routeUrlThroughConfig` is
 * `true` (typically because the URL embeds presigned tokens). All headers are
 * routed through stdin so custom credentials never leak via `sudo` logging or
 * `ps -ef`.
 *
 * @param parameters - The URL plus optional headers and routing options.
 * @param parameters.headers - Additional HTTP headers.
 * @param parameters.routeUrlThroughConfig - When `true`, the URL is written to the stdin payload instead of staying on argv.
 * @param parameters.url - The URL to forward to curl.
 * @returns The stdin config text and an empty argv header list.
 */
export function buildCurlConfigPayload(parameters: {
  headers?: Record<string, string>
  routeUrlThroughConfig?: boolean
  url: string
}): CurlConfigPayload {
  const lines: string[] = []
  if (parameters.routeUrlThroughConfig === true) {
    lines.push(`url = "${escapeCurlConfigValue(parameters.url)}"`)
  }
  const argvHeaders: Array<[string, string]> = []

  for (const [name, value] of Object.entries(parameters.headers ?? {})) {
    validateHeaderPair(name, value)
    const headerLine = `${name}: ${value}`
    lines.push(`header = "${escapeCurlConfigValue(headerLine)}"`)
  }

  // Trailing newline so the final config directive is terminated cleanly.
  return { argvHeaders, configInput: lines.length > 0 ? `${lines.join("\n")}\n` : "" }
}

/**
 * Render an argv-safe `-H` flag string from a caller-supplied header list
 * returned by {@link buildCurlConfigPayload}. Returns an empty string when no
 * headers remain so callers can splice the result into a command unchanged.
 *
 * @param argvHeaders - Header name/value pairs that may appear on argv.
 * @returns The `-H 'name: value' …` segment with trailing space, or `""`.
 */
export function buildCurlArgvHeaderFlags(argvHeaders: Array<[string, string]>): string {
  const flags = argvHeaders
    .map(([name, value]) => {
      const headerLine = `${name}: ${value}`
      return `-H ${shellQuote(headerLine)}`
    })
    .join(" ")
  return flags.length > 0 ? `${flags} ` : ""
}
