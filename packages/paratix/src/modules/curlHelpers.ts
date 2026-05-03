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
 * Headers whose values are considered sensitive and must therefore be fed to
 * curl via stdin (`--config -`) instead of being inlined into argv. Matching
 * is case-insensitive.
 *
 * Bearer tokens, GitHub PATs, Basic-Auth credentials, and presigned tokens
 * land here so they never appear in `/var/log/auth.log` (sudo logging) or in
 * `/proc/<pid>/cmdline` / `ps -ef` while curl runs.
 */
export const SENSITIVE_HEADER_NAMES = new Set(["authorization", "proxy-authorization"])

/**
 * Check whether a header name is considered sensitive.
 *
 * @param name - The HTTP header name (case-insensitive).
 * @returns `true` when the header carries credentials.
 */
export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER_NAMES.has(name.toLowerCase())
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
 * non-sensitive headers the caller should still place on argv.
 */
export type CurlConfigPayload = {
  /** Header pairs that may stay on argv (no Authorization-style values). */
  argvHeaders: Array<[string, string]>
  /** Stdin config payload (terminated with a trailing newline). */
  configInput: string
}

/**
 * Build the stdin config payload for `curl --config -`.
 *
 * The URL is passed through stdin when `parameters.routeUrlThroughConfig`
 * is `true` (typically because the URL embeds presigned tokens). Sensitive
 * headers (Authorization, Proxy-Authorization) are also routed through stdin
 * so bearer tokens and presigned URL secrets never leak via `sudo` logging or
 * `ps -ef`. Non-sensitive headers are returned separately so the caller can
 * place them on argv where the visibility cost is acceptable.
 *
 * @param parameters - The URL plus optional headers and routing options.
 * @param parameters.headers - Additional HTTP headers, possibly including Authorization.
 * @param parameters.routeUrlThroughConfig - When `true`, the URL is written to the stdin payload instead of staying on argv.
 * @param parameters.url - The URL to forward to curl.
 * @returns The stdin config text and the headers that should still go to argv.
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
    if (isSensitiveHeader(name)) {
      const headerLine = `${name}: ${value}`
      lines.push(`header = "${escapeCurlConfigValue(headerLine)}"`)
    } else {
      argvHeaders.push([name, value])
    }
  }

  // Trailing newline so the final config directive is terminated cleanly.
  return { argvHeaders, configInput: lines.length > 0 ? `${lines.join("\n")}\n` : "" }
}

/**
 * Render an argv-safe `-H` flag string from the non-sensitive header list
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
