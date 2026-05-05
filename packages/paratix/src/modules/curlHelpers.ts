import { shellQuote } from "../ssh.js"

/** Last ASCII control character (U+001F). */
const LAST_CONTROL_CHAR = 0x1f
/** ASCII DEL character (U+007F). */
const DEL_CHAR = 0x7f
const SENSITIVE_QUERY_TOKENS = new Set([
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
const QUERY_PARAMETER_SEPARATORS = new Set(["_", "-", "."])

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
 * Validate a string before it is rendered as one curl config value.
 * CR, LF and NUL would terminate or corrupt curl's line-based config grammar.
 *
 * @param label - User-safe description of the value being validated.
 * @param value - The value that will be written to the curl config payload.
 */
export function validateCurlConfigValue(label: string, value: string): void {
  if (isValidHeaderValue(value)) return
  throw new Error(`${label} must not contain CR, LF, or NUL characters`)
}

function isAsciiUppercase(char: string): boolean {
  return char >= "A" && char <= "Z"
}

function isAsciiLowercase(char: string): boolean {
  return char >= "a" && char <= "z"
}

function isAsciiDigit(char: string): boolean {
  return char >= "0" && char <= "9"
}

function appendQueryParameterToken(tokens: string[], current: string): string {
  if (current.length > 0) tokens.push(current.toLowerCase())
  return ""
}

function isCamelCaseBoundary(name: string, index: number): boolean {
  if (index <= 0) return false

  const char = name.charAt(index)
  const previous = name.charAt(index - 1)
  if (!isAsciiUppercase(char) || QUERY_PARAMETER_SEPARATORS.has(previous)) return false
  if (isAsciiLowercase(previous) || isAsciiDigit(previous)) return true

  if (index + 1 >= name.length) return false
  const next = name.charAt(index + 1)
  return isAsciiUppercase(previous) && isAsciiLowercase(next)
}

function tokenizeQueryParameterName(name: string): string[] {
  const tokens: string[] = []
  let current = ""
  for (let index = 0; index < name.length; index++) {
    const char = name.charAt(index)
    if (QUERY_PARAMETER_SEPARATORS.has(char)) {
      current = appendQueryParameterToken(tokens, current)
      continue
    }
    if (isCamelCaseBoundary(name, index)) current = appendQueryParameterToken(tokens, current)
    current += char
  }
  appendQueryParameterToken(tokens, current)
  return tokens
}

/**
 * Check whether a query parameter name looks sensitive.
 *
 * CamelCase boundaries are tokenized before lowercasing so names such as
 * `apiKey` and `clientSecret` match the same token list as `api_key` and
 * `client-secret`, while unrelated substrings such as `monkey` do not match.
 *
 * @param name - The query parameter name to inspect.
 * @returns `true` when at least one token is known to carry credentials.
 */
export function isSensitiveQueryParameterName(name: string): boolean {
  return tokenizeQueryParameterName(name).some((part) => SENSITIVE_QUERY_TOKENS.has(part))
}

/**
 * Check whether the given URL's query string carries sensitive material such
 * as presigned tokens, signatures, or credentials.
 *
 * @param url - The parsed URL to inspect.
 * @returns `true` when at least one query parameter name looks sensitive.
 */
export function hasSensitiveQueryParameters(url: URL): boolean {
  for (const [name] of url.searchParams) {
    if (isSensitiveQueryParameterName(name)) return true
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
  validateCurlConfigValue("curl config value", value)
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
    validateCurlConfigValue("URL", parameters.url)
    lines.push(`url = "${escapeCurlConfigValue(parameters.url)}"`)
  }
  const argvHeaders: Array<[string, string]> = []

  for (const [name, value] of Object.entries(parameters.headers ?? {})) {
    validateHeaderPair(name, value)
    const headerLine = `${name}: ${value}`
    validateCurlConfigValue(`HTTP header line for ${name}`, headerLine)
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
