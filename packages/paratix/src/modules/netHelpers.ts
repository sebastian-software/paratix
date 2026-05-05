import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import {
  buildCurlArgvHeaderFlags,
  buildCurlConfigPayload,
  hasSensitiveQueryParameters,
  isValidHeaderName,
  isValidHeaderValue,
  redactUrlForDisplay as redactParsedUrlForDisplay,
  validateCurlConfigValue,
} from "./curlHelpers.js"

export { isValidHeaderName, isValidHeaderValue } from "./curlHelpers.js"

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
  /** Stdin payload for `curl --config -` carrying the URL when sensitive and any headers. Empty string when no stdin payload is needed. */
  configInput: string
  /** URL safe for module names and user-visible errors. Sensitive query values are redacted. */
  displayUrl: string
  /** Expected substring in the response body, or `undefined` to skip body verification. */
  expectedBody: string | undefined
  /** HTTP status code the response must return (e.g. `200`). */
  expectedStatus: number
  /** Pre-built `-H` curl flags string with trailing space, or empty string. Currently empty for user headers by design. */
  headerFlags: string
  /** Pre-built `-X METHOD ` curl flag string with trailing space, or empty string for GET. */
  methodFlag: string
  /** Strings (header values, signed URLs) registered as secrets so they are masked in CommandError stack traces. */
  secrets: string[]
  /** The URL to request. Only inlined onto argv when `urlOnArgv` is `true`. */
  url: string
  /** When `true`, the URL is appended to the curl argv. When `false`, it must be supplied via the stdin config payload. */
  urlOnArgv: boolean
}

const HTTP_STATUS_MARKER = "\n__PARATIX_HTTP_STATUS__:"

/**
 * Build the shell command used to test a wait-for condition.
 *
 * @param options - The wait-for condition options.
 * @param host - The resolved host address for port checks.
 * @param probeTimeoutSeconds - Timeout passed to `nc -w` for port checks.
 * @returns The shell test command string.
 */
export function buildWaitForTestCommand(
  options: WaitForOptions,
  host: string,
  probeTimeoutSeconds = 1
): string {
  if (options.port != null) {
    const timeout = shellQuote(String(probeTimeoutSeconds))
    return `nc -z -w ${timeout} ${shellQuote(host)} ${shellQuote(String(options.port))}`
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

function hasUrlCredentials(url: URL): boolean {
  return url.username.length > 0 || url.password.length > 0
}

function redactUrlForDisplay(url: string, parsedUrl: URL): string {
  const shouldRedactQuery = hasSensitiveQueryParameters(parsedUrl)
  const shouldRedactCredentials = hasUrlCredentials(parsedUrl)
  if (!shouldRedactQuery && !shouldRedactCredentials) return url

  return redactParsedUrlForDisplay(parsedUrl)
}

/**
 * Build the curl invocation parts for an HTTP request check.
 *
 * Headers are routed through `--config -` via stdin so custom credentials
 * never appear on the curl command line where `ps -ef` or sudo logging could
 * capture them. URLs whose query string carries presigned tokens or
 * signatures are routed through the same stdin payload.
 *
 * @param options - The HTTP request configuration.
 * @param options.body - Expected substring in the response body.
 * @param options.headers - Additional HTTP headers.
 * @param options.method - HTTP method (default: `"GET"`).
 * @param options.status - Expected HTTP status code (default: `200`).
 * @param options.url - The URL to request.
 * @returns The precomputed curl parts plus the secrets to register.
 */
export function buildHttpCheckParameters(options: {
  body?: string
  headers?: Record<string, string>
  method?: string
  status: number
  url: string
}): HttpCheckParameters {
  const headers = options.headers ?? {}
  const method = options.method ?? "GET"
  const parsedUrl = new URL(options.url)
  const urlIsSensitive = hasSensitiveQueryParameters(parsedUrl) || hasUrlCredentials(parsedUrl)

  const { argvHeaders, configInput } = buildCurlConfigPayload({
    headers,
    routeUrlThroughConfig: urlIsSensitive,
    url: options.url,
  })

  const secrets = Object.values(headers).filter((value) => value.length > 0)
  if (urlIsSensitive) {
    secrets.push(options.url)
    if (parsedUrl.username.length > 0) secrets.push(parsedUrl.username)
    if (parsedUrl.password.length > 0) secrets.push(parsedUrl.password)
  }

  return {
    configInput,
    displayUrl: redactUrlForDisplay(options.url, parsedUrl),
    expectedBody: options.body,
    expectedStatus: options.status,
    headerFlags: buildCurlArgvHeaderFlags(argvHeaders),
    methodFlag: method === "GET" ? "" : `-X ${shellQuote(method)} `,
    secrets,
    url: options.url,
    urlOnArgv: !urlIsSensitive,
  }
}

/**
 * Render the URL portion of the curl argv. Returns the empty string when the
 * URL has been routed through the stdin config payload.
 *
 * @param parameters - The precomputed HTTP check parameters.
 * @returns The shell-quoted URL with a leading space, or `""`.
 */
function buildCurlUrlArgvSegment(parameters: HttpCheckParameters): string {
  return parameters.urlOnArgv ? shellQuote(parameters.url) : ""
}

/**
 * Determine whether curl needs `--config -` (because the URL or any header
 * was routed through stdin).
 *
 * @param parameters - The precomputed HTTP check parameters.
 * @returns The `--config -` flag with a leading space, or `""`.
 */
function buildCurlConfigFlag(parameters: HttpCheckParameters): string {
  return parameters.configInput.length > 0 ? "--config -" : ""
}

/**
 * Join the curl argv segments together using single spaces, dropping empty
 * pieces so the resulting command stays well-formed.
 *
 * @param segments - The argv segments to join.
 * @returns The combined argv string.
 */
function joinCurlSegments(segments: string[]): string {
  return segments.filter((segment) => segment.length > 0).join(" ")
}

/**
 * Run a single curl invocation against the remote host. Uses
 * `silent: true` and forwards the stdin config payload (when any) so
 * headers stay out of `/proc/<pid>/cmdline`. Registered secrets keep the curl
 * stderr masked when ssh.exec surfaces a CommandError.
 *
 * @param conn - The active SSH connection.
 * @param argvBase - The curl flags that precede the headers (e.g. `curl -s ...`).
 * @param parameters - The precomputed HTTP check parameters.
 * @returns Trimmed stdout from the curl invocation.
 */
async function execCurl(
  conn: SshConnection,
  argvBase: string,
  parameters: HttpCheckParameters
): Promise<string> {
  const command = joinCurlSegments([
    argvBase,
    parameters.methodFlag.trim(),
    parameters.headerFlags.trim(),
    buildCurlUrlArgvSegment(parameters),
    buildCurlConfigFlag(parameters),
  ])
  const result = await conn.exec(command, {
    input: parameters.configInput.length > 0 ? parameters.configInput : undefined,
    secrets: parameters.secrets,
    silent: true,
  })
  return result.stdout.trim()
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
    if (parameters.expectedBody != null) {
      const output = await execCurl(
        conn,
        "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}'",
        parameters
      )
      const markerIndex = output.lastIndexOf(HTTP_STATUS_MARKER)
      if (markerIndex === -1) return false

      const bodyOutput = output.slice(0, markerIndex)
      const bodyStatusOutput = output.slice(markerIndex + HTTP_STATUS_MARKER.length).trim()
      if (bodyStatusOutput !== String(parameters.expectedStatus)) return false

      return bodyOutput.includes(parameters.expectedBody)
    }

    const statusOutput = await execCurl(conn, "curl -s -o /dev/null -w '%{http_code}'", parameters)
    return statusOutput === String(parameters.expectedStatus)
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
  validateCurlConfigValue("URL", url)
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new Error("Invalid URL: expected an http or https URL")
  }
  const displayUrl = redactParsedUrlForDisplay(parsed)
  if (parsed.protocol === "https:") return
  if (parsed.protocol === "http:" && options?.allowHttp === true) return
  if (parsed.protocol === "http:") {
    throw new Error(
      `Insecure URL scheme 'http' in '${displayUrl}': only https is allowed by default`
    )
  }
  if (parsed.protocol !== "https:") {
    throw new Error(
      `Unsupported URL scheme '${parsed.protocol.replace(/:$/v, "")}' in '${displayUrl}': only http and https are allowed`
    )
  }
}

/**
 * Create a delay promise for use in polling loops.
 *
 * When an `AbortSignal` is supplied, the timer is cleared and the returned
 * promise rejects as soon as the signal fires (or synchronously if the signal
 * is already aborted). The rejection reason is the signal's `reason` when it
 * is an `Error`, otherwise a fresh `Error("delay aborted")`. R-0000052: this
 * lets `net.waitFor` unblock its polling loop within the next iteration tick
 * after the runner observes SIGINT, instead of running until the configured
 * timeout.
 *
 * @param ms - The delay duration in milliseconds.
 * @param abortSignal - Optional signal that, when aborted, rejects the wait.
 * @returns A promise that resolves after the specified delay or rejects on abort.
 */
export async function delay(ms: number, abortSignal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (abortSignal?.aborted === true) {
      reject(normalizeDelayAbortReason(abortSignal.reason))
      return
    }

    const timer = setTimeout(() => {
      abortSignal?.removeEventListener("abort", onAbort)
      resolve()
    }, ms)

    const onAbort = (): void => {
      clearTimeout(timer)
      reject(normalizeDelayAbortReason(abortSignal?.reason))
    }

    abortSignal?.addEventListener("abort", onAbort, { once: true })
  })
}

/**
 * Coerce an unknown abort reason into an `Error` instance.
 *
 * Mirrors the helper in {@link "../builtins.js"} but stays local to keep the
 * net-helpers file self-contained.
 *
 * @param reason - The {@link AbortSignal.reason}, if any.
 * @returns An `Error` with a meaningful message.
 */
function normalizeDelayAbortReason(reason: unknown): Error {
  if (reason instanceof Error) return reason
  if (reason === undefined || reason === null) return new Error("delay aborted")
  if (typeof reason === "string") return new Error(reason)
  return new Error("delay aborted")
}
