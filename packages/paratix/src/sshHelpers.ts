/* eslint-disable max-lines, max-statements -- transport stream handlers are intentionally co-located */
import { StringDecoder } from "node:string_decoder"

import type { TransportExecChannel } from "./transport.js"
import type { ExecOptions, ExecResult } from "./types.js"

import { createTerminalSanitizer } from "./terminalSanitizer.js"

/**
 * Validate that a file mode string is a valid octal permission (e.g. "644", "0755").
 *
 * @param mode - The mode string to validate.
 * @throws {Error} If the mode is not a 3- or 4-digit octal string.
 */
export function validateMode(mode: string): void {
  if (!/^[0-7]{3,4}$/v.test(mode)) {
    throw new Error(
      `Invalid file mode '${mode}': expected a 3- or 4-digit octal string (e.g. "644", "0755")`
    )
  }
}

/**
 * Safely quote a string for use in a POSIX shell command.
 * Wraps the value in single quotes and escapes any embedded single quotes.
 *
 * @param s - The string to quote.
 * @returns The shell-safe quoted string.
 */
export function shellQuote(s: string): string {
  return `'${s.replaceAll("'", "'\\''")}'`
}

export const DEFAULT_MAX_OUTPUT_BYTES = Number("1048576")
/**
 * Marker appended to {@link CapturedOutput} when the captured stream exceeds
 * the configured maxOutputBytes. Exported so callers that compare a captured
 * `result.stdout` against an external source-of-truth (e.g. `ssh.readFile`,
 * `ssh.sha256`) can detect truncation and refuse to act on corrupted data.
 */
export const CAPTURE_TRUNCATION_MARKER = "\n[output truncated]"

/**
 * Maximum number of characters included in a {@link CommandError} message
 * before the output is truncated. Output beyond this limit is still available
 * on {@link CommandError.fullStdout} and {@link CommandError.fullStderr}, up
 * to the configured capture limit.
 */
export const MAX_OUTPUT_LENGTH = 500

/**
 * Truncate `text` to at most {@link MAX_OUTPUT_LENGTH} Unicode code points,
 * appending a `…(truncated)` marker when the limit is exceeded. Counting by
 * code point (not UTF-16 units) keeps a trailing surrogate pair intact so the
 * slice never splits a character. This is the single truncation implementation
 * shared across the SSH layer — both the sudo path ({@link buildCommandError})
 * and the raw path (via {@link collectStreamOutput}) render error snippets
 * through this exact function so their output stays byte-for-byte identical.
 *
 * @param text - The text to truncate.
 * @returns The original text, or a truncated prefix with a `…(truncated)` marker.
 */
export function truncateOutput(text: string): string {
  let count = 0
  let sliceEnd = 0
  for (const char of text) {
    if (count >= MAX_OUTPUT_LENGTH) return `${text.slice(0, sliceEnd)}…(truncated)`
    sliceEnd += char.length
    count++
  }
  return text
}

function codepointLengthExceeds(text: string, limit: number): boolean {
  let count = 0
  for (const _char of text) {
    count++
    if (count > limit) return true
  }
  return false
}

function fitUtf8Prefix(text: string, maxBytes: number): string {
  let bytes = 0
  let sliceEnd = 0
  for (const char of text) {
    const charBytes = Buffer.byteLength(char, "utf8")
    if (bytes + charBytes > maxBytes) break
    bytes += charBytes
    sliceEnd += char.length
  }
  return text.slice(0, sliceEnd)
}

function resolveMaxOutputBytes(options: ExecOptions): number {
  const value = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES
  if (!Number.isFinite(value) || value < 0) {
    throw new Error("ExecOptions.maxOutputBytes must be a non-negative finite number")
  }
  return Math.floor(value)
}

class CapturedOutput {
  private byteLength = 0
  private text = ""
  private truncated = false

  public constructor(private readonly maxBytes: number) {}

  public append(chunk: string): void {
    if (this.truncated) return
    const chunkBytes = Buffer.byteLength(chunk, "utf8")
    const remainingBytes = this.maxBytes - this.byteLength
    if (chunkBytes <= remainingBytes) {
      this.text += chunk
      this.byteLength += chunkBytes
      return
    }

    if (remainingBytes > 0) {
      const prefix = fitUtf8Prefix(chunk, remainingBytes)
      this.text += prefix
      this.byteLength += Buffer.byteLength(prefix, "utf8")
    }
    this.text += CAPTURE_TRUNCATION_MARKER
    this.truncated = true
  }

  public isTruncated(): boolean {
    return this.truncated
  }

  public toString(): string {
    return this.text
  }
}

type CapturedStreams = {
  capturedStderr: string
  capturedStdout: string
  stderr: CapturedOutput
  stdout: CapturedOutput
}

function outputSummaryWasTruncated(streams: CapturedStreams): boolean {
  return (
    streams.stdout.isTruncated() ||
    streams.stderr.isTruncated() ||
    codepointLengthExceeds(streams.capturedStdout, MAX_OUTPUT_LENGTH) ||
    codepointLengthExceeds(streams.capturedStderr, MAX_OUTPUT_LENGTH)
  )
}

type CommandErrorParameters = {
  capturedStderr: string
  capturedStdout: string
  command: string
  reason: string
  secrets: PreparedSecrets
  wasTruncated: boolean
}

function buildCommandError(parameters: CommandErrorParameters): CommandError {
  const hint = parameters.wasTruncated ? "\n(use --verbose for full output)" : ""
  return new CommandError(
    `Command failed with ${parameters.reason}: ${maskPreparedSecrets(parameters.command, parameters.secrets)}\nstdout: ${truncateOutput(parameters.capturedStdout)}\nstderr: ${truncateOutput(parameters.capturedStderr)}${hint}`,
    parameters.capturedStdout,
    parameters.capturedStderr
  )
}

/**
 * Error thrown when a remote command exits with a non-zero exit code.
 *
 * The `message` contains a truncated summary of stdout and stderr (up to
 * {@link MAX_OUTPUT_LENGTH} characters each). Captured output is capped by
 * `ExecOptions.maxOutputBytes`; truncated captures are marked in
 * {@link CommandError.fullStdout} and {@link CommandError.fullStderr}.
 *
 * Inside paratix, match it with {@link isCommandError}: `instanceof` is
 * unreliable because the CLI and library bundles each carry their own copy of
 * this class (#193).
 *
 * @example
 * ```ts
 * try {
 *   await ssh.exec("exit 1")
 * } catch (error) {
 *   if (isCommandError(error)) {
 *     console.error(error.fullStderr)
 *   }
 * }
 * ```
 */
export class CommandError extends Error {
  /** Full, untruncated standard error of the failed command. */
  public readonly fullStderr: string
  /** Full, untruncated standard output of the failed command. */
  public readonly fullStdout: string

  public constructor(message: string, fullStdout: string, fullStderr: string) {
    super(message)
    this.name = "CommandError"
    this.fullStdout = fullStdout
    this.fullStderr = fullStderr
    Error.captureStackTrace(this, CommandError)
  }
}

/**
 * #193: paratix ships this class in two separate bundles — the CLI
 * (`cli.js`, the runner and its failure printer) and the library (`index.js`
 * plus its shared chunk, whose modules run `ssh.exec` and mask failures). An
 * error built by one copy is not an `instanceof` the other copy's class, so a
 * cross-copy check silently loses `fullStdout`/`fullStderr`. The
 * `Symbol.for`-keyed brand on the prototype is identical in every copy, is
 * non-enumerable (so it does not change error equality) and survives the
 * `Object.create(prototype)` clones built while masking secrets.
 */
const COMMAND_ERROR_BRAND = Symbol.for("paratix.sshHelpers.CommandError")
Object.defineProperty(CommandError.prototype, COMMAND_ERROR_BRAND, { value: true })

/**
 * Check whether `value` is a {@link CommandError} from any paratix bundle copy.
 *
 * @param value - The value to test, typically a caught error.
 * @returns `true` when `value` carries the {@link CommandError} brand.
 */
export function isCommandError(value: unknown): value is CommandError {
  return (
    typeof value === "object" && value !== null && Reflect.get(value, COMMAND_ERROR_BRAND) === true
  )
}

export type StreamOutputParameters = {
  command: string
  options: ExecOptions
  reject: (reason: Error) => void
  resolve: (value: ExecResult) => void
  secrets?: PreparedSecrets | SecretSource[]
  stream: TransportExecChannel
  timer: ReturnType<typeof setTimeout>
}

export type SecretSource = (() => string) | string
export type PreparedSecrets = {
  variants: string[]
}

/** Placeholder used when redacting secrets from output. */
const REDACTED = "[REDACTED]"

function resolveSecret(secret: SecretSource): string {
  return typeof secret === "function" ? secret() : secret
}

function getSecretVariants(secrets: SecretSource[]): string[] {
  const variants = new Set<string>()
  for (const source of secrets) {
    const secret = resolveSecret(source)
    if (secret.length === 0) continue
    if (secret.includes(REDACTED)) {
      throw new Error(`Secret must not contain the redaction placeholder "${REDACTED}"`)
    }

    variants.add(secret)

    const encoded = encodeURIComponent(secret)
    // eslint-disable-next-line security/detect-possible-timing-attacks -- not a secret comparison, just checking if URL encoding changed the string
    if (encoded !== secret) variants.add(encoded)

    const quoted = shellQuote(secret)
    // eslint-disable-next-line security/detect-possible-timing-attacks -- not a secret comparison, just checking if shell quoting changed the string
    if (quoted !== secret) variants.add(quoted)
  }
  return [...variants].sort((a, b) => b.length - a.length)
}

export function prepareSecrets(secrets: SecretSource[]): PreparedSecrets {
  return { variants: getSecretVariants(secrets) }
}

function ensurePreparedSecrets(secrets: PreparedSecrets | SecretSource[]): PreparedSecrets {
  return "variants" in secrets ? secrets : prepareSecrets(secrets)
}

function createVariantResolver(secrets: PreparedSecrets): {
  getMaxLength: () => number
  mask: (text: string) => string
} {
  return {
    getMaxLength(): number {
      return Math.max(0, ...secrets.variants.map((variant) => variant.length))
    },
    mask(text: string): string {
      let masked = text
      for (const variant of secrets.variants) {
        masked = masked.replaceAll(variant, REDACTED)
      }
      return masked
    },
  }
}

export function maskPreparedSecrets(text: string, secrets: PreparedSecrets): string {
  return createVariantResolver(secrets).mask(text)
}

export function maskSecrets(text: string, secrets: SecretSource[]): string {
  return maskPreparedSecrets(text, prepareSecrets(secrets))
}

/**
 * Create a sliding-window masker that buffers up to `maxSecretLength - 1`
 * characters so that secrets split across chunk boundaries are still masked
 * in live output.
 *
 * @param write - Callback that receives masked text for live output.
 * @param secrets - List of secret strings to mask.
 * @returns An object with `push` (feed new data) and `flush` (emit remaining buffer).
 */
export function createStreamMasker(
  write: (text: string) => void,
  secrets: PreparedSecrets | SecretSource[]
): { flush: () => void; push: (chunk: string) => void } {
  const resolver = createVariantResolver(ensurePreparedSecrets(secrets))
  let overlap: null | number = null
  const getOverlap = (): number => {
    overlap ??= Math.max(0, resolver.getMaxLength() - 1)
    return overlap
  }

  let pending = ""

  return {
    flush(): void {
      if (pending.length > 0) {
        write(resolver.mask(pending))
        pending = ""
      }
    },
    push(chunk: string): void {
      const currentOverlap = getOverlap()
      if (currentOverlap === 0) {
        write(resolver.mask(chunk))
        return
      }
      pending += chunk
      if (pending.length <= currentOverlap) return
      // Mask the whole buffer first so secrets fully contained in
      // pending are replaced before the split.  The overlap is then
      // taken from the *masked* result — safe because maskSecrets()
      // rejects any secret that contains the redaction placeholder.
      const masked = resolver.mask(pending)
      if (masked.length <= currentOverlap) {
        pending = masked
        return
      }
      write(masked.slice(0, -currentOverlap))
      pending = masked.slice(-currentOverlap)
    },
  }
}

function writeStdout(t: string): void {
  process.stdout.write(t)
}
function writeStderr(t: string): void {
  process.stderr.write(t)
}

function createSanitizedTerminalWriter(silent: boolean): {
  flush: () => void
  stderr: (text: string) => void
  stdout: (text: string) => void
} {
  const stdoutTerminalSanitizer = createTerminalSanitizer()
  const stderrTerminalSanitizer = createTerminalSanitizer()

  return {
    flush(): void {
      if (silent) return
      writeStdout(stdoutTerminalSanitizer.flush())
      writeStderr(stderrTerminalSanitizer.flush())
    },
    stderr(text: string): void {
      if (!silent) writeStderr(stderrTerminalSanitizer.push(text))
    },
    stdout(text: string): void {
      if (!silent) writeStdout(stdoutTerminalSanitizer.push(text))
    },
  }
}

/**
 * Normalize absent transport exit codes to the established successful zero exit.
 * The ssh2 adapter supplies `null` when the server omitted an exit status.
 *
 * @param code - Exit code supplied by the transport channel.
 * @returns A normalized numeric exit code.
 */
export function normalizeSshCloseCode(code: null | number | undefined): number {
  return code ?? 0
}

function normalizeSshCloseSignal(signal: null | string | undefined): string | undefined {
  return signal == null || signal === "" ? undefined : signal
}

/**
 * Error a command rejects with when `ExecOptions.strictUtf8Stdout` is set and
 * its stdout is not valid UTF-8.
 */
export class InvalidUtf8OutputError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = "InvalidUtf8OutputError"
  }
}

/**
 * #193: brand for {@link InvalidUtf8OutputError}, for the same reason as the
 * {@link CommandError} brand — the CLI bundle (`cli.js`) and the library
 * bundle (`index.js` plus its shared chunk) each carry their own copy of the
 * class, so a rejection raised by one copy fails `instanceof` in the other.
 */
const INVALID_UTF8_OUTPUT_ERROR_BRAND = Symbol.for("paratix.sshHelpers.InvalidUtf8OutputError")
Object.defineProperty(InvalidUtf8OutputError.prototype, INVALID_UTF8_OUTPUT_ERROR_BRAND, {
  value: true,
})

/**
 * Check whether `value` is an {@link InvalidUtf8OutputError} from any paratix
 * bundle copy.
 *
 * @param value - The value to test, typically a caught error.
 * @returns `true` when `value` carries the {@link InvalidUtf8OutputError} brand.
 */
export function isInvalidUtf8OutputError(value: unknown): value is InvalidUtf8OutputError {
  return (
    typeof value === "object" &&
    value !== null &&
    Reflect.get(value, INVALID_UTF8_OUTPUT_ERROR_BRAND) === true
  )
}

/** A streaming stdout decoder; `valid` turns false once invalid UTF-8 was seen. */
type StdoutDecoder = { end: () => string; valid: () => boolean; write: (data: Buffer) => string }

/**
 * Create the stdout decoder `collectStreamOutput` uses.
 *
 * By default this is the lenient `StringDecoder`, which replaces invalid byte
 * sequences with U+FFFD. With `strict`, a fatal `TextDecoder` is used instead:
 * once it meets invalid UTF-8 (also when the sequence is split across chunks,
 * or left incomplete at the end), the decoder is marked invalid and decodes
 * nothing further, and the caller rejects the command when the channel exits.
 * `ignoreBOM` keeps a leading byte order mark in the text.
 *
 * @param strict - Whether stdout must be valid UTF-8.
 * @returns A lenient decoder, or a fatal one that reports invalid input.
 */
function createStdoutDecoder(strict: boolean): StdoutDecoder {
  if (!strict) {
    const lenient = new StringDecoder("utf8")
    return { end: () => lenient.end(), valid: () => true, write: (data) => lenient.write(data) }
  }
  const fatal = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
  let valid = true
  const decode = (data?: Buffer): string => {
    if (!valid) return ""
    try {
      return data === undefined ? fatal.decode() : fatal.decode(data, { stream: true })
    } catch {
      valid = false
      return ""
    }
  }
  return { end: () => decode(), valid: () => valid, write: (data) => decode(data) }
}

/**
 * Build the rejection for a strict-UTF-8 command whose stdout was not valid
 * UTF-8, naming how the command ended and its masked command line.
 *
 * @param command - The command that ran.
 * @param secrets - The secrets to mask in the command.
 * @param end - How the command ended.
 * @param end.code - The normalized exit code.
 * @param end.signal - The signal that ended the command, if any.
 * @returns The error to reject the command with.
 */
function invalidUtf8StdoutError(
  command: string,
  secrets: PreparedSecrets,
  end: { code: number; signal: string | undefined }
): InvalidUtf8OutputError {
  const how = end.signal === undefined ? `exit code ${String(end.code)}` : `signal ${end.signal}`
  return new InvalidUtf8OutputError(
    `Command stdout is not valid UTF-8 (${how}): ${maskPreparedSecrets(command, secrets)}`
  )
}

/**
 * Wire up transport stream and exit listeners to collect stdout/stderr
 * and resolve or reject the promise when the channel exits.
 *
 * With `ExecOptions.strictUtf8Stdout`, stdout that is not valid UTF-8 makes
 * the promise reject with an {@link InvalidUtf8OutputError} when the channel
 * exits, instead of resolving with replacement characters. The listeners,
 * the timer and the single settlement work exactly as in the default mode.
 *
 * @param parameters - Stream collection parameters.
 */
export function collectStreamOutput(parameters: StreamOutputParameters): void {
  const { command, options, reject, resolve, stream, timer } = parameters
  let maxOutputBytes: number
  let secrets: PreparedSecrets
  try {
    maxOutputBytes = resolveMaxOutputBytes(options)
    secrets =
      parameters.secrets == null ? prepareSecrets([]) : ensurePreparedSecrets(parameters.secrets)
  } catch (error) {
    clearTimeout(timer)
    reject(error instanceof Error ? error : new Error(String(error)))
    return
  }
  const stdout = new CapturedOutput(maxOutputBytes)
  const stderr = new CapturedOutput(maxOutputBytes)
  const stdoutDecoder = createStdoutDecoder(options.strictUtf8Stdout === true)
  const stderrDecoder = new StringDecoder("utf8")
  const terminalWriter = createSanitizedTerminalWriter(options.silent === true)

  const stdoutMasker = createStreamMasker((text) => {
    stdout.append(text)
    terminalWriter.stdout(text)
  }, secrets)
  const stderrMasker = createStreamMasker((text) => {
    stderr.append(text)
    terminalWriter.stderr(text)
  }, secrets)
  const finishStdoutDecode = (): void => {
    const text = stdoutDecoder.end()
    if (text.length > 0) stdoutMasker.push(text)
  }
  const finishStderrDecode = (): void => {
    const text = stderrDecoder.end()
    if (text.length > 0) stderrMasker.push(text)
  }

  stream.stdout.on("data", (data: Buffer) => {
    stdoutMasker.push(stdoutDecoder.write(data))
  })
  stream.stderr.on("data", (data: Buffer) => {
    stderrMasker.push(stderrDecoder.write(data))
  })
  // Stop the timer and drain every decoder, masker and the terminal writer;
  // shared by the error and close paths, in the same order for both.
  const drain = (): void => {
    clearTimeout(timer)
    finishStdoutDecode()
    finishStderrDecode()
    stdoutMasker.flush()
    stderrMasker.flush()
    terminalWriter.flush()
  }
  const failStream = (error: Error): void => {
    drain()
    reject(error)
  }
  stream.stdout.on("error", failStream)
  stream.stderr.on("error", failStream)
  stream.onExit(({ code, signal }) => {
    drain()
    const capturedStdout = stdout.toString()
    const capturedStderr = stderr.toString()
    const capturedStreams = { capturedStderr, capturedStdout, stderr, stdout }
    const closeSignal = normalizeSshCloseSignal(signal)
    if (!stdoutDecoder.valid()) {
      const end = { code: normalizeSshCloseCode(code), signal: closeSignal }
      reject(invalidUtf8StdoutError(command, secrets, end))
      return
    }
    if (closeSignal !== undefined) {
      reject(
        buildCommandError({
          capturedStderr,
          capturedStdout,
          command,
          reason: `signal ${closeSignal}`,
          secrets,
          wasTruncated: outputSummaryWasTruncated(capturedStreams),
        })
      )
      return
    }
    const exitCode = normalizeSshCloseCode(code)
    if (exitCode !== 0 && options.ignoreExitCode !== true) {
      reject(
        buildCommandError({
          capturedStderr,
          capturedStdout,
          command,
          reason: `exit code ${exitCode}`,
          secrets,
          wasTruncated: outputSummaryWasTruncated(capturedStreams),
        })
      )
      return
    }
    resolve({ code: exitCode, stderr: capturedStderr, stdout: capturedStdout })
  })
}
