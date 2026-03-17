import type { Client, ClientChannel, ConnectConfig } from "ssh2"

import type { ExecOptions, ExecResult } from "./types.js"

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

const CONNECTION_TIMEOUT = 10_000

/**
 * Maximum number of characters included in a {@link CommandError} message
 * before the output is truncated. Output beyond this limit is still available
 * on {@link CommandError.fullStdout} and {@link CommandError.fullStderr}.
 */
export const MAX_OUTPUT_LENGTH = 500

function truncateOutput(text: string): string {
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

/**
 * Error thrown when a remote command exits with a non-zero exit code.
 *
 * The `message` contains a truncated summary of stdout and stderr
 * (up to {@link MAX_OUTPUT_LENGTH} characters each). The full, untruncated
 * output is available on {@link CommandError.fullStdout} and {@link CommandError.fullStderr} for use
 * in verbose error reporting.
 *
 * @example
 * ```ts
 * try {
 *   await ssh.exec("exit 1")
 * } catch (error) {
 *   if (error instanceof CommandError) {
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

export type StreamOutputParameters = {
  command: string
  options: ExecOptions
  reject: (reason: Error) => void
  resolve: (value: ExecResult) => void
  secrets?: string[]
  stream: ClientChannel
  timer: ReturnType<typeof setTimeout>
}

export function maskSecrets(text: string, secrets: string[]): string {
  let masked = text
  for (const secret of secrets) {
    if (secret.length > 0) {
      masked = masked.replaceAll(secret, "***")
    }
  }
  return masked
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
  secrets: string[]
): { flush: () => void; push: (chunk: string) => void } {
  const maxLength = Math.max(0, ...secrets.map((s) => s.length))
  const overlap = Math.max(0, maxLength - 1)

  if (overlap === 0) {
    return {
      flush(): void {
        /* nothing buffered */
      },
      push(chunk: string): void {
        write(maskSecrets(chunk, secrets))
      },
    }
  }

  let pending = ""

  return {
    flush(): void {
      if (pending.length > 0) {
        write(maskSecrets(pending, secrets))
        pending = ""
      }
    },
    push(chunk: string): void {
      pending += chunk
      if (pending.length <= overlap) return
      // Mask the whole buffer first so secrets fully contained in
      // pending are replaced before the split.  The overlap is then
      // taken from the *masked* result — this is correct as long as
      // no secret literally contains the replacement string "***".
      const masked = maskSecrets(pending, secrets)
      if (masked.length <= overlap) {
        pending = masked
        return
      }
      write(masked.slice(0, -overlap))
      pending = masked.slice(-overlap)
    },
  }
}

function writeStdout(t: string): void {
  process.stdout.write(t)
}
function writeStderr(t: string): void {
  process.stderr.write(t)
}

/**
 * Wire up event listeners on an ssh2 stream to collect stdout/stderr
 * and resolve or reject the promise when the stream closes.
 *
 * @param parameters - Stream collection parameters.
 */
export function collectStreamOutput(parameters: StreamOutputParameters): void {
  const { command, options, reject, resolve, stream, timer } = parameters
  let stdout = ""
  let stderr = ""

  const secrets = parameters.secrets ?? []
  const stdoutMasker = options.silent ? null : createStreamMasker(writeStdout, secrets)
  const stderrMasker = options.silent ? null : createStreamMasker(writeStderr, secrets)

  stream.on("data", (data: Buffer) => {
    const text = data.toString()
    stdout += text
    stdoutMasker?.push(text)
  })
  stream.stderr.on("data", (data: Buffer) => {
    const text = data.toString()
    stderr += text
    stderrMasker?.push(text)
  })
  stream.on("error", (error: Error) => {
    clearTimeout(timer)
    stdoutMasker?.flush()
    stderrMasker?.flush()
    reject(error)
  })
  stream.on("close", (code: number) => {
    clearTimeout(timer)
    stdoutMasker?.flush()
    stderrMasker?.flush()
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- ssh2 may pass undefined despite type signature
    const exitCode = code ?? 0
    const mask = (text: string): string => maskSecrets(text, parameters.secrets ?? [])
    if (exitCode !== 0 && options.ignoreExitCode !== true) {
      const maskedStdout = mask(stdout)
      const maskedStderr = mask(stderr)
      const wasTruncated =
        codepointLengthExceeds(maskedStdout, MAX_OUTPUT_LENGTH) ||
        codepointLengthExceeds(maskedStderr, MAX_OUTPUT_LENGTH)
      const hint = wasTruncated ? "\n(use --verbose for full output)" : ""
      reject(
        new CommandError(
          `Command failed with exit code ${exitCode}: ${mask(command)}\nstdout: ${truncateOutput(maskedStdout)}\nstderr: ${truncateOutput(maskedStderr)}${hint}`,
          maskedStdout,
          maskedStderr
        )
      )
      return
    }
    resolve({ code: exitCode, stderr: mask(stderr), stdout: mask(stdout) })
  })
}

/** Parameters for a single SSH connection attempt on one port. */
export type ConnectParameters = {
  /** Path to the SSH agent socket (e.g. `SSH_AUTH_SOCK`). Used when no `privateKey` is provided. */
  agent?: string
  /** Forward the local SSH agent to the remote host during this session. */
  agentForward?: boolean
  /** The ssh2 `Client` instance to connect with. */
  client: Client
  /** Hostname or IP address of the remote host. */
  host: string
  /** Optional host key verifier callback for known_hosts checking. */
  hostVerifier?: (key: Buffer) => boolean
  /** Password for keyboard-interactive or password authentication. */
  password?: string
  /** Port to connect on. */
  port: number
  /** PEM-encoded private key content. Mutually exclusive with `agent`. */
  privateKey?: string
  /** Username to authenticate as. */
  username: string
}

/**
 * Build the ssh2 `ConnectConfig` from the connection parameters.
 *
 * @param parameters - Connection parameters.
 * @returns The populated config object.
 */
function buildConnectConfig(parameters: ConnectParameters): ConnectConfig {
  const { agent, agentForward, host, hostVerifier, password, port, privateKey, username } =
    parameters
  const connectConfig: ConnectConfig = {
    host,
    port,
    readyTimeout: CONNECTION_TIMEOUT,
    username,
  }
  if (privateKey != null) {
    connectConfig.privateKey = privateKey
  }
  if (agent != null) {
    connectConfig.agent = agent
  }
  if (agentForward === true) {
    connectConfig.agentForward = true
  }
  if (typeof password === "string") {
    connectConfig.password = password
    connectConfig.tryKeyboard = true
  }
  if (hostVerifier != null) {
    connectConfig.hostVerifier = hostVerifier
  }
  return connectConfig
}

/**
 * Attempt a single SSH connection on a specific port.
 *
 * @param parameters - Connection parameters.
 */
export async function tryConnectOnPort(parameters: ConnectParameters): Promise<void> {
  const { client, port } = parameters
  const connectConfig = buildConnectConfig(parameters)
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      client.end()
      reject(new Error(`Connection timeout on port ${port}`))
    }, CONNECTION_TIMEOUT)

    client.on("ready", () => {
      clearTimeout(timeout)
      resolve()
    })
    client.on("error", (error: Error) => {
      clearTimeout(timeout)
      reject(error)
    })

    client.connect(connectConfig)
  })
}
