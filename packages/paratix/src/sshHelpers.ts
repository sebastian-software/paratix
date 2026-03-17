import type { Client, ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult } from "./types.js"

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
 * Wire up event listeners on an ssh2 stream to collect stdout/stderr
 * and resolve or reject the promise when the stream closes.
 *
 * @param parameters - Stream collection parameters.
 */
export function collectStreamOutput(parameters: StreamOutputParameters): void {
  const { command, options, reject, resolve, stream, timer } = parameters
  let stdout = ""
  let stderr = ""

  stream.on("data", (data: Buffer) => {
    const text = data.toString()
    stdout += text
    if (!options.silent) process.stdout.write(maskSecrets(text, parameters.secrets ?? []))
  })
  stream.stderr.on("data", (data: Buffer) => {
    const text = data.toString()
    stderr += text
    if (!options.silent) process.stderr.write(maskSecrets(text, parameters.secrets ?? []))
  })
  stream.on("error", (error: Error) => {
    clearTimeout(timer)
    reject(error)
  })
  stream.on("close", (code: number) => {
    clearTimeout(timer)
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

export type ConnectParameters = {
  client: Client
  host: string
  password?: string
  port: number
  privateKey: string
  username: string
}

/**
 * Attempt a single SSH connection on a specific port.
 *
 * @param parameters - Connection parameters.
 */
export async function tryConnectOnPort(parameters: ConnectParameters): Promise<void> {
  const { client, host, password, port, privateKey, username } = parameters
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

    const connectConfig: Record<string, unknown> = {
      host,
      port,
      privateKey,
      readyTimeout: CONNECTION_TIMEOUT,
      username,
    }
    if (typeof password === "string") {
      connectConfig.password = password
      connectConfig.tryKeyboard = true
    }
    client.connect(connectConfig as Parameters<Client["connect"]>[0])
  })
}
