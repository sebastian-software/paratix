import type { Client, ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult } from "./types.js"

const CONNECTION_TIMEOUT = 10_000

export type StreamOutputParameters = {
  command: string
  options: ExecOptions
  reject: (reason: Error) => void
  resolve: (value: ExecResult) => void
  stream: ClientChannel
  timer: ReturnType<typeof setTimeout>
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
    if (!options.silent) process.stdout.write(text)
  })
  stream.stderr.on("data", (data: Buffer) => {
    const text = data.toString()
    stderr += text
    if (!options.silent) process.stderr.write(text)
  })
  stream.on("close", (code: number) => {
    clearTimeout(timer)
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- ssh2 may pass undefined despite type signature
    const exitCode = code ?? 0
    if (exitCode !== 0 && options.ignoreExitCode !== true) {
      reject(
        new Error(
          `Command failed with exit code ${exitCode}: ${command}\nstdout: ${stdout}\nstderr: ${stderr}`
        )
      )
      return
    }
    resolve({ code: exitCode, stderr, stdout })
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
    if (password != null) {
      connectConfig.password = password
      connectConfig.tryKeyboard = true
    }
    client.connect(connectConfig as Parameters<Client["connect"]>[0])
  })
}
