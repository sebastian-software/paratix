import { createReadStream, createWriteStream, readFileSync } from "node:fs"
import { Client, type ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult, SshConfig, SshConnection } from "./types.js"

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
const COMMAND_TIMEOUT = 120_000
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30_000
const MAX_RECONNECT_RETRIES = 6
const JITTER_BASE = 0.75
const JITTER_RANGE = 0.5

export class SshConnectionImpl implements SshConnection {
  private client: Client | null = null
  private readonly config: SshConfig
  private connectedPort = 0
  private readonly host: string

  public constructor(host: string, config: SshConfig) {
    this.host = host
    this.config = config
  }

  public addPort(port: number): void {
    if (!this.config.ports.includes(port)) {
      this.config.ports.push(port)
    }
  }

  public async connect(): Promise<void> {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const privateKey = readFileSync(this.config.privateKey, "utf8")

    for (const port of this.config.ports) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await this.tryConnect(port, privateKey)
        this.connectedPort = port
        return
      } catch {
        // Try next port
      }
    }

    throw new Error(`Failed to connect to ${this.host} on ports: ${this.config.ports.join(", ")}`)
  }

  public disconnect(): void {
    if (this.client) {
      this.client.end()
      this.client = null
    }
  }

  public async downloadFile(remotePath: string, localPath: string): Promise<void> {
    const client = this.ensureClient()

    // If non-root, copy to tmp first
    let sourcePath = remotePath
    if (this.config.user !== "root") {
      sourcePath = await this.output("mktemp /tmp/paratix-download.XXXXXX")
      await this.exec(`cp ${shellQuote(remotePath)} ${shellQuote(sourcePath)}`, { silent: true })
      await this.exec(`chmod 644 ${shellQuote(sourcePath)}`, { silent: true })
    }

    await new Promise<void>((resolve, reject) => {
      client.sftp((error, sftp) => {
        if (error) {
          reject(error)
          return
        }

        const readStream = sftp.createReadStream(sourcePath)
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        const writeStream = createWriteStream(localPath)

        writeStream.on("close", () => {
          sftp.end()
          resolve()
        })

        writeStream.on("error", (writeError: Error) => {
          sftp.end()
          reject(writeError)
        })

        readStream.pipe(writeStream)
      })
    })

    // Clean up tmp file
    if (sourcePath !== remotePath) {
      await this.exec(`rm -f ${shellQuote(sourcePath)}`, { silent: true })
    }
  }

  public async exec(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = this.ensureClient()
    const cmd = this.buildEnvPrefix(options.env) + this.sudoCommand(command)

    return new Promise((resolve, reject) => {
      const timeout = options.timeout ?? COMMAND_TIMEOUT
      let activeStream: ClientChannel | null = null
      const timer = setTimeout(() => {
        activeStream?.close()
        reject(new Error(`Command timed out after ${timeout}ms: ${command}`))
      }, timeout)

      client.exec(cmd, (error: Error | undefined, stream: ClientChannel) => {
        if (error) {
          clearTimeout(timer)
          reject(error)
          return
        }
        activeStream = stream
        this.collectStreamOutput({ command, options, reject, resolve, stream, timer })
      })
    })
  }

  public async exists(remotePath: string): Promise<boolean> {
    return this.test(`[ -e ${shellQuote(remotePath)} ]`)
  }

  public getConnectionInfo(): {
    host: string
    port: number
    privateKeyPath: string
    user: string
  } {
    return {
      host: this.host,
      port: this.connectedPort,
      privateKeyPath: this.config.privateKey,
      user: this.config.user,
    }
  }

  public async lines(command: string): Promise<string[]> {
    const out = await this.output(command)
    if (out === "") return []
    return out.split("\n")
  }

  public async output(command: string): Promise<string> {
    const result = await this.exec(command, { silent: true })
    return result.stdout.trim()
  }

  public async readFile(remotePath: string): Promise<string> {
    return this.output(`${this.sudoPrefix()}cat ${shellQuote(remotePath)}`)
  }

  public async reconnect(): Promise<void> {
    for (let attempt = 0; attempt < MAX_RECONNECT_RETRIES; attempt++) {
      try {
        this.disconnect()
        // eslint-disable-next-line no-await-in-loop
        await this.connect()
        return
      } catch {
        const delay = Math.min(RECONNECT_BASE_DELAY * 2 ** attempt, RECONNECT_MAX_DELAY)
        const jitter = delay * (JITTER_BASE + Math.random() * JITTER_RANGE)
        // eslint-disable-next-line no-await-in-loop
        await new Promise<void>((resolve) => {
          setTimeout(resolve, jitter)
        })
      }
    }

    throw new Error(`Failed to reconnect to ${this.host} after ${MAX_RECONNECT_RETRIES} attempts`)
  }

  public async sha256(remotePath: string): Promise<null | string> {
    const exists = await this.test(`[ -f ${shellQuote(remotePath)} ]`)
    if (!exists) return null
    const out = await this.output(`${this.sudoPrefix()}sha256sum ${shellQuote(remotePath)}`)
    return out.split(/\s+/v)[0] ?? null
  }

  public async test(command: string): Promise<boolean> {
    try {
      const result = await this.exec(command, {
        ignoreExitCode: true,
        silent: true,
      })
      return result.code === 0
    } catch {
      return false
    }
  }

  public async uploadFile(localPath: string, remotePath: string): Promise<void> {
    const client = this.ensureClient()

    const temporaryPath = await this.output("mktemp /tmp/paratix-upload.XXXXXX")

    await new Promise<void>((resolve, reject) => {
      client.sftp((error, sftp) => {
        if (error) {
          reject(error)
          return
        }

        // eslint-disable-next-line security/detect-non-literal-fs-filename
        const readStream = createReadStream(localPath)
        const writeStream = sftp.createWriteStream(temporaryPath)

        writeStream.on("close", () => {
          sftp.end()
          resolve()
        })

        writeStream.on("error", (writeError: Error) => {
          sftp.end()
          reject(writeError)
        })

        readStream.pipe(writeStream)
      })
    })

    // Move to final destination with sudo if needed
    await this.exec(`mv ${shellQuote(temporaryPath)} ${shellQuote(remotePath)}`, { silent: true })
  }

  public async writeFile(remotePath: string, content: string): Promise<void> {
    // Use printf | tee for both root and non-root to avoid heredoc injection
    const escaped = shellQuote(content)
    await this.exec(
      `printf '%s' ${escaped} | ${this.sudoPrefix()}tee ${shellQuote(remotePath)} > /dev/null`,
      { silent: true }
    )
  }

  private buildEnvPrefix(environment?: Record<string, string>): string {
    if (environment == null) return ""
    const prefix = Object.entries(environment)
      .map(([k, v]) => `${k}=${shellQuote(v)}`)
      .join(" ")
    return `${prefix} `
  }

  private collectStreamOutput(parameters: {
    command: string
    options: ExecOptions
    reject: (reason: Error) => void
    resolve: (value: ExecResult) => void
    stream: ClientChannel
    timer: ReturnType<typeof setTimeout>
  }): void {
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

  private ensureClient(): Client {
    if (!this.client) {
      throw new Error("SSH not connected")
    }
    return this.client
  }

  private sudoCommand(command: string): string {
    if (this.config.user === "root") {
      return command
    }
    if (this.config.sudoPassword != null) {
      return `printf '%s\\n' ${shellQuote(this.config.sudoPassword)} | sudo -S bash -c ${shellQuote(command)}`
    }
    return `sudo bash -c ${shellQuote(command)}`
  }

  private sudoPrefix(): string {
    return this.config.user === "root" ? "" : "sudo "
  }

  private async tryConnect(port: number, privateKey: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const client = new Client()
      const timeout = setTimeout(() => {
        client.end()
        reject(new Error(`Connection timeout on port ${port}`))
      }, CONNECTION_TIMEOUT)

      client.on("ready", () => {
        clearTimeout(timeout)
        this.client = client
        resolve()
      })

      client.on("error", (error: Error) => {
        clearTimeout(timeout)
        reject(error)
      })

      const connectConfig: Record<string, unknown> = {
        host: this.host,
        port,
        privateKey,
        readyTimeout: CONNECTION_TIMEOUT,
        username: this.config.user,
      }

      if (this.config.passwordFallback && this.config.sudoPassword != null) {
        connectConfig.password = this.config.sudoPassword
        connectConfig.tryKeyboard = true
      }

      client.connect(connectConfig as Parameters<Client["connect"]>[0])
    })
  }
}
