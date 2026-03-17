import { randomUUID } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { readFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Client, type ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult, SshConfig, SshConnection } from "./types.js"

import { sftpDownload, sftpUpload } from "./sftp.js"
import { collectStreamOutput, maskSecrets, tryConnectOnPort } from "./sshHelpers.js"
import { promptTerminal } from "./terminal.js"

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

const SFTP_WRITE_THRESHOLD = 65_536
const COMMAND_TIMEOUT = 120_000
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30_000
const DEFAULT_RECONNECT_TIMEOUT = 120_000
const JITTER_BASE = 0.75
const JITTER_RANGE = 0.5

export class SshConnectionImpl implements SshConnection {
  private cachedSudoPassword: null | string = null
  private client: Client | null = null
  private readonly config: SshConfig
  private connectedPort = 0
  private host: string
  private readonly pendingRejects = new Set<(reason: Error) => void>()

  public constructor(host: string, config: SshConfig) {
    this.host = host
    this.config = config
    this.cachedSudoPassword = config.sudoPassword ?? null
  }

  public addPort(port: number): void {
    if (!this.config.ports.includes(port)) this.config.ports.push(port)
  }

  public async connect(): Promise<void> {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const privateKey = await readFile(this.config.privateKey, "utf8")

    // Attempt 1: Key-based authentication on all ports
    if (await this.tryConnectOnPorts(privateKey)) return

    // Attempt 2: Interactive password fallback (if enabled)
    if (this.config.passwordFallback) {
      const password = await promptTerminal(`Password for ${this.config.user}@${this.host}: `, true)
      if (await this.tryConnectOnPorts(privateKey, password)) return
    }

    throw new Error(`Failed to connect to ${this.host} on ports: ${this.config.ports.join(", ")}`)
  }

  public disconnect(): void {
    if (this.client) {
      this.client.end()
      this.client = null
    }
    const error = new Error("SSH connection closed")
    for (const rejectFunction of this.pendingRejects) {
      rejectFunction(error)
    }
    this.pendingRejects.clear()
  }

  public async downloadFile(remotePath: string, localPath: string): Promise<void> {
    const client = this.ensureClient()
    let sourcePath = remotePath
    if (this.config.user !== "root") {
      sourcePath = await this.output("mktemp /tmp/paratix-download.XXXXXX")
      await this.exec(`cp ${shellQuote(remotePath)} ${shellQuote(sourcePath)}`, { silent: true })
      await this.exec(`chmod 600 ${shellQuote(sourcePath)}`, { silent: true })
    }
    await sftpDownload(client, sourcePath, localPath)
    if (sourcePath !== remotePath) {
      await this.exec(`rm -f ${shellQuote(sourcePath)}`, { silent: true })
    }
  }

  public async exec(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = this.ensureClient()
    const cmd = this.sudoCommand(command, this.buildEnvPrefix(options.env))
    return new Promise((resolve, reject) => {
      let settled = false
      const wrappedResolve = (value: ExecResult): void => {
        if (settled) return
        settled = true
        this.pendingRejects.delete(wrappedReject)
        resolve(value)
      }
      const wrappedReject = (reason: Error): void => {
        if (settled) return
        settled = true
        this.pendingRejects.delete(wrappedReject)
        reject(reason)
      }
      this.pendingRejects.add(wrappedReject)
      const timeout = options.timeout ?? COMMAND_TIMEOUT
      const sudoPw = this.cachedSudoPassword
      const secrets = [...(sudoPw == null ? [] : [sudoPw]), ...(options.secrets ?? [])]
      let activeStream: ClientChannel | null = null
      const timer = setTimeout(() => {
        activeStream?.close()
        wrappedReject(
          new Error(`Command timed out after ${timeout}ms: ${maskSecrets(command, secrets)}`)
        )
      }, timeout)
      client.exec(cmd, (error: Error | undefined, stream: ClientChannel) => {
        if (error) {
          clearTimeout(timer)
          wrappedReject(error)
          return
        }
        activeStream = stream
        // Write sudo password to stdin instead of embedding in command
        if (this.cachedSudoPassword != null && this.config.user !== "root") {
          stream.write(`${this.cachedSudoPassword}\n`)
        }
        collectStreamOutput({
          command,
          options,
          reject: wrappedReject,
          resolve: wrappedResolve,
          secrets,
          stream,
          timer,
        })
      })
    })
  }

  public async exists(remotePath: string): Promise<boolean> {
    return this.test(`[ -e ${shellQuote(remotePath)} ]`)
  }

  public getConnectionInfo(): { host: string; port: number; privateKeyPath: string; user: string } {
    return {
      host: this.host,
      port: this.connectedPort,
      privateKeyPath: this.config.privateKey,
      user: this.config.user,
    }
  }

  public async lines(command: string): Promise<string[]> {
    const out = await this.output(command)
    return out === "" ? [] : out.split("\n")
  }

  public async output(command: string): Promise<string> {
    const result = await this.exec(command, { silent: true })
    return result.stdout.trim()
  }

  /**
   * Probe whether passwordless sudo is available. If not, prompt the user
   * for a password and cache it for the remainder of the run.
   */
  public async probeSudo(): Promise<void> {
    if (this.config.user === "root" || this.cachedSudoPassword != null) return
    try {
      await this.exec("true", { silent: true, timeout: 10_000 })
      return
    } catch {
      // sudo requires a password — prompt interactively
    }
    const password = await promptTerminal(
      `[sudo] password for ${this.config.user}@${this.host}: `,
      true
    )
    this.cachedSudoPassword = password
    try {
      await this.exec("true", { silent: true, timeout: 10_000 })
    } catch (error) {
      this.cachedSudoPassword = null
      throw new Error(`Sudo authentication failed: ${String(error)}`, { cause: error })
    }
  }

  public async readFile(remotePath: string): Promise<string> {
    return this.output(`cat ${shellQuote(remotePath)}`)
  }

  public async reconnect(): Promise<void> {
    const timeout = this.config.reconnectTimeout ?? DEFAULT_RECONNECT_TIMEOUT
    const deadline = Date.now() + timeout
    let attempt = 0

    while (Date.now() < deadline) {
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
        attempt++
      }
    }
    throw new Error(`Failed to reconnect to ${this.host} after ${timeout}ms`)
  }

  public async sha256(remotePath: string): Promise<null | string> {
    const exists = await this.test(`[ -f ${shellQuote(remotePath)} ]`)
    if (!exists) return null
    const out = await this.output(`sha256sum ${shellQuote(remotePath)}`)
    return out.split(/\s+/v)[0] ?? null
  }

  public async test(command: string): Promise<boolean> {
    try {
      const result = await this.exec(command, { ignoreExitCode: true, silent: true })
      return result.code === 0
    } catch {
      return false
    }
  }

  public updateHost(host: string): void {
    this.host = host
  }

  public async uploadFile(localPath: string, remotePath: string): Promise<void> {
    const client = this.ensureClient()
    const temporaryPath = await this.output("mktemp /tmp/paratix-upload.XXXXXX")
    try {
      await sftpUpload(client, localPath, temporaryPath)
      await this.exec(`mv ${shellQuote(temporaryPath)} ${shellQuote(remotePath)}`, { silent: true })
    } finally {
      try {
        await this.exec(`rm -f ${shellQuote(temporaryPath)}`, { silent: true })
      } catch (cleanupError) {
        process.stderr.write(
          `Warning: failed to remove temp file ${temporaryPath}: ${String(cleanupError)}\n`
        )
      }
    }
  }

  public async writeFile(remotePath: string, content: string): Promise<void> {
    if (Buffer.byteLength(content) <= SFTP_WRITE_THRESHOLD) {
      const escaped = shellQuote(content)
      await this.exec(`printf '%s' ${escaped} | tee ${shellQuote(remotePath)} > /dev/null`, {
        silent: true,
      })
      return
    }
    await this.writeFileLarge(remotePath, content)
  }

  private buildEnvPrefix(environment?: Record<string, string>): string {
    if (environment == null) return ""
    for (const key of Object.keys(environment)) {
      if (!/^[A-Za-z_]\w*$/v.test(key)) {
        throw new Error(`Invalid environment variable name: ${key}`)
      }
    }
    const pairs = Object.entries(environment).map(([k, v]) => `${k}=${shellQuote(v)}`)
    return `${pairs.join(" ")} `
  }

  private ensureClient(): Client {
    if (!this.client) throw new Error("SSH not connected")
    return this.client
  }

  private sudoCommand(command: string, environmentPrefix = ""): string {
    if (this.config.user === "root") return `${environmentPrefix}${command}`
    const quoted = shellQuote(`${environmentPrefix}${command}`)
    if (this.cachedSudoPassword != null) {
      return `SUDO_PROMPT='' sudo -S bash -c ${quoted}`
    }
    return `sudo bash -c ${quoted}`
  }

  private async tryConnectOnPorts(privateKey: string, password?: string): Promise<boolean> {
    for (const port of this.config.ports) {
      try {
        const client = new Client()
        // eslint-disable-next-line no-await-in-loop
        await tryConnectOnPort({
          client,
          host: this.host,
          password,
          port,
          privateKey,
          username: this.config.user,
        })
        client.on("close", () => {
          const error = new Error("SSH connection closed unexpectedly")
          for (const rejectFunction of this.pendingRejects) {
            rejectFunction(error)
          }
          this.pendingRejects.clear()
        })
        this.client = client
        this.connectedPort = port
        return true
      } catch {
        // Try next port
      }
    }
    return false
  }

  private async writeFileLarge(remotePath: string, content: string): Promise<void> {
    const client = this.ensureClient()
    const localTemporary = join(tmpdir(), `paratix-write-${randomUUID()}`)
    const remoteTemporary = await this.output("mktemp /tmp/paratix-write.XXXXXX")
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      writeFileSync(localTemporary, content)
      await sftpUpload(client, localTemporary, remoteTemporary)
      await this.exec(`mv ${shellQuote(remoteTemporary)} ${shellQuote(remotePath)}`, {
        silent: true,
      })
    } finally {
      try {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        unlinkSync(localTemporary)
      } catch {
        // local cleanup is best-effort
      }
      try {
        await this.exec(`rm -f ${shellQuote(remoteTemporary)}`, { silent: true })
      } catch (cleanupError) {
        process.stderr.write(
          `Warning: failed to remove temp file ${remoteTemporary}: ${String(cleanupError)}\n`
        )
      }
    }
  }
}
