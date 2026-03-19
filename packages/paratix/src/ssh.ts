/* eslint-disable max-lines */
import { randomUUID, timingSafeEqual } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { readFile, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, posix } from "node:path"
import { Client, type ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult, SshConfig, SshConnection } from "./types.js"

import { buildHostVerifier, HostKeyVerificationError } from "./knownHosts.js"
import { sftpDownload, sftpUpload } from "./sftp.js"
import {
  collectStreamOutput,
  maskSecrets,
  type SecretSource,
  shellQuote,
  tryConnectOnPort,
  validateMode,
} from "./sshHelpers.js"
import { promptTerminal } from "./terminal.js"

export { shellQuote, validateMode }

/**
 * Validate that a path returned by `mktemp` matches the expected paratix pattern.
 *
 * @param directory - The target directory in which the temp file must be created.
 * @param path - The raw `mktemp` output to validate.
 * @param prefix - The expected Paratix temp-file prefix.
 * @returns The validated path.
 * @throws {Error} When the path does not match the expected pattern.
 */
function validateMktempPath(directory: string, path: string, prefix: string): string {
  const normalizedDirectory = directory === "/" ? "" : directory
  const expectedPrefix = `${normalizedDirectory}/${prefix}.`
  if (!path.startsWith(expectedPrefix) || path.includes("\n") || path.endsWith("/")) {
    throw new Error(`Unexpected mktemp output: ${path}`)
  }
  return path
}

const COMMAND_TIMEOUT = 120_000
const DEFAULT_MAX_RECONNECT_ATTEMPTS = 10
const DEFAULT_RECONNECT_TIMEOUT = 120_000
const JITTER_BASE = 0.75
const JITTER_RANGE = 0.5
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30_000

export class SshConnectionImpl implements SshConnection {
  private agentSocket: null | string = null
  /**
   * Cached sudo password stored as a Buffer so it can be actively zeroed
   * after use via `buffer.fill(0)`.
   *
   * **Limitations:** Buffer zeroing in JavaScript/V8 only reduces the window
   * for potential memory leaks — it cannot eliminate them entirely. The GC may
   * create internal copies. The masking pipeline only materializes a string
   * from this buffer on actual output/error paths. This is a best-effort
   * mitigation, not a guarantee.
   */
  private cachedSudoPassword: Buffer | null = null
  private client: Client | null = null
  private readonly config: SshConfig
  private connectedPort = 0
  private host: string
  private readonly pendingRejects = new Set<(reason: Error) => void>()
  private pinnedHostKey: Buffer | null = null

  public constructor(host: string, config: SshConfig) {
    this.host = host
    this.config = config
    if (
      config.sudoPassword != null &&
      (config.sudoPassword.includes("\n") || config.sudoPassword.includes("\r"))
    ) {
      throw new Error("Sudo password must not contain newline characters")
    }
    this.cachedSudoPassword = config.sudoPassword == null ? null : Buffer.from(config.sudoPassword)
  }

  public addPort(port: number): void {
    if (!this.config.ports.includes(port)) this.config.ports.push(port)
  }

  /**
   * Establish the SSH connection using the configured credentials.
   *
   * Authentication strategy (in order):
   * 1. If `privateKey` is set: connect with the key, optionally falling back to
   *    password authentication when `passwordFallback` is enabled.
   * 2. If `privateKey` is omitted: connect via the SSH agent identified by
   *    `SSH_AUTH_SOCK`, optionally falling back to password authentication
   *    when `passwordFallback` is enabled. Throws if the environment variable
   *    is not set.
   *
   * @throws {Error} When no port in `config.ports` accepts the connection.
   */
  public async connect(): Promise<void> {
    if (this.config.privateKey == null) {
      await this.connectViaAgent()
      return
    }
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const privateKey = await readFile(this.config.privateKey)
    try {
      if (await this.tryConnectOnPorts(privateKey)) return
      if (this.config.passwordFallback) {
        const password = await promptTerminal(
          `Password for ${this.config.user}@${this.host}: `,
          true
        )
        if (await this.tryConnectOnPorts(privateKey, password)) return
      }
      throw new Error(`Failed to connect to ${this.host} on ports: ${this.config.ports.join(", ")}`)
    } finally {
      privateKey.fill(0)
    }
  }

  public disconnect(): void {
    this.clearCachedPassword()
    this.disconnectTransport()
  }

  public async downloadFile(remotePath: string, localPath: string): Promise<void> {
    const client = this.ensureClient()
    let sourcePath = remotePath
    try {
      if (this.config.user !== "root") {
        sourcePath = await this.createRemoteTempPath(
          "mktemp /tmp/paratix-download.XXXXXX",
          "paratix-download"
        )
        await this.exec(`cat ${shellQuote(remotePath)} > ${shellQuote(sourcePath)}`, {
          silent: true,
        })
      }
      await sftpDownload(client, sourcePath, localPath)
    } finally {
      if (sourcePath !== remotePath) {
        try {
          await this.cleanupRemoteTempFile(sourcePath)
        } catch (cleanupError) {
          process.stderr.write(
            `Warning: failed to remove temp file ${sourcePath}: ${maskSecrets(String(cleanupError), this.buildSecrets())}\n`
          )
        }
      }
    }
  }

  public async exec(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = this.ensureClient()
    const environmentPrefix = this.buildEnvPrefix(options.env)
    const { command: cmd, needsPassword } = this.sudoCommand(command, environmentPrefix)
    return new Promise((resolve, reject) => {
      const { wrappedReject, wrappedResolve } = this.createSettledCallbacks<ExecResult>(
        resolve,
        reject
      )
      const timeout = options.timeout ?? COMMAND_TIMEOUT
      const secrets = this.buildSecrets(options.secrets)
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
        collectStreamOutput({
          command,
          options,
          reject: wrappedReject,
          resolve: wrappedResolve,
          secrets,
          stream,
          timer,
        })
        if (needsPassword && this.cachedSudoPassword != null) {
          this.writeSudoPassword(stream)
        }
      })
    })
  }

  public async exists(remotePath: string): Promise<boolean> {
    return this.test(`[ -e ${shellQuote(remotePath)} ]`)
  }

  public getConnectionInfo(): ReturnType<SshConnection["getConnectionInfo"]> {
    return {
      agentSocket: this.agentSocket ?? undefined,
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
    await this.ensureSudoInstalled()
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
    if (password.includes("\n") || password.includes("\r")) {
      throw new Error("Sudo password must not contain newline characters")
    }
    this.cachedSudoPassword = Buffer.from(password)
    try {
      await this.exec("true", { silent: true, timeout: 10_000 })
    } catch (error) {
      const masked = maskSecrets(String(error), [password])
      this.clearCachedPassword()
      throw new Error(`Sudo authentication failed: ${masked}`, { cause: error })
    }
  }

  public async readFile(remotePath: string): Promise<string> {
    return this.output(`cat ${shellQuote(remotePath)}`)
  }

  public async reconnect(): Promise<void> {
    const timeout = this.config.reconnectTimeout ?? DEFAULT_RECONNECT_TIMEOUT
    const maxAttempts = this.config.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT_ATTEMPTS
    const deadline = Date.now() + timeout
    let attempt = 0

    while (Date.now() < deadline && attempt < maxAttempts) {
      try {
        this.disconnectTransport()
        // eslint-disable-next-line no-await-in-loop
        await this.connect()
        return
      } catch (error) {
        if (
          error instanceof HostKeyVerificationError ||
          (error instanceof Error && error.message === "SSH connection closed")
        )
          throw error
        const jitter =
          Math.min(RECONNECT_BASE_DELAY * 2 ** attempt, RECONNECT_MAX_DELAY) *
          (JITTER_BASE + Math.random() * JITTER_RANGE)
        const delay = Math.min(jitter, Math.max(0, deadline - Date.now()))
        // eslint-disable-next-line no-await-in-loop
        await new Promise<void>((resolve) => {
          setTimeout(resolve, delay)
        })
        attempt++
      }
    }
    throw new Error(
      `Failed to reconnect to ${this.host} after ${attempt} attempts (timeout: ${timeout}ms)`
    )
  }

  public removePort(port: number): void {
    this.config.ports = this.config.ports.filter((candidate) => candidate !== port)
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

  public async uploadFile(
    localPath: string,
    remotePath: string,
    options?: { mode?: string }
  ): Promise<void> {
    const client = this.ensureClient()
    const temporaryPath = await this.createRemoteTempPathInDestination(remotePath, "paratix-upload")
    const temporaryMode = options?.mode ?? "0600"
    try {
      await sftpUpload(client, localPath, temporaryPath)
      await this.setRemoteTempMode(temporaryPath, temporaryMode)
      await this.exec(`mv ${shellQuote(temporaryPath)} ${shellQuote(remotePath)}`, { silent: true })
    } finally {
      try {
        await this.cleanupRemoteTempFile(temporaryPath)
      } catch (cleanupError) {
        process.stderr.write(
          `Warning: failed to remove temp file ${temporaryPath}: ${maskSecrets(String(cleanupError), this.buildSecrets())}\n`
        )
      }
    }
  }

  /**
   * Write a string to a remote file atomically via write-to-temp + mv.
   *
   * The content is first written to a local temporary file, uploaded via SFTP
   * to a remote temporary file, then moved to the final destination with `mv`.
   * This ensures the target file is never left in a half-written state.
   *
   * @param remotePath - Destination path on the remote host.
   * @param content - The string content to write.
   * @param options - Optional settings.
   * @param options.mode - File mode to set via `chmod` on the temp file before moving (e.g. `"0644"`).
   */
  public async writeFile(
    remotePath: string,
    content: string,
    options?: { mode?: string }
  ): Promise<void> {
    const client = this.ensureClient()
    const localTemporary = join(tmpdir(), `paratix-write-${randomUUID()}`)
    const remoteTemporary = await this.createRemoteTempPathInDestination(
      remotePath,
      "paratix-write"
    )
    const temporaryMode = options?.mode ?? "0600"
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      writeFileSync(localTemporary, content, { mode: 0o600 })
      await sftpUpload(client, localTemporary, remoteTemporary)
      await this.setRemoteTempMode(remoteTemporary, temporaryMode)
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
        await this.cleanupRemoteTempFile(remoteTemporary)
      } catch (cleanupError) {
        process.stderr.write(
          `Warning: failed to remove temp file ${remoteTemporary}: ${maskSecrets(String(cleanupError), this.buildSecrets())}\n`
        )
      }
    }
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

  private buildSecrets(extra?: string[]): SecretSource[] {
    const cachedPasswordSecret =
      this.cachedSudoPassword == null ? [] : [() => this.cachedSudoPassword?.toString("utf8") ?? ""]
    return [...cachedPasswordSecret, ...(extra ?? [])]
  }

  private async cleanupRemoteTempFile(remotePath: string): Promise<void> {
    const cleanup =
      this.config.user === "root"
        ? this.exec(`rm -f ${shellQuote(remotePath)}`, { silent: true })
        : this.execWithoutSudo(`rm -f ${shellQuote(remotePath)}`)
    await cleanup
  }

  private clearCachedPassword(): void {
    if (this.cachedSudoPassword != null) {
      this.cachedSudoPassword.fill(0)
      this.cachedSudoPassword = null
    }
  }

  private async connectViaAgent(): Promise<void> {
    const agent = process.env.SSH_AUTH_SOCK
    if (agent == null || agent.length === 0) {
      throw new Error("No privateKey configured and SSH_AUTH_SOCK is not set")
    }
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- agent is validated from SSH_AUTH_SOCK env var
      await stat(agent)
    } catch {
      throw new Error(`SSH_AUTH_SOCK points to non-existent path: ${agent}`)
    }
    if (await this.tryConnectOnPorts(undefined, undefined, agent)) {
      this.agentSocket = agent
      return
    }
    if (this.config.passwordFallback) {
      const password = await promptTerminal(`Password for ${this.config.user}@${this.host}: `, true)
      if (await this.tryConnectOnPorts(undefined, password, agent)) {
        this.agentSocket = agent
        return
      }
    }
    throw new Error(
      `Could not connect to ${this.host} via SSH agent on ports ${this.config.ports.join(", ")}`
    )
  }

  private async createRemoteTempPath(command: string, prefix: string): Promise<string> {
    const path =
      this.config.user === "root"
        ? await this.output(command)
        : await this.outputWithoutSudo(command)
    return validateMktempPath("/tmp", path, prefix)
  }

  private async createRemoteTempPathInDestination(
    remotePath: string,
    prefix: string
  ): Promise<string> {
    const directory = posix.dirname(remotePath)
    const template = `${directory}/${prefix}.XXXXXX`
    const command = `mktemp ${shellQuote(template)}`
    const path =
      this.config.user === "root"
        ? await this.output(command)
        : await this.outputWithoutSudo(command)
    return validateMktempPath(directory, path, prefix)
  }

  private createSettledCallbacks<T>(
    resolve: (value: T) => void,
    reject: (reason: Error) => void
  ): { wrappedReject: (reason: Error) => void; wrappedResolve: (value: T) => void } {
    let settled = false
    const wrappedReject = (reason: Error): void => {
      if (settled) return
      settled = true
      this.pendingRejects.delete(wrappedReject)
      reject(reason)
    }
    const wrappedResolve = (value: T): void => {
      if (settled) return
      settled = true
      this.pendingRejects.delete(wrappedReject)
      resolve(value)
    }
    this.pendingRejects.add(wrappedReject)
    return { wrappedReject, wrappedResolve }
  }

  /** Tear down the SSH transport without touching the cached sudo password. */
  private disconnectTransport(): void {
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

  private ensureClient(): Client {
    if (!this.client) throw new Error("SSH not connected")
    return this.client
  }

  /** Verify that `sudo` is available on the remote host. */
  private async ensureSudoInstalled(): Promise<void> {
    const result = await this.execRaw("command -v sudo")
    if (result.exitCode !== 0) {
      throw new Error("sudo is not installed on the remote host")
    }
  }

  /**
   * Execute a command directly over the SSH transport without sudo wrapping.
   * Used only by {@link probeSudo} to check whether `sudo` is installed.
   *
   * @param command - The raw shell command to run.
   * @returns The exit code and captured stdout.
   */
  private async execRaw(command: string): Promise<{ exitCode: number; stdout: string }> {
    const client = this.ensureClient()
    return new Promise((resolve, reject) => {
      const { wrappedReject, wrappedResolve } = this.createSettledCallbacks<{
        exitCode: number
        stdout: string
      }>(resolve, reject)
      let activeStream: ClientChannel | null = null
      const timer = setTimeout(() => {
        activeStream?.close()
        wrappedReject(new Error(`Command timed out after ${COMMAND_TIMEOUT}ms: ${command}`))
      }, COMMAND_TIMEOUT)
      client.exec(command, (error: Error | undefined, stream: ClientChannel) => {
        if (error) {
          clearTimeout(timer)
          wrappedReject(error)
          return
        }
        activeStream = stream
        const chunks: Buffer[] = []
        stream.on("data", (chunk: Buffer) => {
          chunks.push(chunk)
        })
        stream.on("close", (code: number) => {
          clearTimeout(timer)
          wrappedResolve({ exitCode: code, stdout: Buffer.concat(chunks).toString("utf8") })
        })
        stream.stderr.on("data", () => {
          // discard stderr
        })
      })
    })
  }

  private async execWithoutSudo(command: string): Promise<void> {
    const result = await this.execRaw(command)
    if (result.exitCode !== 0) {
      throw new Error(`Command failed (exit code ${result.exitCode}): ${command}`)
    }
  }

  private async outputWithoutSudo(command: string): Promise<string> {
    const result = await this.execRaw(command)
    if (result.exitCode !== 0) {
      throw new Error(`Command failed (exit code ${result.exitCode}): ${command}`)
    }
    return result.stdout.trim()
  }

  private async setRemoteTempMode(remotePath: string, mode: string): Promise<void> {
    validateMode(mode)
    const command = `chmod ${shellQuote(mode)} ${shellQuote(remotePath)}`
    if (this.config.user === "root") {
      await this.exec(command, { silent: true })
      return
    }
    await this.execWithoutSudo(command)
  }

  /**
   * Build the sudo-wrapped command string for execution.
   *
   * @param command - The raw command to execute.
   * @param environmentPrefix - Optional env var prefix string.
   * @returns An object with the final command and whether a password must be written to stdin.
   */
  private sudoCommand(
    command: string,
    environmentPrefix = ""
  ): { command: string; needsPassword: boolean } {
    if (this.config.user === "root") {
      return { command: `${environmentPrefix}${command}`, needsPassword: false }
    }
    const quoted = shellQuote(`${environmentPrefix}${command}`)
    if (this.cachedSudoPassword != null) {
      return { command: `SUDO_PROMPT='' sudo -S bash -c ${quoted}`, needsPassword: true }
    }
    return { command: `sudo bash -c ${quoted}`, needsPassword: false }
  }

  /**
   * Iterate over `config.ports` and attempt a connection on each one.
   *
   * @param privateKey - PEM-encoded private key content, or `undefined` when using agent auth.
   * @param password - Optional password for keyboard-interactive fallback.
   * @param agent - SSH agent socket path (e.g. `SSH_AUTH_SOCK`). Used when `privateKey` is absent.
   * @returns `true` if a port connected successfully, `false` if all ports failed.
   */
  private async tryConnectOnPorts(
    privateKey?: Buffer | string,
    password?: string,
    agent?: string
  ): Promise<boolean> {
    const mode = this.config.strictHostKeyChecking ?? "yes"
    for (const port of this.config.ports) {
      try {
        const client = new Client()
        const { hostVerifier, pendingPersist } = buildHostVerifier(
          mode,
          { host: this.host, port },
          {
            expectedHostFingerprint: this.config.expectedHostFingerprint,
            expectedHostPublicKey: this.config.expectedHostPublicKey,
          }
        )
        const wrappedVerifier = this.wrapHostVerifier(hostVerifier)
        // eslint-disable-next-line no-await-in-loop
        await tryConnectOnPort({
          agent,
          agentForward: this.config.agentForward,
          client,
          host: this.host,
          hostVerifier: wrappedVerifier,
          password,
          port,
          privateKey,
          username: this.config.user,
        })
        // Ensure the host key is persisted to disk before returning
        // eslint-disable-next-line no-await-in-loop
        if (pendingPersist) await pendingPersist
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
      } catch (error) {
        if (error instanceof HostKeyVerificationError) throw error
        // Try next port
      }
    }
    return false
  }

  /**
   * Wrap a host-key verifier to pin the accepted key on first connection and
   * reject key changes on subsequent connections (reconnects).
   *
   * @param original - The original verifier from `buildHostVerifier`, if any.
   * @returns A verifier that enforces host-key pinning.
   */
  private wrapHostVerifier(original?: (key: Buffer) => boolean): (key: Buffer) => boolean {
    return (key: Buffer): boolean => {
      if (
        this.pinnedHostKey != null &&
        (this.pinnedHostKey.length !== key.length || !timingSafeEqual(this.pinnedHostKey, key))
      ) {
        this.clearCachedPassword()
        throw new HostKeyVerificationError(
          `HOST KEY CHANGED on reconnect to ${this.host}: ` +
            "the remote host key does not match the key from the initial connection. " +
            "This could indicate a man-in-the-middle attack."
        )
      }
      if (original != null) {
        const accepted = original(key)
        if (!accepted) return false
      }
      this.pinnedHostKey ??= Buffer.from(key)
      return true
    }
  }

  /**
   * Write the cached sudo password followed by a newline to the given stream.
   *
   * @param stream - The SSH channel to write the password to.
   */
  private writeSudoPassword(stream: ClientChannel): void {
    stream.write(this.cachedSudoPassword)
    stream.write("\n")
  }
}
