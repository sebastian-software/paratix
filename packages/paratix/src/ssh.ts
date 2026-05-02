/* eslint-disable max-lines */
import { randomUUID, timingSafeEqual } from "node:crypto"
import { type Stats, unlinkSync, writeFileSync } from "node:fs"
import { readFile, stat } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import { join, posix } from "node:path"
import { Client, type ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult, SshConfig, SshConnection } from "./types.js"

import { buildHostVerifier, extractAlgoFromKey, HostKeyVerificationError } from "./knownHosts.js"
import { sftpDownload, sftpUpload } from "./sftp.js"
import {
  collectStreamOutput,
  maskSecrets,
  normalizeSshCloseCode,
  type SecretSource,
  shellQuote,
  tryConnectOnPort,
  validateMode,
} from "./sshHelpers.js"
import { promptTerminal } from "./terminal.js"

export { shellQuote, validateMode }

async function statLocalFile(path: string): Promise<Stats> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- localPath is an explicit caller-provided upload source that must be stat'ed before transfer
  return stat(path)
}

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

function expandHomePath(path: string): string {
  if (path === "~") return homedir()
  if (path.startsWith("~/")) return join(homedir(), path.slice(2))
  return path
}

function resolveWriteFileMode(
  remotePath: string,
  options: { mode?: string } | null | undefined
): string {
  if (options?.mode == null) {
    throw new Error(
      `[ssh.writeFile: ${remotePath}] missing options.mode; pass { mode: "0644" } or another explicit file mode`
    )
  }

  try {
    validateMode(options.mode)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(
      `[ssh.writeFile: ${remotePath}] invalid options.mode "${options.mode}": ${reason}`,
      { cause: error }
    )
  }

  return options.mode
}

const COMMAND_TIMEOUT = 120_000
const DEFAULT_MAX_RECONNECT_ATTEMPTS = 10
const DEFAULT_RECONNECT_TIMEOUT = 120_000
const JITTER_BASE = 0.75
const JITTER_RANGE = 0.5
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30_000

type AuthMethod = "agent" | "password" | "privateKey" | null
type PromptOptions = { abortSignal?: AbortSignal }

type SshRuntimeState = {
  host: string
  ports: number[]
}

export class SshConnectionImpl implements SshConnection {
  private agentSocket: null | string = null
  private authMethod: AuthMethod = null
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
  private readonly pendingRejects = new Set<(reason: Error) => void>()
  private pinnedHostKey: Buffer | null = null
  private promptAbortSignal: AbortSignal | undefined
  private readonly runtime: SshRuntimeState
  private sudoProbePromise: null | Promise<void> = null
  private sudoReady = false
  private verifiedHostKey: Buffer | null = null

  public constructor(host: string, config: SshConfig) {
    this.runtime = {
      host,
      ports: [...config.ports],
    }
    this.config = {
      ...config,
      ports: [...config.ports],
    }
    if (
      config.sudoPassword != null &&
      (config.sudoPassword.includes("\n") || config.sudoPassword.includes("\r"))
    ) {
      throw new Error("Sudo password must not contain newline characters")
    }
    this.cachedSudoPassword = config.sudoPassword == null ? null : Buffer.from(config.sudoPassword)
  }

  public addPort(port: number): void {
    if (!this.runtime.ports.includes(port)) this.runtime.ports.push(port)
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
   * @param options - Optional prompt behavior for interactive password fallback.
   * @throws {Error} When no port in `config.ports` accepts the connection.
   */
  public async connect(options?: PromptOptions): Promise<void> {
    this.promptAbortSignal = options?.abortSignal
    if (this.config.privateKey == null) {
      await this.connectViaAgent(options)
      return
    }
    await this.connectViaPrivateKey(options)
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
    await this.ensureSudoReady()
    return this.execPrepared(command, options)
  }

  public async exists(remotePath: string): Promise<boolean> {
    return this.test(`[ -e ${shellQuote(remotePath)} ]`)
  }

  public getConnectionInfo(): ReturnType<SshConnection["getConnectionInfo"]> {
    return {
      agentSocket: this.authMethod === "agent" ? (this.agentSocket ?? undefined) : undefined,
      authMethod: this.authMethod ?? undefined,
      host: this.runtime.host,
      port: this.connectedPort,
      privateKeyPath:
        this.authMethod === "privateKey" && this.config.privateKey != null
          ? expandHomePath(this.config.privateKey)
          : undefined,
      user: this.config.user,
      verifiedHostPublicKey:
        this.verifiedHostKey == null
          ? undefined
          : `${extractAlgoFromKey(this.verifiedHostKey)} ${this.verifiedHostKey.toString("base64")}`,
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
   *
   * @param options - Optional prompt behavior for the interactive sudo password prompt.
   */
  public async probeSudo(options?: PromptOptions): Promise<void> {
    this.promptAbortSignal = options?.abortSignal ?? this.promptAbortSignal
    if (this.isSudoReadyWithoutProbe()) {
      this.sudoReady = true
      return
    }
    await this.ensureSudoInstalled()
    if (await this.hasPasswordlessSudo()) {
      this.sudoReady = true
      return
    }
    await this.promptAndCacheSudoPassword()
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
      `Failed to reconnect to ${this.runtime.host} after ${attempt} attempts (timeout: ${timeout}ms)`
    )
  }

  public removePort(port: number): void {
    this.runtime.ports = this.runtime.ports.filter((candidate) => candidate !== port)
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
    this.runtime.host = host
  }

  public async uploadFile(
    localPath: string,
    remotePath: string,
    options?: { mode?: string }
  ): Promise<void> {
    const client = this.ensureClient()
    const localFileStats = await statLocalFile(localPath)
    const localFileSize = localFileStats.size
    const temporaryPath = await this.createRemoteWritableTempPath(remotePath, "paratix-upload")
    const temporaryMode = options?.mode ?? "0600"
    try {
      await sftpUpload(client, localPath, temporaryPath)
      await this.setRemoteTempMode(temporaryPath, temporaryMode)
      await this.finalizeRemoteTempFile(temporaryPath, remotePath, temporaryMode)
      await this.assertRemoteFileSize(remotePath, localFileSize)
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
   * @param options - Settings for the remote write.
   * @param options.mode - File mode to set via `chmod` on the temp file before moving (e.g. `"0644"`).
   */
  public async writeFile(
    remotePath: string,
    content: string,
    options: { mode: string }
  ): Promise<void> {
    const client = this.ensureClient()
    const localTemporary = join(tmpdir(), `paratix-write-${randomUUID()}`)
    const remoteTemporary = await this.createRemoteWritableTempPath(remotePath, "paratix-write")
    const temporaryMode = resolveWriteFileMode(
      remotePath,
      options as { mode?: string } | null | undefined
    )
    const expectedSize = Buffer.byteLength(content, "utf8")
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      writeFileSync(localTemporary, content, { mode: 0o600 })
      await sftpUpload(client, localTemporary, remoteTemporary)
      await this.setRemoteTempMode(remoteTemporary, temporaryMode)
      await this.finalizeRemoteTempFile(remoteTemporary, remotePath, temporaryMode)
      await this.ensureRemoteWriteFile({
        content,
        expectedSize,
        mode: temporaryMode,
        remotePath,
      })
    } finally {
      await this.cleanupWriteFileTemporaryPaths(localTemporary, remoteTemporary)
    }
  }

  private async assertRemoteFileSize(remotePath: string, expectedSize: number): Promise<void> {
    const rawSize = await this.output(`stat -c '%s' ${shellQuote(remotePath)}`)
    const actualSize = Number(rawSize.trim())

    if (!Number.isFinite(actualSize)) {
      throw new TypeError(
        `[ssh.uploadFile: ${remotePath}] could not determine remote file size after upload`
      )
    }

    if (actualSize === 0 && expectedSize > 0) {
      const diskInfo = await this.checkRemoteDiskSpace(remotePath)
      if (diskInfo != null && diskInfo.availableBytes < expectedSize) {
        throw new Error(
          `[ssh.uploadFile: ${remotePath}] disk full – ${diskInfo.availableBytes} bytes available on ${diskInfo.mountpoint}; the file was written as 0 bytes because there is no space left on the device`
        )
      }
    }

    if (actualSize !== expectedSize) {
      throw new Error(
        `[ssh.uploadFile: ${remotePath}] remote file size mismatch after upload/finalize; expected ${expectedSize} bytes, got ${actualSize}`
      )
    }
  }

  private async checkRemoteDiskSpace(
    remotePath: string
  ): Promise<{ availableBytes: number; mountpoint: string } | null> {
    const DF_MIN_COLUMNS = 6
    const DF_AVAILABLE_INDEX = 3
    const DF_MOUNTPOINT_INDEX = 5
    const KB_TO_BYTES = 1024
    try {
      const directory = remotePath.includes("/")
        ? remotePath.slice(0, remotePath.lastIndexOf("/")) || "/"
        : "."
      const dfOutput = await this.output(`df -P ${shellQuote(directory)}`)
      const lines = dfOutput.trim().split("\n")
      if (lines.length < 2) return null
      const columns = lines[1].split(/\s+/v)
      if (columns.length < DF_MIN_COLUMNS) return null
      const availableKb = Number(columns[DF_AVAILABLE_INDEX])
      if (!Number.isFinite(availableKb)) return null
      return { availableBytes: availableKb * KB_TO_BYTES, mountpoint: columns[DF_MOUNTPOINT_INDEX] }
    } catch {
      return null
    }
  }

  /* eslint-disable perfectionist/sort-classes -- writeFile recovery helpers stay grouped for this fix */
  private async cleanupWriteFileTemporaryPaths(
    localTemporary: string,
    remoteTemporary: string
  ): Promise<void> {
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

  private async cleanupPrivilegedRemoteTempFile(remotePath: string): Promise<void> {
    await this.exec(`rm -f ${shellQuote(remotePath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
  }

  private async createRemotePrivilegedTempPathInDestination(
    remotePath: string,
    prefix: string
  ): Promise<string> {
    const directory = posix.dirname(remotePath)
    const template = `${directory}/${prefix}.XXXXXX`
    const path = await this.output(`mktemp ${shellQuote(template)}`)
    return validateMktempPath(directory, path, prefix)
  }

  private async ensureRemoteWriteFile(options: {
    content: string
    expectedSize: number
    mode: string
    remotePath: string
  }): Promise<void> {
    const verification = await this.verifyRemoteWriteFile(options.remotePath, options.expectedSize)
    if (verification === "matches") return

    await this.rewriteRemoteFileViaShell(options.remotePath, options.content, options.mode)
    const fallbackVerification = await this.verifyRemoteWriteFile(
      options.remotePath,
      options.expectedSize
    )
    if (fallbackVerification === "matches") return
    if (fallbackVerification === "empty") {
      const diskInfo = await this.checkRemoteDiskSpace(options.remotePath)
      if (diskInfo != null && diskInfo.availableBytes < options.expectedSize) {
        throw new Error(
          `[ssh.writeFile: ${options.remotePath}] disk full – ${diskInfo.availableBytes} bytes available on ${diskInfo.mountpoint}; the file was written as 0 bytes because there is no space left on the device`
        )
      }
      throw new Error(
        `[ssh.writeFile: ${options.remotePath}] remote file is empty after upload/finalize and shell fallback; refusing successful write result`
      )
    }
    throw new Error(
      `[ssh.writeFile: ${options.remotePath}] remote file size mismatch after upload/finalize and shell fallback; expected ${options.expectedSize} bytes`
    )
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

  private async cacheAndValidateSudoPassword(password: string): Promise<void> {
    if (password.includes("\n") || password.includes("\r")) {
      throw new Error("Sudo password must not contain newline characters")
    }
    this.cachedSudoPassword = Buffer.from(password)
    try {
      await this.execPrepared("true", { silent: true, timeout: 10_000 })
      this.sudoReady = true
    } catch (error) {
      const masked = maskSecrets(String(error), [password])
      this.clearCachedPassword()
      throw new Error(`Sudo authentication failed: ${masked}`, { cause: error })
    }
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

  private async connectViaAgent(options?: PromptOptions): Promise<void> {
    const agent = process.env.SSH_AUTH_SOCK
    if (agent == null || agent.length === 0) {
      if (await this.tryPasswordFallback(options)) return
      if (this.config.passwordFallback) {
        throw new Error(
          `Failed to connect to ${this.runtime.host} on ports: ${this.runtime.ports.join(", ")}`
        )
      }
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
      this.authMethod = "agent"
      return
    }
    if (await this.tryPasswordFallback(options, agent)) return
    throw new Error(
      `Could not connect to ${this.runtime.host} via SSH agent on ports ${this.runtime.ports.join(", ")}`
    )
  }

  private async connectViaPrivateKey(options?: PromptOptions): Promise<void> {
    const privateKeyPath = this.config.privateKey
    if (privateKeyPath == null) {
      throw new Error("connectViaPrivateKey requires config.privateKey")
    }
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const privateKey = await readFile(expandHomePath(privateKeyPath))
    try {
      if (await this.tryConnectOnPorts(privateKey)) {
        this.authMethod = "privateKey"
        return
      }
      if (this.config.passwordFallback) {
        const password = await promptTerminal(
          `Password for ${this.config.user}@${this.runtime.host}: `,
          true,
          options
        )
        if (await this.tryConnectOnPorts(privateKey, password)) {
          this.authMethod = "password"
          return
        }
      }
      throw new Error(
        `Failed to connect to ${this.runtime.host} on ports: ${this.runtime.ports.join(", ")}`
      )
    } finally {
      privateKey.fill(0)
    }
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

  private async createRemoteWritableTempPath(remotePath: string, prefix: string): Promise<string> {
    if (this.config.user === "root") {
      return this.createRemoteTempPathInDestination(remotePath, prefix)
    }
    return this.createRemoteTempPath(`mktemp '/tmp/${prefix}.XXXXXX'`, prefix)
  }

  private createSettledCallbacks<T>(
    resolve: (value: T) => void,
    reject: (reason: Error) => void
  ): {
    isSettled: () => boolean
    wrappedReject: (reason: Error) => void
    wrappedResolve: (value: T) => void
  } {
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
    return { isSettled: () => settled, wrappedReject, wrappedResolve }
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

  private async ensureSudoReady(): Promise<void> {
    if (this.config.user === "root" || this.sudoReady) return
    if (this.cachedSudoPassword != null) {
      this.sudoReady = true
      return
    }
    if (this.sudoProbePromise != null) {
      await this.sudoProbePromise
      return
    }
    this.sudoProbePromise = this.probeSudo({ abortSignal: this.promptAbortSignal }).finally(() => {
      this.sudoProbePromise = null
    })
    await this.sudoProbePromise
  }

  private async execPrepared(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = this.ensureClient()
    const environmentPrefix = this.buildEnvPrefix(options.env)
    const { command: cmd, needsPassword } = this.sudoCommand(command, environmentPrefix)
    return new Promise((resolve, reject) => {
      const { isSettled, wrappedReject, wrappedResolve } = this.createSettledCallbacks<ExecResult>(
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
        // If the timer already fired (or the promise was otherwise settled) before
        // ssh2 invoked this callback, we must not attach listeners that can never
        // resolve the already-rejected promise. Close the stream immediately so
        // ssh2 releases the channel and discards any buffered data.
        if (isSettled()) {
          stream.close()
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
      const { isSettled, wrappedReject, wrappedResolve } = this.createSettledCallbacks<{
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
        // If the timer already fired (or the promise was otherwise settled) before
        // ssh2 invoked this callback, we must not attach listeners that can never
        // resolve the already-rejected promise. Close the stream immediately so
        // ssh2 releases the channel and discards any buffered data.
        if (isSettled()) {
          stream.close()
          return
        }
        activeStream = stream
        const chunks: Buffer[] = []
        stream.on("data", (chunk: Buffer) => {
          chunks.push(chunk)
        })
        stream.on("close", (code: number) => {
          clearTimeout(timer)
          wrappedResolve({
            exitCode: normalizeSshCloseCode(code),
            stdout: Buffer.concat(chunks).toString("utf8"),
          })
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

  private async finalizeRemoteTempFile(
    temporaryPath: string,
    remotePath: string,
    mode: string
  ): Promise<void> {
    validateMode(mode)
    if (this.config.user === "root") {
      await this.exec(`mv ${shellQuote(temporaryPath)} ${shellQuote(remotePath)}`, {
        silent: true,
      })
      return
    }

    const directory = posix.dirname(remotePath)
    const basename = posix.basename(remotePath)
    const finalTemplate = `${directory}/.${basename}.paratix.XXXXXX`
    const finalizeScript = `
target_owner=$(stat -c '%u:%g' ${shellQuote(remotePath)} 2>/dev/null || printf '0:0')
target_temp=''
cleanup() {
  if [ -n "$target_temp" ]; then
    rm -f "$target_temp"
  fi
}
trap cleanup EXIT
target_temp=$(mktemp ${shellQuote(finalTemplate)})
mv ${shellQuote(temporaryPath)} "$target_temp"
chmod ${shellQuote(mode)} "$target_temp"
chown "$target_owner" "$target_temp"
mv "$target_temp" ${shellQuote(remotePath)}
trap - EXIT
`
    await this.exec(finalizeScript, { silent: true })
  }

  private async hasPasswordlessSudo(): Promise<boolean> {
    try {
      await this.execPrepared("true", { silent: true, timeout: 10_000 })
      return true
    } catch {
      return false
    }
  }

  private isSudoReadyWithoutProbe(): boolean {
    return this.config.user === "root" || this.cachedSudoPassword != null
  }

  private async outputWithoutSudo(command: string): Promise<string> {
    const result = await this.execRaw(command)
    if (result.exitCode !== 0) {
      throw new Error(`Command failed (exit code ${result.exitCode}): ${command}`)
    }
    return result.stdout.trim()
  }

  private async promptAndCacheSudoPassword(): Promise<void> {
    const password = await promptTerminal(
      `[sudo] password for ${this.config.user}@${this.runtime.host}: `,
      true,
      { abortSignal: this.promptAbortSignal }
    )
    await this.cacheAndValidateSudoPassword(password)
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
    for (const port of this.runtime.ports) {
      try {
        const client = new Client()
        const verifier = buildHostVerifier(
          mode,
          { host: this.runtime.host, port },
          {
            expectedHostFingerprint: this.config.expectedHostFingerprint,
            expectedHostPublicKey: this.config.expectedHostPublicKey,
          }
        )
        const wrappedVerifier = this.wrapHostVerifier(verifier.hostVerifier)
        // eslint-disable-next-line no-await-in-loop
        await tryConnectOnPort({
          agent,
          agentForward: this.config.agentForward,
          client,
          host: this.runtime.host,
          hostVerifier: wrappedVerifier,
          password,
          port,
          privateKey,
          username: this.config.user,
        })
        // Ensure the host key is persisted to disk before returning
        // eslint-disable-next-line no-await-in-loop
        if (verifier.pendingPersist != null) await verifier.pendingPersist
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

  private async tryPasswordFallback(options?: PromptOptions, agent?: string): Promise<boolean> {
    if (!this.config.passwordFallback) return false
    const password = await promptTerminal(
      `Password for ${this.config.user}@${this.runtime.host}: `,
      true,
      options
    )
    if (!(await this.tryConnectOnPorts(undefined, password, agent))) return false
    this.authMethod = "password"
    return true
  }

  private async rewriteRemoteFileViaShell(
    remotePath: string,
    content: string,
    mode: string
  ): Promise<void> {
    const remoteTemporary = await this.createRemotePrivilegedTempPathInDestination(
      remotePath,
      "paratix-write"
    )
    const encodedContent = Buffer.from(content, "utf8").toString("base64")

    try {
      await this.exec(
        `printf '%s' ${shellQuote(encodedContent)} | base64 -d > ${shellQuote(remoteTemporary)}`,
        { silent: true }
      )
      await this.exec(`chmod ${shellQuote(mode)} ${shellQuote(remoteTemporary)}`, { silent: true })
      await this.finalizeRemoteTempFile(remoteTemporary, remotePath, mode)
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      throw new Error(`[ssh.writeFile: ${remotePath}] shell fallback write failed: ${reason}`, {
        cause: error,
      })
    } finally {
      try {
        await this.cleanupPrivilegedRemoteTempFile(remoteTemporary)
      } catch (cleanupError) {
        process.stderr.write(
          `Warning: failed to remove temp file ${remoteTemporary}: ${maskSecrets(String(cleanupError), this.buildSecrets())}\n`
        )
      }
    }
  }

  private async verifyRemoteWriteFile(
    remotePath: string,
    expectedSize: number
  ): Promise<"empty" | "matches" | "size-mismatch"> {
    const rawSize = await this.output(`stat -c '%s' ${shellQuote(remotePath)}`)
    const actualSize = Number(rawSize.trim())

    if (!Number.isFinite(actualSize)) {
      throw new TypeError(
        `[ssh.writeFile: ${remotePath}] could not determine remote file size after upload/finalize`
      )
    }

    if (expectedSize === 0 && actualSize === 0) return "matches"
    if (actualSize === 0) return "empty"
    return actualSize === expectedSize ? "matches" : "size-mismatch"
  }
  /* eslint-enable perfectionist/sort-classes */

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
          `HOST KEY CHANGED on reconnect to ${this.runtime.host}: ` +
            "the remote host key does not match the key from the initial connection. " +
            "This could indicate a man-in-the-middle attack."
        )
      }
      if (original != null) {
        const accepted = original(key)
        if (!accepted) return false
        this.verifiedHostKey ??= Buffer.from(key)
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
