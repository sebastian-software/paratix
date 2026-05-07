/* eslint-disable max-lines -- SSH transport methods keep callback wiring local */
import type { Stats } from "node:fs"

import { timingSafeEqual } from "node:crypto"
import { readFile, stat } from "node:fs/promises"
import { homedir } from "node:os"
import { join, posix } from "node:path"
import { Client, type ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult, SshConfig, SshConnection } from "./types.js"

import {
  buildHostVerifier,
  extractAlgoFromKey,
  HostKeyVerificationError,
  type HostVerifierResult,
} from "./knownHosts.js"
import { getRegisteredSecrets, withRegisteredSecrets } from "./secretSink.js"
import { sftpDownload, sftpUpload, sftpUploadContent } from "./sftp.js"
import {
  cleanupFailedSshClient,
  collectStreamOutput,
  maskPreparedSecrets,
  maskSecrets,
  normalizeSshCloseCode,
  prepareSecrets,
  type SecretSource,
  shellQuote,
  tryConnectOnPort,
  validateMode,
} from "./sshHelpers.js"
import { promptTerminal } from "./terminal.js"

export { shellQuote, validateMktempPath, validateMode }

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
type ConnectOptions = { reconnectDeadline?: number } & PromptOptions
type TryConnectOnPortsOptions = {
  agent?: string
  password?: string
  privateKey?: Buffer | string
  reconnectDeadline?: number
}
type HostKeyAttempt = {
  commit: () => void
  hostVerifier: (key: Buffer) => boolean
}

type SshRuntimeState = {
  host: string
  ports: number[]
}

function getAbortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("SSH operation aborted")
}

function hasReconnectDeadlineExpired(reconnectDeadline?: number): boolean {
  return reconnectDeadline != null && reconnectDeadline <= Date.now()
}

function getRemainingReconnectTimeout(reconnectDeadline?: number): number | undefined {
  return reconnectDeadline == null ? undefined : reconnectDeadline - Date.now()
}

async function sleepWithAbort(delay: number, abortSignal?: AbortSignal): Promise<void> {
  if (delay <= 0) return
  if (abortSignal?.aborted === true) throw getAbortReason(abortSignal)
  if (abortSignal == null) {
    await new Promise<void>((resolve) => {
      setTimeout(resolve, delay)
    })
    return
  }

  await new Promise<void>((resolve, reject) => {
    const handleAbort = (): void => {
      clearTimeout(timer)
      cleanup()
      reject(getAbortReason(abortSignal))
    }
    const cleanup = (): void => {
      abortSignal.removeEventListener("abort", handleAbort)
    }
    const timer = setTimeout(() => {
      cleanup()
      resolve()
    }, delay)

    abortSignal.addEventListener("abort", handleAbort, { once: true })
  })
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
  /**
   * Tracks whether the remote host accepts passwordless sudo for the configured
   * user. Set to `true` after a successful `sudo -n true` probe (see
   * `hasPasswordlessSudo`). Used by `sudoCommand()` to safely route stdin
   * payloads via `sudo -n bash -c` only when no real password challenge would
   * appear; when a sudo password is required, `sudo -S` cannot share a single
   * stdin channel with caller-provided input and the call must fail-closed.
   */
  private passwordlessSudo = false
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

  public addPort(port: number): boolean {
    if (this.runtime.ports.includes(port)) return false
    this.runtime.ports.push(port)
    return true
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
  public async connect(options?: ConnectOptions): Promise<void> {
    // R-0000090: only overwrite the cached prompt signal when the caller
    // actually passed one. `reconnect()` calls `connect()` without options;
    // unconditionally writing `undefined` would silently discard the signal
    // installed by an earlier `connect()` / `probeSudo()` call and break the
    // graceful-shutdown path during reconnect attempts.
    if (options?.abortSignal !== undefined) {
      this.promptAbortSignal = options.abortSignal
    }
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
    const result = await this.exec(`cat ${shellQuote(remotePath)}`, { silent: true })
    return result.stdout
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
        await this.connect({ reconnectDeadline: deadline })
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
        await sleepWithAbort(delay, this.promptAbortSignal)
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
    const result = await this.exec(command, { ignoreExitCode: true, silent: true })
    return result.code === 0
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
   * The content is streamed via SFTP to a remote temporary file, then moved to
   * the final destination with `mv`. This ensures the target file is never
   * left in a half-written state.
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
    const remoteTemporary = await this.createRemoteWritableTempPath(remotePath, "paratix-write")
    const temporaryMode = resolveWriteFileMode(remotePath, options)
    const expectedSize = Buffer.byteLength(content, "utf8")
    try {
      await sftpUploadContent(client, content, remoteTemporary)
      await this.setRemoteTempMode(remoteTemporary, temporaryMode)
      await this.finalizeRemoteTempFile(remoteTemporary, remotePath, temporaryMode)
      await this.ensureRemoteWriteFile({
        content,
        expectedSize,
        mode: temporaryMode,
        remotePath,
      })
    } finally {
      await this.cleanupWriteFileTemporaryPath(remoteTemporary)
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
  private async cleanupWriteFileTemporaryPath(remoteTemporary: string): Promise<void> {
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
    // R-0000092: include the process-wide secret sink (op tokens, signed
    // download URLs, user password hashes, ...) so every consumer of
    // `buildSecrets` — including the cleanup-warning path — masks the same
    // material that `printCommandFailure` would mask. Snapshot the registered
    // values at call time so each one is treated as an independent secret
    // variant by the masking pipeline.
    const registeredSecrets: SecretSource[] = getRegisteredSecrets()
    return [...cachedPasswordSecret, ...registeredSecrets, ...(extra ?? [])]
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

  private async agentSocketExists(agent: string): Promise<boolean> {
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- agent is validated from SSH_AUTH_SOCK env var
      await stat(agent)
      return true
    } catch {
      return false
    }
  }

  private async connectViaAgent(options?: ConnectOptions): Promise<void> {
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
    if (!(await this.agentSocketExists(agent))) {
      if (await this.tryPasswordFallback(options)) return
      throw new Error(`SSH_AUTH_SOCK points to non-existent path: ${agent}`)
    }
    if (await this.tryConnectOnPorts({ agent, reconnectDeadline: options?.reconnectDeadline })) {
      this.agentSocket = agent
      this.authMethod = "agent"
      return
    }
    if (await this.tryPasswordFallback(options, agent)) return
    throw new Error(
      `Could not connect to ${this.runtime.host} via SSH agent on ports ${this.runtime.ports.join(", ")}`
    )
  }

  private async connectViaPrivateKey(options?: ConnectOptions): Promise<void> {
    const privateKeyPath = this.config.privateKey
    if (privateKeyPath == null) {
      throw new Error("connectViaPrivateKey requires config.privateKey")
    }
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    const privateKey = await readFile(expandHomePath(privateKeyPath))
    try {
      if (
        await this.tryConnectOnPorts({
          privateKey,
          reconnectDeadline: options?.reconnectDeadline,
        })
      ) {
        this.authMethod = "privateKey"
        return
      }
      if (await this.tryPrivateKeyPasswordFallback(privateKey, options)) return
      throw new Error(
        `Failed to connect to ${this.runtime.host} on ports: ${this.runtime.ports.join(", ")}`
      )
    } finally {
      privateKey.fill(0)
    }
  }

  /**
   * Prompt for a password and retry the connect using both the loaded
   * private key and the prompt response. R-0000095: the prompt response is
   * registered in the process-wide secret sink for the duration of the
   * connect attempt so any thrown diagnostic masks the credential.
   *
   * @param privateKey - The loaded private key buffer to combine with the prompt response.
   * @param options - Prompt options (e.g. abort signal) forwarded from `connect()`.
   * @returns `true` when the password attempt succeeded, `false` when the fallback was disabled or all ports refused the credential.
   */
  private async tryPrivateKeyPasswordFallback(
    privateKey: Buffer,
    options?: ConnectOptions
  ): Promise<boolean> {
    if (!this.config.passwordFallback) return false
    const password = await promptTerminal(
      `Password for ${this.config.user}@${this.runtime.host}: `,
      true,
      options
    )
    const accepted = await withRegisteredSecrets([password], async () =>
      this.tryConnectOnPorts({
        password,
        privateKey,
        reconnectDeadline: options?.reconnectDeadline,
      })
    )
    if (!accepted) return false
    this.authMethod = "password"
    return true
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

  /**
   * Forward sudo password / `options.input` to a stream while tolerating
   * EPIPE errors that may arrive between the `isSettled()` check and the
   * actual write call (R-0000054). The stream is owned by ssh2 and may
   * have been closed by the timeout path; emitting an `error` event on a
   * closed channel without a listener would crash the process.
   *
   * @param stream - The ssh2 channel that just became available.
   * @param needsPassword - Whether the command needs a sudo password.
   * @param input - Optional stdin payload from the caller.
   */
  private writeStreamInput(
    stream: ClientChannel,
    needsPassword: boolean,
    input: ExecOptions["input"]
  ): void {
    // R-0000054: attach an EPIPE-safe error handler before any subsequent
    // write to the stream. The settle path (timeout / remote close)
    // already owns the rejection reason; later stream errors are dropped.
    stream.once("error", () => {
      // Defensive no-op.
    })
    if (needsPassword && this.cachedSudoPassword != null) {
      try {
        this.writeSudoPassword(stream)
      } catch {
        // Defense in depth: a synchronous EPIPE during write must not
        // propagate — the timer / remote-close path owns the rejection.
      }
    }
    if (input != null) {
      try {
        stream.end(input)
      } catch {
        // Defense in depth: same as writeSudoPassword above.
      }
    }
  }

  private async execPrepared(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = this.ensureClient()
    const environmentPrefix = this.buildEnvPrefix(options.env)
    const { command: cmd, needsPassword } = this.sudoCommand(
      command,
      environmentPrefix,
      options.input != null
    )
    const secrets = prepareSecrets(this.buildSecrets(options.secrets))
    return new Promise((resolve, reject) => {
      const { isSettled, wrappedReject, wrappedResolve } = this.createSettledCallbacks<ExecResult>(
        resolve,
        reject
      )
      const timeout = options.timeout ?? COMMAND_TIMEOUT
      let activeStream: ClientChannel | null = null
      const timer = setTimeout(() => {
        activeStream?.close()
        wrappedReject(
          new Error(
            `Command timed out after ${timeout}ms: ${maskPreparedSecrets(command, secrets)}`
          )
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
        this.writeStreamInput(stream, needsPassword, options.input)
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
        stream.on("close", (code: null | number | undefined, signal?: null | string) => {
          clearTimeout(timer)
          if (signal != null && signal !== "") {
            wrappedReject(new Error(`Command failed with signal ${signal}: ${command}`))
            return
          }
          wrappedResolve({
            exitCode: normalizeSshCloseCode(code),
            stdout: Buffer.concat(chunks).toString("utf8"),
          })
        })
        // R-0000089: attach error listeners on both the stream and its stderr
        // channel. ssh2 emits `error` (e.g. EPIPE during the sudo probe path)
        // synchronously and an unhandled `error` on a ClientChannel crashes
        // the process. Pattern mirrors `collectStreamOutput` in sshHelpers.ts.
        stream.on("error", (error: Error) => {
          clearTimeout(timer)
          wrappedReject(error)
        })
        stream.stderr.on("data", () => {
          // discard stderr
        })
        stream.stderr.on("error", (error: Error) => {
          clearTimeout(timer)
          wrappedReject(error)
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
    const targetGuard = `[ ! -d ${shellQuote(remotePath)} ] && [ ! -L ${shellQuote(remotePath)} ]`
    if (this.config.user === "root") {
      await this.exec(
        `${targetGuard} && mv -T -- ${shellQuote(temporaryPath)} ${shellQuote(remotePath)}`,
        {
          silent: true,
        }
      )
      return
    }

    const directory = posix.dirname(remotePath)
    const basename = posix.basename(remotePath)
    const finalTemplate = `${directory}/.${basename}.paratix.XXXXXX`
    const finalizeScript = `
if ! ${targetGuard}; then
  printf '%s\n' 'target path must not be a directory or symlink' >&2
  exit 1
fi
target_owner=$(stat -c '%u:%g' ${shellQuote(remotePath)} 2>/dev/null || printf '0:0')
target_temp=''
cleanup() {
  if [ -n "$target_temp" ]; then
    rm -f "$target_temp"
  fi
}
trap cleanup EXIT
target_temp=$(mktemp ${shellQuote(finalTemplate)})
mv -T -- ${shellQuote(temporaryPath)} "$target_temp"
chmod ${shellQuote(mode)} "$target_temp"
chown "$target_owner" "$target_temp"
mv -T -- "$target_temp" ${shellQuote(remotePath)}
trap - EXIT
`
    await this.exec(finalizeScript, { silent: true })
  }

  /**
   * Probe whether passwordless sudo is available without provoking an
   * interactive prompt in the SSH channel.
   *
   * R-0000138: previously this method funneled through `execPrepared` →
   * `sudoCommand`, which—when no sudo password was cached—routed the probe
   * through `sudo bash -c …` (without `-n`). On hosts requiring an actual
   * sudo password this hung on a blocking prompt until the 10s watchdog
   * fired and additionally produced `auth.log` failure entries. The probe
   * now runs a dedicated `sudo -n true` via `execRaw`, so a host without
   * passwordless sudo fails fast with a non-zero exit code in one RTT.
   *
   * @returns `true` when `sudo -n true` exits with code 0; `false` otherwise.
   */
  private async hasPasswordlessSudo(): Promise<boolean> {
    try {
      const result = await this.execRaw("sudo -n true")
      if (result.exitCode === 0) {
        this.passwordlessSudo = true
        return true
      }
      return false
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

  private registerConnectedClient(client: Client, port: number): void {
    const rejectPending = (error: Error): void => {
      for (const rejectFunction of this.pendingRejects) {
        rejectFunction(error)
      }
      this.pendingRejects.clear()
    }
    client.on("close", () => {
      rejectPending(new Error("SSH connection closed unexpectedly"))
    })
    client.on("error", (error) => {
      rejectPending(error)
    })
    this.client = client
    this.connectedPort = port
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
   * @param hasInput - Whether the command receives caller-provided stdin.
   * @returns An object with the final command and whether a password must be written to stdin.
   */
  private sudoCommand(
    command: string,
    environmentPrefix = "",
    hasInput = false
  ): { command: string; needsPassword: boolean } {
    if (this.config.user === "root") {
      return { command: `${environmentPrefix}${command}`, needsPassword: false }
    }
    const quoted = shellQuote(`${environmentPrefix}${command}`)
    if (this.cachedSudoPassword != null && hasInput) {
      // R-0000127: a single SSH channel only exposes one stdin stream. When
      // sudo would prompt for a password (`sudo -S`), the password and the
      // caller-provided input cannot share that stream — sudo would consume
      // the input as the password and then fail with `sudo: a password is
      // required`. We can only safely route the input via `sudo -n bash -c`
      // if a previous probe confirmed passwordless sudo is available;
      // otherwise we must fail-closed with an actionable error instead of
      // silently producing a `sudo -n` command that breaks at runtime.
      if (!this.passwordlessSudo) {
        throw new Error(
          "exec with input is not supported when sudo requires a password: " +
            "configure passwordless sudo for the connecting user or remove the input payload"
        )
      }
      return { command: `sudo -n bash -c ${quoted}`, needsPassword: false }
    }
    if (this.cachedSudoPassword != null) {
      return { command: `SUDO_PROMPT='' sudo -S bash -c ${quoted}`, needsPassword: true }
    }
    return { command: `sudo bash -c ${quoted}`, needsPassword: false }
  }

  /**
   * Iterate over `config.ports` and attempt a connection on each one.
   *
   * @param options - Auth parameters and optional reconnect deadline for bounded per-port attempts.
   * @returns `true` if a port connected successfully, `false` if all ports failed.
   */
  // R-0000139: iterate on a snapshot of `runtime.ports` so that concurrent
  // `addPort`/`removePort` calls (e.g. from `handlePortChange` rollback in
  // runner.ts) cannot mutate the array mid-iteration and cause skipped or
  // re-visited entries.
  /* eslint-disable max-statements, sonarjs/cognitive-complexity -- port fallback, host-key errors, and abort handling belong together */
  private async tryConnectOnPorts(options: TryConnectOnPortsOptions = {}): Promise<boolean> {
    const ports: number[] = [...this.runtime.ports]
    for (const port of ports) {
      if (hasReconnectDeadlineExpired(options.reconnectDeadline)) return false
      // R-0000039: keep the Client reference outside the try-block so the
      // catch path can close it explicitly. ssh2's Client retains internal
      // sockets, buffers, and listeners after a failed connect; without an
      // explicit cleanup, lingering FDs and listeners accumulate across
      // reconnect attempts.
      const client = new Client()
      try {
        const verifier = buildHostVerifier(
          this.config.strictHostKeyChecking ?? "yes",
          { host: this.runtime.host, port },
          {
            expectedHostFingerprint: this.config.expectedHostFingerprint,
            expectedHostPublicKey: this.config.expectedHostPublicKey,
          }
        )
        const hostKeyAttempt = this.createHostKeyAttempt(verifier.hostVerifier)
        // eslint-disable-next-line no-await-in-loop
        await tryConnectOnPort({
          abortSignal: this.promptAbortSignal,
          agent: options.agent,
          agentForward: this.config.agentForward,
          client,
          host: this.runtime.host,
          hostVerifier: hostKeyAttempt.hostVerifier,
          password: options.password,
          port,
          privateKey: options.privateKey,
          readyTimeout: getRemainingReconnectTimeout(options.reconnectDeadline),
          username: this.config.user,
        })
        hostKeyAttempt.commit()
        // Ensure the host key is persisted to disk before returning.
        // eslint-disable-next-line no-await-in-loop
        await this.commitAcceptedHostKey(verifier)
        this.registerConnectedClient(client, port)
        return true
      } catch (error) {
        // Always release the failed Client so its sockets, buffers, and
        // listeners do not leak before the loop tries the next port.
        cleanupFailedSshClient(client)
        if (this.promptAbortSignal?.aborted === true) throw getAbortReason(this.promptAbortSignal)
        if (error instanceof HostKeyVerificationError) throw error
        // Try next port
      }
    }
    return false
  }
  /* eslint-enable max-statements, sonarjs/cognitive-complexity */

  private async tryPasswordFallback(options?: ConnectOptions, agent?: string): Promise<boolean> {
    if (!this.config.passwordFallback) return false
    const password = await promptTerminal(
      `Password for ${this.config.user}@${this.runtime.host}: `,
      true,
      options
    )
    // R-0000095: register the interactively entered SSH login password in
    // the process-wide secret sink for the duration of the connect attempt.
    // Without this, a thrown error from `tryConnectOnPorts` (e.g. an ssh2
    // protocol failure that includes the credential in its trace) would
    // surface the plaintext password to stderr via `printCommandFailure` /
    // `printVerboseGenericError`. Mirroring the sudo-password handling, the
    // sink registration is released as soon as the connect attempt resolves.
    return withRegisteredSecrets([password], async () => {
      if (
        !(await this.tryConnectOnPorts({
          agent,
          password,
          reconnectDeadline: options?.reconnectDeadline,
        }))
      )
        return false
      this.authMethod = "password"
      return true
    })
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
    // R-0000093: stream the encoded payload over stdin instead of passing it
    // as a shell argument. The previous `printf '%s' '<encodedContent>'`
    // pipeline placed the entire base64 blob on the argv list, where it was
    // capped by the kernel `ARG_MAX` limit and a real-world write of a few
    // hundred KB would fail with E2BIG. Reading from stdin removes the cap
    // and matches the sudo-stdin pattern used elsewhere in this class.
    const encodedContent = Buffer.from(content, "utf8").toString("base64")

    try {
      await this.exec(`base64 -d > ${shellQuote(remoteTemporary)}`, {
        input: encodedContent,
        silent: true,
      })
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

  private async commitAcceptedHostKey(verifier: HostVerifierResult): Promise<void> {
    if (verifier.commitAcceptedHostKey != null) {
      await verifier.commitAcceptedHostKey()
      return
    }
    if (verifier.pendingPersist != null) await verifier.pendingPersist
  }

  /**
   * Create a host-key verification attempt that only commits accepted trust
   * state after the SSH handshake succeeds.
   *
   * @param original - The original verifier from `buildHostVerifier`, if any.
   * @returns A verifier and commit callback for host-key pinning.
   */
  private createHostKeyAttempt(original?: (key: Buffer) => boolean): HostKeyAttempt {
    let acceptedPinnedHostKey: Buffer | null = null
    let acceptedVerifiedHostKey: Buffer | null = null

    return {
      commit: (): void => {
        if (acceptedVerifiedHostKey != null) this.verifiedHostKey ??= acceptedVerifiedHostKey
        if (acceptedPinnedHostKey != null) this.pinnedHostKey ??= acceptedPinnedHostKey
      },
      hostVerifier: (key: Buffer): boolean => {
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
          acceptedVerifiedHostKey ??= Buffer.from(key)
        }
        acceptedPinnedHostKey ??= Buffer.from(key)
        return true
      },
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
   * Write the cached sudo password followed by a newline to the given stream.
   *
   * @param stream - The SSH channel to write the password to.
   */
  private writeSudoPassword(stream: ClientChannel): void {
    stream.write(this.cachedSudoPassword)
    stream.write("\n")
  }
}
