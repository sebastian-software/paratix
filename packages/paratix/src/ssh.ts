/* eslint-disable max-lines -- SSH transport methods keep callback wiring local */
import type { Stats } from "node:fs"

import { createHash, timingSafeEqual } from "node:crypto"
import { createReadStream } from "node:fs"
import { readFile, stat } from "node:fs/promises"
import { homedir } from "node:os"
import { join, posix } from "node:path"
import { pipeline } from "node:stream/promises"
import { Client, type ClientChannel } from "ssh2"

import type { ExecOptions, ExecResult, SshConfig, SshConnection } from "./types.js"

import {
  buildHostVerifier,
  createHostKeyCache,
  extractAlgoFromKey,
  type HostKeyCache,
  HostKeyVerificationError,
  type HostVerifierResult,
} from "./knownHosts.js"
import {
  getRegisteredSecrets,
  registerSecret,
  unregisterSecret,
  withRegisteredSecrets,
} from "./secretSink.js"
import { SFTP_TIMEOUT, sftpDownload, sftpUpload, sftpUploadContent } from "./sftp.js"
import {
  attachSshClientTeardownErrorSink,
  CAPTURE_TRUNCATION_MARKER,
  cleanupFailedSshClient,
  collectStreamOutput,
  CommandError,
  DEFAULT_MAX_OUTPUT_BYTES,
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
 * Stream the local upload source through SHA-256 so the post-finalize
 * verification can compare hashes instead of byte counts (R-0000599). Hashing
 * via `createReadStream` keeps memory usage flat regardless of the file size
 * — `uploadFile` may transfer arbitrarily large artifacts.
 *
 * @param path - Absolute or relative path to the local upload source.
 * @returns Lowercase hex SHA-256 digest of the file contents.
 */
async function computeLocalFileSha256(path: string): Promise<string> {
  const hash = createHash("sha256")
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- localPath is the caller-provided upload source that must be hashed before transfer
  const readStream = createReadStream(path)
  await pipeline(readStream, hash)
  return hash.digest("hex")
}

/**
 * Reject any `directory` argument that contains characters mktemp output
 * validation cannot reason about safely. R-0000202: an unchecked directory
 * with embedded newlines, backslashes, double slashes, or a trailing slash
 * either smuggles control characters into the matched path or builds an
 * invalid expectedPrefix that defeats the startsWith check downstream.
 *
 * @param directory - The candidate target directory for `mktemp`.
 * @throws {Error} When the directory contains forbidden characters.
 */
function assertValidMktempDirectory(directory: string): void {
  const hasInvalidCharacter =
    directory.length === 0 ||
    directory.includes("\n") ||
    directory.includes("\r") ||
    directory.includes("\\") ||
    directory.includes("//") ||
    (directory !== "/" && directory.endsWith("/"))
  if (hasInvalidCharacter) {
    throw new Error(`Unexpected mktemp directory: ${directory}`)
  }
}

/**
 * Validate that a path returned by `mktemp` matches the expected paratix pattern.
 *
 * @param directory - The target directory in which the temp file must be created.
 * @param path - The raw `mktemp` output to validate.
 * @param prefix - The expected Paratix temp-file prefix.
 * @returns The validated path.
 * @throws {Error} When the path or directory does not match the expected pattern.
 */
function validateMktempPath(directory: string, path: string, prefix: string): string {
  assertValidMktempDirectory(directory)
  const normalizedDirectory = directory === "/" ? "" : directory
  const expectedPrefix = `${normalizedDirectory}/${prefix}.`
  // R-0000155: reject CR explicitly alongside LF. A remote host that emits
  // Windows-style line endings (or a misconfigured shell that injects a
  // stray CR) could otherwise smuggle control characters into the path
  // verbatim and break downstream argument parsing.
  if (
    !path.startsWith(expectedPrefix) ||
    path.includes("\n") ||
    path.includes("\r") ||
    path.endsWith("/")
  ) {
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
const DEFAULT_RECONNECT_TIMEOUT = 120_000

/**
 * Resolve the effective reconnect time window and attempt cap for a reconnect.
 *
 * Timeout precedence: an explicit `reconnectTimeout` (from `--reconnect-timeout`)
 * always wins for every reconnect path. When it is unset, callers may pass a
 * path-specific default (e.g. the longer reboot window), otherwise the generic
 * reconnect default applies.
 *
 * The attempt count is bounded by the time window, not by a fixed default cap:
 * with the 30 s backoff ceiling a small default cap would silently cut a
 * configured window short (e.g. only ~7-8 tries fit a 120 s window). Only an
 * explicitly configured `maxReconnectAttempts` still imposes a hard cap.
 *
 * @param config - The SSH config carrying any explicit reconnect overrides.
 * @param defaultTimeout - Optional path-specific default timeout in milliseconds.
 * @returns The resolved `timeout` (ms) and `maxAttempts` for this reconnect.
 */
function resolveReconnectBudget(
  config: SshConfig,
  defaultTimeout?: number
): { maxAttempts: number; timeout: number } {
  return {
    maxAttempts: config.maxReconnectAttempts ?? Number.POSITIVE_INFINITY,
    timeout: config.reconnectTimeout ?? defaultTimeout ?? DEFAULT_RECONNECT_TIMEOUT,
  }
}
// SHA-256 of an empty byte sequence. Used by `verifyRemoteWriteFile` to detect
// a remote file that was finalized as 0 bytes (e.g. disk full) — when the
// expected content hash is anything other than this constant and the remote
// hash matches it, we know the destination is empty even without rerunning a
// separate `stat` call. The literal must match `sha256("")` exactly.
const EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
// R-0000209: how long to wait for `client.end()` to complete before
// forcibly destroying the underlying socket.
const DISCONNECT_DESTROY_FALLBACK_MS = 5000
const JITTER_BASE = 0.75
const JITTER_RANGE = 0.5
const RECONNECT_BASE_DELAY = 1000
const RECONNECT_MAX_DELAY = 30_000
const RAW_OUTPUT_ERROR_SNIPPET_LENGTH = 500

type AuthMethod = "agent" | "password" | "privateKey" | null
type PromptOptions = { abortSignal?: AbortSignal }
type SudoCommandMode = "none" | "noninteractive" | "password"
type SudoCommandResult = { command: string; mode: SudoCommandMode; needsPassword: boolean }
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

type ClientLifecycleListeners = {
  close: () => void
  error: (error: Error) => void
}

type SshRuntimeState = {
  host: string
  ports: number[]
}

function getAbortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("SSH operation aborted")
}

function truncateRawOutputErrorSnippet(text: string): string {
  let count = 0
  let sliceEnd = 0
  for (const char of text) {
    if (count >= RAW_OUTPUT_ERROR_SNIPPET_LENGTH) {
      return `${text.slice(0, sliceEnd)}…(truncated)`
    }
    sliceEnd += char.length
    count++
  }
  return text
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error))
}

/**
 * Signals that `verifyRemoteWriteFile` could not evaluate the remote
 * verification command (non-zero exit code, unparseable hash output,
 * transport hiccup). Surfacing the failure as a dedicated error lets the
 * caller distinguish it from a real content mismatch: a transient
 * verification failure must propagate so the run can retry, never trigger
 * the Shell-Fallback that would overwrite a file that may well be finalized
 * correctly on disk. R-0000522: the verification now hashes the remote
 * file via `sha256sum` instead of comparing sizes, closing the TOCTOU
 * window where an attacker could swap the file content without changing
 * its byte length. The class name is preserved for backward-compatibility
 * with existing callers that import the symbol.
 */
export class RemoteStatTransientError extends Error {
  public constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = "RemoteStatTransientError"
  }
}

function closeClientChannel(channel: ClientChannel | null): void {
  if (channel == null) return
  channel.close()
}

function hasReconnectDeadlineExpired(reconnectDeadline?: number): boolean {
  return reconnectDeadline != null && reconnectDeadline <= Date.now()
}

function getRemainingReconnectTimeout(reconnectDeadline?: number): number | undefined {
  return reconnectDeadline == null ? undefined : reconnectDeadline - Date.now()
}

async function sleepWithAbort(delay: number, abortSignal?: AbortSignal): Promise<void> {
  // R-0000142: still honour the abort status when delay is non-positive.
  // The reconnect loop reaches `delay = 0` once the deadline has expired and
  // would otherwise spin through additional connect attempts before noticing
  // a queued abort. Always probe the abort state up front so the next
  // `await sleepWithAbort(...)` propagates the abort reason immediately.
  if (abortSignal?.aborted === true) throw getAbortReason(abortSignal)
  if (delay <= 0) return
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
  private readonly clientLifecycleListeners = new WeakMap<Client, ClientLifecycleListeners>()
  private readonly config: SshConfig
  private connectedPort = 0
  /**
   * AbortController whose signal is fed to every SFTP transfer started over
   * the current transport. R-0000255: when `disconnectTransport()` runs (e.g.
   * the SIGINT path in runner.ts), this controller is aborted so any
   * in-flight SFTP upload/download rejects in <1 s instead of waiting for the
   * default 120 s SFTP timeout. A fresh controller is installed on the next
   * `disconnectTransport()` call so future transfers can subscribe again.
   */
  private connectionAbortController: AbortController = new AbortController()
  /**
   * Tracks whether the remote host's sudo timestamp has been primed so that
   * subsequent `sudo -n` calls can succeed without prompting. Set to `true`
   * once `cacheAndValidateSudoPassword` has authenticated via `sudo -S` and
   * cleared on disconnect / clearCachedPassword.
   *
   * R-0000152: this lets `sudoCommand` route caller-provided input through
   * `sudo -n bash -c` even on hosts that require a real sudo password — the
   * password no longer has to share the single SSH stdin stream with the
   * payload, so the previous fail-closed branch becomes a working path.
   */
  private credentialCachePrimed = false
  /**
   * R-0000479: per-instance in-memory cache for host keys accepted via
   * accept-new TOFU. Scoping the map to the connection prevents two parallel
   * SshConnectionImpl instances pointed at the same `[host]:port` from
   * overwriting each other's pinned keys. The cache survives reconnects of
   * the same instance, preserving the original process-lifetime caching
   * behavior expected by the reconnect path.
   */
  private readonly hostKeyCache: HostKeyCache = createHostKeyCache()
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
  /**
   * Cached error from a previous sudo probe failure. Once a probe has failed
   * (sudo not installed, wrong password, etc.) we re-throw this error on
   * subsequent privileged exec calls instead of repeating the probe and
   * re-prompting the user (R-0000145). A successful `cacheAndValidateSudoPassword`
   * clears the cache.
   */
  private sudoProbeFailedReason: Error | null = null
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
    // R-0000785: register the seeded sudo password in the process-wide secret
    // sink so the rotation logic in `cacheAndValidateSudoPassword` can release
    // it cleanly when the operator re-prompts. Without this seed registration
    // the rotation path could not balance its `unregisterSecret(previous)`
    // call when the constructor-supplied password is replaced.
    if (config.sudoPassword != null) {
      registerSecret(config.sudoPassword)
    }
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
    // R-0000145 / R-0000258: disconnectTransport now resets the sudo-related
    // state (sudoProbeFailedReason, sudoReady, credentialCachePrimed,
    // passwordlessSudo) so reconnect()/updateHost paths inherit the same
    // fresh-probe semantics that public disconnect() needs.
    // R-0000669: disconnectTransport also rotates connectionAbortController,
    // which now propagates into performConnectAttemptOnPort. A SIGINT-driven
    // disconnect() while tryConnectOnPort is still running therefore aborts
    // the in-flight connect via the abort-signal path instead of leaving an
    // orphaned client that disconnectTransport already nulled.
    this.disconnectTransport()
  }

  public async downloadFile(remotePath: string, localPath: string): Promise<void> {
    const client = this.ensureClient()
    let sourcePath = remotePath
    try {
      if (this.config.user !== "root") {
        // R-0000565: pass `/tmp` via `-p` and the template via `--` so the
        // prefix cannot be parsed as a `mktemp` option.
        sourcePath = await this.createRemoteTempPath(
          "mktemp -p /tmp -- paratix-download.XXXXXX",
          "paratix-download"
        )
        await this.exec(`cat ${shellQuote(remotePath)} > ${shellQuote(sourcePath)}`, {
          silent: true,
        })
      }
      await sftpDownload(
        client,
        sourcePath,
        localPath,
        SFTP_TIMEOUT,
        this.connectionAbortController.signal,
        // R-0000689: bridge the same prepared-secret variants that
        // `exec`/`writeFile` already mask through so a tampered remote path
        // cannot leak a registered secret into the SFTP error message.
        prepareSecrets(this.buildSecrets())
      )
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

  /**
   * R-0000694: synchronous hard-stop used by the second-SIGINT path in
   * `runner.ts`. The regular `disconnect()` is queued via a microtask so
   * ssh2 stream internals have a coherent tick to drain; the second SIGINT
   * arrives before that microtask runs and is followed immediately by
   * `process.exit`, which leaves ssh2 cleanup in the middle of an
   * outstanding stream operation. Calling `client.destroy()` synchronously
   * tears the underlying socket down inside the same tick so no in-flight
   * ssh2 callback survives the imminent exit.
   */
  public forceDestroy(): void {
    if (this.client == null) return
    const closing = this.client
    this.client = null
    try {
      closing.destroy()
    } catch {
      // destroy() may throw if the socket has already been torn down. The
      // hard-exit path cannot do anything useful with that error.
    }
  }

  public getConnectionInfo(): ReturnType<SshConnection["getConnectionInfo"]> {
    return {
      agentSocket: this.authMethod === "agent" ? (this.agentSocket ?? undefined) : undefined,
      authMethod: this.authMethod ?? undefined,
      configuredPorts: [...this.config.ports],
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
    // R-0000668: the default 1 MiB output cap silently appends the capture
    // truncation marker to result.stdout. Returning that to callers corrupts
    // readFile contents and breaks guardedWriteFile's originalContent
    // precondition — surface a clear error instead so the caller sees the
    // real failure and can raise maxOutputBytes if the file legitimately
    // exceeds the cap.
    if (result.stdout.endsWith(CAPTURE_TRUNCATION_MARKER)) {
      throw new Error(
        `[ssh.readFile: ${remotePath}] remote file exceeds the captured-output cap of ${DEFAULT_MAX_OUTPUT_BYTES} bytes; refusing to return truncated contents`
      )
    }
    return result.stdout
  }

  public async reconnect(options?: { defaultTimeout?: number }): Promise<void> {
    const { maxAttempts, timeout } = resolveReconnectBudget(this.config, options?.defaultTimeout)
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
    // R-0000668: `output()` strips trailing whitespace which would remove the
    // newline that precedes the truncation marker, but the marker text itself
    // survives. Run a raw exec to detect truncation directly on the captured
    // stream before any trimming corrupts the digest comparison.
    const result = await this.exec(`sha256sum ${shellQuote(remotePath)}`, { silent: true })
    if (result.stdout.endsWith(CAPTURE_TRUNCATION_MARKER)) {
      throw new Error(
        `[ssh.sha256: ${remotePath}] sha256sum output exceeds the captured-output cap of ${DEFAULT_MAX_OUTPUT_BYTES} bytes; refusing to return a digest derived from truncated output`
      )
    }
    return result.stdout.trim().split(/\s+/v)[0] ?? null
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
    // R-0000599: pre-compute the SHA-256 of the local upload source so the
    // post-finalize verification can compare hashes instead of byte counts —
    // the same threat model that drove `writeFile` to a SHA-256 post-finalize
    // check (R-0000522) applies here. Streaming via `createReadStream` keeps
    // memory usage flat regardless of the uploaded file's size.
    const expectedHash = await computeLocalFileSha256(localPath)
    const temporaryPath = await this.createRemoteWritableTempPath(remotePath, "paratix-upload")
    const temporaryMode = options?.mode ?? "0600"
    try {
      await sftpUpload(
        client,
        localPath,
        temporaryPath,
        SFTP_TIMEOUT,
        this.connectionAbortController.signal,
        // R-0000689: mask registered secrets that could appear in the
        // remote temp path before they reach an operator-visible error.
        prepareSecrets(this.buildSecrets())
      )
      await this.setRemoteTempMode(temporaryPath, temporaryMode)
      // R-0000150: verify the size on the staged temp file BEFORE the
      // privileged finalize (`mv -T`). After the move, an attacker with
      // write access to the destination directory could swap the final
      // file and our `stat` would report a size for an attacker-controlled
      // inode rather than the file we actually wrote. Asserting on the
      // temp path eliminates that TOCTOU window.
      // R-0000266: assertRemoteFileSize routes the stat call through raw
      // exec for non-root users so an expired sudo credential cache between
      // upload and finalize cannot mask a real size mismatch with a
      // sudo-auth error.
      await this.assertRemoteFileSize(temporaryPath, localFileSize)
      await this.finalizeRemoteTempFile(temporaryPath, remotePath, temporaryMode)
      // R-0000599: re-hash the finalized destination so a same-length TOCTOU
      // swap between the staged temp file and the privileged `mv -T` cannot
      // slip past. Mirrors the post-finalize SHA-256 check `writeFile`
      // performs via `ensureRemoteWriteFile`; the shell-fallback rewrite
      // there is specific to in-memory content and does not apply to a
      // streamed local upload source.
      await this.ensureRemoteUploadFile({
        expectedHash,
        expectedSize: localFileSize,
        remotePath,
      })
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
    // R-0000522: pre-compute the SHA-256 of the local content so the
    // post-finalize verification can compare hashes instead of byte counts.
    // The content is already fully in memory (writeFile takes a `string`),
    // so a one-shot `update()` is sufficient — no need for a streaming
    // hash.
    const expectedHash = createHash("sha256").update(content, "utf8").digest("hex")
    try {
      await sftpUploadContent(
        client,
        content,
        remoteTemporary,
        SFTP_TIMEOUT,
        this.connectionAbortController.signal,
        // R-0000689: same masking bridge as `uploadFile`; the remote
        // temp path is derived from `remotePath` which may be templated
        // with values registered in the secret sink.
        prepareSecrets(this.buildSecrets())
      )
      await this.setRemoteTempMode(remoteTemporary, temporaryMode)
      // R-0000150: the pre-finalize size check on the staged temp file is a
      // cheap smoke-test that catches obvious upload failures (0-byte writes,
      // truncated transfers) before we ever move the file into place. The
      // post-finalize verification below tightens this to a full SHA-256
      // comparison so a same-length TOCTOU swap of the finalized inode
      // cannot slip past.
      await this.assertRemoteFileSize(remoteTemporary, expectedSize, "writeFile")
      await this.finalizeRemoteTempFile(remoteTemporary, remotePath, temporaryMode)
      await this.ensureRemoteWriteFile({
        content,
        expectedHash,
        expectedSize,
        mode: temporaryMode,
        remotePath,
      })
    } finally {
      await this.cleanupWriteFileTemporaryPath(remoteTemporary)
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

  /**
   * Reject any destination directory whose path contains a symbolic link
   * component. Resolving via `realpath -m` lets the check tolerate trailing
   * components that do not yet exist while still detecting symlinks earlier
   * in the path.
   *
   * @param directory - The destination directory derived from `posix.dirname`.
   * @param remotePath - Original remote path (used for the diagnostic message).
   * @throws {Error} when at least one component of `directory` is a symlink.
   */
  private async assertDirnameHasNoSymlinkComponent(
    directory: string,
    remotePath: string
  ): Promise<void> {
    if (directory === "" || directory === "/") return
    // R-0000693: invoke `realpath` via `command -p` so the lookup runs
    // against the POSIX default PATH (`getconf PATH`). The previous
    // unqualified `realpath` call inherited whatever PATH the connected
    // shell exposed, which on a manipulated remote (e.g. a wrapper script
    // earlier in PATH) could short-circuit the symlink resolution and let
    // a planted symlink survive the guard. `command -p` is a POSIX builtin
    // available in bash/sh on every supported target, so the call resolves
    // to a system-shipped `realpath` regardless of how the user's PATH is
    // shaped.
    const result = await this.output(`command -p realpath -m -- ${shellQuote(directory)}`)
    const resolved = result.trim()
    if (resolved !== directory) {
      throw new Error(
        `[ssh.mktemp: ${remotePath}] destination directory ${directory} resolves to ${resolved}; refusing to mktemp because at least one path component is a symbolic link`
      )
    }
  }

  private async assertRemoteFileSize(
    remotePath: string,
    expectedSize: number,
    operation: "uploadFile" | "writeFile" = "uploadFile"
  ): Promise<void> {
    // R-0000266: the upload temp path is owned by the connecting user (mktemp
    // staged it under /tmp without sudo). Reading the size through `output`
    // would funnel the call through `ensureSudoReady` and could fail with a
    // sudo-auth error after the cached credentials expired. Use the raw exec
    // path for non-root users so the size check stays a pure stat call and
    // surfaces a real size mismatch instead of a sudo prompt failure.
    const statCommand = `stat -c '%s' ${shellQuote(remotePath)}`
    const rawSize =
      this.config.user === "root"
        ? await this.output(statCommand)
        : await this.outputWithoutSudo(statCommand)
    const actualSize = Number(rawSize.trim())

    if (!Number.isFinite(actualSize)) {
      throw new TypeError(
        `[ssh.${operation}: ${remotePath}] could not determine remote file size after upload`
      )
    }

    if (actualSize === 0 && expectedSize > 0) {
      const diskInfo = await this.checkRemoteDiskSpace(remotePath)
      if (diskInfo != null && diskInfo.availableBytes < expectedSize) {
        throw new Error(
          `[ssh.${operation}: ${remotePath}] disk full – ${diskInfo.availableBytes} bytes available on ${diskInfo.mountpoint}; the file was written as 0 bytes because there is no space left on the device`
        )
      }
    }

    if (actualSize !== expectedSize) {
      throw new Error(
        `[ssh.${operation}: ${remotePath}] remote file size mismatch after upload; expected ${expectedSize} bytes, got ${actualSize}`
      )
    }
  }

  /**
   * R-0000669: build the abort signal that {@link tryConnectOnPort} subscribes
   * to. Combines the prompt-level abort signal (which fires from the SIGINT
   * handler) with the connection-level abort signal (which fires from
   * {@link disconnect}/{@link disconnectTransport} via
   * {@link rotateConnectionAbortController}). The combination ensures that
   * any caller-initiated disconnect aborts an in-flight connect attempt,
   * even when the prompt signal was not also aborted (e.g. a programmatic
   * disconnect from a custom error handler).
   *
   * @returns A signal that aborts on the first of the inputs to abort, or
   *   undefined when there is no signal to subscribe to.
   */
  private buildConnectAbortSignal(): AbortSignal {
    const signals: AbortSignal[] = [this.connectionAbortController.signal]
    if (this.promptAbortSignal != null) signals.push(this.promptAbortSignal)
    return signals.length === 1 ? signals[0] : AbortSignal.any(signals)
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
    // R-0000785: when the cached password rotates (a previous probe primed the
    // sink with an older value, or the caller re-runs `probeSudo` with a fresh
    // prompt), release the old sink registration before overwriting the
    // buffer. Otherwise the orphaned counter keeps masking the now-irrelevant
    // value while the freshly cached password never enters the global sink at
    // all, leaving its plaintext exposed in subsequent diagnostics.
    const previousPassword = this.cachedSudoPassword?.toString("utf8") ?? null
    this.cachedSudoPassword = Buffer.from(password)
    registerSecret(password)
    // The comparisons below are not credential validations — they decide
    // which sink registration to release after a rotation. Constant-time
    // comparison would not change the security properties here, so the
    // ESLint timing-attack heuristic is silenced for the whole branch.
    if (previousPassword != null && previousPassword !== password) {
      unregisterSecret(previousPassword)
      // eslint-disable-next-line security/detect-possible-timing-attacks -- bookkeeping comparison, see note above
    } else if (previousPassword === password) {
      // The caller re-cached the same value (e.g. retry after a transient
      // failure). Drop the now-redundant registration so the counter stays
      // balanced when `clearCachedPassword` releases it later.
      unregisterSecret(password)
    }
    // R-0000146: register the entered password in the process-wide secret
    // sink for the duration of the probe. Without this, a thrown
    // diagnostic—including the wrapping `cause` chain printed by
    // `printCauseChain` in cli.ts via `errorToString(cause)`—could leak
    // the plain-text password through paths that mask only the global
    // sink (not the locally-passed `[password]` array). The registration
    // is released as soon as the probe resolves; on success the caller
    // typically registers the password elsewhere via the buffered cached
    // copy used by buildSecrets.
    try {
      await withRegisteredSecrets([password], async () => {
        await this.execPrepared("true", { silent: true, timeout: 10_000 })
      })
      this.sudoReady = true
      // R-0000152: a successful `sudo -S` authentication primes the remote
      // host's sudo timestamp so subsequent `sudo -n` calls can proceed
      // without re-prompting. Track this state so `sudoCommand` can route
      // caller-provided stdin via `sudo -n` even on password-protected hosts.
      this.credentialCachePrimed = true
    } catch (error) {
      const masked = maskSecrets(String(error), [password])
      this.clearCachedPassword()
      throw new Error(`Sudo authentication failed: ${masked}`, { cause: error })
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

  private async cleanupPrivilegedRemoteTempFile(remotePath: string): Promise<void> {
    // R-0000565: pass `--` so the mktemp-allocated path cannot be parsed as
    // an `rm` option after a future refactor that loosens the prefix.
    await this.exec(`rm -f -- ${shellQuote(remotePath)}`, {
      ignoreExitCode: true,
      silent: true,
    })
  }

  private async cleanupRemoteTempFile(remotePath: string): Promise<void> {
    // R-0000690: a concurrent disconnect (e.g. SIGINT) may null out
    // `this.client` between the upload path completing and the `finally`
    // cleanup running. Returning early when the transport is already gone
    // avoids racing with `ensureClient()` and prevents `cleanupRemoteTempFile`
    // from emitting a misleading "Warning: failed to remove temp file"
    // line for what is really an in-flight shutdown. The original
    // diagnostic from the failing upload / writeFile is preserved because
    // we never enter `this.exec`.
    if (this.client == null) return
    // R-0000196: best-effort cleanup must not propagate errors — a transient
    // SSH failure in a `finally` block would otherwise overwrite the
    // original diagnostic with a misleading rm-failure trace. Mirror the
    // ignoreExitCode pattern used by cleanupPrivilegedRemoteTempFile and
    // emit a masked warning to stderr instead of throwing.
    //
    // R-0000565: pass `--` so the mktemp-allocated path cannot be parsed as
    // an `rm` option after a future refactor that loosens the prefix.
    const command = `rm -f -- ${shellQuote(remotePath)}`
    try {
      if (this.config.user === "root") {
        await this.exec(command, { ignoreExitCode: true, silent: true })
        return
      }
      await this.execWithoutSudo(command)
    } catch (cleanupError) {
      process.stderr.write(
        `Warning: failed to remove temp file ${remotePath}: ${maskSecrets(String(cleanupError), this.buildSecrets())}\n`
      )
    }
  }

  private async cleanupWriteFileTemporaryPath(remoteTemporary: string): Promise<void> {
    // R-0000690: short-circuit when the underlying client was nulled by
    // a concurrent disconnect. Mirrors the guard in `cleanupRemoteTempFile`
    // so the writeFile cleanup path stays silent during an in-flight
    // shutdown rather than racing the disconnect logic.
    if (this.client == null) return
    try {
      await this.cleanupRemoteTempFile(remoteTemporary)
    } catch (cleanupError) {
      process.stderr.write(
        `Warning: failed to remove temp file ${remoteTemporary}: ${maskSecrets(String(cleanupError), this.buildSecrets())}\n`
      )
    }
  }

  private clearCachedPassword(): void {
    if (this.cachedSudoPassword != null) {
      // R-0000785: release the sink registration before zeroing the buffer so
      // a rotation that calls `cacheAndValidateSudoPassword` again later (or
      // a final shutdown) cannot leave a dangling reference-counted entry in
      // the process-wide secret sink.
      const passwordValue = this.cachedSudoPassword.toString("utf8")
      this.cachedSudoPassword.fill(0)
      this.cachedSudoPassword = null
      unregisterSecret(passwordValue)
    }
    // R-0000152: a cleared password invalidates our local view of the
    // remote sudo cred cache too — even if the remote timestamp lingers,
    // we have no way to refresh it without prompting again.
    this.credentialCachePrimed = false
  }

  private async commitAcceptedHostKey(verifier: HostVerifierResult): Promise<void> {
    if (verifier.commitAcceptedHostKey != null) {
      await verifier.commitAcceptedHostKey()
      return
    }
    if (verifier.pendingPersist != null) await verifier.pendingPersist
  }

  private async commitAcceptedHostKeyAndRegisterClient(parameters: {
    client: Client
    port: number
    transitionErrorSink: { assertNoError: () => void }
    verifier: HostVerifierResult
  }): Promise<void> {
    const { client, port, transitionErrorSink, verifier } = parameters
    await this.commitAcceptedHostKey(verifier)
    transitionErrorSink.assertNoError()
    this.registerConnectedClient(client, port)
  }

  private async connectViaAgent(options?: ConnectOptions): Promise<void> {
    const agent = process.env.SSH_AUTH_SOCK
    if (agent == null || agent.length === 0) {
      await this.connectWithoutAgentSocket(options)
      return
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
    // R-0000521: do not zero the buffer in the success path. ssh2 keeps an
    // internal reference to the same Buffer object, so a re-key or reconnect
    // would access a zeroed buffer. The GC reclaims the buffer once all
    // references are dropped. Only scrub the bytes on the error path for
    // defensive security hygiene.
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
      privateKey.fill(0)
      throw new Error(
        `Failed to connect to ${this.runtime.host} on ports: ${this.runtime.ports.join(", ")}`
      )
    } catch (error) {
      privateKey.fill(0)
      throw error
    }
  }

  /**
   * Handle the no-agent / no-private-key configuration. When `SSH_AUTH_SOCK`
   * is unset and `passwordFallback` is enabled, attempt the password path and
   * surface a diagnostic that names both root causes (missing agent + failed
   * password auth) instead of a generic "Failed to connect on ports" message.
   *
   * @param options - Prompt options forwarded from `connect()`.
   */
  private async connectWithoutAgentSocket(options?: ConnectOptions): Promise<void> {
    if (!this.config.passwordFallback) {
      throw new Error("No privateKey configured and SSH_AUTH_SOCK is not set")
    }
    if (await this.tryPasswordFallback(options)) return
    throw new Error(
      `No SSH agent (SSH_AUTH_SOCK is not set) and password authentication failed for ${this.config.user}@${this.runtime.host}`
    )
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

  private async createRemotePrivilegedTempPathInDestination(
    remotePath: string,
    prefix: string
  ): Promise<string> {
    const directory = posix.dirname(remotePath)
    // R-0000141: refuse to mktemp into a directory whose resolved path differs
    // from the literal one — that means at least one component of the
    // destination is a symlink and an attacker could redirect the privileged
    // temp file (and the subsequent `mv -T`) into a location they control.
    await this.assertDirnameHasNoSymlinkComponent(directory, remotePath)
    // R-0000565: pass the directory via `-p` and separate the template with
    // `--` so a future refactor that loosens the prefix cannot let an
    // attacker-controlled value be interpreted as a `mktemp` option.
    const template = `${prefix}.XXXXXX`
    const path = await this.output(`mktemp -p ${shellQuote(directory)} -- ${shellQuote(template)}`)
    return validateMktempPath(directory, path, prefix)
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
    // R-0000141: same dirname-symlink protection as for the privileged path.
    await this.assertDirnameHasNoSymlinkComponent(directory, remotePath)
    // R-0000565: pass the directory via `-p` and separate the template with
    // `--` so the prefix cannot be parsed as a `mktemp` option after a future
    // refactor that loosens the prefix validation.
    const template = `${prefix}.XXXXXX`
    const command = `mktemp -p ${shellQuote(directory)} -- ${shellQuote(template)}`
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
    // R-0000565: pass `/tmp` via `-p` and the template via `--` so the prefix
    // cannot be parsed as a `mktemp` option after a future refactor that
    // loosens the prefix validation.
    const template = `${prefix}.XXXXXX`
    return this.createRemoteTempPath(`mktemp -p /tmp -- ${shellQuote(template)}`, prefix)
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

  /**
   * Detach the lifecycle listeners installed by registerConnectedClient.
   *
   * R-0000254: `registerConnectedClient` stores `client.once("close", () =>
   * rejectPending(...))` where `rejectPending` is a closure over
   * `this.pendingRejects` (no snapshot). Without removing these listeners on
   * disconnect, a delayed `close`/`error` event from the OLD client would run
   * the closure against the NEW connection's pendingRejects after a reconnect
   * and falsely reject freshly queued operations with
   * "SSH connection closed unexpectedly".
   *
   * @param closing - The ssh2 client whose lifecycle listeners should be removed.
   */
  private detachClientLifecycleListeners(closing: Client): void {
    const listeners = this.clientLifecycleListeners.get(closing)
    if (listeners == null) return
    try {
      closing.removeListener("close", listeners.close)
      closing.removeListener("error", listeners.error)
      this.clientLifecycleListeners.delete(closing)
    } catch {
      // removeListener must never propagate from the disconnect path.
    }
  }

  private disconnectTransport(): void {
    this.rotateConnectionAbortController()
    if (this.client) {
      const closing = this.client
      this.client = null
      this.tearDownClient(closing)
    }
    this.resetTransportDerivedState()
    const error = new Error("SSH connection closed")
    for (const rejectFunction of this.pendingRejects) {
      rejectFunction(error)
    }
    this.pendingRejects.clear()
  }

  private endStreamInput(stream: ClientChannel, input?: Exclude<ExecOptions["input"], null>): void {
    try {
      if (input === undefined) {
        stream.end()
      } else {
        stream.end(input)
      }
    } catch {
      // Defense in depth: same as writeSudoPassword above.
    }
  }

  private ensureClient(): Client {
    if (!this.client) throw new Error("SSH not connected")
    return this.client
  }

  /**
   * R-0000599: post-finalize verification for `uploadFile`. Compares the
   * SHA-256 of the finalized remote file against the streaming digest
   * computed from `localPath`. Mirrors the verdict handling of
   * {@link ensureRemoteWriteFile} ("matches" / "empty" / "hash-mismatch")
   * but does not invoke the shell-fallback rewrite — that fallback is
   * specific to in-memory `writeFile` content and cannot be reproduced for
   * a streamed local upload source. A transient verification failure
   * propagates as {@link RemoteStatTransientError} so the caller can retry
   * instead of acting on a non-verdict result.
   *
   * @param options - Verification inputs.
   * @param options.expectedHash - Lowercase hex SHA-256 digest of the local file.
   * @param options.expectedSize - Byte length of the local file (used for disk-full diagnostics).
   * @param options.remotePath - The finalized destination path on the remote host.
   * @throws {Error} When the remote file is empty (disk-full) or its hash does not match.
   */
  private async ensureRemoteUploadFile(options: {
    expectedHash: string
    expectedSize: number
    remotePath: string
  }): Promise<void> {
    const verification = await this.verifyRemoteWriteFile(options.remotePath, options.expectedHash)
    if (verification === "matches") return
    if (verification === "empty") {
      const diskInfo = await this.checkRemoteDiskSpace(options.remotePath)
      if (diskInfo != null && diskInfo.availableBytes < options.expectedSize) {
        throw new Error(
          `[ssh.uploadFile: ${options.remotePath}] disk full – ${diskInfo.availableBytes} bytes available on ${diskInfo.mountpoint}; the file was written as 0 bytes because there is no space left on the device`
        )
      }
      throw new Error(
        `[ssh.uploadFile: ${options.remotePath}] remote file is empty after upload/finalize; refusing successful upload result`
      )
    }
    throw new Error(
      `[ssh.uploadFile: ${options.remotePath}] remote file hash mismatch after upload/finalize; expected ${options.expectedSize} bytes with SHA-256 ${options.expectedHash}`
    )
  }

  private async ensureRemoteWriteFile(options: {
    content: string
    expectedHash: string
    expectedSize: number
    mode: string
    remotePath: string
  }): Promise<void> {
    // R-0000476: `verifyRemoteWriteFile` reports the content verdict
    // ("matches" / "empty" / "hash-mismatch") and throws
    // `RemoteStatTransientError` when the underlying verification command
    // cannot be evaluated. The Shell-Fallback only fires for an explicit
    // "needs rewrite" verdict — transient verification failures propagate so
    // callers can retry instead of overwriting a remote file that may
    // already be finalized correctly.
    // R-0000522: the verification compares SHA-256 hashes instead of byte
    // counts so an attacker with write access to the destination directory
    // cannot TOCTOU-swap the file content past the verify call.
    const verification = await this.verifyRemoteWriteFile(options.remotePath, options.expectedHash)
    if (verification === "matches") return

    await this.rewriteRemoteFileViaShell(options.remotePath, options.content, options.mode)
    const fallbackVerification = await this.verifyRemoteWriteFile(
      options.remotePath,
      options.expectedHash
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
      `[ssh.writeFile: ${options.remotePath}] remote file hash mismatch after upload/finalize and shell fallback; expected ${options.expectedSize} bytes with SHA-256 ${options.expectedHash}`
    )
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
    // R-0000145: once a probe has failed, fail fast on every subsequent call
    // instead of re-running the probe (which would re-prompt the user and
    // could produce an endless prompt loop on hosts without working sudo).
    if (this.sudoProbeFailedReason != null) {
      throw this.sudoProbeFailedReason
    }
    if (this.sudoProbePromise != null) {
      await this.sudoProbePromise
      return
    }
    this.sudoProbePromise = this.probeSudo({ abortSignal: this.promptAbortSignal }).finally(() => {
      this.sudoProbePromise = null
    })
    try {
      await this.sudoProbePromise
    } catch (error) {
      // Cache the failure so further `exec` calls do not re-trigger a prompt.
      this.sudoProbeFailedReason = error instanceof Error ? error : new Error(String(error))
      throw error
    }
  }

  private async execPrepared(command: string, options: ExecOptions = {}): Promise<ExecResult> {
    const client = this.ensureClient()
    const environmentPrefix = this.buildEnvPrefix(options.env)
    const sudo = this.sudoCommand(command, environmentPrefix, options.input != null)
    const secrets = prepareSecrets(this.buildSecrets(options.secrets))
    try {
      return await new Promise((resolve, reject) => {
        const { isSettled, wrappedReject, wrappedResolve } =
          this.createSettledCallbacks<ExecResult>(resolve, reject)
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
        try {
          client.exec(sudo.command, (error: Error | undefined, stream: ClientChannel) => {
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
            this.writeStreamInput(stream, sudo.needsPassword, options.input)
          })
        } catch (error) {
          clearTimeout(timer)
          closeClientChannel(activeStream)
          wrappedReject(toError(error))
        }
      })
    } catch (error) {
      if (sudo.mode === "noninteractive" && this.isNoninteractiveSudoAuthError(error)) {
        this.invalidateSudoReadiness()
      }
      throw error
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
      const { isSettled, wrappedReject, wrappedResolve } = this.createSettledCallbacks<{
        exitCode: number
        stdout: string
      }>(resolve, reject)
      let activeStream: ClientChannel | null = null
      const timer = setTimeout(() => {
        activeStream?.close()
        // R-0000667: route command interpolation through the same secret sink
        // execPrepared uses so future callers with secret-bearing commands
        // cannot leak through verbose error rendering.
        const secrets = prepareSecrets(this.buildSecrets())
        wrappedReject(
          new Error(
            `Command timed out after ${COMMAND_TIMEOUT}ms: ${maskPreparedSecrets(command, secrets)}`
          )
        )
      }, COMMAND_TIMEOUT)
      try {
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
          let stdoutBytes = 0
          stream.on("data", (chunk: Buffer) => {
            if (stdoutBytes > DEFAULT_MAX_OUTPUT_BYTES) return
            stdoutBytes += chunk.length
            if (stdoutBytes > DEFAULT_MAX_OUTPUT_BYTES) {
              const remainingBytes = Math.max(
                0,
                DEFAULT_MAX_OUTPUT_BYTES - (stdoutBytes - chunk.length)
              )
              if (remainingBytes > 0) {
                chunks.push(chunk.subarray(0, remainingBytes))
              }
              const capturedStdout = Buffer.concat(chunks).toString("utf8")
              const secrets = prepareSecrets(this.buildSecrets())
              activeStream?.close()
              wrappedReject(
                new Error(
                  `Command stdout exceeded ${DEFAULT_MAX_OUTPUT_BYTES} bytes: ${maskPreparedSecrets(
                    command,
                    secrets
                  )}\nstdout: ${truncateRawOutputErrorSnippet(
                    maskPreparedSecrets(capturedStdout, secrets)
                  )}`
                )
              )
              return
            }
            chunks.push(chunk)
          })
          stream.on("close", (code: null | number | undefined, signal?: null | string) => {
            clearTimeout(timer)
            if (signal != null && signal !== "") {
              // R-0000667: mask command before interpolating it into the
              // Error.message; mirrors the secret sink used in execPrepared.
              const secrets = prepareSecrets(this.buildSecrets())
              wrappedReject(
                new Error(
                  `Command failed with signal ${signal}: ${maskPreparedSecrets(command, secrets)}`
                )
              )
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
      } catch (error) {
        clearTimeout(timer)
        closeClientChannel(activeStream)
        wrappedReject(toError(error))
      }
    })
  }

  private async execWithoutSudo(command: string): Promise<void> {
    const result = await this.execRaw(command)
    if (result.exitCode !== 0) {
      // R-0000667: mask the command before interpolating it into the
      // Error.message; mirrors the secret sink used in execPrepared.
      const secrets = prepareSecrets(this.buildSecrets())
      throw new Error(
        `Command failed (exit code ${result.exitCode}): ${maskPreparedSecrets(command, secrets)}`
      )
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
    await this.assertDirnameHasNoSymlinkComponent(directory, remotePath)
    const basename = posix.basename(remotePath)
    // R-0000565: pass the directory via `-p` and separate the template with
    // `--` so the prefix cannot be parsed as a `mktemp` option after a future
    // refactor that loosens the basename validation. Same `--` for the
    // `rm -f` cleanup so `$target_temp` cannot be parsed as an `rm` option.
    const finalTemplate = `.${basename}.paratix.XXXXXX`
    // R-0000517: enable strict shell error handling. Without `set -eu` a
    // failed `mktemp` would leave `$target_temp` empty, the subsequent
    // `mv`/`chmod`/`chown` would silently misbehave, and `trap - EXIT` would
    // produce exit code 0 — letting `uploadFile`/`writeFile` believe the
    // finalize succeeded even though the destination was never written.
    // Guarding `target_temp` immediately after `mktemp` makes any failure
    // surface as a non-zero exit code that `ssh.exec` translates into a
    // `CommandError`.
    const finalizeScript = `set -eu
if ! ${targetGuard}; then
  printf '%s\n' 'target path must not be a directory or symlink' >&2
  exit 1
fi
target_owner=$(stat -c '%u:%g' ${shellQuote(remotePath)} 2>/dev/null || stat -c '%u:%g' ${shellQuote(directory)} 2>/dev/null || printf '0:0')
target_temp=''
cleanup() {
  if [ -n "$target_temp" ]; then
    rm -f -- "$target_temp"
  fi
}
trap cleanup EXIT
target_temp=$(mktemp -p ${shellQuote(directory)} -- ${shellQuote(finalTemplate)})
[ -n "$target_temp" ] || exit 1
mv -T -- ${shellQuote(temporaryPath)} "$target_temp"
chmod ${shellQuote(mode)} "$target_temp"
chown "$target_owner" "$target_temp"
mv -T -- "$target_temp" ${shellQuote(remotePath)}
trap - EXIT
`
    await this.exec(finalizeScript, { silent: true })
  }

  private handleTryConnectError(parameters: {
    client: Client
    error: unknown
    registered: boolean
    tryConnectResolved: boolean
  }): void {
    const { client, error, registered, tryConnectResolved } = parameters
    // Only release the client when nothing else has taken responsibility:
    // tryConnectOnPort cleans up internally on rejection, and a registered
    // client is owned by `this` and must not be force-closed mid-iteration.
    if (tryConnectResolved && !registered) cleanupFailedSshClient(client)
    // R-0000256: rethrow HostKeyVerificationError before any abort handling
    // so the caller sees the verification failure verbatim. When the abort
    // fired simultaneously with a post-handshake commit failure, surface the
    // commit-failure cause via a new Error preserving the original message
    // instead of falling through to the abort path.
    if (error instanceof HostKeyVerificationError) throw error
    if (tryConnectResolved && this.promptAbortSignal?.aborted === true) {
      throw error instanceof Error
        ? new Error(error.message, { cause: error })
        : new Error(String(error))
    }
    if (this.promptAbortSignal?.aborted === true) throw getAbortReason(this.promptAbortSignal)
    // Otherwise fall through to try the next port.
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

  private installConnectedClientTransitionErrorSink(client: Client): {
    assertNoError: () => void
    dispose: () => void
  } {
    const transitionState: { error?: Error } = {}
    const handleTransitionError = (error: Error): void => {
      transitionState.error ??= error
    }
    client.on("error", handleTransitionError)
    return {
      assertNoError() {
        if (transitionState.error != null) throw transitionState.error
      },
      dispose() {
        client.removeListener("error", handleTransitionError)
      },
    }
  }

  private invalidateSudoReadiness(): void {
    this.sudoReady = false
    this.credentialCachePrimed = false
    this.passwordlessSudo = false
  }

  private isNoninteractiveSudoAuthError(error: unknown): boolean {
    if (!(error instanceof CommandError)) return false
    return /sudo: (?:a password is required|a terminal is required|no tty present)/iv.test(
      error.fullStderr
    )
  }

  private isSudoReadyWithoutProbe(): boolean {
    return this.config.user === "root" || this.cachedSudoPassword != null
  }

  private async outputWithoutSudo(command: string): Promise<string> {
    const result = await this.execRaw(command)
    if (result.exitCode !== 0) {
      // R-0000667: mask the command before interpolating it into the
      // Error.message; mirrors the secret sink used in execPrepared.
      const secrets = prepareSecrets(this.buildSecrets())
      throw new Error(
        `Command failed (exit code ${result.exitCode}): ${maskPreparedSecrets(command, secrets)}`
      )
    }
    return result.stdout.trim()
  }

  private async performConnectAttemptOnPort(parameters: {
    client: Client
    options: TryConnectOnPortsOptions
    port: number
    state: { registered: boolean; tryConnectResolved: boolean }
  }): Promise<void> {
    const { client, options, port, state } = parameters
    const verifier = await buildHostVerifier(
      this.config.strictHostKeyChecking ?? "yes",
      { host: this.runtime.host, port },
      {
        cache: this.hostKeyCache,
        expectedHostFingerprint: this.config.expectedHostFingerprint,
        expectedHostPublicKey: this.config.expectedHostPublicKey,
      }
    )
    const hostKeyAttempt = this.createHostKeyAttempt(verifier.hostVerifier)
    // R-0000669: combine the prompt-level abort signal (SIGINT-driven prompt
    // cancellation) with the connection-level abort signal so an in-flight
    // tryConnectOnPort is aborted whenever disconnect() runs — including
    // programmatic disconnect paths that did not also abort promptAbortSignal.
    // Without this, disconnectTransport nulled the client while the connect
    // continued and emitted a `ready` event on a no-longer-tracked client.
    const connectAbortSignal = this.buildConnectAbortSignal()
    const transitionErrorSink = this.installConnectedClientTransitionErrorSink(client)
    try {
      await tryConnectOnPort({
        abortSignal: connectAbortSignal,
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
      state.tryConnectResolved = true
      transitionErrorSink.assertNoError()
      hostKeyAttempt.commit()
      await this.commitAcceptedHostKeyAndRegisterClient({
        client,
        port,
        transitionErrorSink,
        verifier,
      })
      state.registered = true
    } finally {
      transitionErrorSink.dispose()
    }
  }

  private async promptAndCacheSudoPassword(): Promise<void> {
    const password = await promptTerminal(
      `[sudo] password for ${this.config.user}@${this.runtime.host}: `,
      true,
      { abortSignal: this.promptAbortSignal }
    )
    await this.cacheAndValidateSudoPassword(password)
  }

  /**
   * R-0000581: read the SHA-256 output for the post-finalize verify step
   * without going through `sudo` when possible. For non-root users the
   * finalize step chowns the destination to the parent-directory owner, so
   * the unprivileged user usually has read access; bypassing sudo avoids the
   * worst-case command timeout if the sudo channel hangs. The privileged
   * `output()` fallback runs only when the unprivileged attempt fails — for
   * example because the destination directory denies traverse access to the
   * connected user.
   *
   * @param hashCommand - The `sha256sum -- …` command to execute.
   * @returns Raw stdout of the successful `sha256sum` invocation.
   */
  private async readSha256OutputForVerify(hashCommand: string): Promise<string> {
    if (this.config.user === "root") {
      return this.output(hashCommand)
    }
    try {
      return await this.outputWithoutSudo(hashCommand)
    } catch {
      // Fall back to the privileged path when the unprivileged read fails
      // (typically a permission error). `this.output` adds the same sudo
      // wrapper used elsewhere so the caller still gets a stable result.
      return this.output(hashCommand)
    }
  }

  private registerConnectedClient(client: Client, port: number): void {
    const rejectPending = (error: Error): void => {
      for (const rejectFunction of this.pendingRejects) {
        rejectFunction(error)
      }
      this.pendingRejects.clear()
    }
    const closeListener = (): void => {
      rejectPending(new Error("SSH connection closed unexpectedly"))
    }
    const errorListener = (error: Error): void => {
      rejectPending(error)
    }
    // R-0000143: ssh2 emits both `close` and `error` for a single
    // disconnect event (e.g. error escalation followed by close). Use
    // `once` for the close handler so the cleanup logic and stderr
    // logging fire exactly once per lifecycle, avoiding duplicated lines
    // for the operator. `rejectPending` itself is idempotent (it clears
    // the set after calling), but the handler is also responsible for
    // diagnostics that should not be repeated.
    client.once("close", closeListener)
    client.on("error", errorListener)
    this.clientLifecycleListeners.set(client, { close: closeListener, error: errorListener })
    this.client = client
    this.connectedPort = port
  }

  /**
   * Tear down the SSH transport without touching the cached sudo password.
   *
   * R-0000209: `client.end()` initiates a graceful disconnect, which can
   * hang on TCP half-open until the OS keepalive expires (default ~2 hours).
   * Schedule a `client.destroy()` fallback so test runners and reconnect
   * loops do not leak sockets when the peer never replies.
   */
  /**
   * Reset connection-derived state that must not survive a transport teardown.
   *
   * - R-0000236 clears the identity fields (connectedPort, authMethod,
   *   agentSocket) so getConnectionInfo() does not return stale values that
   *   would mislead reconnect-rollback logic.
   * - R-0000258 clears the sudo-related state (sudoProbeFailedReason,
   *   sudoReady, credentialCachePrimed, passwordlessSudo) so reconnect()/
   *   updateHost paths start with a fresh sudo reality and do not re-throw a
   *   cached probe failure from the previous host.
   */
  private resetTransportDerivedState(): void {
    this.connectedPort = 0
    this.authMethod = null
    this.agentSocket = null
    this.sudoProbeFailedReason = null
    this.sudoReady = false
    this.credentialCachePrimed = false
    this.passwordlessSudo = false
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

  /**
   * R-0000255: fire the SFTP-coupled abort signal so any in-flight SFTP
   * operations stop waiting on their dedicated channels immediately. The
   * new AbortController replaces the old one unconditionally so subsequent
   * connect()s expose a fresh, non-aborted signal that future SFTP operations
   * can subscribe to.
   */
  private rotateConnectionAbortController(): void {
    const previousConnectionAbort = this.connectionAbortController
    this.connectionAbortController = new AbortController()
    try {
      previousConnectionAbort.abort(new Error("ssh disconnect"))
    } catch {
      // AbortController.abort never throws on modern runtimes; defense in
      // depth only.
    }
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
  ): SudoCommandResult {
    if (this.config.user === "root") {
      return { command: `${environmentPrefix}${command}`, mode: "none", needsPassword: false }
    }
    const quoted = shellQuote(`${environmentPrefix}${command}`)
    if (this.cachedSudoPassword != null && hasInput) {
      // R-0000127: a single SSH channel only exposes one stdin stream. When
      // sudo would prompt for a password (`sudo -S`), the password and the
      // caller-provided input cannot share that stream — sudo would consume
      // the input as the password and then fail with `sudo: a password is
      // required`. We can only safely route the input via `sudo -n bash -c`
      // if either a previous probe confirmed passwordless sudo, or a prior
      // successful `sudo -S` authentication has primed the remote sudo
      // timestamp (R-0000152). Otherwise fail-closed with an actionable error
      // instead of silently producing a `sudo -n` command that breaks at
      // runtime.
      if (!this.passwordlessSudo && !this.credentialCachePrimed) {
        throw new Error(
          "exec with input is not supported when sudo requires a password: " +
            "configure passwordless sudo for the connecting user or remove the input payload"
        )
      }
      return { command: `sudo -n bash -c ${quoted}`, mode: "noninteractive", needsPassword: false }
    }
    if (this.cachedSudoPassword != null) {
      return {
        command: `SUDO_PROMPT='' sudo -S bash -c ${quoted}`,
        mode: "password",
        needsPassword: true,
      }
    }
    return { command: `sudo -n bash -c ${quoted}`, mode: "noninteractive", needsPassword: false }
  }

  private tearDownClient(closing: Client): void {
    // R-0000582: attach the teardown error sink BEFORE detaching the lifecycle
    // listeners so the client never goes without an `error` listener even for
    // a single tick. Otherwise an `error` event emitted between the detach
    // and the new sink registration would crash the process via Node's
    // "unhandled error" path.
    attachSshClientTeardownErrorSink(closing)
    this.detachClientLifecycleListeners(closing)
    try {
      closing.end()
    } catch {
      // end() may throw when the underlying socket has already been destroyed
    }
    const fallback = setTimeout(() => {
      try {
        closing.destroy()
      } catch {
        // destroy() must never propagate from a best-effort fallback
      }
    }, DISCONNECT_DESTROY_FALLBACK_MS)
    // Do not keep the event loop alive solely for the destroy fallback —
    // when the program is otherwise idle, it can exit and the GC will
    // reclaim the socket.
    fallback.unref()
    // R-0000524: when `end()` completes a clean shutdown before the fallback
    // fires, cancel the pending `destroy()` so it does not run on an already
    // closed socket.
    closing.once("close", () => {
      clearTimeout(fallback)
    })
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
  private async tryConnectOnPorts(options: TryConnectOnPortsOptions = {}): Promise<boolean> {
    const ports: number[] = [...this.runtime.ports]
    for (const port of ports) {
      if (hasReconnectDeadlineExpired(options.reconnectDeadline)) return false
      // R-0000039 / R-0000198: keep the Client reference outside the try-block so
      // the catch path can close it explicitly when ownership did not transfer.
      const client = new Client()
      const state = { registered: false, tryConnectResolved: false }
      try {
        // eslint-disable-next-line no-await-in-loop -- buildHostVerifier serializes the known_hosts read; sequential per-port is intentional.
        await this.performConnectAttemptOnPort({ client, options, port, state })
        return true
      } catch (error) {
        this.handleTryConnectError({ client, error, ...state })
      }
    }
    return false
  }

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

  private async verifyRemoteWriteFile(
    remotePath: string,
    expectedHash: string
  ): Promise<"empty" | "hash-mismatch" | "matches"> {
    // R-0000522: verify the post-finalize remote file via SHA-256 instead of
    // a plain byte-count comparison. A size-only check left a TOCTOU window
    // where an attacker with write access to the destination directory could
    // swap the finalized inode with a different file of the same length and
    // our verification would still report "matches". Hashing the actual byte
    // contents closes that window because SHA-256 is collision-resistant.
    // R-0000581: for non-root sessions try the unprivileged `sha256sum` path
    // first. The finalize step chowns the destination to the parent-directory
    // owner, so the connected user can usually read the file directly. This
    // avoids running `sudo bash -c …` for the verify step, which would burn
    // the full per-command timeout when a sudo prompt hangs (worst-case twice
    // for upload + verify). Only fall back to the privileged `output()` path
    // when the unprivileged read fails with a permission error.
    const hashCommand = `sha256sum -- ${shellQuote(remotePath)}`
    let rawHash: string
    try {
      rawHash = await this.readSha256OutputForVerify(hashCommand)
    } catch (error) {
      // R-0000476: a transient verification failure (non-zero exit code,
      // channel error, sudo hiccup) must not look like a content mismatch.
      // Surfacing it as a dedicated transient error stops the caller from
      // entering the Shell-Fallback and overwriting a remote file that may
      // well be finalized correctly on disk.
      throw new RemoteStatTransientError(
        `[ssh.writeFile: ${remotePath}] could not hash remote file after upload/finalize`,
        { cause: error }
      )
    }
    // R-0000686: mirror the truncation detection from R-0000668 (sha256 /
    // readFile) for the verify path. When the captured stdout is suffixed
    // with `CAPTURE_TRUNCATION_MARKER`, the underlying exec hit the 1 MiB
    // output cap and the trailing 64-hex digest may have been chopped off.
    // Treat that as a transient verification failure so the caller can
    // re-run the verify rather than mis-classifying a truncated reply as
    // a content mismatch (which would then walk into the Shell-Fallback
    // overwrite path).
    if (rawHash.endsWith(CAPTURE_TRUNCATION_MARKER)) {
      throw new RemoteStatTransientError(
        `[ssh.writeFile: ${remotePath}] sha256sum output exceeds the captured-output cap of ${DEFAULT_MAX_OUTPUT_BYTES} bytes; refusing to derive a verdict from truncated output`
      )
    }
    // `sha256sum -- <file>` prints `<64-hex>  <filename>` on success. Split
    // on whitespace and take the first token so a stray newline or filename
    // that contains whitespace cannot confuse the parser.
    const actualHash = rawHash.trim().split(/\s+/v)[0]?.toLowerCase() ?? ""

    if (!/^[0-9a-f]{64}$/v.test(actualHash)) {
      throw new RemoteStatTransientError(
        `[ssh.writeFile: ${remotePath}] could not determine remote file hash after upload/finalize`
      )
    }

    const expected = expectedHash.toLowerCase()
    if (actualHash === expected) return "matches"
    // Disk-full indicator: the remote file hashes to the canonical empty
    // SHA-256 even though we expected non-empty content. Caller uses this
    // verdict to surface a precise "disk full" diagnostic when df agrees.
    if (actualHash === EMPTY_FILE_SHA256 && expected !== EMPTY_FILE_SHA256) return "empty"
    return "hash-mismatch"
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
    // R-0000140: ssh2 emits stderr `error` events (e.g. EPIPE during the
    // sudo password write) on the stderr channel separately from the main
    // stream. `collectStreamOutput` only attaches its own stderr listener
    // *after* `writeStreamInput` returns, so a synchronous stderr EPIPE
    // emitted while the password is being written would have no listener
    // and the channel could hang silently until the 120s watchdog fires.
    // Install a defensive stderr listener so the event is always consumed.
    stream.stderr.once("error", () => {
      // Defensive no-op — collectStreamOutput owns the actual rejection path.
    })
    const writesPassword = needsPassword && this.cachedSudoPassword != null
    if (writesPassword) {
      try {
        this.writeSudoPassword(stream)
      } catch {
        // Defense in depth: a synchronous EPIPE during write must not
        // propagate — the timer / remote-close path owns the rejection.
      }
    }
    if (input != null) {
      this.endStreamInput(stream, input)
      return
    }
    if (writesPassword) {
      this.endStreamInput(stream)
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
