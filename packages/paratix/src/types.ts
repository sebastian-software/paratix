/**
 * A scalar env value, or a lazy function that returns one.
 * Functions may be async, allowing secrets to be fetched on demand.
 */
export type EnvironmentValue =
  | (() => boolean | number | string)
  | (() => Promise<boolean | number | string>)
  | boolean
  | number
  | string

/** A key-value map of environment values available to modules and templates. */
export type Environment = Record<string, EnvironmentValue>

/** Environment values that can be emitted through the typed meta system. */
export type MetaEnvironmentValue = EnvironmentValue

/** Generic meta entry that propagates a value into the downstream environment. */
export type EnvironmentMetaEntry = {
  kind: "env"
  name: string
  resolve: () => Promise<boolean | number | string>
  valueType: "boolean" | "number" | "string"
  valueTypeExplicit?: boolean
}

/** Runner control-plane meta entry emitted when sshd changed its listen port. */
export type SshdPortMetaEntry = {
  kind: "sshd.port"
  port: number
}

/** Runner control-plane meta entry emitted when the target host changed. */
export type SystemHostMetaEntry = {
  host: string
  kind: "system.host"
}

/** Runner control-plane meta entry emitted when a reboot should trigger reconnect logic. */
export type SystemRebootMetaEntry = {
  kind: "system.reboot"
}

/** Any meta entry that modules may emit. */
export type ModuleMetaEntry =
  | EnvironmentMetaEntry
  | SshdPortMetaEntry
  | SystemHostMetaEntry
  | SystemRebootMetaEntry

/** Check result indicating the module's desired state is not yet present. */
export const NEEDS_APPLY = "needs-apply" as const

/** Execution status emitted by a module apply step. */
export type ModuleStatus = "changed" | "failed" | "ok" | "skipped"

/** The outcome of a module's apply step. */
export type ModuleResult = {
  /**
   * Optional internal dry-run detail shown instead of the generic `(dry-run)`
   * suffix when a module performed custom dry-run verification.
   * @internal
   */
  _dryRunDetail?: string
  /**
   * Optional internal control-plane marker that tells the current scope to
   * execute all pending signals immediately at this point in the run.
   * @internal
   */
  _flushSignals?: true
  /**
   * Optional internal control-plane marker that tells the runner to stop the
   * current run successfully after this module completed.
   * @internal
   */
  _stopRun?: true
  /** Optional short detail appended to the printed module status line. */
  detail?: string
  /**
   * Optional multi-line unified-diff string rendered below the module status
   * line when the runner was started with the `--diff` CLI flag (or with
   * the runner option `diff`). Modules that participate in diff output produce
   * the string in their `_applyDryRun` hook and mark themselves with
   * `_dryRunDiffProducer: true`. The runner never modifies the string; the
   * output layer applies registered-secret masking and terminal sanitizing
   * before printing each line.
   *
   * Renders independently of `_dryRunDetail` — both fields may be set at the
   * same time, and the runner shows both (detail inline next to the status,
   * diff in a block beneath it).
   */
  diff?: string
  /** Optional error details consumed by the runner for centralized CLI output. */
  error?: Error
  /** Optional typed meta entries for env propagation and runner control-plane updates. */
  meta?: ModuleMetaEntry[]
  /** Execution status of the module. */
  status: ModuleStatus
}

/**
 * Internal orchestration step shape shared between runner and recipe execution.
 * Contains the merged downstream environment after a single apply step.
 * @internal
 */
export type OrchestrationStep = {
  /** @internal */
  _flushSignals?: true
  /** @internal */
  _stopRun?: true
  env: Environment
  meta?: ModuleMetaEntry[]
  status: ModuleStatus
}

/**
 * Optional internal apply hooks used by composite modules to expose child
 * orchestration steps to their surrounding runner scope.
 * @internal
 */
export type ModuleApplyOptions = {
  onChildStep?: (step: OrchestrationStep) => Promise<void>
  shutdownSignal?: () => null | ShutdownSignal
}

/**
 * Shutdown signal names observed by Paratix orchestration hooks.
 *
 * This intentionally mirrors Node's process signal strings without referencing
 * the ambient `NodeJS` namespace, so published declarations remain usable in
 * consumers that do not install `@types/node`.
 */
export type ShutdownSignal =
  | "SIGABRT"
  | "SIGALRM"
  | "SIGBREAK"
  | "SIGBUS"
  | "SIGCHLD"
  | "SIGCONT"
  | "SIGFPE"
  | "SIGHUP"
  | "SIGILL"
  | "SIGINFO"
  | "SIGINT"
  | "SIGIO"
  | "SIGIOT"
  | "SIGKILL"
  | "SIGLOST"
  | "SIGPIPE"
  | "SIGPOLL"
  | "SIGPROF"
  | "SIGPWR"
  | "SIGQUIT"
  | "SIGSEGV"
  | "SIGSTKFLT"
  | "SIGSTOP"
  | "SIGSYS"
  | "SIGTERM"
  | "SIGTRAP"
  | "SIGTSTP"
  | "SIGTTIN"
  | "SIGTTOU"
  | "SIGUNUSED"
  | "SIGURG"
  | "SIGUSR1"
  | "SIGUSR2"
  | "SIGVTALRM"
  | "SIGWINCH"
  | "SIGXCPU"
  | "SIGXFSZ"

/**
 * A single idempotent unit of work that can be checked and applied.
 * Modules form the building blocks of a server recipe.
 */
export type Module = {
  /**
   * Optional internal dry-run apply hook for modules that need custom dry-run
   * execution semantics beyond the generic blocker/meta-producer markers.
   * @internal
   */
  _applyDryRun?: (
    ssh: null | SshConnection,
    environment: Environment,
    options?: ModuleApplyOptions
  ) => Promise<ModuleResult>
  /**
   * Internal marker for modules that must still execute their apply step in dry-run mode
   * because they act as run blockers rather than mutating state.
   * @internal
   */
  _dryRunBlocker?: true
  /**
   * Internal marker for modules that can produce a {@link ModuleResult.diff}
   * during dry-run by running their `_applyDryRun` hook. The runner only
   * dispatches `_applyDryRun` for diff production when the user passed the
   * `--diff` CLI flag (i.e. the runner option `diff` is `true`); otherwise the
   * generic `(dry-run)` suffix is shown without any extra remote round-trips.
   * @internal
   */
  _dryRunDiffProducer?: true
  /**
   * Internal marker for non-mutating modules whose apply step emits meta that must
   * still be materialized during dry-run so downstream modules see the same environment.
   * @internal
   */
  _dryRunMetaProducer?: true
  /**
   * Internal marker for composite modules that can expose child orchestration
   * steps to the surrounding runner scope.
   * @internal
   */
  _supportsChildStepHook?: true
  /**
   * Enforce the desired state.
   * @returns A {@link ModuleResult} describing what happened.
   */
  apply: (
    ssh: null | SshConnection,
    environment: Environment,
    options?: ModuleApplyOptions
  ) => Promise<ModuleResult>
  /**
   * Determine whether the module needs to run.
   * @returns `"ok"` if the desired state is already present, `"needs-apply"` otherwise.
   */
  check: (ssh: null | SshConnection, environment: Environment) => Promise<"needs-apply" | "ok">
  /**
   * Internal discriminator that distinguishes leaf modules from recipes.
   *
   * Leaf modules leave this `undefined` (treated as `"module"`); recipes set
   * `"recipe"` so the runner can narrow to the recipe contract via the
   * `isRecipe` type guard instead of an unsafe structural cast. Intentionally
   * optional so existing custom modules and playbooks stay source-compatible —
   * they never need to set it.
   * @internal
   */
  kind?: "module" | "recipe"
  /**
   * When true the module runs locally instead of over SSH.
   * The `ssh` parameter will be `null` in check/apply.
   */
  local?: boolean
  /** Human-readable name shown in the run output. */
  name: string
}

/** Raw output from a remote or local command execution. */
export type ExecResult = {
  /** Exit code of the process. */
  code: number
  /** Captured standard error. */
  stderr: string
  /** Captured standard output. */
  stdout: string
}

/** Options that control how a command is executed. */
export type ExecOptions = {
  /** Additional environment variables to inject into the process. */
  env?: Record<string, string>
  /** Return a result even when the exit code is non-zero instead of throwing. */
  ignoreExitCode?: boolean
  /**
   * Optional payload written to the remote command's stdin before EOF is
   * signalled. Used to pass secret material (password hashes, signed URLs,
   * Authorization headers) to a remote tool without exposing it on the
   * command line, where it would otherwise leak into `/var/log/auth.log`,
   * `ps -ef`, or `/proc/<pid>/cmdline`.
   */
  input?: string
  /**
   * Maximum number of UTF-8 bytes captured per output stream for `stdout` and
   * `stderr`. Live output still streams fully; only the stored ExecResult and
   * CommandError output are capped.
   */
  maxOutputBytes?: number
  /** Strings to mask in error messages (e.g. tokens, passwords). */
  secrets?: string[]
  /** Suppress stdout/stderr from the console while running. */
  silent?: boolean
  /** Abort the command after this many milliseconds. */
  timeout?: number
}

/**
 * Abstraction over an active SSH session.
 * All methods that accept a `command` string run it on the remote host.
 */
export type SshConnection = {
  /** Register an additional port that was opened on the remote host. Returns `true` when added. */
  addPort: (port: number) => boolean
  /** Close the SSH connection and free resources. */
  disconnect: () => void
  /** Download a remote file to the local filesystem. */
  downloadFile: (remotePath: string, localPath: string) => Promise<void>
  /** Run a command and return the full result including exit code and output. */
  exec: (command: string, options?: ExecOptions) => Promise<ExecResult>
  /** Return `true` if the remote path exists. */
  exists: (remotePath: string) => Promise<boolean>
  /**
   * Return the low-level connection parameters for this session.
   * `privateKeyPath` and `agentSocket` reflect the authentication method that
   * was actually used for the current session. `privateKeyPath` is returned as
   * an expanded filesystem path.
   */
  getConnectionInfo: () => {
    agentSocket?: string
    authMethod?: "agent" | "password" | "privateKey"
    configuredPorts: number[]
    host: string
    port: number
    privateKeyPath?: string
    user: string
    verifiedHostPublicKey?: string
  }
  /** Run a command and return stdout split into lines. */
  lines: (command: string) => Promise<string[]>
  /** Run a command and return trimmed stdout. */
  output: (command: string) => Promise<string>
  /** Probe whether passwordless sudo works; prompt interactively if not and cache the password. */
  probeSudo: () => Promise<void>
  /** Read the full contents of a remote file as a string. */
  readFile: (remotePath: string) => Promise<string>
  /**
   * Reconnect the SSH session using the current host and registered port
   * candidates. An explicit `reconnectTimeout` in the SSH config always takes
   * precedence; when it is unset, `options.defaultTimeout` (in milliseconds)
   * overrides the generic reconnect default for this call — used by the reboot
   * path to grant a longer window.
   */
  reconnect: (options?: { defaultTimeout?: number }) => Promise<void>
  /** Remove a previously registered port from the reconnect candidate list. */
  removePort: (port: number) => void
  /** Return the SHA-256 hex digest of a remote file, or `null` if not found. */
  sha256: (remotePath: string) => Promise<null | string>
  /** Run a command and return `true` if the exit code is zero. */
  test: (command: string) => Promise<boolean>
  /** Update the target host address (e.g. after a reboot with new IP). */
  updateHost: (host: string) => void
  /** Upload a local file to the remote host via SFTP. `options.mode` is optional and defaults to `"0600"`. */
  uploadFile: (localPath: string, remotePath: string, options?: { mode?: string }) => Promise<void>
  /** Write a string to a remote file, creating or overwriting it. `options.mode` is optional and defaults to `"0600"`. */
  writeFile: (remotePath: string, content: string, options?: { mode?: string }) => Promise<void>
}

/**
 * Write a file only if its content has not changed since it was read.
 * Re-reads the file before writing and throws if the current content
 * differs from `originalContent`, preventing lost updates from concurrent modifications.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param parameters - Parameters for the guarded write operation.
 * @param parameters.mode - Chmod mode string for the written file.
 * @param parameters.newContent - The transformed content to write.
 * @param parameters.originalContent - The content that was read before the transformation.
 * @param parameters.remotePath - Path to the file on the remote host.
 */
export async function guardedWriteFile(
  ssh: SshConnection,
  parameters: {
    mode: string
    newContent: string
    originalContent: string
    remotePath: string
  }
): Promise<void> {
  const currentContent = await ssh.readFile(parameters.remotePath)
  if (currentContent !== parameters.originalContent) {
    throw new Error(
      `Concurrent modification detected on ${parameters.remotePath}: ` +
        "file content changed between read and write. Aborting to prevent data loss."
    )
  }
  await ssh.writeFile(parameters.remotePath, parameters.newContent, { mode: parameters.mode })
}

/** SSH connection parameters for a server. */
export type SshConfig = {
  /** Forward the local SSH agent to the remote host. */
  agentForward?: boolean
  /** Expected SHA256 host fingerprint used as a pinned trust anchor. */
  expectedHostFingerprint?: string
  /** Expected OpenSSH public key (`"<algorithm> <base64>"`) used as a pinned trust anchor. */
  expectedHostPublicKey?: string
  /** Maximum number of reconnection attempts before giving up. */
  maxReconnectAttempts?: number
  /** Fall back to password authentication if key auth fails. */
  passwordFallback?: boolean
  /** Ordered list of candidate ports -- the runner tries each until one connects. */
  ports: number[]
  /**
   * Absolute path to the private key file used for authentication.
   * When omitted, the SSH agent referenced by `SSH_AUTH_SOCK` is used instead.
   * Exactly one of `privateKey` or a running SSH agent must be available.
   */
  privateKey?: string
  /** Maximum time in milliseconds to spend attempting reconnection before giving up. */
  reconnectTimeout?: number
  /**
   * Host key verification strategy.
   * - `"accept-new"` — explicit TOFU opt-in: accept unknown keys and append them to `~/.ssh/known_hosts`.
   * - `"yes"` — reject unknown keys; only connect when the key is already in `known_hosts`.
   * - `"no"` — skip host key verification entirely.
   *
   * When omitted, Paratix now defaults to `"yes"`. To connect to a new host
   * safely without TOFU, set `expectedHostFingerprint` or `expectedHostPublicKey`.
   */
  strictHostKeyChecking?: "accept-new" | "no" | "yes"
  /** Password used for `sudo` escalation on the remote host. */
  sudoPassword?: string
  /** Username to authenticate as. */
  user: string
}

/** Top-level definition of a server and the modules to run on it. */
export type ServerDefinition = {
  /** Server-level env values merged with global env before running modules. */
  env?: Environment
  /** Hostname or IP address. */
  host: string
  /** Display name for the server. */
  name: string
  /** Ordered list of modules (or recipes) to apply. */
  run: Module[]
  /**
   * Modules triggered as signals after the run completes with status `"changed"`.
   * Typically used for service reloads or notifications.
   */
  signals?: Module[]
  /** SSH connection parameters. */
  ssh: SshConfig
}
