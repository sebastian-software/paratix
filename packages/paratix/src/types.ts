/**
 * A scalar env value, or a lazy function that returns one.
 * Functions may be async, allowing secrets to be fetched on demand.
 */
export type EnvironmentValue =
  | (() => number | string)
  | (() => Promise<number | string>)
  | number
  | string

/** A key-value map of environment values available to modules and templates. */
export type Environment = Record<string, EnvironmentValue>

/** Check result indicating the module's desired state is not yet present. */
export const NEEDS_APPLY = "needs-apply" as const

/** @deprecated Use `Environment` instead. */
// eslint-disable-next-line unicorn/prevent-abbreviations -- Backward-compatible alias
export type Env = Environment
/** @deprecated Use `EnvironmentValue` instead. */
// eslint-disable-next-line unicorn/prevent-abbreviations -- Backward-compatible alias
export type EnvValue = EnvironmentValue

/** The outcome of a module's apply step. */
export type ModuleResult = {
  /** Optional key-value pairs to merge into the env for subsequent modules. */
  meta?: Environment
  /** Execution status of the module. */
  status: "changed" | "failed" | "ok" | "skipped"
}

/**
 * A single idempotent unit of work that can be checked and applied.
 * Modules form the building blocks of a server recipe.
 */
export type Module = {
  /**
   * Enforce the desired state.
   * @returns A {@link ModuleResult} describing what happened.
   */
  apply: (ssh: null | SshConnection, environment: Environment) => Promise<ModuleResult>
  /**
   * Determine whether the module needs to run.
   * @returns `"ok"` if the desired state is already present, `"needs-apply"` otherwise.
   */
  check: (ssh: null | SshConnection, environment: Environment) => Promise<"needs-apply" | "ok">
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
  /** Register an additional port that was opened on the remote host. */
  addPort: (port: number) => void
  /** Close the SSH connection and free resources. */
  disconnect: () => void
  /** Download a remote file to the local filesystem. */
  downloadFile: (remotePath: string, localPath: string) => Promise<void>
  /** Run a command and return the full result including exit code and output. */
  exec: (command: string, options?: ExecOptions) => Promise<ExecResult>
  /** Return `true` if the remote path exists. */
  exists: (remotePath: string) => Promise<boolean>
  /** Return the low-level connection parameters for this session. */
  getConnectionInfo: () => { host: string; port: number; privateKeyPath: string; user: string }
  /** Run a command and return stdout split into lines. */
  lines: (command: string) => Promise<string[]>
  /** Run a command and return trimmed stdout. */
  output: (command: string) => Promise<string>
  /** Probe whether passwordless sudo works; prompt interactively if not and cache the password. */
  probeSudo: () => Promise<void>
  /** Read the full contents of a remote file as a string. */
  readFile: (remotePath: string) => Promise<string>
  /** Return the SHA-256 hex digest of a remote file, or `null` if not found. */
  sha256: (remotePath: string) => Promise<null | string>
  /** Run a command and return `true` if the exit code is zero. */
  test: (command: string) => Promise<boolean>
  /** Update the target host address (e.g. after a reboot with new IP). */
  updateHost: (host: string) => void
  /** Upload a local file to the remote host via SFTP. */
  uploadFile: (localPath: string, remotePath: string) => Promise<void>
  /** Write a string to a remote file, creating or overwriting it. */
  writeFile: (remotePath: string, content: string) => Promise<void>
}

/** SSH connection parameters for a server. */
export type SshConfig = {
  /** Fall back to password authentication if key auth fails. */
  passwordFallback?: boolean
  /** Ordered list of candidate ports -- the runner tries each until one connects. */
  ports: number[]
  /** Absolute path to the private key file used for authentication. */
  privateKey: string
  /** Maximum time in milliseconds to spend attempting reconnection before giving up. */
  reconnectTimeout?: number
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
