import { execFile, type ExecFileException } from "node:child_process"
import { randomUUID } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { CommandError } from "../sshHelpers.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

type RsyncPhase = "apply" | "check"
const DEFAULT_SSH_PORT = 22

type SyncOptions = {
  /** Permission mode applied via `--chmod`, e.g. `"Du=rwx,go=rx,Fu=rw,go=r"`. */
  chmod?: string
  /** Remove files on the remote that are absent from the source (`--delete`). */
  delete?: boolean
  /** Absolute destination path on the remote host. */
  dest: string
  /** Patterns passed to rsync `--exclude` in order, applied after includes. */
  exclude?: string[]
  /** Group name for `--chown`; defaults to `owner` when only `owner` is set. */
  group?: string
  /** Patterns passed to rsync `--include` in order, applied before excludes. */
  include?: string[]
  /** Owner name for `--chown`. */
  owner?: string
  /** Local source path (file or directory) to synchronize. */
  src: string
  /**
   * SSH `StrictHostKeyChecking` option passed to the `-o` flag.
   *
   * Defaults to `"yes"`. Use `"accept-new"` for explicit TOFU when first-time
   * connections must be auto-accepted, or `"no"` to disable checking entirely
   * (not recommended for production).
   */
  strictHostKeyChecking?: "accept-new" | "no" | "off" | "yes"
}

/**
 * Build the rsync filter arguments for include/exclude patterns and deletion.
 *
 * Includes are appended before excludes so that rsync evaluates them in the
 * correct order (first matching rule wins).
 *
 * @param options - Sync options containing include, exclude, and delete settings.
 * @returns An array of rsync arguments for filter rules.
 */
function buildFilterArguments(options: SyncOptions): string[] {
  const result: string[] = []

  for (const pattern of options.include ?? []) {
    result.push("--include", pattern)
  }

  for (const pattern of options.exclude ?? []) {
    result.push("--exclude", pattern)
  }

  if (options.delete) {
    result.push("--delete")
  }

  return result
}

/**
 * Build the rsync ownership arguments for `--chown` and `--chmod`.
 *
 * When only `owner` is set, the group defaults to the same value so that
 * rsync receives a valid `owner:group` pair.
 *
 * @param options - Sync options containing owner, group, and chmod settings.
 * @returns An array of rsync arguments for ownership and permissions.
 */
function buildOwnershipArguments(options: SyncOptions): string[] {
  const result: string[] = []

  if (options.owner != null || options.group != null) {
    const ownerPart = options.owner ?? ""
    const groupPart = options.group ?? options.owner ?? ""
    result.push(`--chown=${ownerPart}:${groupPart}`)
  }

  if (options.chmod != null) {
    result.push(`--chmod=${options.chmod}`)
  }

  return result
}

function buildRemoteSpec(
  connectionInfo: {
    host: string
    user: string
  },
  destination: string
): string {
  const remoteHost = connectionInfo.host.includes(":")
    ? `[${connectionInfo.host}]`
    : connectionInfo.host
  return `${connectionInfo.user}@${remoteHost}:${destination}`
}

function formatKnownHostsLabel(host: string, port: number): string {
  return port === DEFAULT_SSH_PORT ? host : `[${host}]:${port}`
}

function createVerifiedKnownHostsFile(connectionInfo: {
  host: string
  port: number
  verifiedHostPublicKey?: string
}): null | string {
  if (connectionInfo.verifiedHostPublicKey == null) return null

  const filePath = join(tmpdir(), `paratix-rsync-known-hosts-${randomUUID()}`)
  const content = `${formatKnownHostsLabel(connectionInfo.host, connectionInfo.port)} ${connectionInfo.verifiedHostPublicKey}\n`
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(filePath, content, { mode: 0o600 })
  return filePath
}

function cleanupVerifiedKnownHostsFile(path: null | string): void {
  if (path == null) return
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    unlinkSync(path)
  } catch {
    // local cleanup is best-effort
  }
}

/**
 * Assemble the full rsync argument list for a transfer.
 *
 * Always enables archive mode (`-a`), compression (`-z`), and itemized
 * output (`--itemize-changes`). The SSH transport is configured from
 * the connection info with host-key checking set to `yes` by default.
 * Use `strictHostKeyChecking: "accept-new"` for explicit TOFU when
 * first-time connections must be auto-accepted.
 *
 * @param parameters - Argument bundle for the rsync command construction.
 * @param parameters.options - Sync options describing source, destination, and filters.
 * @param parameters.connectionInfo - SSH connection details obtained from `SshConnection.getConnectionInfo`.
 * @param parameters.connectionInfo.agentSocket - SSH agent socket path (`SSH_AUTH_SOCK`), used when no private key is configured.
 * @param parameters.connectionInfo.authMethod - Authentication method that established the current SSH session.
 * @param parameters.connectionInfo.host - The remote host address.
 * @param parameters.connectionInfo.port - The SSH port number.
 * @param parameters.connectionInfo.privateKeyPath - Absolute path to the SSH private key.
 * @param parameters.connectionInfo.user - The SSH username.
 * @param parameters.dryRun - When `true`, adds `--dry-run` so no files are transferred.
 * @param parameters.verifiedKnownHostsPath - Optional temporary known_hosts file containing the verified session host key.
 * @returns The complete list of arguments to pass to the `rsync` binary.
 */
function buildArguments(parameters: {
  connectionInfo: {
    agentSocket?: string
    authMethod?: "agent" | "password" | "privateKey"
    host: string
    port: number
    privateKeyPath?: string
    user: string
  }
  dryRun: boolean
  options: SyncOptions
  verifiedKnownHostsPath?: string
}): string[] {
  const { connectionInfo, dryRun, options, verifiedKnownHostsPath } = parameters
  const result: string[] = ["-az", "--itemize-changes"]

  if (dryRun) {
    result.push("--dry-run")
  }

  let sshFlags = ""
  if (connectionInfo.privateKeyPath != null) {
    sshFlags = ` -i ${shellQuote(connectionInfo.privateKeyPath)}`
  } else if (connectionInfo.agentSocket != null) {
    sshFlags = ` -o IdentityAgent=${shellQuote(connectionInfo.agentSocket)}`
  }
  const strictHostKeyChecking =
    verifiedKnownHostsPath == null ? (options.strictHostKeyChecking ?? "yes") : "yes"
  const knownHostsFlags =
    verifiedKnownHostsPath == null
      ? ""
      : ` -o UserKnownHostsFile=${shellQuote(verifiedKnownHostsPath)} -o GlobalKnownHostsFile=/dev/null`
  result.push(
    "-e",
    `ssh -p ${connectionInfo.port}${sshFlags}${knownHostsFlags} -o StrictHostKeyChecking=${strictHostKeyChecking}`
  )
  result.push(...buildFilterArguments(options))
  result.push(...buildOwnershipArguments(options))
  result.push("--", options.src, buildRemoteSpec(connectionInfo, options.dest))

  return result
}

type RsyncFailureDetails = {
  code?: number | string
  error: unknown
  stderr: string
  stdout: string
}

function firstNonEmptyLine(text: string): null | string {
  for (const line of text.split("\n")) {
    const trimmed = line.trim()
    if (trimmed.length > 0) return trimmed
  }
  return null
}

function createRsyncError(
  options: SyncOptions,
  phase: RsyncPhase,
  details: RsyncFailureDetails
): Error {
  const exitCodeSuffix = details.code == null ? "" : ` (exit code ${String(details.code)})`
  const messageDetails =
    firstNonEmptyLine(details.stderr) ??
    firstNonEmptyLine(details.stdout) ??
    (details.error instanceof Error ? details.error.message : String(details.error))

  return new CommandError(
    `[rsync.sync] ${phase} failed for ${options.src} -> ${options.dest}${exitCodeSuffix}\n${messageDetails}`,
    details.stdout,
    details.stderr
  )
}

async function executeRsync(parameters: {
  dryRun: boolean
  options: SyncOptions
  phase: RsyncPhase
  ssh: SshConnection
}): Promise<string> {
  const { dryRun, options, phase, ssh } = parameters
  const connectionInfo = ssh.getConnectionInfo()
  if (connectionInfo.authMethod === "password") {
    throw new Error(
      `[rsync.sync] ${phase} requires agent or private-key SSH authentication; password fallback sessions are not supported`
    )
  }
  const verifiedKnownHostsPath = createVerifiedKnownHostsFile(connectionInfo)
  const rsyncArguments = buildArguments({
    connectionInfo,
    dryRun,
    options,
    verifiedKnownHostsPath: verifiedKnownHostsPath ?? undefined,
  })

  try {
    return await new Promise((resolve, reject) => {
      execFile("rsync", rsyncArguments, (error: ExecFileException | null, stdout, stderr) => {
        if (error != null) {
          reject(
            createRsyncError(options, phase, {
              code: error.code ?? undefined,
              error,
              stderr,
              stdout,
            })
          )
          return
        }
        resolve(stdout)
      })
    })
  } finally {
    cleanupVerifiedKnownHostsFile(verifiedKnownHostsPath)
  }
}

/**
 * Modules for synchronizing files to a remote host using rsync.
 */
export const rsync = {
  /**
   * Synchronize a local path to a remote destination using rsync over SSH.
   *
   * The `check` phase runs rsync with `--dry-run` and reports `needs-apply`
   * when the itemized output is non-empty. The `apply` phase returns
   * `"changed"` when rsync reports transferred items, or `"ok"` when the
   * destination was already in sync.
   *
   * @param options - Sync configuration including source, destination, and optional filters.
   * @returns A Module that manages the rsync synchronization.
   *
   * @example
   * ```ts
   * rsync.sync({
   *   src: "./dist/",
   *   dest: "/var/www/app",
   *   delete: true,
   *   exclude: ["*.map"],
   *   owner: "www-data",
   * })
   * ```
   *
   * @example Enforce strict host-key checking for a host that is already known:
   * ```ts
   * rsync.sync({
   *   src: "./dist/",
   *   dest: "/var/www/app",
   *   strictHostKeyChecking: "yes",
   * })
   * ```
   */
  sync(options: SyncOptions): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[rsync.sync] SSH connection is required")

        try {
          const stdout = await executeRsync({ dryRun: false, options, phase: "apply", ssh })
          return { status: stdout.trim().length > 0 ? "changed" : "ok" }
        } catch (error) {
          return {
            error: error instanceof Error ? error : new Error(String(error)),
            status: "failed",
          }
        }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const stdout = await executeRsync({ dryRun: true, options, phase: "check", ssh })
        return stdout.trim().length > 0 ? NEEDS_APPLY : "ok"
      },
      name: `rsync.sync: ${options.src} -> ${options.dest}`,
    }
  },
}
