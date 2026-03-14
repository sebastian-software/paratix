import { execFile } from "node:child_process"
import { promisify } from "node:util"

import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

// eslint-disable-next-line @typescript-eslint/strict-void-return -- promisify requires the callback-based overload
const execFileAsync = promisify(execFile)

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

/**
 * Assemble the full rsync argument list for a transfer.
 *
 * Always enables archive mode (`-a`), compression (`-z`), and itemized
 * output (`--itemize-changes`). The SSH transport is configured from
 * the connection info with strict host-key checking disabled so that
 * first-time connections do not block.
 *
 * @param options - Sync options describing source, destination, and filters.
 * @param connectionInfo - SSH connection details obtained from `SshConnection.getConnectionInfo`.
 * @param connectionInfo.host - The remote host address.
 * @param connectionInfo.port - The SSH port number.
 * @param connectionInfo.privateKeyPath - Absolute path to the SSH private key.
 * @param connectionInfo.user - The SSH username.
 * @param dryRun - When `true`, adds `--dry-run` so no files are transferred.
 * @returns The complete list of arguments to pass to the `rsync` binary.
 */
function buildArguments(
  options: SyncOptions,
  connectionInfo: { host: string; port: number; privateKeyPath: string; user: string },
  dryRun: boolean
): string[] {
  const result: string[] = ["-az", "--itemize-changes"]

  if (dryRun) {
    result.push("--dry-run")
  }

  result.push(
    "-e",
    `ssh -p ${connectionInfo.port} -i "${connectionInfo.privateKeyPath}" -o StrictHostKeyChecking=no`
  )
  result.push(...buildFilterArguments(options))
  result.push(...buildOwnershipArguments(options))
  result.push("--", options.src, `${connectionInfo.user}@${connectionInfo.host}:${options.dest}`)

  return result
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
   */
  sync(options: SyncOptions): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const connectionInfo = ssh.getConnectionInfo()
        const rsyncArguments = buildArguments(options, connectionInfo, false)

        try {
          const { stdout } = await execFileAsync("rsync", rsyncArguments)
          return { status: stdout.trim().length > 0 ? "changed" : "ok" }
        } catch (error) {
          console.error(`[rsync.sync] ${options.src} -> ${options.dest}: ${String(error)}`)
          return { status: "failed" }
        }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const connectionInfo = ssh.getConnectionInfo()
        const rsyncArguments = buildArguments(options, connectionInfo, true)

        try {
          const { stdout } = await execFileAsync("rsync", rsyncArguments)
          return stdout.trim().length > 0 ? NEEDS_APPLY : "ok"
        } catch (error) {
          console.error(
            `[rsync.sync] check failed for ${options.src} -> ${options.dest}: ${String(error)}`
          )
          return NEEDS_APPLY
        }
      },
      name: `rsync.sync: ${options.src} -> ${options.dest}`,
    }
  },
}
