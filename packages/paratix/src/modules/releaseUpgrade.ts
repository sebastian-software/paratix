/* eslint-disable max-lines -- releaseUpgrade keeps distro-specific upgrade flow in one module. */
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecOptions,
  type ExecResult,
  guardedWriteFile,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { withMutexLock } from "./moduleHelpers.js"
import { type Distro, parseOsReleaseDistro } from "./releaseUpgradeDistro.js"
import {
  isAcceptableSourcesPath,
  isSupportedDebianUpgradePath,
  isVanishedSourcesFileError,
  readSourcesFileMode,
  RELEASE_UPGRADE_DEFAULT_TIMEOUT_MS,
  rewriteAptSourcesContent,
  wrapMissingSourcesFileError,
} from "./releaseUpgradeSources.js"
import { isSymlink } from "./remoteFileChecks.js"
import {
  buildRebootMetaEntriesWithTimeout,
  type ResolveHostCallback,
} from "./resolveHostTimeout.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const CODENAME_RE = /^[a-z]{3,20}$/v
const NO_UBUNTU_RELEASE_PATTERN = /no new release (?:found|available)/iv
const DEBIAN_RELEASE_UPGRADE_MUTEX = "release-upgrade-mutex"
function isNoUbuntuReleaseAvailable(result: ExecResult): boolean {
  if (result.code === 0) return false
  return NO_UBUNTU_RELEASE_PATTERN.test(`${result.stdout}\n${result.stderr}`)
}

/**
 * Options for the {@link releaseUpgrade.upgrade} module.
 */
type ReleaseUpgradeOptions = {
  /**
   * When `true`, only check whether an upgrade is available without applying
   * any changes. The module returns `"ok"` regardless of what is found.
   */
  dryRun?: boolean
  /**
   * Optional async function to resolve the new host address after the
   * post-upgrade reboot. Useful when the server's IP address may change
   * (e.g. DHCP or cloud environments). The resolved value is emitted as
   * `system.host` meta so the runner can reconnect to the correct address.
   *
   * R-0000575: the callback receives an `AbortSignal` that fires when the
   * configured timeout elapses. Honoring the signal lets DNS/cloud lookups
   * abort their in-flight work promptly.
   */
  resolveHost?: ResolveHostCallback
  /**
   * Wall-clock timeout (ms) applied to {@link ReleaseUpgradeOptions.resolveHost}.
   * Defaults to 30 seconds (R-0000243) so a hanging DNS/cloud lookup cannot
   * stall the playbook indefinitely.
   */
  resolveHostTimeoutMs?: number
  /** Override the per-step command timeout (ms). Default: 30 minutes. */
  timeout?: number
}

/**
 * Detect the Linux distribution of the remote host by reading
 * `/etc/os-release`. See {@link parseOsReleaseDistro} for the comparison
 * rules (case-insensitive explicit `ID=` only).
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns `"debian"`, `"ubuntu"`, or `null` when the distribution cannot be
 *   identified.
 */
async function detectDistro(ssh: SshConnection): Promise<Distro | null> {
  const osRelease = await ssh.readFile("/etc/os-release")
  return parseOsReleaseDistro(osRelease)
}

/**
 * Return the current Debian/Ubuntu release codename via `lsb_release -cs`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns The codename string (e.g. `"bookworm"` or `"noble"`).
 */
async function getDebianCurrentCodename(ssh: SshConnection): Promise<string> {
  const codename = await ssh.output("lsb_release -cs")
  if (!CODENAME_RE.test(codename)) {
    throw new Error(`Invalid codename from lsb_release: ${JSON.stringify(codename)}`)
  }
  return codename
}

/**
 * Fetch the codename of the current Debian stable release from the official mirrors.
 *
 * @param ssh - Active SSH connection.
 * @returns The stable codename (e.g. `"bookworm"`).
 * @throws {Error} When the `Codename:` field is absent.
 */
async function getDebianStableCodename(ssh: SshConnection): Promise<string> {
  // R-0000177: --max-time bounds the wall-clock duration of the request.
  const result = await ssh.exec(
    "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release",
    { ignoreExitCode: true, silent: true }
  )
  for (const line of result.stdout.split("\n")) {
    const match = /^Codename:\s+(?<name>\S+)$/v.exec(line)
    if (match?.groups) {
      const codename = match.groups.name
      if (!CODENAME_RE.test(codename)) {
        throw new Error(`Invalid stable codename from Debian mirrors: ${JSON.stringify(codename)}`)
      }
      return codename
    }
  }
  throw new Error("Could not determine Debian stable codename")
}

const APT_SOURCES_LIST = "/etc/apt/sources.list"

/**
 * Snapshot of an apt sources file as it was before
 * {@link replaceCodenameInSourcesList} rewrote it. Used by
 * {@link restoreSourcesSnapshots} to roll back when a subsequent apt step
 * fails so the host never ends up with sources pointing at the new suite
 * while the upgrade itself failed. Mirrors the snapshot format used in
 * `quadlet.ts` and `timerFileSnapshots.ts` (R-0000241/R-0000217) where the
 * captured mode preserves operator-specific permissions across the
 * rollback.
 */
type SourcesSnapshot = {
  mode: string
  originalContent: string
  remotePath: string
}

type RestoreSourcesFailure = {
  error: unknown
  remotePath: string
}

type RewriteSourcesParameters = {
  currentCodename: string
  originalContent: string
  remotePath: string
  ssh: SshConnection
  targetCodename: string
}

async function rewriteSourcesFile(
  parameters: RewriteSourcesParameters
): Promise<null | SourcesSnapshot> {
  const { currentCodename, originalContent, remotePath, ssh, targetCodename } = parameters
  // Rewrite only apt suite fields. URLs, comments and unrelated deb822 fields
  // may contain release codenames as substrings and must remain untouched.
  const updatedContent = rewriteAptSourcesContent({
    currentCodename,
    originalContent,
    remotePath,
    targetCodename,
  })
  if (updatedContent === originalContent) return null

  // R-0000241: capture the original mode before overwriting so the rollback
  // can restore the operator's exact permissions instead of forcing 0644.
  const mode = await readSourcesFileMode(ssh, remotePath, shellQuote)
  await guardedWriteFile(ssh, {
    mode,
    newContent: updatedContent,
    originalContent,
    remotePath,
  })
  return { mode, originalContent, remotePath }
}

type SnapshotSourcesParameters = Omit<RewriteSourcesParameters, "originalContent">

// R-0000240: a sources file enumerated by `find -print0` may vanish between
// enumeration and the subsequent read. Skip ENOENT-style errors so a single
// transient absence does not abort the entire release upgrade.
//
// R-0000286: decorate the raw error with `code: "ENOENT"` so downstream
// detection can rely on the structured field rather than scanning the
// (possibly localized) message text.
async function snapshotSourcesFileSafely(
  parameters: SnapshotSourcesParameters
): Promise<null | SourcesSnapshot> {
  try {
    const originalContent = await parameters.ssh.readFile(parameters.remotePath)
    return await rewriteSourcesFile({ ...parameters, originalContent })
  } catch (error) {
    const decorated = wrapMissingSourcesFileError(error)
    if (isVanishedSourcesFileError(decorated)) return null
    throw decorated
  }
}

// R-0000571: defend against a TOCTOU window between `find -type f` and the
// subsequent read/write by re-probing each path immediately before reading.
// Extracted into a helper to keep `replaceCodenameInSourcesList`'s cognitive
// complexity within the project limit while keeping the symlink guard close
// to the per-file read.
async function snapshotEnumeratedSourcesFile(parameters: {
  currentCodename: string
  filePath: string
  ssh: SshConnection
  targetCodename: string
}): Promise<null | SourcesSnapshot> {
  if (parameters.filePath.length === 0 || !isAcceptableSourcesPath(parameters.filePath)) return null
  // Even though `find` already excludes symlinks (it runs with the default
  // `-P`), an attacker with write access to `/etc/apt/sources.list.d/` could
  // swap the regular file for a symlink between enumeration and the per-file
  // `readFile`/`writeFile` calls. Skip when the target is now a symbolic
  // link so we never follow it into an arbitrary location.
  if (await isSymlink(parameters.ssh, parameters.filePath)) return null
  return snapshotSourcesFileSafely({
    currentCodename: parameters.currentCodename,
    remotePath: parameters.filePath,
    ssh: parameters.ssh,
    targetCodename: parameters.targetCodename,
  })
}

/**
 * Replace all occurrences of `currentCodename` with `targetCodename` in
 * `/etc/apt/sources.list` and every `.list` and `.sources` file under
 * `/etc/apt/sources.list.d/`.
 *
 * This is the core step for upgrading Debian: pointing apt at the new release
 * suite before running `apt-get full-upgrade`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param currentCodename - The codename that is currently in use (e.g. `"bullseye"`).
 * @param targetCodename - The codename to upgrade to (e.g. `"bookworm"`).
 * @returns Snapshots of every sources file that was modified, in the order
 *   they were rewritten. The caller can hand these to
 *   {@link restoreSourcesSnapshots} to roll back on a downstream apt failure.
 */
async function replaceCodenameInSourcesList(
  ssh: SshConnection,
  currentCodename: string,
  targetCodename: string
): Promise<SourcesSnapshot[]> {
  const snapshots: SourcesSnapshot[] = []

  if (await ssh.exists(APT_SOURCES_LIST)) {
    const mainSnapshot = await snapshotSourcesFileSafely({
      currentCodename,
      remotePath: APT_SOURCES_LIST,
      ssh,
      targetCodename,
    })
    if (mainSnapshot != null) snapshots.push(mainSnapshot)
  }

  // R-0000053: use `find ... -print0` and split on the NUL byte so the
  // pipeline stays safe against pathological filenames containing
  // newlines, leading dashes (which `find` could otherwise treat as
  // flags), or embedded whitespace. The previous newline-split approach
  // could miss files or corrupt their paths in those edge cases.
  const listFilesResult = await ssh.exec(
    "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0",
    { ignoreExitCode: true, silent: true }
  )
  if (listFilesResult.code !== 0 || listFilesResult.stdout.length === 0) {
    return snapshots
  }

  // R-0000172: defense-in-depth — paths that escape the sources directory or
  // carry ASCII control characters are skipped before readFile / writeFile.
  for (const filePath of listFilesResult.stdout.split("\0")) {
    // eslint-disable-next-line no-await-in-loop
    const snapshot = await snapshotEnumeratedSourcesFile({
      currentCodename,
      filePath,
      ssh,
      targetCodename,
    })
    if (snapshot != null) snapshots.push(snapshot)
  }

  return snapshots
}

/**
 * Restore every snapshot returned by {@link replaceCodenameInSourcesList} so
 * the host's apt sources point at the original suite again. Failures during
 * the rollback are swallowed per file: a single missing or now-protected file
 * must not prevent the remaining snapshots from being restored.
 *
 * Mirrors the rollback strategy used by `sshd.config` (see
 * `validateSshdConfig` in `packages/paratix/src/modules/sshd.ts`), where a
 * failed `sshd -t` validation also writes the original content back via
 * `ssh.writeFile`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param snapshots - The snapshots to restore, in any order.
 * @returns Restore failures collected while attempting all snapshots.
 */
async function restoreSourcesSnapshots(
  ssh: SshConnection,
  snapshots: SourcesSnapshot[]
): Promise<RestoreSourcesFailure[]> {
  const failures: RestoreSourcesFailure[] = []
  for (const snapshot of snapshots) {
    try {
      // Intentional: unguarded write — restoring the original sources is
      // more important than concurrency safety during a failed-upgrade
      // rollback. An additional guarded write would refuse to roll back if
      // the file content changed mid-flight. R-0000241: the mode captured
      // in the snapshot is restored so operator-specific permissions
      // (e.g. `chmod 0640` for a sources file with secrets) survive the
      // rollback unchanged.
      // eslint-disable-next-line no-await-in-loop
      await ssh.writeFile(snapshot.remotePath, snapshot.originalContent, {
        mode: snapshot.mode,
      })
    } catch (error) {
      // Best-effort: if a single file cannot be restored, keep going so the
      // remaining snapshots still revert. The caller appends these failures
      // to the original apt error so incomplete rollbacks remain visible.
      failures.push({ error, remotePath: snapshot.remotePath })
    }
  }
  return failures
}

function formatRestoreSourcesFailure(failure: RestoreSourcesFailure): string {
  const reason = failure.error instanceof Error ? failure.error.message : String(failure.error)
  return `${failure.remotePath}: ${reason}`
}

function appendRestoreSourcesFailures(
  pipelineFailure: ModuleResult,
  restoreFailures: RestoreSourcesFailure[]
): ModuleResult {
  if (restoreFailures.length === 0) return pipelineFailure
  const pipelineMessage = pipelineFailure.error?.message ?? "[releaseUpgrade.upgrade] failed"
  const restoreMessage = restoreFailures
    .map((failure) => formatRestoreSourcesFailure(failure))
    .join("; ")
  return failed(
    `${pipelineMessage}\nsources rollback failed for ${String(restoreFailures.length)} file(s): ${restoreMessage}`
  )
}

async function refreshAptCacheAfterSourcesRollback(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult | null> {
  const result = await ssh.exec(
    `${NONINTERACTIVE} apt-get update`,
    releaseUpgradeExecOptions(options)
  )
  if (result.code === 0) return null
  return failedCommand("[releaseUpgrade.upgrade] apt-get update on restored sources failed", result)
}

function appendRollbackRefreshFailure(
  pipelineFailure: ModuleResult,
  refreshFailure: ModuleResult | null
): ModuleResult {
  if (refreshFailure == null) return pipelineFailure
  const pipelineMessage = pipelineFailure.error?.message ?? "[releaseUpgrade.upgrade] failed"
  const refreshMessage =
    refreshFailure.error?.message ?? "apt-get update on restored sources failed"
  return failed(`${pipelineMessage}\nrollback succeeded but ${refreshMessage}`)
}

async function handleDebianPipelineFailure(parameters: {
  options: ReleaseUpgradeOptions
  pipelineFailure: ModuleResult
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, pipelineFailure, snapshots, ssh } = parameters
  const restoreFailures = await restoreSourcesSnapshots(ssh, snapshots)
  if (restoreFailures.length > 0) {
    return appendRestoreSourcesFailures(pipelineFailure, restoreFailures)
  }
  const refreshFailure = await refreshAptCacheAfterSourcesRollback(ssh, options)
  return appendRollbackRefreshFailure(pipelineFailure, refreshFailure)
}

/**
 * Build the meta signal map that triggers a runner reboot and optional host
 * re-resolution after the upgrade completes.
 *
 * Always sets `system.reboot` to `"true"`. If `options.resolveHost` is
 * provided, `system.host` is set to the returned address. Failures from
 * `resolveHost` are returned as module failures so reconnect drift is visible.
 *
 * @param options - Upgrade options containing an optional `resolveHost` callback.
 * @returns A meta map suitable for inclusion in a `ModuleResult`, or a failure result.
 */
async function buildRebootMeta(
  options: ReleaseUpgradeOptions
): Promise<ModuleMetaEntry[] | ModuleResult> {
  // R-0000243: bound the resolver with a wall-clock timeout so a hanging
  // DNS/cloud lookup surfaces as a `failed` result instead of stalling the
  // playbook forever.
  return buildRebootMetaEntriesWithTimeout({
    failurePrefix: "[releaseUpgrade.upgrade]",
    resolveHost: options.resolveHost,
    timeoutMs: options.resolveHostTimeoutMs,
  })
}

function releaseUpgradeExecOptions(options: ReleaseUpgradeOptions): ExecOptions {
  // prettier-ignore
  return { ignoreExitCode: true, silent: true, timeout: options.timeout ?? RELEASE_UPGRADE_DEFAULT_TIMEOUT_MS }
}

async function runReleaseUpgradeCommand(parameters: {
  command: string
  failureMessage: string
  options: ReleaseUpgradeOptions
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const result = await parameters.ssh.exec(
    parameters.command,
    releaseUpgradeExecOptions(parameters.options)
  )
  return result.code === 0 ? null : failedCommand(parameters.failureMessage, result)
}

/**
 * Run the Ubuntu release upgrade via `do-release-upgrade`.
 *
 * Executes `apt-get update` first, then invokes `do-release-upgrade` in
 * non-interactive mode. When `dryRun` is set, only the check flag (`-c`) is
 * passed and no changes are made.
 *
 * On success, returns `status: "changed"` with reboot meta so the runner
 * can reconnect after the post-upgrade restart.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options (see {@link ReleaseUpgradeOptions}).
 * @returns A `ModuleResult` — `"changed"` with reboot meta on success,
 *   `"ok"` on dry-run, or `"failed"` when any command returns a non-zero
 *   exit code.
 */
async function applyUbuntu(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult> {
  if (options.dryRun === true) {
    const result = await ssh.exec("do-release-upgrade -c", releaseUpgradeExecOptions(options))
    if (result.code !== 0 && !isNoUbuntuReleaseAvailable(result)) {
      return failedCommand("[releaseUpgrade.upgrade] do-release-upgrade -c failed", result)
    }
    return { status: "ok" }
  }

  const updateFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get update`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get update failed",
    options,
    ssh,
  })
  if (updateFailure != null) return updateFailure

  const upgradeFailure = await runReleaseUpgradeCommand({
    command: "do-release-upgrade -f DistUpgradeViewNonInteractive",
    failureMessage: "[releaseUpgrade.upgrade] do-release-upgrade failed",
    options,
    ssh,
  })
  if (upgradeFailure != null) return upgradeFailure

  const entries = await buildRebootMeta(options)
  if (!Array.isArray(entries)) return entries
  return { meta: entries, status: "changed" }
}

/**
 * Run the four-step Debian apt upgrade pipeline (`apt-get update`,
 * `dpkg --configure -a`, `apt-get full-upgrade -y`, `apt-get autoremove -y`)
 * and return the first failure encountered, or `null` when all four steps
 * succeeded.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options used to derive per-command exec options.
 * @returns The first non-zero apt-step failure, or `null`.
 */
async function runDebianUpgradePipeline(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult | null> {
  const updateFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get update`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get update failed",
    options,
    ssh,
  })
  if (updateFailure != null) return updateFailure

  const configureFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} dpkg --configure -a`,
    failureMessage: "[releaseUpgrade.upgrade] dpkg --configure -a failed",
    options,
    ssh,
  })
  if (configureFailure != null) return configureFailure

  const upgradeFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get full-upgrade -y`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get full-upgrade failed",
    options,
    ssh,
  })
  if (upgradeFailure != null) return upgradeFailure

  const autoremoveFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get autoremove -y`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get autoremove failed",
    options,
    ssh,
  })
  if (autoremoveFailure != null) return autoremoveFailure

  return null
}

async function runDebianUpgradeCriticalSection(parameters: {
  options: ReleaseUpgradeOptions
  ssh: SshConnection
  targetCodename: string
}): Promise<ModuleResult> {
  const { options, ssh, targetCodename } = parameters
  const currentCodename = await getDebianCurrentCodename(ssh)
  if (currentCodename === targetCodename) return { status: "ok" }

  if (!isSupportedDebianUpgradePath(currentCodename, targetCodename)) {
    return failed(
      `[releaseUpgrade.upgrade] unsupported Debian release upgrade path: ${currentCodename} -> ${targetCodename}`
    )
  }

  // R-0000046: snapshot every sources file before rewriting it so a
  // downstream apt failure can roll the sources back to the original suite.
  // Without rollback, a partial failure would leave the host pointing at the
  // new suite while no upgrade has actually completed — the next apt run
  // would then operate on a half-migrated system.
  const snapshots = await replaceCodenameInSourcesList(ssh, currentCodename, targetCodename)

  const pipelineFailure = await runDebianUpgradePipeline(ssh, options)
  if (pipelineFailure != null) {
    return handleDebianPipelineFailure({ options, pipelineFailure, snapshots, ssh })
  }

  const entries = await buildRebootMeta(options)
  if (!Array.isArray(entries)) return entries
  return { meta: entries, status: "changed" }
}

function isMutexLockFailure(error: unknown): boolean {
  if (!(error instanceof Error)) return false
  return (
    error.message.includes("[moduleHelpers]") ||
    error.message.includes(DEBIAN_RELEASE_UPGRADE_MUTEX) ||
    error.message.includes("/var/lib/paratix/flags")
  )
}

async function runDebianUpgradeWithMutex(parameters: {
  options: ReleaseUpgradeOptions
  ssh: SshConnection
  targetCodename: string
}): Promise<ModuleResult> {
  try {
    return await withMutexLock(parameters.ssh, {
      lockName: DEBIAN_RELEASE_UPGRADE_MUTEX,
      section: async () => runDebianUpgradeCriticalSection(parameters),
    })
  } catch (error) {
    if (!isMutexLockFailure(error)) throw error
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[releaseUpgrade.upgrade] failed to acquire release upgrade mutex: ${reason}`)
  }
}

/**
 * Run the Debian release upgrade by rewriting sources and running
 * `apt-get full-upgrade`.
 *
 * Determines the current and target (stable) codenames, rewrites all
 * apt sources to point at the new suite, then executes the four-step
 * upgrade sequence: `apt-get update`, `dpkg --configure -a` (to resolve
 * any previously interrupted package configurations), `apt-get full-upgrade`,
 * and `apt-get autoremove`. When `dryRun` is set or the host already runs
 * the target codename, the upgrade is skipped entirely and `"ok"` is returned.
 *
 * On success, returns `status: "changed"` with reboot meta so the runner
 * can reconnect after the post-upgrade restart. On failure of any apt
 * step, the rewritten sources files are restored from the snapshots taken
 * before the rewrite (R-0000046).
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options (see {@link ReleaseUpgradeOptions}).
 * @returns A `ModuleResult` — `"changed"` with reboot meta on success,
 *   `"ok"` on dry-run, or `"failed"` when any command returns a non-zero
 *   exit code.
 */
async function applyDebian(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult> {
  const currentCodename = await getDebianCurrentCodename(ssh)
  const targetCodename = await getDebianStableCodename(ssh)

  if (options.dryRun === true || currentCodename === targetCodename) return { status: "ok" }

  if (!isSupportedDebianUpgradePath(currentCodename, targetCodename)) {
    return failed(
      `[releaseUpgrade.upgrade] unsupported Debian release upgrade path: ${currentCodename} -> ${targetCodename}`
    )
  }

  return runDebianUpgradeWithMutex({ options, ssh, targetCodename })
}

/**
 * Modules for upgrading the operating system to the next major release.
 *
 * Supports Ubuntu (via `do-release-upgrade`) and Debian (via sources.list
 * rewrite + `apt-get full-upgrade`). After a successful upgrade the module
 * signals the runner to reboot and optionally reconnect to a new host address
 * via the `system.reboot` / `system.host` meta keys.
 */
export const releaseUpgrade = {
  /**
   * Upgrade the remote host to the next major OS release.
   *
   * The distribution is auto-detected from `/etc/os-release`. Ubuntu hosts
   * are upgraded with `do-release-upgrade`; Debian hosts are upgraded by
   * rewriting apt sources to the current stable suite and running
   * `apt-get full-upgrade`.
   *
   * The `check` phase returns `"needs-apply"` when an upgrade is available
   * (Ubuntu: `do-release-upgrade -c` exits 0; Debian: current codename differs
   * from stable codename) and `"ok"` when the host is already up to date.
   *
   * @param options - Optional settings.
   * @param options.dryRun - When `true`, only inspect whether an upgrade is
   *   available without modifying the system.
   * @param options.resolveHost - Async callback invoked after the upgrade to
   *   determine the new host address before the runner reconnects.
   * @returns A Module that performs the OS release upgrade.
   *
   * @example
   * // Simple upgrade — auto-detect distro and apply
   * releaseUpgrade.upgrade()
   *
   * @example
   * // Dry-run: check availability without making changes
   * releaseUpgrade.upgrade({ dryRun: true })
   *
   * @example
   * // Resolve the new host address after reboot (e.g. dynamic DNS or DHCP)
   * releaseUpgrade.upgrade({
   *   resolveHost: async () => {
   *     const ip = await myDns.resolve("my-server.example.com")
   *     return ip
   *   },
   * })
   */
  upgrade(options: ReleaseUpgradeOptions = {}): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[releaseUpgrade.upgrade] SSH connection is required")

        const distro = await detectDistro(ssh)
        if (distro == null) return failed("[releaseUpgrade.upgrade] Unsupported distribution")

        if (distro === "ubuntu") return applyUbuntu(ssh, options)
        return applyDebian(ssh, options)
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const distro = await detectDistro(ssh)
        if (distro == null) return NEEDS_APPLY

        if (distro === "ubuntu") {
          const result = await ssh.exec("do-release-upgrade -c", releaseUpgradeExecOptions(options))
          if (isNoUbuntuReleaseAvailable(result)) return "ok"
          return NEEDS_APPLY
        }

        // Debian: compare current codename to stable
        try {
          const currentCodename = await getDebianCurrentCodename(ssh)
          const targetCodename = await getDebianStableCodename(ssh)
          return currentCodename === targetCodename ? "ok" : NEEDS_APPLY
        } catch {
          return NEEDS_APPLY
        }
      },

      name: "releaseUpgrade.upgrade",
    }
  },
}
