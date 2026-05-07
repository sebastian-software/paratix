import { meta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
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
import {
  isAcceptableSourcesPath,
  isSupportedDebianUpgradePath,
  rewriteAptSourcesContent,
} from "./releaseUpgradeSources.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const CODENAME_RE = /^[a-z]{3,20}$/v
const APT_SOURCES_MODE = "0644"
const NO_UBUNTU_RELEASE_PATTERN = /no new release (?:found|available)/iv
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
   */
  resolveHost?: () => Promise<string>
  /** Override the SSH layer's command timeout (milliseconds) for upgrade steps. */
  timeout?: number
}

type Distro = "debian" | "ubuntu"

/**
 * Detect the Linux distribution of the remote host by reading `/etc/os-release`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns `"debian"`, `"ubuntu"`, or `null` when the distribution cannot be
 *   identified from the `ID=` field.
 */
async function detectDistro(ssh: SshConnection): Promise<Distro | null> {
  const osRelease = await ssh.readFile("/etc/os-release")
  for (const line of osRelease.split("\n")) {
    const match = /^ID=(?<value>.*)$/v.exec(line)
    if (match?.groups) {
      const id = match.groups.value.replaceAll('"', "").trim()
      if (id === "ubuntu") return "ubuntu"
      if (id === "debian") return "debian"
      return null
    }
  }
  return null
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
 * Fetch the codename of the current Debian stable release from the official
 * Debian mirrors by downloading the `Release` metadata file.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns The stable codename (e.g. `"bookworm"`).
 * @throws {Error} When the `Codename:` field is absent from the Release file.
 */
async function getDebianStableCodename(ssh: SshConnection): Promise<string> {
  // R-0000177: --max-time bounds the wall-clock duration of the request so
  // that a stuck mirror cannot hang the entire upgrade module.
  const result = await ssh.exec(
    "curl --max-time 30 -fsSL https://deb.debian.org/debian/dists/stable/Release",
    {
      ignoreExitCode: true,
      silent: true,
    }
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
 * while the upgrade itself failed.
 */
type SourcesSnapshot = {
  originalContent: string
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

  await guardedWriteFile(ssh, {
    mode: APT_SOURCES_MODE,
    newContent: updatedContent,
    originalContent,
    remotePath,
  })
  return { originalContent, remotePath }
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
    const sourcesContent = await ssh.readFile(APT_SOURCES_LIST)
    const mainSnapshot = await rewriteSourcesFile({
      currentCodename,
      originalContent: sourcesContent,
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
    if (filePath.length === 0 || !isAcceptableSourcesPath(filePath)) continue
    // eslint-disable-next-line no-await-in-loop
    const content = await ssh.readFile(filePath)
    // eslint-disable-next-line no-await-in-loop
    const snapshot = await rewriteSourcesFile({
      currentCodename,
      originalContent: content,
      remotePath: filePath,
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
 */
async function restoreSourcesSnapshots(
  ssh: SshConnection,
  snapshots: SourcesSnapshot[]
): Promise<void> {
  for (const snapshot of snapshots) {
    try {
      // Intentional: unguarded write — restoring the original sources is
      // more important than concurrency safety during a failed-upgrade
      // rollback. An additional guarded write would refuse to roll back if
      // the file content changed mid-flight.
      // eslint-disable-next-line no-await-in-loop
      await ssh.writeFile(snapshot.remotePath, snapshot.originalContent, {
        mode: APT_SOURCES_MODE,
      })
    } catch {
      // Best-effort: if a single file cannot be restored, keep going so the
      // remaining snapshots still revert. The original failure is what the
      // caller surfaces — this rollback only widens the recovery window.
    }
  }
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
  const entries: ModuleMetaEntry[] = [meta.systemReboot()]
  if (options.resolveHost != null) {
    try {
      const newHost = await options.resolveHost()
      entries.push(meta.systemHost(newHost))
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      return failed(`[releaseUpgrade.upgrade] resolveHost failed\n${message}`)
    }
  }
  return entries
}

function releaseUpgradeExecOptions(options: ReleaseUpgradeOptions): ExecOptions {
  if (options.timeout === undefined) return { ignoreExitCode: true, silent: true }
  return { ignoreExitCode: true, silent: true, timeout: options.timeout }
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
 * Extracted from `applyDebian` so the failure-path rollback in `applyDebian`
 * stays straightforward and the per-step retry order remains explicit.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options used to derive per-command exec options.
 * @returns The first non-zero apt-step failure as a `ModuleResult`, or
 *   `null` when all four steps succeeded.
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

  // R-0000046: snapshot every sources file before rewriting it so a
  // downstream apt failure can roll the sources back to the original suite.
  // Without rollback, a partial failure would leave the host pointing at the
  // new suite while no upgrade has actually completed — the next apt run
  // would then operate on a half-migrated system.
  const snapshots = await replaceCodenameInSourcesList(ssh, currentCodename, targetCodename)

  const pipelineFailure = await runDebianUpgradePipeline(ssh, options)
  if (pipelineFailure != null) {
    await restoreSourcesSnapshots(ssh, snapshots)
    return pipelineFailure
  }

  const entries = await buildRebootMeta(options)
  if (!Array.isArray(entries)) return entries
  return { meta: entries, status: "changed" }
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
