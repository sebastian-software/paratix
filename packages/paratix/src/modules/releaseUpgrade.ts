import { meta } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const CODENAME_RE = /^[a-z]{3,20}$/v
const APT_SOURCES_MODE = "0644"

// prettier-ignore
const REGEXP_SPECIAL = new Set(["?", ".", "(", ")", "[", "]", "{", "}", "*", "\\", "^", "+", "|", "$"])

/**
 * Escape every regex special character in `value` so the string can be used
 * verbatim inside a `RegExp` source. Used by {@link rewriteSourcesFile} to
 * build a token-boundary anchored pattern from the codename without giving
 * the codename the chance to inject regex syntax. Mirrors the helper used
 * by `sshd.ts` so the two modules stay consistent.
 *
 * @param value - The string to escape.
 * @returns A regex-safe version of `value`.
 */
function escapeRegExp(value: string): string {
  let result = ""
  for (const ch of value) {
    result += REGEXP_SPECIAL.has(ch) ? `\\${ch}` : ch
  }
  return result
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
  const result = await ssh.exec("curl -fsSL https://deb.debian.org/debian/dists/stable/Release", {
    ignoreExitCode: true,
    silent: true,
  })
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

/**
 * Apply the codename rewrite to a single sources file when the new content
 * differs from the original, returning the snapshot needed to roll back.
 *
 * @param parameters - The rewrite parameters: ssh handle, remote path,
 *   original content, current codename and target codename.
 * @returns The snapshot when the file was modified, or `null` when no
 *   rewrite was necessary.
 */
async function rewriteSourcesFile(
  parameters: RewriteSourcesParameters
): Promise<null | SourcesSnapshot> {
  const { currentCodename, originalContent, remotePath, ssh, targetCodename } = parameters
  // R-0000103: anchor the substitution at token boundaries so the codename
  // is only swapped when it appears as a standalone field. The naive
  // `replaceAll` corrupts URLs (`archive.ubuntu.com/ubuntu-trusty-updates/`),
  // comments, hyphenated backports/security suites (`trusty-backports`,
  // `trusty-security`) and any repository whose name happens to contain the
  // codename as a substring. Plain `\b` is not enough because JavaScript
  // treats `-` as a non-word character, so `\btrusty\b` would still match
  // inside `ubuntu-trusty-updates`. The look-behind/look-ahead pair extends
  // the boundary to also reject adjacent hyphens, dots and `_`, which are
  // the separators used in apt sources, URLs and hyphenated suite names.
  const codenamePattern = new RegExp(
    `(?<![\\w.\\-])${escapeRegExp(currentCodename)}(?![\\w.\\-])`,
    "gv"
  )
  const updatedContent = originalContent.replaceAll(codenamePattern, targetCodename)
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

  const sourcesContent = await ssh.readFile(APT_SOURCES_LIST)
  const mainSnapshot = await rewriteSourcesFile({
    currentCodename,
    originalContent: sourcesContent,
    remotePath: APT_SOURCES_LIST,
    ssh,
    targetCodename,
  })
  if (mainSnapshot != null) snapshots.push(mainSnapshot)

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

  // Split on the NUL byte; the trailing empty string (after the last NUL)
  // is filtered out below.
  for (const filePath of listFilesResult.stdout.split("\0")) {
    if (filePath.length === 0) continue
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
 * provided and resolves successfully, `system.host` is set to the returned
 * address. Failures from `resolveHost` are silently ignored so the runner
 * falls back to the current host.
 *
 * @param options - Upgrade options containing an optional `resolveHost` callback.
 * @returns A meta map suitable for inclusion in a `ModuleResult`.
 */
async function buildRebootMeta(options: ReleaseUpgradeOptions): Promise<ModuleMetaEntry[]> {
  const entries: ModuleMetaEntry[] = [meta.systemReboot()]
  if (options.resolveHost != null) {
    try {
      const newHost = await options.resolveHost()
      entries.push(meta.systemHost(newHost))
    } catch {
      // resolveHost failed — reconnect will use current host
    }
  }
  return entries
}

async function runReleaseUpgradeCommand(
  ssh: SshConnection,
  command: string,
  failureMessage: string
): Promise<ModuleResult | null> {
  const result = await ssh.exec(command, {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0 ? null : failedCommand(failureMessage, result)
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
  const updateFailure = await runReleaseUpgradeCommand(
    ssh,
    `${NONINTERACTIVE} apt-get update`,
    "[releaseUpgrade.upgrade] apt-get update failed"
  )
  if (updateFailure != null) return updateFailure

  if (options.dryRun === true) {
    await ssh.exec("do-release-upgrade -c", {
      ignoreExitCode: true,
      silent: true,
    })
    return { status: "ok" }
  }

  const upgradeFailure = await runReleaseUpgradeCommand(
    ssh,
    "do-release-upgrade -f DistUpgradeViewNonInteractive",
    "[releaseUpgrade.upgrade] do-release-upgrade failed"
  )
  if (upgradeFailure != null) return upgradeFailure

  const entries = await buildRebootMeta(options)
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
 * @returns The first non-zero apt-step failure as a `ModuleResult`, or
 *   `null` when all four steps succeeded.
 */
async function runDebianUpgradePipeline(ssh: SshConnection): Promise<ModuleResult | null> {
  const updateFailure = await runReleaseUpgradeCommand(
    ssh,
    `${NONINTERACTIVE} apt-get update`,
    "[releaseUpgrade.upgrade] apt-get update failed"
  )
  if (updateFailure != null) return updateFailure

  const configureFailure = await runReleaseUpgradeCommand(
    ssh,
    `${NONINTERACTIVE} dpkg --configure -a`,
    "[releaseUpgrade.upgrade] dpkg --configure -a failed"
  )
  if (configureFailure != null) return configureFailure

  const upgradeFailure = await runReleaseUpgradeCommand(
    ssh,
    `${NONINTERACTIVE} apt-get full-upgrade -y`,
    "[releaseUpgrade.upgrade] apt-get full-upgrade failed"
  )
  if (upgradeFailure != null) return upgradeFailure

  const autoremoveFailure = await runReleaseUpgradeCommand(
    ssh,
    `${NONINTERACTIVE} apt-get autoremove -y`,
    "[releaseUpgrade.upgrade] apt-get autoremove failed"
  )
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
 * and `apt-get autoremove`. When `dryRun` is set, the upgrade is skipped
 * entirely and `"ok"` is returned.
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

  if (options.dryRun === true) {
    return { status: "ok" }
  }

  // R-0000046: snapshot every sources file before rewriting it so a
  // downstream apt failure can roll the sources back to the original suite.
  // Without rollback, a partial failure would leave the host pointing at the
  // new suite while no upgrade has actually completed — the next apt run
  // would then operate on a half-migrated system.
  const snapshots = await replaceCodenameInSourcesList(ssh, currentCodename, targetCodename)

  const pipelineFailure = await runDebianUpgradePipeline(ssh)
  if (pipelineFailure != null) {
    await restoreSourcesSnapshots(ssh, snapshots)
    return pipelineFailure
  }

  const entries = await buildRebootMeta(options)
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
          const result = await ssh.exec("do-release-upgrade -c", {
            ignoreExitCode: true,
            silent: true,
          })
          return result.code === 0 ? NEEDS_APPLY : "ok"
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
