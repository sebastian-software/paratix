import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const CODENAME_RE = /^[a-z]{3,20}$/v

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
 */
async function replaceCodenameInSourcesList(
  ssh: SshConnection,
  currentCodename: string,
  targetCodename: string
): Promise<void> {
  const sourcesContent = await ssh.readFile("/etc/apt/sources.list")
  const updatedContent = sourcesContent.replaceAll(currentCodename, targetCodename)
  await guardedWriteFile(ssh, {
    newContent: updatedContent,
    originalContent: sourcesContent,
    remotePath: "/etc/apt/sources.list",
  })

  const listFilesResult = await ssh.exec(
    "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f",
    { ignoreExitCode: true, silent: true }
  )
  if (listFilesResult.code === 0 && listFilesResult.stdout.trim()) {
    for (const filePath of listFilesResult.stdout.trim().split("\n")) {
      const trimmedPath = filePath.trim()
      if (!trimmedPath) continue
      // eslint-disable-next-line no-await-in-loop
      const content = await ssh.readFile(trimmedPath)
      const updated = content.replaceAll(currentCodename, targetCodename)
      if (updated !== content) {
        // eslint-disable-next-line no-await-in-loop
        await guardedWriteFile(ssh, {
          newContent: updated,
          originalContent: content,
          remotePath: trimmedPath,
        })
      }
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
async function buildRebootMeta(options: ReleaseUpgradeOptions): Promise<Record<string, string>> {
  const meta: Record<string, string> = { "system.reboot": "true" }
  if (options.resolveHost != null) {
    try {
      const newHost = await options.resolveHost()
      meta["system.host"] = newHost
    } catch {
      // resolveHost failed — reconnect will use current host
    }
  }
  return meta
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
  const updateResult = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (updateResult.code !== 0) return { status: "failed" }

  if (options.dryRun === true) {
    await ssh.exec("do-release-upgrade -c", {
      ignoreExitCode: true,
      silent: true,
    })
    return { status: "ok" }
  }

  const upgradeResult = await ssh.exec("do-release-upgrade -f DistUpgradeViewNonInteractive", {
    ignoreExitCode: true,
    silent: true,
  })
  if (upgradeResult.code !== 0) return { status: "failed" }

  const meta = await buildRebootMeta(options)
  return { meta, status: "changed" }
}

/**
 * Run the Debian release upgrade by rewriting sources and running
 * `apt-get full-upgrade`.
 *
 * Determines the current and target (stable) codenames, rewrites all
 * apt sources to point at the new suite, then executes the three-step
 * upgrade sequence: `apt-get update`, `apt-get full-upgrade`, and
 * `apt-get autoremove`. When `dryRun` is set, the upgrade is skipped
 * entirely and `"ok"` is returned.
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
async function applyDebian(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult> {
  const currentCodename = await getDebianCurrentCodename(ssh)
  const targetCodename = await getDebianStableCodename(ssh)

  if (options.dryRun === true) {
    return { status: "ok" }
  }

  await replaceCodenameInSourcesList(ssh, currentCodename, targetCodename)

  const updateResult = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (updateResult.code !== 0) return { status: "failed" }

  const upgradeResult = await ssh.exec(`${NONINTERACTIVE} apt-get full-upgrade -y`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (upgradeResult.code !== 0) return { status: "failed" }

  const autoremoveResult = await ssh.exec(`${NONINTERACTIVE} apt-get autoremove -y`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (autoremoveResult.code !== 0) return { status: "failed" }

  const meta = await buildRebootMeta(options)
  return { meta, status: "changed" }
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
        if (!ssh) return { status: "failed" }

        const distro = await detectDistro(ssh)
        if (distro == null) return { status: "failed" }

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
