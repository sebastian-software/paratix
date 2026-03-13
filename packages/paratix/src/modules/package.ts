import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/** Supported system package managers. */
type PackageManager = "apk" | "apt" | "dnf" | "yum"

const INSTALL_COMMANDS = {
  apk: (pkgs: string) => `apk add ${pkgs}`,
  apt: (pkgs: string) => `DEBIAN_FRONTEND=noninteractive apt-get install -y ${pkgs}`,
  dnf: (pkgs: string) => `dnf install -y ${pkgs}`,
  yum: (pkgs: string) => `yum install -y ${pkgs}`,
} as const

const REMOVE_COMMANDS = {
  apk: (pkgs: string) => `apk del ${pkgs}`,
  apt: (pkgs: string) => `DEBIAN_FRONTEND=noninteractive apt-get remove -y ${pkgs}`,
  dnf: (pkgs: string) => `dnf remove -y ${pkgs}`,
  yum: (pkgs: string) => `yum remove -y ${pkgs}`,
} as const

const UPDATE_COMMANDS = {
  apk: "apk update",
  apt: "apt-get update",
  dnf: "dnf makecache",
  yum: "yum makecache",
} as const

const UPGRADE_COMMANDS = {
  apk: "apk update && apk upgrade",
  apt: "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
  dnf: "dnf upgrade -y",
  yum: "yum update -y",
} as const

/**
 * Detect the system package manager by probing for known binaries.
 *
 * Checks in order: apt, dnf, yum, apk.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns The detected package manager, or `null` when none is found.
 */
async function detectPackageManager(ssh: SshConnection): Promise<null | PackageManager> {
  if (await ssh.test("which apt-get")) return "apt"
  if (await ssh.test("which dnf")) return "dnf"
  if (await ssh.test("which yum")) return "yum"
  if (await ssh.test("which apk")) return "apk"
  return null
}

/**
 * Check whether a single package is installed using the appropriate
 * command for the detected package manager.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param pm - The detected package manager.
 * @param packageName - Name of the package to check.
 * @returns `true` if the package is installed.
 */
async function isPackageInstalled(
  ssh: SshConnection,
  pm: PackageManager,
  packageName: string
): Promise<boolean> {
  const quoted = shellQuote(packageName)
  switch (pm) {
    case "apk": {
      return ssh.test(`apk info -e ${quoted}`)
    }
    case "apt": {
      return ssh.test(
        `dpkg-query -W -f='\${Status}' ${quoted} 2>/dev/null | grep -q 'install ok installed'`
      )
    }
    case "dnf":
    case "yum": {
      return ssh.test(`rpm -q ${quoted}`)
    }
  }
}

/**
 * Ensure the flags directory exists on the remote host.
 *
 * @param ssh - Active SSH connection to the remote host.
 */
async function ensureFlagsDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, { silent: true })
}

/**
 * Distro-agnostic package management module.
 *
 * Automatically detects the system package manager (apt, dnf, yum, apk)
 * and delegates to the appropriate commands. All methods are idempotent.
 *
 * For Debian/Ubuntu-specific configuration (debconf pre-seeding, GPG keys,
 * apt repositories) use the `apt` module instead.
 *
 * @example
 * // Install packages
 * pkg.installed("git", "curl")
 *
 * @example
 * // Refresh package lists and upgrade all packages on a specific date
 * pkg.update("2024-01-15")
 * pkg.upgrade("2024-01-15")
 */
// eslint-disable-next-line unicorn/prevent-abbreviations -- `package` is a JS reserved word; re-exported as `package` in index.ts
export const pkg = {
  /**
   * Ensure the given packages are not installed.
   *
   * The check phase queries the package database for each package individually;
   * the remove command is only executed when at least one package is present.
   *
   * @param packages - One or more package names to remove.
   * @returns A Module that removes the packages if any are present.
   *
   * @example
   * pkg.absent("vim", "nano")
   */
  absent(...packages: string[]): Module {
    if (packages.length === 0) {
      throw new Error("package.absent: at least one package name is required")
    }
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const pm = await detectPackageManager(ssh)
        if (!pm) return { status: "failed" }
        const quoted = packages.map((p) => shellQuote(p)).join(" ")
        const result = await ssh.exec(REMOVE_COMMANDS[pm](quoted), EXEC_OPTS)
        if (result.code !== 0) return { status: "failed" }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const pm = await detectPackageManager(ssh)
        if (!pm) return NEEDS_APPLY
        for (const p of packages) {
          // eslint-disable-next-line no-await-in-loop
          if (await isPackageInstalled(ssh, pm, p)) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `package.absent: ${packages.join(", ")}`,
    }
  },

  /**
   * Ensure the given packages are installed.
   *
   * The check phase queries the package database for each package individually;
   * the install command is only executed when at least one package is missing.
   *
   * @param packages - One or more package names to install.
   * @returns A Module that installs missing packages.
   *
   * @example
   * pkg.installed("git", "curl", "unzip")
   */
  installed(...packages: string[]): Module {
    if (packages.length === 0) {
      throw new Error("package.installed: at least one package name is required")
    }
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const pm = await detectPackageManager(ssh)
        if (!pm) return { status: "failed" }
        const quoted = packages.map((p) => shellQuote(p)).join(" ")
        const result = await ssh.exec(INSTALL_COMMANDS[pm](quoted), EXEC_OPTS)
        if (result.code !== 0) return { status: "failed" }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const pm = await detectPackageManager(ssh)
        if (!pm) return NEEDS_APPLY
        for (const p of packages) {
          // eslint-disable-next-line no-await-in-loop
          if (!(await isPackageInstalled(ssh, pm, p))) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `package.installed: ${packages.join(", ")}`,
    }
  },

  /**
   * Refresh the package manager's package lists once per dated flag.
   *
   * A flag file at `${FLAGS_DIRECTORY}/package-update-<date>` is created after
   * a successful run. On the next run the flag is detected and the module
   * reports `"ok"` without running the update again. Changing `date` to a new
   * value invalidates all previous flags for this operation.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @returns A Module that refreshes package lists.
   *
   * @example
   * pkg.update("2024-01-15")
   */
  update(date: string): Module {
    const flagName = `package-update-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const pm = await detectPackageManager(ssh)
        if (!pm) return { status: "failed" }
        await ensureFlagsDirectory(ssh)

        const result = await ssh.exec(UPDATE_COMMANDS[pm], EXEC_OPTS)
        if (result.code !== 0) return { status: "failed" }

        await ssh.exec(
          `rm -f ${FLAGS_DIRECTORY}/package-update-* && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
          { silent: true }
        )

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`))
          ? "ok"
          : NEEDS_APPLY
      },
      name: `package.update: ${date}`,
    }
  },

  /**
   * Upgrade all installed packages once per dated flag.
   *
   * A flag file at `${FLAGS_DIRECTORY}/package-upgrade-<date>` is created after
   * a successful run. On the next run the flag is detected and the module
   * reports `"ok"` without running the upgrade again. Changing `date` to a new
   * value invalidates all previous flags for this operation.
   *
   * On apt systems this runs `apt-get update && apt-get upgrade -y` (not
   * `dist-upgrade`); use `apt.distUpgrade` for full dependency resolution.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @returns A Module that upgrades all packages.
   *
   * @example
   * pkg.upgrade("2024-01-15")
   *
   * @see apt.distUpgrade
   */
  upgrade(date: string): Module {
    const flagName = `package-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const pm = await detectPackageManager(ssh)
        if (!pm) return { status: "failed" }
        await ensureFlagsDirectory(ssh)

        const result = await ssh.exec(UPGRADE_COMMANDS[pm], EXEC_OPTS)
        if (result.code !== 0) return { status: "failed" }

        await ssh.exec(
          `rm -f ${FLAGS_DIRECTORY}/package-upgrade-* && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
          { silent: true }
        )

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`))
          ? "ok"
          : NEEDS_APPLY
      },
      name: `package.upgrade: ${date}`,
    }
  },
}
