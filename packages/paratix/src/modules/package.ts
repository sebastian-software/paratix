import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecOptions,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/** Per-call overrides for package operations that can take a long time. */
export type UpgradeOptions = {
  /** Override the SSH layer's command timeout (milliseconds). */
  timeout?: number
}

function execOptions(options?: UpgradeOptions): ExecOptions {
  if (options?.timeout === undefined) return EXEC_OPTS
  return { ...EXEC_OPTS, timeout: options.timeout }
}

function splitPackagesAndOptions(values: ReadonlyArray<string | UpgradeOptions>): {
  options: undefined | UpgradeOptions
  packages: string[]
} {
  const packages: string[] = []
  let options: undefined | UpgradeOptions
  for (const [index, value] of values.entries()) {
    if (typeof value === "string") {
      packages.push(value)
    } else if (index === values.length - 1) {
      options = value
    }
  }
  return { options, packages }
}

// R-0000812: reject both leading and trailing affix characters in addition
// to whitespace and option-like prefixes. A trailing `-` is `apt`'s
// "remove this package" suffix, a trailing `+` is "(re)install this
// package" — accepting either would let a caller smuggle a state change
// past `pkg.installed`/`pkg.absent` even though the surrounding command
// uses the `--` argument terminator. A leading `+` is also disallowed:
// while `apt` does not treat it as an option, some downstream tooling
// does, so we keep the allowlist tight.
const PACKAGE_NAME_PATTERN = /^[a-z0-9][a-z0-9+._-]*[a-z0-9.]$/v

function validatePackageNames(moduleName: string, packages: readonly string[]): void {
  if (packages.length === 0) {
    throw new Error(`${moduleName}: at least one package name is required`)
  }

  for (const packageName of packages) {
    // Single-character names are permitted only if they consist of a single
    // lowercase alnum character — the multi-character regex above requires
    // a trailing non-affix character which forbids the single-char case.
    const isSingleAlnum = packageName.length === 1 && /^[a-z0-9]$/v.test(packageName)
    if (!isSingleAlnum && !PACKAGE_NAME_PATTERN.test(packageName)) {
      throw new Error(`${moduleName}: invalid package name ${JSON.stringify(packageName)}`)
    }
  }
}

/** Supported system package managers. */
type PackageManager = "apk" | "apt" | "dnf" | "yum"

/**
 * Per-connection cache for the detected package manager (avoids repeated SSH
 * roundtrips).
 *
 * R-0000577: only successful detections are written here. A `null` outcome
 * (no PM found) is intentionally NOT cached so a bootstrap playbook that
 * installs a package manager mid-run can be picked up on the next probe.
 */
const pmCache = new WeakMap<SshConnection, PackageManager>()

// R-0000534: pass `--` as the argument-list terminator for every supported
// package manager (including apk) so package names that look like options
// can never be interpreted as flags. Defense-in-depth alongside the strict
// package-name validation in `validatePackageNames`.
const INSTALL_COMMANDS = {
  apk: (pkgs: string) => `apk add -- ${pkgs}`,
  apt: (pkgs: string) => `DEBIAN_FRONTEND=noninteractive apt-get install -y -- ${pkgs}`,
  dnf: (pkgs: string) => `dnf install -y -- ${pkgs}`,
  yum: (pkgs: string) => `yum install -y -- ${pkgs}`,
} as const

const REMOVE_COMMANDS = {
  apk: (pkgs: string) => `apk del -- ${pkgs}`,
  apt: (pkgs: string) => `DEBIAN_FRONTEND=noninteractive apt-get remove -y -- ${pkgs}`,
  dnf: (pkgs: string) => `dnf remove -y -- ${pkgs}`,
  yum: (pkgs: string) => `yum remove -y -- ${pkgs}`,
} as const

const UPDATE_COMMANDS = {
  apk: "apk update",
  apt: "apt-get update",
  dnf: "dnf makecache",
  yum: "yum makecache",
} as const

/**
 * Upgrade pipelines per package manager.
 *
 * Multi-step pipelines (apt, apk) are split into individual commands so each
 * step gets its own SSH timeout window and produces a precise failure label
 * when a single step times out or fails.
 */
const UPGRADE_COMMANDS: Record<PackageManager, readonly string[]> = {
  apk: ["apk update", "apk upgrade"],
  apt: [
    "DEBIAN_FRONTEND=noninteractive dpkg --configure -a",
    "DEBIAN_FRONTEND=noninteractive apt-get update",
    "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y",
  ],
  dnf: ["dnf upgrade -y"],
  yum: ["yum update -y"],
} as const

function missingPackageManager(moduleName: string): ModuleResult {
  return failed(`[${moduleName}] No supported package manager found (apt, dnf, yum, apk)`)
}

/**
 * Probe whether a single package-manager binary is on `PATH` using
 * `ssh.exec`. R-0000646: `ssh.test` collapses a non-zero exit (the binary is
 * missing) and a transport-level failure into the same `false`. Using
 * `ssh.exec` with `ignoreExitCode: true` keeps the two cases distinct —
 * connection-level errors propagate as exceptions while a missing binary
 * surfaces as a non-zero exit code that we translate into `false`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param binary - The package-manager binary to probe (e.g. `"apt-get"`).
 * @returns `true` when `which` reported the binary as present, otherwise `false`.
 */
async function probePackageManagerBinary(ssh: SshConnection, binary: string): Promise<boolean> {
  const result = await ssh.exec(`which ${binary}`, EXEC_OPTS)
  return result.code === 0
}

/**
 * Detect the system package manager by probing for known binaries.
 *
 * Checks in order: apt, dnf, yum, apk. The result is cached per
 * {@link SshConnection} instance so subsequent calls avoid extra SSH roundtrips.
 *
 * R-0000646: probes use `ssh.exec` with explicit exit-code handling so a
 * flaky SSH transport during detection bubbles up as an exception instead of
 * being silently misinterpreted as "no package manager found".
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns The detected package manager, or `null` when none is found.
 */
export async function detectPackageManager(ssh: SshConnection): Promise<null | PackageManager> {
  const cached = pmCache.get(ssh)
  if (cached !== undefined) return cached

  let result: null | PackageManager = null
  if (await probePackageManagerBinary(ssh, "apt-get")) result = "apt"
  else if (await probePackageManagerBinary(ssh, "dnf")) result = "dnf"
  else if (await probePackageManagerBinary(ssh, "yum")) result = "yum"
  else if (await probePackageManagerBinary(ssh, "apk")) result = "apk"

  // R-0000577: only persist a successful detection. Caching the negative
  // result would lock a bootstrap-style playbook into "no package manager"
  // forever, even after an earlier step installs one. Re-detecting on every
  // miss is cheap (four `exec` invocations on the SSH layer) and avoids
  // that trap.
  if (result !== null) pmCache.set(ssh, result)
  return result
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
export async function isPackageInstalled(
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

async function hasAnyMissingPackage(
  ssh: SshConnection,
  pm: PackageManager,
  packages: readonly string[]
): Promise<boolean> {
  for (const packageName of packages) {
    // eslint-disable-next-line no-await-in-loop -- probe packages sequentially to avoid SSH-channel pressure
    if (!(await isPackageInstalled(ssh, pm, packageName))) return true
  }
  return false
}

// R-0000535: a zero exit code from the package-manager install
// is not sufficient evidence that every requested package is
// actually present (e.g. apt-get can "succeed" with partial
// installs, virtual packages can resolve to nothing, mirrors can
// skip packages without erroring). Re-check each requested
// package individually and surface the still-missing names as a
// failed result instead of optimistically reporting `changed`.
async function collectStillMissingPackages(
  ssh: SshConnection,
  pm: PackageManager,
  packages: readonly string[]
): Promise<string[]> {
  const stillMissing: string[] = []
  for (const verifyName of packages) {
    // eslint-disable-next-line no-await-in-loop -- post-install verification per package
    if (!(await isPackageInstalled(ssh, pm, verifyName))) {
      stillMissing.push(verifyName)
    }
  }
  return stillMissing
}

async function runInstallAndVerify(parameters: {
  options: undefined | UpgradeOptions
  packages: readonly string[]
  pm: PackageManager
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, packages, pm, ssh } = parameters
  const quoted = packages.map((p) => shellQuote(p)).join(" ")
  const result = await ssh.exec(INSTALL_COMMANDS[pm](quoted), execOptions(options))
  if (result.code !== 0) {
    return failedCommand(
      `[package.installed: ${packages.join(", ")}] package installation failed`,
      result
    )
  }
  const stillMissing = await collectStillMissingPackages(ssh, pm, packages)
  if (stillMissing.length > 0) {
    return failed(
      `[package.installed: ${packages.join(", ")}] packages still missing after install: ${stillMissing.join(", ")}`
    )
  }
  return { status: "changed" }
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
   * Pass an `UpgradeOptions` object as the last argument to override the SSH
   * timeout for slow remove operations.
   *
   * @param packagesAndOptions - One or more package names, optionally followed
   *   by an `UpgradeOptions` object as the last argument.
   * @returns A Module that removes the packages if any are present.
   *
   * @example
   * pkg.absent("vim", "nano")
   * pkg.absent("vim", "nano", { timeout: 600_000 })
   */
  absent(...packagesAndOptions: Array<string | UpgradeOptions>): Module {
    const { options, packages } = splitPackagesAndOptions(packagesAndOptions)
    validatePackageNames("package.absent", packages)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh)
          return failed(`[package.absent: ${packages.join(", ")}] SSH connection is required`)
        const pm = await detectPackageManager(ssh)
        if (!pm) return missingPackageManager(`package.absent: ${packages.join(", ")}`)
        let anyInstalled = false
        for (const packageName of packages) {
          // eslint-disable-next-line no-await-in-loop
          if (await isPackageInstalled(ssh, pm, packageName)) {
            anyInstalled = true
            break
          }
        }
        if (!anyInstalled) return { status: "ok" }
        const quoted = packages.map((p) => shellQuote(p)).join(" ")
        const result = await ssh.exec(REMOVE_COMMANDS[pm](quoted), execOptions(options))
        if (result.code !== 0) {
          return failedCommand(
            `[package.absent: ${packages.join(", ")}] package removal failed`,
            result
          )
        }
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
   * Pass an `UpgradeOptions` object as the last argument to override the SSH
   * timeout for slow install operations.
   *
   * @param packagesAndOptions - One or more package names, optionally followed
   *   by an `UpgradeOptions` object as the last argument.
   * @returns A Module that installs missing packages.
   *
   * @example
   * pkg.installed("git", "curl", "unzip")
   * pkg.installed("texlive-full", { timeout: 900_000 })
   */
  installed(...packagesAndOptions: Array<string | UpgradeOptions>): Module {
    const { options, packages } = splitPackagesAndOptions(packagesAndOptions)
    validatePackageNames("package.installed", packages)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) {
          return failed(`[package.installed: ${packages.join(", ")}] SSH connection is required`)
        }
        const pm = await detectPackageManager(ssh)
        if (!pm) return missingPackageManager(`package.installed: ${packages.join(", ")}`)
        const anyMissing = await hasAnyMissingPackage(ssh, pm, packages)
        if (!anyMissing) return { status: "ok" }
        return runInstallAndVerify({ options, packages, pm, ssh })
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
   * @param options - Optional per-call overrides (e.g. SSH command `timeout`).
   * @returns A Module that refreshes package lists.
   *
   * @example
   * pkg.update("2024-01-15")
   * pkg.update("2024-01-15", { timeout: 600_000 })
   */
  update(date: string, options?: UpgradeOptions): Module {
    const flagName = `package-update-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[package.update: ${date}] SSH connection is required`)
        if (await hasFlag(ssh, flagName)) return { status: "ok" }
        const pm = await detectPackageManager(ssh)
        if (!pm) return missingPackageManager(`package.update: ${date}`)
        const result = await ssh.exec(UPDATE_COMMANDS[pm], execOptions(options))
        if (result.code !== 0) {
          return failedCommand(`[package.update: ${date}] package index refresh failed`, result)
        }

        // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC)
        // through the failedCommand path; the helper no longer throws.
        const flagFailure = await setVersionedFlag(ssh, flagName, "package-update-")
        if (flagFailure) return flagFailure

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
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
   * On apt systems this runs `dpkg --configure -a`, `apt-get update`, and
   * `apt-get upgrade -y` as three separate commands (each subject to its own
   * SSH `timeout`). For full dependency resolution use `apt.distUpgrade`.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @param options - Optional per-call overrides (e.g. SSH command `timeout`).
   *   The same `timeout` is applied to every step of the upgrade pipeline.
   * @returns A Module that upgrades all packages.
   *
   * @example
   * pkg.upgrade("2024-01-15")
   * pkg.upgrade("2024-01-15", { timeout: 900_000 })
   *
   * @see apt.distUpgrade
   */
  upgrade(date: string, options?: UpgradeOptions): Module {
    const flagName = `package-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[package.upgrade: ${date}] SSH connection is required`)
        if (await hasFlag(ssh, flagName)) return { status: "ok" }
        const pm = await detectPackageManager(ssh)
        if (!pm) return missingPackageManager(`package.upgrade: ${date}`)

        const pipelineOptions = execOptions(options)
        for (const command of UPGRADE_COMMANDS[pm]) {
          // eslint-disable-next-line no-await-in-loop -- upgrade steps must run sequentially
          const result = await ssh.exec(command, pipelineOptions)
          if (result.code !== 0) {
            return failedCommand(`[package.upgrade: ${date}] package upgrade failed`, result)
          }
        }

        // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC)
        // through the failedCommand path; the helper no longer throws.
        const flagFailure = await setVersionedFlag(ssh, flagName, "package-upgrade-")
        if (flagFailure) return flagFailure

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `package.upgrade: ${date}`,
    }
  },
}
