import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecOptions,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { hasFlag, setFlag } from "./moduleHelpers.js"
import {
  describeAptUpgradeOutcome,
  UNKNOWN_UPGRADE_OUTCOME_DETAIL,
} from "./packageUpgradeSummary.js"
import {
  describePackages,
  getInstalledVersion,
  type NormalizedPackage,
  type PackageArgument,
  type PackageManager,
  runVersionedInstall,
  splitPackagesAndOptions,
  type UpgradeOptions,
  validatePackages,
  versionsEqual,
} from "./packageVersion.js"

export type { PackageSpec, UpgradeOptions } from "./packageVersion.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/**
 * Detail reported by `package.update` when it refreshed the package index.
 * The step name already carries the date, so the detail states what the run
 * did rather than repeating the idempotency key.
 */
const PACKAGE_INDEX_REFRESHED_DETAIL = "marker was missing, package index refreshed"

function execOptions(options?: UpgradeOptions): ExecOptions {
  if (options?.timeout === undefined) return EXEC_OPTS
  return { ...EXEC_OPTS, timeout: options.timeout }
}

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
// package-name validation in `validatePackages`.
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
  // Issue #89: `binary` is a compile-time constant — every caller passes a
  // hardcoded package-manager binary literal (`"apt-get"`, `"dnf"`, `"yum"`,
  // `"apk"` in `detectPackageManager`), never user input, so no shellQuote is
  // required for this interpolation.
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

/**
 * Determine whether a package satisfies its desired state on the target.
 *
 * Without a pinned version this is a pure presence check (today's behavior).
 * With a pinned version the installed version must exactly equal the pin
 * (see {@link versionsEqual}).
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param pm - Detected package manager.
 * @param target - The normalized package with an optional pinned version.
 * @returns `true` when the package is present and (if pinned) at the pin.
 */
async function isPackageSatisfied(
  ssh: SshConnection,
  pm: PackageManager,
  target: NormalizedPackage
): Promise<boolean> {
  if (target.version === undefined) {
    return isPackageInstalled(ssh, pm, target.name)
  }
  const installed = await getInstalledVersion(ssh, pm, target.name)
  if (installed === null) return false
  return versionsEqual({ installed, pinned: target.version, pm, ssh })
}

async function hasAnyMissingPackage(
  ssh: SshConnection,
  pm: PackageManager,
  packages: readonly NormalizedPackage[]
): Promise<boolean> {
  for (const package_ of packages) {
    // eslint-disable-next-line no-await-in-loop -- probe packages sequentially to avoid SSH-channel pressure
    if (!(await isPackageSatisfied(ssh, pm, package_))) return true
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
// R-0000812 (version pinning): post-install verification checks the pinned
// version, not just presence. A partial or wrong-version install must surface
// as `failed`, never a false `changed`.
async function collectStillMissingPackages(
  ssh: SshConnection,
  pm: PackageManager,
  packages: readonly NormalizedPackage[]
): Promise<string[]> {
  const stillMissing: string[] = []
  for (const package_ of packages) {
    // eslint-disable-next-line no-await-in-loop -- post-install verification per package
    if (!(await isPackageSatisfied(ssh, pm, package_))) {
      stillMissing.push(package_.name)
    }
  }
  return stillMissing
}

async function runInstallAndVerify(parameters: {
  options: undefined | UpgradeOptions
  packages: readonly NormalizedPackage[]
  pm: PackageManager
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, packages, pm, ssh } = parameters
  const label = describePackages(packages)

  // Run any required downgrades and the install (with `--allow-downgrades` for
  // pinned apt packages); the version-aware orchestration lives in
  // `packageVersion.ts`.
  const failure = await runVersionedInstall({
    baseInstall: INSTALL_COMMANDS[pm],
    execOpts: execOptions(options),
    label,
    packages,
    pm,
    ssh,
  })
  if (failure) return failure

  const stillMissing = await collectStillMissingPackages(ssh, pm, packages)
  if (stillMissing.length > 0) {
    return failed(
      `[package.installed: ${label}] packages still missing after install: ${stillMissing.join(", ")}`
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
   * @param packagesAndOptions - One or more package names (bare strings or
   *   `PackageSpec` objects without a `version`), optionally followed by an
   *   `UpgradeOptions` object as the last argument.
   * @returns A Module that removes the packages if any are present.
   *
   * @example
   * pkg.absent("vim", "nano")
   * pkg.absent("vim", "nano", { timeout: 600_000 })
   */
  absent(...packagesAndOptions: PackageArgument[]): Module {
    const { options, packages } = splitPackagesAndOptions(packagesAndOptions)
    validatePackages("package.absent", packages)
    // `absent` is presence-based; a version pin has no meaning here and must
    // not be silently ignored — reject it loudly.
    for (const p of packages) {
      if (p.version !== undefined) {
        throw new Error(
          `package.absent: version pinning is not supported (package ${JSON.stringify(p.name)})`
        )
      }
    }
    const names = packages.map((p) => p.name)
    const label = names.join(", ")
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[package.absent: ${label}] SSH connection is required`)
        const pm = await detectPackageManager(ssh)
        if (!pm) return missingPackageManager(`package.absent: ${label}`)
        let anyInstalled = false
        for (const packageName of names) {
          // eslint-disable-next-line no-await-in-loop
          if (await isPackageInstalled(ssh, pm, packageName)) {
            anyInstalled = true
            break
          }
        }
        if (!anyInstalled) return { status: "ok" }
        const quoted = names.map((p) => shellQuote(p)).join(" ")
        const result = await ssh.exec(REMOVE_COMMANDS[pm](quoted), execOptions(options))
        if (result.code !== 0) {
          return failedCommand(`[package.absent: ${label}] package removal failed`, result)
        }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const pm = await detectPackageManager(ssh)
        if (!pm) return NEEDS_APPLY
        for (const p of names) {
          // eslint-disable-next-line no-await-in-loop
          if (await isPackageInstalled(ssh, pm, p)) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `package.absent: ${label}`,
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
   * Pass a `PackageSpec` (`{ name, version }`) to pin a package to an exact
   * version; `check` then reports drift against the installed version and
   * `apply` converges on the pin, including a downgrade. No package holds are
   * created — only the requested version is installed.
   *
   * @param packagesAndOptions - One or more packages (bare name strings or
   *   `PackageSpec` objects), optionally followed by an `UpgradeOptions` object
   *   as the last argument.
   * @returns A Module that installs missing packages.
   *
   * @example
   * pkg.installed("git", "curl", "unzip")
   * pkg.installed("texlive-full", { timeout: 900_000 })
   * pkg.installed({ name: "grafana", version: "13.1.0" })
   */
  installed(...packagesAndOptions: PackageArgument[]): Module {
    const { options, packages } = splitPackagesAndOptions(packagesAndOptions)
    validatePackages("package.installed", packages)
    const label = describePackages(packages)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) {
          return failed(`[package.installed: ${label}] SSH connection is required`)
        }
        const pm = await detectPackageManager(ssh)
        if (!pm) return missingPackageManager(`package.installed: ${label}`)
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
          if (!(await isPackageSatisfied(ssh, pm, p))) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `package.installed: ${label}`,
    }
  },

  /**
   * Refresh the package manager's package lists once per dated flag.
   *
   * A flag file at `${FLAGS_DIRECTORY}/package-update-<date>` is created after
   * a successful run. On the next run the flag is detected and the module
   * reports `"ok"` without running the update again. Changing `date` to a new
   * value selects a new flag file, so the update runs once more.
   *
   * The marker is written with `setFlag`, not `setVersionedFlag`: the flag
   * name carries no call-site identity, only the date. An evicting prefix
   * would therefore be host-global, and two `package.update` calls with
   * different dates would delete each other's marker on every run so that
   * neither could ever converge. Two consequences are accepted deliberately:
   * markers for retired dates are not pruned (one empty file per distinct
   * date), and re-using an earlier date is skipped rather than re-run,
   * because that marker still exists.
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
        const flagFailure = await setFlag(ssh, flagName)
        if (flagFailure) return flagFailure

        // An index refresh has no countable outcome, so the detail states the
        // reason the step ran at all instead of a package count.
        return { detail: PACKAGE_INDEX_REFRESHED_DETAIL, status: "changed" }
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
   * value selects a new flag file, so the upgrade runs once more.
   *
   * The marker is written with `setFlag` for the same reason as in
   * `pkg.update`: the flag name carries only the date, so an
   * evicting prefix would be host-global and sibling calls could never
   * converge. Retired markers are therefore not pruned, and re-using an
   * earlier date is skipped rather than re-run.
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
        // The upgrade summary is printed by the last step of the pipeline, so
        // its stdout is what the outcome detail is derived from.
        let lastStdout = ""
        for (const command of UPGRADE_COMMANDS[pm]) {
          // eslint-disable-next-line no-await-in-loop -- upgrade steps must run sequentially
          const result = await ssh.exec(command, pipelineOptions)
          if (result.code !== 0) {
            return failedCommand(`[package.upgrade: ${date}] package upgrade failed`, result)
          }
          lastStdout = result.stdout
        }

        // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC)
        // through the failedCommand path; the helper no longer throws.
        const flagFailure = await setFlag(ssh, flagName)
        if (flagFailure) return flagFailure

        // Only apt's summary shape is parsed; dnf, yum and apk report through
        // formats this parser does not know and take the generic detail.
        return {
          detail:
            pm === "apt" ? describeAptUpgradeOutcome(lastStdout) : UNKNOWN_UPGRADE_OUTCOME_DETAIL,
          status: "changed",
        }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `package.upgrade: ${date}`,
    }
  },
}
