import type { ExecOptions, ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

/** Supported system package managers (kept in sync with `package.ts`). */
export type PackageManager = "apk" | "apt" | "dnf" | "yum"

/** A normalized install target: a name plus an optional pinned version. */
export type NormalizedPackage = {
  name: string
  version: string | undefined
}

/** Per-call overrides for package operations that can take a long time. */
export type UpgradeOptions = {
  /** Override the SSH layer's command timeout (milliseconds). */
  timeout?: number
}

/**
 * A package to install, optionally pinned to an exact version.
 *
 * A bare string package name is equivalent to `{ name }` (no version pin). The
 * package-manager-specific version syntax (`name=version`, `name-version`) is
 * never accepted as a pass-through string — it is built from the structured
 * `name`/`version` fields so the raw PM syntax can never leak into a playbook.
 */
export type PackageSpec = {
  /** Package name (validated against {@link PACKAGE_NAME_PATTERN}). */
  name: string
  /**
   * Exact version to pin to. When set, `check` reports drift against the
   * installed version and `apply` converges on this version (including a
   * downgrade). When omitted, only presence is enforced.
   */
  version?: string
}

/** Argument accepted by the variadic `installed`/`absent` package methods. */
export type PackageArgument = PackageSpec | string | UpgradeOptions

const VERSION_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// A `PackageSpec` carries a `name` field; an `UpgradeOptions` object does not.
// We disambiguate on the shape (presence of `name`), not the position, so a
// `PackageSpec` may appear anywhere in the argument list — including last — and
// a trailing options object is still recognized.
function isPackageSpec(value: PackageSpec | UpgradeOptions): value is PackageSpec {
  return "name" in value && typeof value.name === "string"
}

// Split a variadic argument list into normalized packages plus an optional
// trailing `UpgradeOptions` object (an object without a `name` field at the
// final position).
export function splitPackagesAndOptions(values: readonly PackageArgument[]): {
  options: undefined | UpgradeOptions
  packages: NormalizedPackage[]
} {
  const packages: NormalizedPackage[] = []
  let options: undefined | UpgradeOptions
  for (const [index, value] of values.entries()) {
    if (typeof value === "string") {
      packages.push({ name: value, version: undefined })
    } else if (isPackageSpec(value)) {
      packages.push({ name: value.name, version: value.version })
    } else if (index === values.length - 1) {
      options = value
    }
  }
  return { options, packages }
}

// R-0000812: reject both leading and trailing affix characters in addition to
// whitespace and option-like prefixes. A trailing `-` is apt's "remove" suffix,
// a trailing `+` is "(re)install" — accepting either would let a caller smuggle
// a state change past `pkg.installed`/`pkg.absent` even with the `--` terminator.
// A leading `+` is also disallowed for downstream-tooling safety.
const PACKAGE_NAME_PATTERN = /^[a-z0-9][a-z0-9+._\-]*[a-z0-9.]$/v

// R-0000812 (version pinning): the pinned `version` must begin alphanumerically
// and may then contain `[A-Za-z0-9]` plus `. + ~ : _ -`. This covers apt
// epoch/revision versions (`1:2.3-1ubuntu0.2`) and rpm `version-release`
// (`13.1.0-1.el9`). Whitespace and shell metacharacters are rejected. A single
// alphanumeric character is a valid version, so the tail is optional.
const PACKAGE_VERSION_PATTERN = /^[A-Za-z0-9][\w.+~:\-]*$/v

function isValidPackageName(packageName: string): boolean {
  // A single lowercase alnum char is valid; the multi-char regex requires a
  // trailing non-affix char which forbids the single-char case.
  const isSingleAlnum = packageName.length === 1 && /^[a-z0-9]$/v.test(packageName)
  return isSingleAlnum || PACKAGE_NAME_PATTERN.test(packageName)
}

// Validate package names (and pinned versions when present). Also rejects a
// duplicate name that appears with conflicting pinned versions in the same call.
export function validatePackages(moduleName: string, packages: readonly NormalizedPackage[]): void {
  if (packages.length === 0) {
    throw new Error(`${moduleName}: at least one package name is required`)
  }
  const seenVersions = new Map<string, string | undefined>()
  for (const { name, version } of packages) {
    if (!isValidPackageName(name)) {
      throw new Error(`${moduleName}: invalid package name ${JSON.stringify(name)}`)
    }
    if (version !== undefined && !PACKAGE_VERSION_PATTERN.test(version)) {
      throw new Error(
        `${moduleName}: invalid package version ${JSON.stringify(version)} for ${JSON.stringify(name)}`
      )
    }
    if (seenVersions.has(name) && seenVersions.get(name) !== version) {
      throw new Error(
        `${moduleName}: conflicting versions requested for package ${JSON.stringify(name)}`
      )
    }
    seenVersions.set(name, version)
  }
}

/**
 * Build the package-manager install token for a package, translating an
 * optional pinned version into the PM-native syntax:
 *
 * - apt / apk: `name=version`
 * - dnf / yum: `name-version`
 * - no version: just `name` (today's behavior).
 *
 * The token is `shellQuote`-d as a whole so both name and version are quoted.
 *
 * @param pm - Detected package manager.
 * @param packageName - Bare package name to install.
 * @param version - Pinned version, or `undefined` for no pin.
 * @returns The shell-quoted install token.
 */
export function installToken(
  pm: PackageManager,
  packageName: string,
  version: string | undefined
): string {
  if (version === undefined) return shellQuote(packageName)
  const separator = pm === "dnf" || pm === "yum" ? "-" : "="
  return shellQuote(`${packageName}${separator}${version}`)
}

/**
 * Parse the installed version out of a single `apk version -v <name>` line.
 *
 * Lines look like `curl-8.5.0-r0 = 8.5.0-r0`; the installed version is the
 * tail of the first whitespace-delimited token after the `<name>-` prefix.
 *
 * @param out - Trimmed command output.
 * @param packageName - Package name whose prefix is stripped.
 * @returns The installed version, or `null` when it cannot be derived.
 */
function parseApkVersion(out: string, packageName: string): null | string {
  if (out.length === 0) return null
  const firstToken = out.split(/\s+/v)[0] ?? ""
  const prefix = `${packageName}-`
  if (!firstToken.startsWith(prefix)) return null
  const version = firstToken.slice(prefix.length)
  return version.length > 0 ? version : null
}

/**
 * Return the installed version of a package as reported by the package
 * manager, or `null` when the package is not installed.
 *
 * The reported format is chosen to match the `version` a user pins:
 *
 * - apt: `dpkg-query -W -f='${Version}'` → the full Debian version
 *   (including epoch/revision), e.g. `1:2.3-1ubuntu0.2`. Presence is derived
 *   from a non-empty result.
 * - dnf/yum (rpm): `rpm -q --qf '%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n'`
 *   → `[epoch:]version-release`. The epoch-conditional prints an `epoch:`
 *   prefix only when an epoch is set (e.g. `1:2.0-1`) and nothing otherwise
 *   (e.g. `13.1.0-1.el9`), so an epoch-qualified pin is not lost. The trailing
 *   `\n` separates the (rare) case of multiple installed versions — installonly
 *   packages such as the kernel — instead of concatenating them into an
 *   unusable blob; we take the last line as the representative version. Exact
 *   pinning of installonly packages with several versions installed at once is
 *   out of scope. A missing package makes `rpm -q` exit non-zero → `null`.
 * - apk: `apk version -v <name>` prints `<name-version> <op> <candidate>`;
 *   the trailing `-version` segment of the first field is the installed
 *   version. When the package is absent the command prints nothing, yielding
 *   `null`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param pm - Detected package manager.
 * @param packageName - Package to query.
 * @returns The installed version string, or `null` when not installed.
 */
export async function getInstalledVersion(
  ssh: SshConnection,
  pm: PackageManager,
  packageName: string
): Promise<null | string> {
  const quoted = shellQuote(packageName)
  if (pm === "apk") {
    const raw = await ssh.output(`apk version -v ${quoted}`)
    return parseApkVersion(raw.trim(), packageName)
  }
  if (pm === "apt") {
    const raw = await ssh.output(`dpkg-query -W -f='\${Version}' ${quoted} 2>/dev/null`)
    const aptVersion = raw.trim()
    return aptVersion.length > 0 ? aptVersion : null
  }
  // dnf / yum (rpm): epoch-aware, newline-terminated query — see the doc above.
  const result = await ssh.exec(
    `rpm -q --qf '%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\n' ${quoted}`,
    VERSION_EXEC_OPTS
  )
  if (result.code !== 0) return null
  const lines = result.stdout
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
  // Multiple lines → installonly package with several versions installed; use
  // the last one as the representative. Zero lines → treat as not installed.
  return lines.at(-1) ?? null
}

// Compare the installed version of a pinned package against the pin for exact
// equality. For apt this uses `dpkg --compare-versions ... eq ...` so Debian
// version normalization (e.g. a `0:` epoch) is handled by dpkg itself; for
// rpm/apk the reported string is compared directly.
export async function versionsEqual(parameters: {
  installed: string
  pinned: string
  pm: PackageManager
  ssh: SshConnection
}): Promise<boolean> {
  const { installed, pinned, pm, ssh } = parameters
  if (pm === "apt") {
    return ssh.test(`dpkg --compare-versions ${shellQuote(installed)} eq ${shellQuote(pinned)}`)
  }
  return installed === pinned
}

// Render a package list for human-readable module names / error messages.
export function describePackages(packages: readonly NormalizedPackage[]): string {
  return packages
    .map((p) => (p.version === undefined ? p.name : `${p.name}=${p.version}`))
    .join(", ")
}

// R-0000812 (version pinning): apt refuses to install an older version than the
// one already present unless `--allow-downgrades` is passed. Only add it when at
// least one package in the batch is pinned, so the unpinned path stays
// byte-for-byte identical to the base install command.
function aptInstallCommand(tokens: string, hasPin: boolean): string {
  return hasPin
    ? `DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades -- ${tokens}`
    : `DEBIAN_FRONTEND=noninteractive apt-get install -y -- ${tokens}`
}

// R-0000812 (version pinning): `dnf install name-version` does NOT downgrade
// when a higher version is already installed — `dnf downgrade` is required for
// that direction. `yum` behaves the same.
const DOWNGRADE_COMMANDS = {
  dnf: (tokens: string) => `dnf downgrade -y -- ${tokens}`,
  yum: (tokens: string) => `yum downgrade -y -- ${tokens}`,
} as const

// Build the install command for a batch of packages, adding
// `--allow-downgrades` for pinned apt packages.
function buildInstallCommand(
  baseInstall: (tokens: string) => string,
  pm: PackageManager,
  packages: readonly NormalizedPackage[]
): string {
  const tokens = packages.map((p) => installToken(pm, p.name, p.version)).join(" ")
  const hasPin = packages.some((p) => p.version !== undefined)
  return pm === "apt" ? aptInstallCommand(tokens, hasPin) : baseInstall(tokens)
}

// Determine whether the installed version is strictly HIGHER than the pinned
// one, using the remote's version-aware `sort -V` (coreutils) instead of a
// lexicographic JS compare — `13.9.0` vs `13.10.0` orders wrong lexically
// (and `2.0` vs `10.0`, etc.). A downgrade is required exactly when the
// installed version is strictly higher than the pin.
async function installedIsHigher(
  ssh: SshConnection,
  installed: string,
  pinned: string
): Promise<boolean> {
  if (installed === pinned) return false
  const result = await ssh.exec(
    `printf '%s\\n%s\\n' ${shellQuote(pinned)} ${shellQuote(installed)} | sort -V | tail -n1`,
    VERSION_EXEC_OPTS
  )
  // Only a successful `sort -V` (coreutils, always present on dnf/yum hosts) is
  // authoritative: the higher version sorts last, so if it equals the installed
  // version a downgrade is required. If the pipeline could not run (non-zero
  // exit) we do NOT assume a downgrade — a plain install converges for the
  // common upgrade/equal case, and a genuinely required downgrade on such a
  // host then surfaces as a clear post-install verification failure rather than
  // a silent wrong action.
  if (result.code !== 0) return false
  return result.stdout.trim() === installed
}

// Decide, per package, whether an rpm-based install must instead go through
// `dnf downgrade` / `yum downgrade`: that is the case exactly when the package
// is pinned and a strictly higher version is already installed. Everything else
// (absent, lower, or equal-but-not-yet-satisfied) is handled by `install`.
async function collectDowngradeTokens(
  ssh: SshConnection,
  pm: "dnf" | "yum",
  packages: readonly NormalizedPackage[]
): Promise<{ downgrade: string[]; install: NormalizedPackage[] }> {
  const downgrade: string[] = []
  const install: NormalizedPackage[] = []
  for (const package_ of packages) {
    if (package_.version === undefined) {
      install.push(package_)
      continue
    }
    // eslint-disable-next-line no-await-in-loop -- sequential per-package queries
    const installed = await getInstalledVersion(ssh, pm, package_.name)
    // A downgrade is needed only when the installed version is strictly higher
    // than the pin; the version comparison runs on the remote via `sort -V`.
    // eslint-disable-next-line no-await-in-loop -- sequential per-package queries
    if (installed !== null && (await installedIsHigher(ssh, installed, package_.version))) {
      downgrade.push(installToken(pm, package_.name, package_.version))
    } else {
      install.push(package_)
    }
  }
  return { downgrade, install }
}

// Run the version-aware install for a batch of packages: an explicit
// `dnf`/`yum downgrade` for any pinned package already at a higher version,
// followed by the install (with `--allow-downgrades` for pinned apt packages).
// Returns a failure `ModuleResult` if a command failed, otherwise `null`.
export async function runVersionedInstall(parameters: {
  baseInstall: (tokens: string) => string
  execOpts: ExecOptions
  label: string
  packages: readonly NormalizedPackage[]
  pm: PackageManager
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { baseInstall, execOpts, label, packages, pm, ssh } = parameters
  const failure = (result: { code: number; stderr: string; stdout: string }): ModuleResult =>
    failedCommand(`[package.installed: ${label}] package installation failed`, result)

  let installTargets: readonly NormalizedPackage[] = packages
  if (pm === "dnf" || pm === "yum") {
    const split = await collectDowngradeTokens(ssh, pm, packages)
    installTargets = split.install
    if (split.downgrade.length > 0) {
      const down = await ssh.exec(DOWNGRADE_COMMANDS[pm](split.downgrade.join(" ")), execOpts)
      if (down.code !== 0) return failure(down)
    }
  }
  if (installTargets.length === 0) return null
  const install = await ssh.exec(buildInstallCommand(baseInstall, pm, installTargets), execOpts)
  return install.code === 0 ? null : failure(install)
}
