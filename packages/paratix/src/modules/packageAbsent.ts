/**
 * `package.absent` helpers: construction-time argument validation and the
 * dpkg-based purge path (`purge: true` on apt).
 *
 * The plain remove path stays in `package.ts`; this file owns the argument
 * parsing, the dpkg remnant detection and the `apt-get purge` call.
 */
import type { ExecOptions, ExecResult, ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type AbsentOptions,
  type PackageSpec,
  splitPackagesAndOptions,
  validatePackages,
} from "./packageVersion.js"

// Same options as the other package probes: the exit code is interpreted here
// and no `timeout` is forwarded (the SSH default applies).
const QUERY_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// `purge` is apt-only: apk, dnf and yum have no config-files remnant state, so
// `package.absent` maps `purge: true` to `REMOVE_COMMANDS` there.
const APT_PURGE_COMMAND = (pkgs: string): string =>
  `DEBIAN_FRONTEND=noninteractive apt-get purge -y -- ${pkgs}`

/** dpkg status that means "dpkg knows the name but nothing of it is on disk". */
const DPKG_NOT_INSTALLED = "not-installed"

/** One dpkg database entry: its exact identifier and its package status. */
type DpkgEntry = { id: string; status: string }

/** Outcome of querying every dpkg entry of a single package name. */
type DpkgQueryOutcome =
  | { entries: DpkgEntry[]; kind: "entries" }
  | { kind: "query-failed"; result: ExecResult }
  | { kind: "unparsable"; line: string }

// One `dpkg-query` line: `${binary:Package}` (bare `name` or `name:arch`),
// a single space, then `${db:Status-Status}` (e.g. `config-files`).
const DPKG_ENTRY_PATTERN = /^(?<id>\S+) (?<status>\S+)$/v

/**
 * Build the dpkg query that lists every dpkg entry of a package name across
 * all architectures, one `<identifier> <status>` line per entry.
 *
 * The `\n` reaches the remote shell as a literal backslash-n inside the
 * single-quoted format, which dpkg-query expands to a newline so multiarch
 * entries never run together.
 *
 * Exported for test reuse only; it is not part of the public module surface.
 *
 * @param packageName - Package name to query (shell-quoted here).
 * @returns The complete shell command.
 */
export function dpkgStatusQueryCommand(packageName: string): string {
  return `dpkg-query -W -f='\${binary:Package} \${db:Status-Status}\\n' ${shellQuote(packageName)} 2>/dev/null`
}

function parseDpkgEntries(stdout: string): DpkgQueryOutcome {
  const entries: DpkgEntry[] = []
  for (const rawLine of stdout.split("\n")) {
    const line = rawLine.trim()
    if (line.length === 0) continue
    const groups = DPKG_ENTRY_PATTERN.exec(line)?.groups
    // Both groups are mandatory in the pattern, so a match always carries them.
    if (groups === undefined) return { kind: "unparsable", line }
    entries.push({ id: groups.id, status: groups.status })
  }
  return { entries, kind: "entries" }
}

/**
 * Query every dpkg entry of a package name for the purge path of
 * `package.absent`. Exit 1 means dpkg does not know the name at all (no
 * remnants); any other non-zero exit is a query failure. No `timeout` is
 * forwarded — like `isPackageInstalled`, the probe uses the SSH default.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param packageName - Package name to query.
 * @returns The parsed entries, or the reason they could not be determined.
 */
async function queryDpkgEntries(
  ssh: SshConnection,
  packageName: string
): Promise<DpkgQueryOutcome> {
  const result = await ssh.exec(dpkgStatusQueryCommand(packageName), QUERY_EXEC_OPTS)
  if (result.code === 1) return { entries: [], kind: "entries" }
  if (result.code !== 0) return { kind: "query-failed", result }
  return parseDpkgEntries(result.stdout)
}

// Any status other than exactly `not-installed` leaves something to purge:
// `installed`, `config-files` (`rc`) and intermediate states alike.
function isDpkgRemnant(entry: DpkgEntry): boolean {
  return entry.status !== DPKG_NOT_INSTALLED
}

/**
 * Report whether any of the named packages still has a dpkg remnant. Used by
 * `check()` with `purge: true`, so a dry run sees the same state as `apply`.
 * Stops at the first remnant; a failed or unparsable query also counts as
 * "remnant", because absence cannot be proven.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param names - Package names to query.
 * @returns `true` when at least one name has a remnant or cannot be queried.
 */
export async function hasAnyDpkgRemnant(
  ssh: SshConnection,
  names: readonly string[]
): Promise<boolean> {
  for (const packageName of names) {
    // eslint-disable-next-line no-await-in-loop -- probe packages sequentially to avoid SSH-channel pressure
    const outcome = await queryDpkgEntries(ssh, packageName)
    // A failed or unparsable query cannot prove absence; never guess `ok`.
    if (outcome.kind !== "entries" || outcome.entries.some((entry) => isDpkgRemnant(entry))) {
      return true
    }
  }
  return false
}

function dpkgQueryFailure(
  label: string,
  packageName: string,
  outcome: Exclude<DpkgQueryOutcome, { kind: "entries" }>
): ModuleResult {
  if (outcome.kind === "query-failed") {
    return failedCommand(`[package.absent: ${label}] package status query failed`, outcome.result)
  }
  return failed(
    `[package.absent: ${label}] unexpected dpkg-query output for ${packageName}: ${outcome.line}`
  )
}

// Collect the exact dpkg identifiers of every remnant entry, deduplicated in
// first-seen order. Unlike the plain remove path every name is queried, so the
// purge covers the complete list in a single `apt-get purge` call.
async function collectDpkgRemnantIds(
  ssh: SshConnection,
  names: readonly string[],
  label: string
): Promise<{ failure: ModuleResult } | { ids: string[] }> {
  const ids = new Set<string>()
  for (const packageName of names) {
    // eslint-disable-next-line no-await-in-loop -- probe packages sequentially to avoid SSH-channel pressure
    const outcome = await queryDpkgEntries(ssh, packageName)
    if (outcome.kind !== "entries") {
      return { failure: dpkgQueryFailure(label, packageName, outcome) }
    }
    for (const entry of outcome.entries) {
      if (isDpkgRemnant(entry)) ids.add(entry.id)
    }
  }
  return { ids: [...ids] }
}

/**
 * Purge every dpkg remnant of the named packages with one `apt-get purge`
 * call on exactly the identifiers dpkg reported. Returns `ok` without running
 * a command when nothing is left to purge.
 *
 * @param parameters - Named arguments.
 * @param parameters.execOpts - Exec options for the purge call (carries `timeout`).
 * @param parameters.label - Module label used in failure messages.
 * @param parameters.names - Package names to query and purge.
 * @param parameters.ssh - Active SSH connection to the remote host.
 * @returns `ok`, `changed`, or a failure for a query or purge error.
 */
export async function purgeAptPackages(parameters: {
  execOpts: ExecOptions
  label: string
  names: readonly string[]
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { execOpts, label, names, ssh } = parameters
  const scan = await collectDpkgRemnantIds(ssh, names, label)
  if ("failure" in scan) return scan.failure
  if (scan.ids.length === 0) return { status: "ok" }
  const quoted = scan.ids.map((id) => shellQuote(id)).join(" ")
  const result = await ssh.exec(APT_PURGE_COMMAND(quoted), execOpts)
  if (result.code !== 0) {
    return failedCommand(`[package.absent: ${label}] package removal failed`, result)
  }
  return { status: "changed" }
}

/**
 * Parse and validate the `absent` arguments at construction time.
 *
 * @param packagesAndOptions - The variadic `absent` arguments.
 * @returns The package names, the trailing options object and the `purge` flag.
 * @throws {Error} When a package name is invalid, a version is pinned, or
 *   `purge` is set to anything other than a boolean.
 */
export function parseAbsentArguments(
  packagesAndOptions: ReadonlyArray<AbsentOptions | PackageSpec | string>
): { names: string[]; options: AbsentOptions | undefined; purge: boolean } {
  const { options, packages } = splitPackagesAndOptions<AbsentOptions>(packagesAndOptions)
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
  // Typed as `unknown` so the runtime guard also covers untyped callers.
  const purge: unknown = options?.purge
  if (purge !== undefined && typeof purge !== "boolean") {
    throw new Error("package.absent: purge must be a boolean")
  }
  return { names: packages.map((p) => p.name), options, purge: purge === true }
}
