import type { UpgradeOptions } from "./package.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecOptions,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import {
  applyAptKey,
  normalizeOpenPgpFingerprint,
  validateAptKeyUrl,
  verifyAptKeyFingerprint,
} from "./aptKeyHelpers.js"
import { sha256String } from "./fileHelpers.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const APT_REPOSITORY_MODE = "0644"

// R-0000098: apt resource names land directly in shell paths like
// `/etc/apt/keyrings/${name}.gpg` and `/etc/apt/sources.list.d/${name}.list`.
// Reject any value that could resolve to a path-traversal segment (`..`),
// contain a path separator, or otherwise escape the intended directory.
// The pattern allows word characters, dots and dashes; the explicit
// `..` reject below forbids the only single-character-class form that
// could still produce a traversal segment.
const APT_RESOURCE_NAME_PATTERN = /^[\w.\-]+$/v

function validateAptResourceName(name: string): void {
  if (name.length === 0 || name.includes("..") || !APT_RESOURCE_NAME_PATTERN.test(name)) {
    throw new Error(
      `apt: name must match ${String(APT_RESOURCE_NAME_PATTERN)} and must not contain '..', got: ${JSON.stringify(name)}`
    )
  }
}

const APT_BASE_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

function aptExecOptions(options?: UpgradeOptions): ExecOptions {
  if (options?.timeout === undefined) return APT_BASE_EXEC_OPTS
  return { ...APT_BASE_EXEC_OPTS, timeout: options.timeout }
}

const PPA_PREFIX = "ppa:"
/**
 * Parse the output of `debconf-show` into a question-to-value map.
 *
 * Each line has the form `[*] <question>: <value>`. The leading asterisk
 * (marking the currently active value) is stripped, and blank lines are
 * ignored.
 *
 * @param stdout - Raw stdout of `debconf-show <package>`.
 * @returns A map of debconf question names to their current values.
 */
function parseDebconfOutput(stdout: string): Record<string, string> {
  const values: Record<string, string> = {}
  for (const line of stdout.split("\n")) {
    const colonIndex = line.indexOf(":")
    if (colonIndex === -1) continue
    const rawQuestion = line.slice(0, colonIndex).replace(/^\s*\*?\s*/v, "")
    if (rawQuestion) {
      values[rawQuestion] = line.slice(colonIndex + 1).trim()
    }
  }
  return values
}

// R-0000104: short hash length for the per-package and per-selections
// segments of the debconf marker flag. 16 hex chars = 64 bits, which
// gives a collision-resistant identifier without bloating the flag
// file name.
const APT_DEBCONF_HASH_LENGTH = 16

/**
 * Build the marker flag prefix and full flag name for an apt.debconf
 * configuration. The prefix is keyed only to `packageName` so that
 * `setVersionedFlag` deletes stale flags from previous selection sets
 * when the desired selections change. The full flag name additionally
 * encodes a hash of the selections so that drift in the desired values
 * is detected as `needs-apply` instead of being masked by an existing
 * flag.
 *
 * @param packageName - The package name whose debconf selections are pre-seeded.
 * @param selectionsText - Newline-joined `pkg question type value` lines.
 * @returns The flag prefix (for cleanup) and the full flag name.
 */
function buildDebconfFlagInfo(
  packageName: string,
  selectionsText: string
): { flagName: string; flagPrefix: string } {
  const packageHash = sha256String(packageName).slice(0, APT_DEBCONF_HASH_LENGTH)
  const selectionsHash = sha256String(`${packageName}\n${selectionsText}`).slice(
    0,
    APT_DEBCONF_HASH_LENGTH
  )
  const flagPrefix = `apt-debconf-${packageHash}-`
  const flagName = `${flagPrefix}${selectionsHash}`
  return { flagName, flagPrefix }
}

/**
 * Build the newline-joined selections text fed to `debconf-set-selections`.
 *
 * Each line has the form `<package> <question> <type> <value>` and uses
 * the type returned by `resolveDebconfType`. Newline characters in
 * questions or values are rejected up-front because debconf's flat-file
 * format cannot represent them.
 *
 * @param ssh - Active SSH connection used to query debconf types.
 * @param packageName - The package name whose selections are pre-seeded.
 * @param selections - A map of `question -> value` entries.
 * @returns A `failed` ModuleResult on rejection, otherwise the joined text.
 */
async function buildDebconfSelectionsText(
  ssh: SshConnection,
  packageName: string,
  selections: Record<string, string>
): Promise<ModuleResult | string> {
  const lines: string[] = []
  for (const [question, value] of Object.entries(selections)) {
    if (question.includes("\n") || value.includes("\n")) {
      return failed(
        `[apt.debconf] selections for ${packageName} must not contain newline characters`
      )
    }
    // eslint-disable-next-line no-await-in-loop
    const type = await resolveDebconfType(ssh, question)
    lines.push(`${packageName} ${question} ${type} ${value}`)
  }
  return lines.join("\n")
}

/**
 * Compare the live debconf database for an installed package against
 * the desired selections. Returns `ok` when every requested question
 * already holds the desired value, otherwise `needs-apply`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param packageName - The package name to probe.
 * @param selections - Desired `question -> value` map.
 * @returns `ok` when the live database matches, otherwise `needs-apply`.
 */
async function checkInstalledDebconfState(
  ssh: SshConnection,
  packageName: string,
  selections: Record<string, string>
): Promise<"needs-apply" | "ok"> {
  const result = await ssh.exec(`debconf-show ${shellQuote(packageName)}`, APT_BASE_EXEC_OPTS)
  if (result.code !== 0) return NEEDS_APPLY

  const currentValues = parseDebconfOutput(result.stdout)
  for (const [question, value] of Object.entries(selections)) {
    if (currentValues[question] !== value) return NEEDS_APPLY
  }
  return "ok"
}

/**
 * Consult the versioned marker flag for an apt.debconf configuration.
 * Used as the fallback idempotency signal when the package is not yet
 * installed and `debconf-show` therefore cannot report state.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param packageName - The package name whose selections are pre-seeded.
 * @param selections - Desired `question -> value` map.
 * @returns `ok` when the marker for the current selections exists,
 *   otherwise `needs-apply`.
 */
async function checkBufferedDebconfMarker(
  ssh: SshConnection,
  packageName: string,
  selections: Record<string, string>
): Promise<"needs-apply" | "ok"> {
  const selectionsTextOrFailure = await buildDebconfSelectionsText(ssh, packageName, selections)
  if (typeof selectionsTextOrFailure !== "string") return NEEDS_APPLY

  const { flagName } = buildDebconfFlagInfo(packageName, selectionsTextOrFailure)
  return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
}

/**
 * Probe whether the given Debian package is installed.
 *
 * Uses `dpkg-query -W -f='${Status}'` and matches the freeform status
 * line against the canonical `install ok installed` token. This avoids
 * false positives for packages that are merely partially installed,
 * unpacked, or whose configuration was removed (`config-files` /
 * `not-installed` / `unpacked` states), where the debconf database
 * may be stale or incomplete.
 *
 * @param ssh - Active SSH connection.
 * @param packageName - The package name to probe.
 * @returns `true` when dpkg reports the package as fully installed.
 */
async function isAptPackageInstalled(ssh: SshConnection, packageName: string): Promise<boolean> {
  const result = await ssh.exec(
    `dpkg-query -W -f='\${Status}' ${shellQuote(packageName)}`,
    APT_BASE_EXEC_OPTS
  )
  if (result.code !== 0) return false
  return result.stdout.trim() === "install ok installed"
}

/**
 * Build a Module that adds a Launchpad PPA via `add-apt-repository`.
 *
 * The check phase queries `/etc/apt/sources.list.d/` for the PPA path
 * so that the command is not re-run if the repository is already present.
 *
 * @param ppa - PPA identifier in the form `"ppa:user/name"`.
 * @returns A Module that registers the PPA.
 */
function buildPpaRepository(ppa: string): Module {
  const ppaPath = ppa.slice(PPA_PREFIX.length)
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[apt.repository] SSH connection is required for ${ppa}`)
      const result = await ssh.exec(`add-apt-repository -y ${shellQuote(ppa)}`, {
        ignoreExitCode: true,
        silent: true,
      })
      if (result.code !== 0) return failedCommand(`[apt.repository] failed to add ${ppa}`, result)
      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      return (await ssh.test(`grep -rq ${shellQuote(ppaPath)} /etc/apt/sources.list.d/`))
        ? "ok"
        : NEEDS_APPLY
    },
    name: `apt.repository: ${ppa}`,
  }
}

/**
 * Query the debconf database for the type of a question (e.g. `select`, `string`).
 * Falls back to `"string"` when the type cannot be determined.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param question - Fully-qualified debconf question key.
 * @returns Debconf type string (defaults to `"string"`).
 */
async function resolveDebconfType(ssh: SshConnection, question: string): Promise<string> {
  const metagetCommand = `METAGET ${question} type`
  const typeResult = await ssh.exec(`echo ${shellQuote(metagetCommand)} | debconf-communicate`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (typeResult.code === 0 && typeResult.stdout.trim()) {
    const parts = typeResult.stdout.trim().split(/\s+/v)
    if (parts.length >= 2 && parts[0] === "0") {
      return parts[1]
    }
  }
  return "string"
}

const BRACKETED_SOURCE_RE = /^(?<prefix>deb(?:-src)?)\s+\[(?<opts>[^\]]*)\](?<rest>.*)$/v
const PLAIN_SOURCE_RE = /^(?<prefix>deb(?:-src)?)\s(?<rest>.+)$/v

/**
 * Inject a `signed-by=<keyPath>` option into a deb source line.
 *
 * Handles both the bracketed form (`deb [arch=amd64] ...`) and the plain
 * form (`deb https://...`). If the line does not match either pattern it is
 * returned unchanged.
 *
 * @param sourceLine - A single deb/deb-src source line.
 * @param keyPath - Absolute path to the GPG keyring file on the remote host.
 * @returns The source line with the `signed-by` option inserted.
 */
function injectSignedBy(sourceLine: string, keyPath: string): string {
  const withBrackets = BRACKETED_SOURCE_RE.exec(sourceLine)
  if (withBrackets?.groups) {
    if (withBrackets.groups.opts.includes("signed-by=")) return sourceLine
    return `${withBrackets.groups.prefix} [${withBrackets.groups.opts} signed-by=${keyPath}]${withBrackets.groups.rest}`
  }
  const withoutBrackets = PLAIN_SOURCE_RE.exec(sourceLine)
  if (withoutBrackets?.groups) {
    return `${withoutBrackets.groups.prefix} [signed-by=${keyPath}] ${withoutBrackets.groups.rest}`
  }
  return sourceLine
}

/**
 * Modules for Debian/Ubuntu-specific apt configuration.
 *
 * Provides four apt-specific helpers:
 * - `debconf` — pre-seed debconf answers for non-interactive installs
 * - `distUpgrade` — run `apt-get dist-upgrade` with full dependency resolution
 * - `key` — import a GPG key into `/etc/apt/keyrings/`
 * - `repository` — add a PPA or custom `.list` source file
 *
 * For installing, removing and upgrading packages use the distro-agnostic
 * `package` module instead.
 *
 * @see pkg
 */
export const apt = {
  /**
   * Set debconf selections for a package so that installs/upgrades
   * can proceed non-interactively with the desired answers.
   *
   * @param packageName - The package name whose debconf questions to pre-seed.
   * @param selections - A map of `question -> value` entries where the key is
   *   the full debconf question name (e.g. `"postfix/main_mailer_type"`).
   * @returns A Module that applies the debconf selections.
   *
   * @example
   * apt.debconf("postfix", {
   *   "postfix/main_mailer_type": "Internet Site",
   *   "postfix/mailname": "example.com",
   * })
   */
  debconf(packageName: string, selections: Record<string, string>): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.debconf] SSH connection is required for ${packageName}`)

        const selectionsTextOrFailure = await buildDebconfSelectionsText(
          ssh,
          packageName,
          selections
        )
        if (typeof selectionsTextOrFailure !== "string") return selectionsTextOrFailure

        const selectionsText = selectionsTextOrFailure
        // R-0000063: use `printf '%s' …` instead of `echo …` so selection
        // values that begin with `-` (interpreted as flags by some echo
        // implementations) or contain backslash sequences (interpreted by
        // POSIX echo) are passed through verbatim regardless of which shell
        // `/bin/sh` resolves to. Mirrors the pattern used by
        // cron.writeCrontab.
        const result = await ssh.exec(
          `printf '%s' ${shellQuote(selectionsText)} | debconf-set-selections`,
          { ignoreExitCode: true, silent: true }
        )
        if (result.code !== 0)
          return failedCommand(`[apt.debconf] failed to set selections for ${packageName}`, result)

        // R-0000104: persist a versioned marker flag so that subsequent
        // `check` runs return `ok` even when the package is not yet
        // installed (in which case `debconf-show` would exit non-zero
        // and yield a permanent `needs-apply`). The flag prefix is keyed
        // to the package, so changing the desired selections evicts the
        // stale flag and `check` will correctly report `needs-apply`.
        const { flagName, flagPrefix } = buildDebconfFlagInfo(packageName, selectionsText)
        await setVersionedFlag(ssh, flagName, flagPrefix)

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        // R-0000104: distinguish between `package installed, drift` and
        // `package not installed, selections buffered`. When the package
        // is installed the live debconf database is the source of truth.
        // When it is not yet installed `debconf-show` exits non-zero and
        // we must instead consult the versioned marker flag set by
        // `apply` to decide whether the buffered selections still match
        // the desired set.
        return (await isAptPackageInstalled(ssh, packageName))
          ? checkInstalledDebconfState(ssh, packageName, selections)
          : checkBufferedDebconfMarker(ssh, packageName, selections)
      },
      name: `apt.debconf: ${packageName}`,
    }
  },

  /**
   * Run `apt-get update && apt-get dist-upgrade` once per dated flag.
   * Performs a full distribution upgrade with dependency resolution.
   *
   * The pipeline is split into three separate SSH commands so that each step
   * gets its own timeout window and produces a precise failure label.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @param options - Optional per-call overrides (e.g. SSH command `timeout`).
   *   The same `timeout` is applied to every step of the dist-upgrade pipeline.
   * @returns A Module that performs the dist-upgrade.
   *
   * @example
   * apt.distUpgrade("2024-01-15")
   * apt.distUpgrade("2024-01-15", { timeout: 900_000 })
   */
  distUpgrade(date: string, options?: UpgradeOptions): Module {
    const flagName = `apt-dist-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.distUpgrade] SSH connection is required for ${date}`)
        const pipelineOptions = aptExecOptions(options)

        // R-0000055: run `dpkg --configure -a` first so an interrupted
        // package configuration is healed before the next apt step. The
        // previous order put `apt-get update` first, which would fail on
        // dpkg-broken hosts and never give configure -a a chance to run.
        // Mirrors the order used by package.ts apt-upgrade pipeline.
        const configure = await ssh.exec(`${NONINTERACTIVE} dpkg --configure -a`, pipelineOptions)
        if (configure.code !== 0)
          return failedCommand("[apt.distUpgrade] dpkg --configure -a failed", configure)

        const update = await ssh.exec(`${NONINTERACTIVE} apt-get update`, pipelineOptions)
        if (update.code !== 0)
          return failedCommand("[apt.distUpgrade] apt-get update failed", update)

        const upgrade = await ssh.exec(`${NONINTERACTIVE} apt-get dist-upgrade -y`, pipelineOptions)
        if (upgrade.code !== 0)
          return failedCommand("[apt.distUpgrade] apt-get dist-upgrade failed", upgrade)

        await setVersionedFlag(ssh, flagName, "apt-dist-upgrade-")

        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await hasFlag(ssh, flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `apt.distUpgrade: ${date}`,
    }
  },

  /**
   * Import a GPG key into `/etc/apt/keyrings/` for use with signed repositories.
   * @param name - Key file name (without `.gpg` extension).
   * @param url - URL to download the key from.
   * @param options - Required trust anchor for the downloaded key.
   * @param options.fingerprint - Expected OpenPGP fingerprint of the repository key.
   * @returns A Module that imports the GPG key.
   */
  key(name: string, url: string, options: { fingerprint: string }): Module {
    validateAptResourceName(name)
    validateAptKeyUrl(url)
    const expectedFingerprint = normalizeOpenPgpFingerprint(options.fingerprint)
    const keyringPath = `/etc/apt/keyrings/${name}.gpg`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.key] SSH connection is required for ${name}`)

        const mkdirResult = await ssh.exec("mkdir -p /etc/apt/keyrings", {
          ignoreExitCode: true,
          silent: true,
        })
        if (mkdirResult.code !== 0)
          return failedCommand("[apt.key] failed to create /etc/apt/keyrings", mkdirResult)

        return applyAptKey(ssh, { expectedFingerprint, keyringPath, name, url })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const keyExists = await ssh.test(`[ -f ${shellQuote(keyringPath)} ]`)
        if (!keyExists) return NEEDS_APPLY

        return (await verifyAptKeyFingerprint({
          expectedFingerprint,
          name,
          path: keyringPath,
          ssh,
        })) === "ok"
          ? "ok"
          : NEEDS_APPLY
      },
      name: `apt.key: ${name}`,
    }
  },

  /**
   * Add an apt repository source, either as a PPA or a custom source line.
   *
   * **PPA form**: pass `"ppa:user/name"` as the first argument (no `source`).
   * Uses `add-apt-repository` internally.
   *
   * **Standard form**: pass a name and a deb source line. The source is
   * written to `/etc/apt/sources.list.d/<name>.list`. The `signed-by` option
   * is automatically derived from `name` (pointing to
   * `/etc/apt/keyrings/<name>.gpg`) unless overridden.
   *
   * @param nameOrPpa - Repository name or PPA identifier (e.g. `"ppa:user/name"`).
   * @param source - The deb source line (omit for PPA form).
   * @param options - Optional settings.
   * @param options.signedBy - Override the key name used for `signed-by`
   *   (`false` to disable auto-derivation, a string to use a different key name).
   * @returns A Module that configures the repository.
   *
   * @example
   * // PPA form
   * apt.repository("ppa:ondrej/php")
   *
   * @example
   * // Standard form – signed-by is auto-derived from "nodejs"
   * apt.repository(
   *   "nodejs",
   *   "deb https://deb.nodesource.com/node_20.x nodistro main",
   * )
   *
   * @example
   * // Standard form with signed-by disabled
   * apt.repository(
   *   "internal",
   *   "deb [arch=amd64] https://packages.example.com stable main",
   *   { signedBy: false },
   * )
   */
  repository(nameOrPpa: string, source?: string, options?: { signedBy?: false | string }): Module {
    if (nameOrPpa.startsWith(PPA_PREFIX) && source === undefined) {
      return buildPpaRepository(nameOrPpa)
    }

    if (source === undefined) {
      throw new Error("apt.repository: source is required for non-PPA repositories")
    }

    const name = nameOrPpa
    validateAptResourceName(name)
    const signedBy = options?.signedBy
    let expectedContent = source

    if (signedBy !== false) {
      const keyName = typeof signedBy === "string" ? signedBy : name
      validateAptResourceName(keyName)
      expectedContent = injectSignedBy(expectedContent, `/etc/apt/keyrings/${keyName}.gpg`)
    }

    const filePath = `/etc/apt/sources.list.d/${name}.list`

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.repository] SSH connection is required for ${name}`)
        await ssh.writeFile(filePath, `${expectedContent}\n`, { mode: APT_REPOSITORY_MODE })
        const result = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0)
          return failedCommand(`[apt.repository] apt-get update failed for ${name}`, result)
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.test(`[ -f ${shellQuote(filePath)} ]`)
        if (!exists) return NEEDS_APPLY
        const content = await ssh.readFile(filePath)
        // R-0000051: tolerate whitespace-only drift (tabs vs. spaces,
        // collapsed vs. multiple spaces, trailing whitespace) by
        // normalizing consecutive whitespace to a single space and
        // trimming both sides before comparing. The deb source-line
        // grammar treats any whitespace as a field separator, so
        // `deb<TAB>https://...` and `deb https://...` are semantically
        // identical and must not flap between `ok` and `needs-apply`.
        if (normalizeAptSourceContent(content) !== normalizeAptSourceContent(expectedContent)) {
          return NEEDS_APPLY
        }

        const mode = await ssh.output(`stat -c '%a' ${shellQuote(filePath)}`)
        return mode.trim() === APT_REPOSITORY_MODE.replace(/^0+/v, "") ? "ok" : NEEDS_APPLY
      },
      name: `apt.repository: ${name}`,
    }
  },
}

/**
 * Normalize an apt source-list file content so superficial whitespace
 * differences (tabs vs. spaces, collapsed runs, trailing whitespace) do
 * not cause spurious drift. Each non-empty, non-comment line is collapsed
 * to a single-space-separated form.
 *
 * @param content - The raw file content as read from disk.
 * @returns The normalized comparison form.
 */
function normalizeAptSourceContent(content: string): string {
  return content
    .split(/\r?\n/v)
    .map((line) => line.replaceAll(/\s+/gv, " ").trim())
    .filter((line) => line.length > 0)
    .join("\n")
}
