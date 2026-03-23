import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  applyAptKey,
  normalizeOpenPgpFingerprint,
  validateAptKeyUrl,
  verifyAptKeyFingerprint,
} from "./aptKeyHelpers.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const APT_REPOSITORY_MODE = "0644"

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

        const selectionsText = lines.join("\n")
        const result = await ssh.exec(
          `echo ${shellQuote(selectionsText)} | debconf-set-selections`,
          { ignoreExitCode: true, silent: true }
        )
        if (result.code !== 0)
          return failedCommand(`[apt.debconf] failed to set selections for ${packageName}`, result)
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const result = await ssh.exec(`debconf-show ${shellQuote(packageName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) return NEEDS_APPLY

        const currentValues = parseDebconfOutput(result.stdout)
        for (const [question, value] of Object.entries(selections)) {
          if (currentValues[question] !== value) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `apt.debconf: ${packageName}`,
    }
  },

  /**
   * Run `apt-get update && apt-get dist-upgrade` once per dated flag.
   * Performs a full distribution upgrade with dependency resolution.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @returns A Module that performs the dist-upgrade.
   */
  distUpgrade(date: string): Module {
    const flagName = `apt-dist-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[apt.distUpgrade] SSH connection is required for ${date}`)
        const update = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (update.code !== 0)
          return failedCommand("[apt.distUpgrade] apt-get update failed", update)

        const configure = await ssh.exec(`${NONINTERACTIVE} dpkg --configure -a`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (configure.code !== 0)
          return failedCommand("[apt.distUpgrade] dpkg --configure -a failed", configure)

        const upgrade = await ssh.exec(`${NONINTERACTIVE} apt-get dist-upgrade -y`, {
          ignoreExitCode: true,
          silent: true,
        })
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
    const signedBy = options?.signedBy
    let expectedContent = source

    if (signedBy !== false) {
      const keyName = typeof signedBy === "string" ? signedBy : name
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
        return content.trim() === expectedContent.trim() ? "ok" : NEEDS_APPLY
      },
      name: `apt.repository: ${name}`,
    }
  },
}
