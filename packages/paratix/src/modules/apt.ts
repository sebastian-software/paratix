import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"

const PPA_PREFIX = "ppa:"

async function ensureFlagsDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, { silent: true })
}

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
      if (!ssh) return { status: "failed" }
      const result = await ssh.exec(`add-apt-repository -y ${shellQuote(ppa)}`, {
        ignoreExitCode: true,
        silent: true,
      })
      if (result.code !== 0) return { status: "failed" }
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
 * Modules for managing Debian/Ubuntu packages via `apt-get`.
 *
 * All methods are idempotent: the check phase verifies the current state and
 * apply runs only when a change is necessary.
 */
export const apt = {
  /**
   * Ensure the given packages are removed via `apt-get remove`.
   * @param packages - One or more package names to remove.
   * @returns A Module that removes the packages.
   */
  absent(...packages: string[]): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const quoted = packages.map((p) => shellQuote(p)).join(" ")
        const result = await ssh.exec(`${NONINTERACTIVE} apt-get remove -y ${quoted}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) {
          return { status: "failed" }
        }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        for (const package_ of packages) {
          // eslint-disable-next-line no-await-in-loop
          const installed = await ssh.test(`dpkg -l | grep '^ii' | grep -w ${shellQuote(package_)}`)
          if (installed) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `apt.absent: ${packages.join(", ")}`,
    }
  },

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
        if (!ssh) return { status: "failed" }

        const lines: string[] = []
        for (const [question, value] of Object.entries(selections)) {
          if (question.includes("\n") || value.includes("\n")) {
            return { status: "failed" }
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
        if (result.code !== 0) return { status: "failed" }
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
   * Behaves like {@link apt.upgrade} but performs a full distribution upgrade.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @returns A Module that performs the dist-upgrade.
   */
  distUpgrade(date: string): Module {
    const flagName = `apt-dist-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        await ensureFlagsDirectory(ssh)

        const update = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (update.code !== 0) return { status: "failed" }

        const upgrade = await ssh.exec(`${NONINTERACTIVE} apt-get dist-upgrade -y`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (upgrade.code !== 0) return { status: "failed" }

        await ssh.exec(
          `rm -f ${FLAGS_DIRECTORY}/apt-dist-upgrade-* && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
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
      name: `apt.distUpgrade: ${date}`,
    }
  },

  /**
   * Ensure the given packages are installed via `apt-get install`.
   * @param packages - One or more package names to install.
   * @returns A Module that installs the packages.
   */
  installed(...packages: string[]): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const quoted = packages.map((p) => shellQuote(p)).join(" ")
        const result = await ssh.exec(`${NONINTERACTIVE} apt-get install -y ${quoted}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) {
          return { status: "failed" }
        }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        for (const package_ of packages) {
          // eslint-disable-next-line no-await-in-loop
          const installed = await ssh.test(`dpkg -l | grep '^ii' | grep -w ${shellQuote(package_)}`)
          if (!installed) return NEEDS_APPLY
        }
        return "ok"
      },
      name: `apt: ${packages.join(", ")}`,
    }
  },

  /**
   * Import a GPG key into `/etc/apt/keyrings/` for use with signed repositories.
   * @param name - Key file name (without `.gpg` extension).
   * @param url - URL to download the key from.
   * @returns A Module that imports the GPG key.
   */
  key(name: string, url: string): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const mkdirResult = await ssh.exec("mkdir -p /etc/apt/keyrings", {
          ignoreExitCode: true,
          silent: true,
        })
        if (mkdirResult.code !== 0) return { status: "failed" }

        const result = await ssh.exec(
          `curl -fsSL ${shellQuote(url)} | gpg --dearmor --yes -o /etc/apt/keyrings/${shellQuote(name)}.gpg`,
          { ignoreExitCode: true, silent: true }
        )
        if (result.code !== 0) return { status: "failed" }
        return { status: "changed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`[ -f /etc/apt/keyrings/${shellQuote(name)}.gpg ]`))
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
        if (!ssh) return { status: "failed" }
        await ssh.writeFile(filePath, `${expectedContent}\n`)
        const result = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code !== 0) return { status: "failed" }
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

  /**
   * Run `apt-get update && apt-get upgrade` once per dated flag.
   * The flag file in `FLAGS_DIRECTORY` prevents the upgrade from running again
   * on subsequent runs with the same `date` string.
   *
   * @param date - A date string used as the idempotency key (e.g. `"2024-01-15"`).
   * @returns A Module that performs the upgrade.
   */
  upgrade(date: string): Module {
    const flagName = `apt-upgrade-${date}`
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        await ensureFlagsDirectory(ssh)

        const update = await ssh.exec(`${NONINTERACTIVE} apt-get update`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (update.code !== 0) return { status: "failed" }

        const upgrade = await ssh.exec(`${NONINTERACTIVE} apt-get upgrade -y`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (upgrade.code !== 0) return { status: "failed" }

        // Remove old flags with same prefix and set new one
        await ssh.exec(
          `rm -f ${FLAGS_DIRECTORY}/apt-upgrade-* && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
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
      name: `apt.upgrade: ${date}`,
    }
  },
}
