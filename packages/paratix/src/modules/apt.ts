import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"

async function ensureFlagsDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, { silent: true })
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
