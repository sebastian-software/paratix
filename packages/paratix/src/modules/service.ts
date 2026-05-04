import { environmentToMetaEntries } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const SYSTEMCTL = "systemctl"
const SYSTEMD_UNIT_NAME_PATTERN = /^[\w.@:\-]+$/v

function validateUnitName(name: string): string {
  if (!name || name.startsWith("-") || !SYSTEMD_UNIT_NAME_PATTERN.test(name)) {
    throw new Error(`Invalid systemd unit name: ${name}`)
  }
  return name
}

/**
 * Modules for managing systemd services.
 *
 * State-checking methods (`running`, `stopped`, `enabled`, `disabled`) are
 * idempotent. Signal-style methods (`restart`, `reload`) always apply.
 */
export const service = {
  /**
   * Ensure a systemd service is disabled and will not start on boot.
   * @param name - The systemd unit name.
   * @returns A Module that ensures the service is disabled.
   */
  disabled(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[service.disabled: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} disable -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[service.disabled: ${name}] systemctl disable failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(unitName)}`)
        return enabled ? "needs-apply" : "ok"
      },
      name: `service.disabled: ${name}`,
    }
  },

  /**
   * Ensure a systemd service is enabled to start on boot.
   * @param name - The systemd unit name.
   * @returns A Module that ensures the service is enabled.
   */
  enabled(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[service.enabled: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} enable -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[service.enabled: ${name}] systemctl enable failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(unitName)}`))
          ? "ok"
          : NEEDS_APPLY
      },
      name: `service.enabled: ${name}`,
    }
  },

  /**
   * Collect status information for all systemd services and expose them as
   * meta entries. Does not change anything on the server.
   * @returns A Module that gathers service facts into `service.<name>` meta keys.
   */
  facts(): Module {
    return {
      _dryRunMetaProducer: true,
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[service.facts] SSH connection is required")
        const result = await ssh.exec(
          `${SYSTEMCTL} list-units --type=service --all --no-pager --no-legend`,
          { ignoreExitCode: true, silent: true }
        )
        if (result.code !== 0) {
          return failedCommand("[service.facts] systemctl list-units failed", result)
        }
        const facts: Record<string, string> = {}
        for (const line of result.stdout.split("\n")) {
          // Strip leading Unicode bullet (● or ○) that systemd prepends to failed units
          const trimmed = line.trim().replace(/^[\u25CF\u25CB]\s*/v, "")
          if (!trimmed) continue
          const parts = trimmed.split(/\s+/v)
          const unit = parts[0]
          const active = parts[2]
          if (!unit || !active) continue
          const name = unit.replace(/\.service$/v, "")
          facts[`service.${name}`] = active
        }
        return { meta: environmentToMetaEntries(facts), status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: "service.facts",
    }
  },

  /**
   * Reload a systemd service. Intended as a recipe signal -- always applies.
   * @param name - The systemd unit name.
   * @returns A Module that reloads the service.
   */
  reload(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[service.reload: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} reload -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[service.reload: ${name}] systemctl reload failed`, result)
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        // Signal: always needs apply
        return NEEDS_APPLY
      },
      name: `service.reload: ${name}`,
    }
  },

  /**
   * Restart a systemd service. Intended as a recipe signal -- always applies.
   * @param name - The systemd unit name.
   * @returns A Module that restarts the service.
   */
  restart(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[service.restart: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} restart -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[service.restart: ${name}] systemctl restart failed`, result)
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        // Signal: always needs apply
        return NEEDS_APPLY
      },
      name: `service.restart: ${name}`,
    }
  },

  /**
   * Ensure a systemd service is running. Starts the service if inactive.
   * @param name - The systemd unit name (e.g. `"nginx"`).
   * @returns A Module that ensures the service is running.
   */
  running(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[service.running: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} start -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[service.running: ${name}] systemctl start failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(unitName)}`))
          ? "ok"
          : NEEDS_APPLY
      },
      name: `service.running: ${name}`,
    }
  },

  /**
   * Ensure a systemd service is stopped. Stops the service if active.
   * @param name - The systemd unit name.
   * @returns A Module that ensures the service is stopped.
   */
  stopped(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[service.stopped: ${name}] SSH connection is required`)
        const result = await ssh.exec(`${SYSTEMCTL} stop -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[service.stopped: ${name}] systemctl stop failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const active = await ssh.test(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(unitName)}`)
        return active ? "needs-apply" : "ok"
      },
      name: `service.stopped: ${name}`,
    }
  },
}
