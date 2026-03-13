import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const SYSTEMCTL = "systemctl"

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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} disable ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet ${shellQuote(name)}`)
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} enable ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${SYSTEMCTL} is-enabled --quiet ${shellQuote(name)}`))
          ? "ok"
          : NEEDS_APPLY
      },
      name: `service.enabled: ${name}`,
    }
  },

  /**
   * Reload a systemd service. Intended as a recipe signal -- always applies.
   * @param name - The systemd unit name.
   * @returns A Module that reloads the service.
   */
  reload(name: string): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} reload ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} restart ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} start ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${SYSTEMCTL} is-active --quiet ${shellQuote(name)}`))
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
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`${SYSTEMCTL} stop ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const active = await ssh.test(`${SYSTEMCTL} is-active --quiet ${shellQuote(name)}`)
        return active ? "needs-apply" : "ok"
      },
      name: `service.stopped: ${name}`,
    }
  },
}
