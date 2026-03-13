import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

/**
 * Options for the reboot module.
 */
export type RebootOptions = {
  /**
   * Optional async function to resolve the new host address after a reboot.
   * Useful when the server's IP address may change (e.g. DHCP or cloud environments).
   */
  resolveHost?: () => Promise<string>
}

/**
 * Modules for managing system-level operations.
 */
export const system = {
  /**
   * Reboot the remote system via `shutdown -r now`.
   * Always applies because a reboot is an imperative action.
   *
   * When `resolveHost` is provided, the resolved address is emitted as
   * `system.host` meta so the runner can update the SSH connection.
   * The `system.reboot` meta signal is always set to `"true"`.
   *
   * @param options - Optional settings including a host resolver.
   * @returns A Module that reboots the system.
   */
  reboot(options: RebootOptions = {}): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        try {
          await ssh.exec("shutdown -r now", { ignoreExitCode: true, silent: true })
        } catch {
          // Connection will drop during reboot — this is expected
        }

        const meta: Record<string, string> = { "system.reboot": "true" }

        if (options.resolveHost != null) {
          try {
            const newHost = await options.resolveHost()
            meta["system.host"] = newHost
          } catch {
            // resolveHost failed — reconnect will use current host
          }
        }

        return { meta, status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: "system.reboot",
    }
  },

  /**
   * Read the system uptime in seconds from `/proc/uptime`.
   * Always applies because it is informational and should always report.
   *
   * The uptime value is emitted as `system.uptime` meta.
   *
   * @returns A Module that reads the system uptime.
   */
  uptime(): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return { status: "failed" }

        const seconds = await ssh.output("awk '{print int($1)}' /proc/uptime")

        return { meta: { "system.uptime": seconds }, status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await
      async check(): Promise<"needs-apply" | "ok"> {
        return NEEDS_APPLY
      },
      name: "system.uptime",
    }
  },
}
