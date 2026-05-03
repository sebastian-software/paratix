import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

/**
 * Modules for managing the system hostname.
 */
export const hostname = {
  /**
   * Set the system hostname via `hostnamectl set-hostname`.
   * Checks the current hostname first and skips the command when it already matches.
   *
   * @param name - The desired hostname.
   * @returns A Module that sets the hostname.
   */
  set(name: string): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[hostname.set: ${name}] SSH connection is required`)
        const result = await ssh.exec(`hostnamectl set-hostname ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[hostname.set: ${name}] hostnamectl set-hostname failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        // Use `hostnamectl --static` to read the persisted hostname from /etc/hostname
        // rather than the kernel-resolved hostname returned by `hostname`, which can
        // differ (e.g. FQDN vs. short name) depending on /etc/hosts and nsswitch.conf
        // and would otherwise cause check to report drift even after a successful apply.
        const current = await ssh.output("hostnamectl --static")
        return current === name ? "ok" : NEEDS_APPLY
      },
      name: `hostname.set: ${name}`,
    }
  },
}
