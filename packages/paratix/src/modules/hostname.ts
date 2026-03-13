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
        if (!ssh) return { status: "failed" }
        const result = await ssh.exec(`hostnamectl set-hostname ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0 ? { status: "changed" } : { status: "failed" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const current = await ssh.output("hostname")
        return current === name ? "ok" : NEEDS_APPLY
      },
      name: `hostname.set: ${name}`,
    }
  },
}
