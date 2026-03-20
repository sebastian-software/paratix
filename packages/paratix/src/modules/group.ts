import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const GETENT_GROUP = "getent group"

/**
 * Modules for managing Linux groups.
 */
export const group = {
  /**
   * Ensure a group does not exist. Removes it via `groupdel` if present.
   *
   * @param name - The group name to remove.
   * @returns A Module that ensures the group is absent.
   */
  absent(name: string): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[group.absent: ${name}] SSH connection is required`)
        const result = await ssh.exec(`groupdel ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[group.absent: ${name}] groupdel failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${GETENT_GROUP} ${shellQuote(name)}`)) ? "needs-apply" : "ok"
      },
      name: `group.absent: ${name}`,
    }
  },

  /**
   * Ensure a group exists. Creates it via `groupadd` if absent.
   *
   * @param name - The group name.
   * @param options - Optional group configuration.
   * @param options.gid - Desired numeric GID.
   * @returns A Module that ensures the group is present.
   */
  present(name: string, options?: { gid?: number }): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[group.present: ${name}] SSH connection is required`)
        const gidArgument = options?.gid == null ? "" : `--gid ${String(options.gid)}`
        const result = await ssh.exec(`groupadd ${gidArgument} ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[group.present: ${name}] groupadd failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return (await ssh.test(`${GETENT_GROUP} ${shellQuote(name)}`)) ? "ok" : NEEDS_APPLY
      },
      name: `group.present: ${name}`,
    }
  },
}
