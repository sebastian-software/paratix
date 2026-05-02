import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const GETENT_GROUP = "getent group"

/**
 * Read the GID of an existing group via `getent group <name>`. Returns the
 * GID as the string it appears in `/etc/group` (third colon-separated
 * field), or `null` when the group does not exist.
 *
 * `getent group` exits non-zero when the group is absent, which we surface
 * by returning `null` instead of throwing — both `check` and `apply` need
 * to disambiguate "missing" from "drifted".
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param name - Group name to look up.
 * @returns The GID string, or `null` when the group does not exist.
 */
async function readGroupGid(ssh: SshConnection, name: string): Promise<null | string> {
  const result = await ssh.exec(`${GETENT_GROUP} ${shellQuote(name)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return null
  // /etc/group format: name:passwd:gid:userlist
  const fields = result.stdout.trim().split(":")
  return fields[2] ?? null
}

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
   * Ensure a group exists. Creates it via `groupadd` if absent. When the
   * group already exists but its GID differs from `options.gid`, the GID
   * is healed via `groupmod -g <gid>` so the drift becomes recoverable.
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

        const existingGid = await readGroupGid(ssh, name)
        if (existingGid == null) {
          // Group does not exist yet — create it with the desired GID.
          const gidArgument = options?.gid == null ? "" : `--gid ${String(options.gid)}`
          const result = await ssh.exec(`groupadd ${gidArgument} ${shellQuote(name)}`, {
            ignoreExitCode: true,
            silent: true,
          })
          return result.code === 0
            ? { status: "changed" }
            : failedCommand(`[group.present: ${name}] groupadd failed`, result)
        }

        if (options?.gid == null || existingGid === String(options.gid)) {
          // Group exists with the desired GID (or no GID was requested) —
          // nothing to do.
          return { status: "ok" }
        }

        // R-0000048: group exists but GID drifted — heal it via groupmod
        // so the drift becomes recoverable instead of blocking on
        // `groupadd: group already exists`.
        const groupmodResult = await ssh.exec(
          `groupmod -g ${String(options.gid)} ${shellQuote(name)}`,
          { ignoreExitCode: true, silent: true }
        )
        return groupmodResult.code === 0
          ? { status: "changed" }
          : failedCommand(`[group.present: ${name}] groupmod failed`, groupmodResult)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const existingGid = await readGroupGid(ssh, name)
        if (existingGid == null) return NEEDS_APPLY
        // R-0000048: when a desired GID is set, treat a mismatched GID as
        // drift so apply can heal it via groupmod.
        if (options?.gid != null && existingGid !== String(options.gid)) return NEEDS_APPLY
        return "ok"
      },
      name: `group.present: ${name}`,
    }
  },
}
