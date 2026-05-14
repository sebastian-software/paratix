import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const GETENT_GROUP = "getent group"

// R-0000238: validate group names at module-construction time so empty,
// flag-shaped, or shell-control-shaped names cannot reach groupadd,
// groupmod, or groupdel. This mirrors the user module's POSIX whitelist.
const GROUP_NAME_PATTERN = /^[a-z_][a-z0-9_\-]*\$?$/v
const GID_BIT_WIDTH = 32
const GID_MAX_EXCLUSIVE = 2 ** GID_BIT_WIDTH

function assertValidGroupName(name: string): void {
  if (!GROUP_NAME_PATTERN.test(name)) {
    throw new Error(`group name ${JSON.stringify(name)} is invalid`)
  }
}

function assertValidGid(gid: number): void {
  if (!Number.isInteger(gid) || gid < 0 || gid >= GID_MAX_EXCLUSIVE) {
    throw new Error(`gid ${JSON.stringify(gid)} is invalid`)
  }
}

async function healGidDrift(ssh: SshConnection, name: string, gid: number): Promise<ModuleResult> {
  const groupmodResult = await ssh.exec(`groupmod -g ${String(gid)} -- ${shellQuote(name)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return groupmodResult.code === 0
    ? { status: "changed" }
    : failedCommand(`[group.present: ${name}] groupmod failed`, groupmodResult)
}

async function convergeExistingGroup(input: {
  existingGid: string
  gid: number | undefined
  name: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { existingGid, gid, name, ssh } = input
  if (gid == null || existingGid === String(gid)) return { status: "ok" }
  // R-0000048: group exists but GID drifted — heal it via groupmod
  // so the drift becomes recoverable instead of blocking on
  // `groupadd: group already exists`.
  return healGidDrift(ssh, name, gid)
}

async function handleFailedGroupadd(input: {
  gid: number | undefined
  name: string
  result: Awaited<ReturnType<SshConnection["exec"]>>
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { gid, name, result, ssh } = input
  const concurrentGid = await readGroupGid(ssh, name)
  if (concurrentGid == null)
    return failedCommand(`[group.present: ${name}] groupadd failed`, result)
  return convergeExistingGroup({ existingGid: concurrentGid, gid, name, ssh })
}

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
    assertValidGroupName(name)
    // R-0000080: groupdel returns exit code 6 ("specified group doesn't
    // exist") when the group has already been removed. Treat this case as
    // idempotent success — both by probing `getent group` first to mirror
    // cron.absent's early-return pattern (and user.absent after R-0000077),
    // and by mapping exit code 6 to status ok as a defensive fallback when
    // the group is removed between the probe and the groupdel call.
    const GROUPDEL_NOT_FOUND_EXIT_CODE = 6
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[group.absent: ${name}] SSH connection is required`)
        if ((await readGroupGid(ssh, name)) == null) return { status: "ok" }
        const result = await ssh.exec(`groupdel -- ${shellQuote(name)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (result.code === 0) return { status: "changed" }
        if (result.code === GROUPDEL_NOT_FOUND_EXIT_CODE) return { status: "ok" }
        return failedCommand(`[group.absent: ${name}] groupdel failed`, result)
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
    assertValidGroupName(name)
    if (options?.gid != null) assertValidGid(options.gid)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[group.present: ${name}] SSH connection is required`)

        const existingGid = await readGroupGid(ssh, name)
        if (existingGid == null) {
          // Group does not exist yet — create it with the desired GID.
          const arguments_ = options?.gid == null ? ["--"] : ["--gid", String(options.gid), "--"]
          const result = await ssh.exec(`groupadd ${arguments_.join(" ")} ${shellQuote(name)}`, {
            ignoreExitCode: true,
            silent: true,
          })
          if (result.code === 0) return { status: "changed" }
          return handleFailedGroupadd({ gid: options?.gid, name, result, ssh })
        }

        return convergeExistingGroup({ existingGid, gid: options?.gid, name, ssh })
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
