import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const GETENT_GROUP = "getent group"
const GETENT_NOT_FOUND_EXIT_CODE = 2
const GROUP_ENTRY_FIELD_COUNT = 4

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
  const concurrentGroup = await readGroupGid(ssh, name)
  if (concurrentGroup.kind === "missing")
    return failedCommand(`[group.present: ${name}] groupadd failed`, result)
  if (concurrentGroup.kind === "error") return concurrentGroup.failure
  return convergeExistingGroup({ existingGid: concurrentGroup.gid, gid, name, ssh })
}

type GroupLookupResult =
  { failure: ModuleResult; kind: "error" } | { gid: string; kind: "found" } | { kind: "missing" }

function failCheckWithLookupError(
  name: string,
  lookup: Extract<GroupLookupResult, { kind: "error" }>
): never {
  throw lookup.failure.error ?? new Error(`[group: ${name}] group lookup failed`)
}

function parseGroupEntry(name: string, stdout: string): GroupLookupResult {
  const entry = stdout.trim()
  const lines = entry.length === 0 ? [] : entry.split(/\r?\n/v)
  if (lines.length !== 1) {
    return {
      failure: failed(
        `[group: ${name}] getent group returned ${String(lines.length)} entries (expected 1)`
      ),
      kind: "error",
    }
  }
  const fields = lines[0].split(":")
  const gid = fields[2] ?? ""
  const numericGid = Number(gid)
  if (
    fields.length !== GROUP_ENTRY_FIELD_COUNT ||
    !/^(?:0|[1-9]\d*)$/v.test(gid) ||
    !Number.isInteger(numericGid) ||
    numericGid < 0 ||
    numericGid >= GID_MAX_EXCLUSIVE
  ) {
    return {
      failure: failed(`[group: ${name}] getent group returned a malformed group entry`),
      kind: "error",
    }
  }
  return { gid, kind: "found" }
}

/**
 * Read the GID of an existing group via `getent group <name>`.
 *
 * `getent group` uses exit code 2 for an absent key. Other non-zero exit
 * codes are lookup/toolchain errors and must not be treated as converged.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param name - Group name to look up.
 * @returns A discriminated group lookup result.
 */
async function readGroupGid(ssh: SshConnection, name: string): Promise<GroupLookupResult> {
  const result = await ssh.exec(`${GETENT_GROUP} ${shellQuote(name)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === GETENT_NOT_FOUND_EXIT_CODE) return { kind: "missing" }
  if (result.code !== 0) {
    return {
      failure: failedCommand(`[group: ${name}] getent group failed`, result),
      kind: "error",
    }
  }
  return parseGroupEntry(name, result.stdout)
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
        const existingGroup = await readGroupGid(ssh, name)
        if (existingGroup.kind === "missing") return { status: "ok" }
        if (existingGroup.kind === "error") return existingGroup.failure
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
        const existingGroup = await readGroupGid(ssh, name)
        if (existingGroup.kind === "error") failCheckWithLookupError(name, existingGroup)
        return existingGroup.kind === "found" ? NEEDS_APPLY : "ok"
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

        const existingGroup = await readGroupGid(ssh, name)
        if (existingGroup.kind === "error") return existingGroup.failure
        if (existingGroup.kind === "missing") {
          // Group does not exist yet — create it with the desired GID.
          const arguments_ = options?.gid == null ? ["--"] : ["--gid", String(options.gid), "--"]
          const result = await ssh.exec(`groupadd ${arguments_.join(" ")} ${shellQuote(name)}`, {
            ignoreExitCode: true,
            silent: true,
          })
          if (result.code === 0) return { status: "changed" }
          return handleFailedGroupadd({ gid: options?.gid, name, result, ssh })
        }

        return convergeExistingGroup({
          existingGid: existingGroup.gid,
          gid: options?.gid,
          name,
          ssh,
        })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const existingGroup = await readGroupGid(ssh, name)
        if (existingGroup.kind === "error") failCheckWithLookupError(name, existingGroup)
        if (existingGroup.kind === "missing") return NEEDS_APPLY
        // R-0000048: when a desired GID is set, treat a mismatched GID as
        // drift so apply can heal it via groupmod.
        if (options?.gid != null && existingGroup.gid !== String(options.gid)) return NEEDS_APPLY
        return "ok"
      },
      name: `group.present: ${name}`,
    }
  },
}
