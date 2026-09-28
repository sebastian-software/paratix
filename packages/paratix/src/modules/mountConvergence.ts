import type { ModuleResult, SshConnection } from "../types.js"
import type { BindSource, LiveMount } from "./mountTypes.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { liveMountIdentityMatches } from "./mountBind.js"
import { restorePreviousMountAfterFailure } from "./mountFailureHelpers.js"
import { renderBindRemountVfsFlags } from "./mountOptions.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const MOUNT_PRESENT = "mount.present"

type MountConvergenceParameters = {
  /** The resolved bind source, or `null` for a non-bind mount. */
  bindSource: BindSource | null
  fstype: string
  live: LiveMount
  opts: string
  path: string
  src: string
}

/**
 * Result of a convergence attempt: which kind of live change was made
 * (`remount` keeps the mount identity, `replace` unmounted and mounted anew)
 * and the failure, if any.
 */
export type MountConvergenceOutcome = {
  change: "remount" | "replace"
  failure: ModuleResult | null
}

export function buildMountCommand(parameters: {
  fstype: string
  opts: string
  path: string
  src: string
}): string {
  return `mount -t ${shellQuote(parameters.fstype)} -o ${shellQuote(parameters.opts)} -- ${shellQuote(parameters.src)} ${shellQuote(parameters.path)}`
}

/**
 * Build the command that recreates a previous live mount from its SOURCE,
 * fstype and options. Only a mount of a whole filesystem (FSROOT `/`) can be
 * recreated that way; a bind of a subdirectory or a subvolume mount would be
 * recreated as the wrong tree, so no command is returned for them.
 *
 * @param live - The previous live mount.
 * @param path - The mountpoint path.
 * @returns The restore command, or `null` when the previous mount cannot be
 *   restored automatically.
 */
export function buildRestoreMountCommand(live: LiveMount, path: string): null | string {
  if (live.fsroot !== "/") return null
  return buildMountCommand({
    fstype: live.fstype,
    opts: live.options,
    path,
    src: live.source,
  })
}

/**
 * Build the bind remount command `mount -o remount,bind,<flags> -- <src> <path>`.
 * The flags are known VFS flag tokens only (never free text), so they are not
 * quoted. Passing both `src` and `path` stops mount(8) from merging in an
 * older fstab line for the mountpoint.
 *
 * @param parameters - Remount inputs.
 * @param parameters.flags - Comma-separated VFS flag tokens (may be empty).
 * @param parameters.path - The mountpoint path.
 * @param parameters.src - The configured bind source.
 * @returns The remount command string.
 */
export function buildBindRemountCommand(parameters: {
  flags: string
  path: string
  src: string
}): string {
  const options = parameters.flags.length > 0 ? `remount,bind,${parameters.flags}` : "remount,bind"
  return `mount -o ${options} -- ${shellQuote(parameters.src)} ${shellQuote(parameters.path)}`
}

function buildRemountCommand(parameters: MountConvergenceParameters): string {
  const { bindSource, live, opts, path, src } = parameters
  if (bindSource != null) {
    // rbind is verified like bind on the top mount only, so the remount
    // always uses `bind`. It carries the complete resulting VFS flag state
    // (live flags overridden by the explicitly named ones), so a flag that
    // `opts` does not name is never cleared by the legacy mount API.
    return buildBindRemountCommand({
      flags: renderBindRemountVfsFlags(live.vfsOptions, opts),
      path,
      src,
    })
  }
  return `mount -o remount,${shellQuote(opts)} -- ${shellQuote(src)} ${shellQuote(path)}`
}

/**
 * Converge a drifted live mount via remount, or umount + mount when needed.
 * The remount shortcut applies only when the live identity matches (see
 * `liveMountIdentityMatches`): a remount cannot change the source tree, so
 * FSROOT or `MAJ:MIN` drift always takes the umount + mount path.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - Desired mount values plus the live snapshot.
 * @returns The kind of change and the failure, if convergence failed.
 */
export async function applyMountConvergence(
  ssh: SshConnection,
  parameters: MountConvergenceParameters
): Promise<MountConvergenceOutcome> {
  const { bindSource, fstype, live, opts, path, src } = parameters
  if (liveMountIdentityMatches(live, { bindSource, fstype, src })) {
    const remountResult = await ssh.exec(buildRemountCommand(parameters), EXEC_OPTS)
    return {
      change: "remount",
      failure:
        remountResult.code === 0
          ? null
          : failedCommand(`[${MOUNT_PRESENT}: ${path}] mount -o remount failed`, remountResult),
    }
  }

  const umountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (umountResult.code !== 0) {
    return {
      change: "replace",
      failure: failedCommand(
        `[${MOUNT_PRESENT}: ${path}] umount before remount failed`,
        umountResult
      ),
    }
  }

  const mountResult = await ssh.exec(buildMountCommand({ fstype, opts, path, src }), EXEC_OPTS)
  return {
    change: "replace",
    failure:
      mountResult.code === 0
        ? null
        : await restorePreviousMountAfterFailure({
            moduleName: MOUNT_PRESENT,
            mountFailure: mountResult,
            path,
            restoreCommand: buildRestoreMountCommand(live, path),
            ssh,
          }),
  }
}
