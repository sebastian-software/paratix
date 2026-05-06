import type { ModuleResult, SshConnection } from "../types.js"
import type { LiveMount } from "./mountTypes.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { restorePreviousMountAfterFailure } from "./mountFailureHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

type MountConvergenceParameters = {
  fstype: string
  live: LiveMount
  opts: string
  path: string
  src: string
}

function buildMountCommand(parameters: {
  fstype: string
  opts: string
  path: string
  src: string
}): string {
  return `mount -t ${shellQuote(parameters.fstype)} -o ${shellQuote(parameters.opts)} -- ${shellQuote(parameters.src)} ${shellQuote(parameters.path)}`
}

function buildRestoreMountCommand(live: LiveMount, path: string): string {
  return buildMountCommand({
    fstype: live.fstype,
    opts: live.options,
    path,
    src: live.source,
  })
}

/**
 * Converge a drifted live mount via remount, or umount + mount when needed.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - Desired mount values plus the live snapshot.
 * @returns A failure result when convergence failed, or `null` on success.
 */
export async function applyMountConvergence(
  ssh: SshConnection,
  parameters: MountConvergenceParameters
): Promise<ModuleResult | null> {
  const { fstype, live, opts, path, src } = parameters
  if (live.source === src && live.fstype === fstype) {
    const remountResult = await ssh.exec(
      `mount -o remount,${shellQuote(opts)} -- ${shellQuote(src)} ${shellQuote(path)}`,
      EXEC_OPTS
    )
    return remountResult.code === 0
      ? null
      : failedCommand(`[mount.present: ${path}] mount -o remount failed`, remountResult)
  }

  const umountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (umountResult.code !== 0) {
    return failedCommand(`[mount.present: ${path}] umount before remount failed`, umountResult)
  }

  const mountResult = await ssh.exec(buildMountCommand({ fstype, opts, path, src }), EXEC_OPTS)
  return mountResult.code === 0
    ? null
    : restorePreviousMountAfterFailure({
        mountFailure: mountResult,
        path,
        restoreCommand: buildRestoreMountCommand(live, path),
        ssh,
      })
}
