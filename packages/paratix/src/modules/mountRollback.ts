import type { ModuleResult, SshConnection } from "../types.js"
import type { BindSource, LiveMount, LiveMountChange } from "./mountTypes.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { buildBindRemountCommand, buildRestoreMountCommand } from "./mountConvergence.js"
import { knownLiveVfsFlags } from "./mountOptions.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const MOUNT_PRESENT = "mount.present"
const MOUNT_ABSENT = "mount.absent"

export type LiveMountRollbackParameters = {
  /** The resolved bind source, or `null` for a non-bind desired mount. */
  bindSource: BindSource | null
  change: LiveMountChange
  path: string
  previousLive: LiveMount | null
  src: string
}

export function appendLiveRollbackFailure(
  fstabFailure: ModuleResult,
  rollbackFailure: ModuleResult | null
): ModuleResult {
  if (rollbackFailure == null) return fstabFailure
  const fstabMessage = fstabFailure.error?.message ?? "failed to update /etc/fstab"
  const rollbackMessage =
    rollbackFailure.error?.message ?? "failed to roll back live mount after fstab update failure"
  return failed(`${fstabMessage}\n${rollbackMessage}`)
}

/**
 * Roll a bind mount back after the fstab write failed, for a change that
 * kept or replaced an existing mount: a remount-only change is remounted back
 * to the previous VFS flags without an unmount, and an identity change keeps
 * the new mount (an unmount would leave the path empty, and the previous
 * mount cannot be recreated from its SOURCE text) and only adds a note. A
 * fresh bind mount is not handled here; it is unmounted like any other mount.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - Rollback inputs.
 * @returns A rollback failure or note, or `null` on success.
 */
async function rollbackBindChangeAfterFstabFailure(
  ssh: SshConnection,
  parameters: LiveMountRollbackParameters
): Promise<ModuleResult | null> {
  const { change, path, previousLive, src } = parameters
  if (change === "replace") {
    return failed(
      `[${MOUNT_PRESENT}: ${path}] note: the new bind mount was kept in place and the ` +
        `previous mount was not restored; re-run to persist /etc/fstab`
    )
  }
  if (previousLive == null) return null

  const remountResult = await ssh.exec(
    buildBindRemountCommand({ flags: knownLiveVfsFlags(previousLive.vfsOptions), path, src }),
    EXEC_OPTS
  )
  return remountResult.code === 0
    ? null
    : failedCommand(
        `[${MOUNT_PRESENT}: ${path}] failed to roll back live bind remount after fstab update failure`,
        remountResult
      )
}

export async function rollbackLiveMountAfterFstabFailure(
  ssh: SshConnection,
  parameters: LiveMountRollbackParameters
): Promise<ModuleResult | null> {
  const { bindSource, change, path, previousLive } = parameters
  if (bindSource != null && (change === "remount" || change === "replace")) {
    return rollbackBindChangeAfterFstabFailure(ssh, parameters)
  }

  // Decide on the restore before unmounting: a previous mount whose FSROOT
  // is not `/` cannot be recreated from its SOURCE text, so the new mount is
  // kept in place instead of leaving the path empty.
  const restoreCommand = previousLive == null ? null : buildRestoreMountCommand(previousLive, path)
  if (previousLive != null && restoreCommand == null) {
    return failed(
      `[${MOUNT_PRESENT}: ${path}] previous mount could not be restored automatically ` +
        `after fstab update failure (previous FSROOT ${previousLive.fsroot} is not /); ` +
        `the new mount was kept in place`
    )
  }

  const unmountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (unmountResult.code !== 0) {
    return failedCommand(
      `[${MOUNT_PRESENT}: ${path}] failed to roll back live mount after fstab update failure`,
      unmountResult
    )
  }

  if (restoreCommand == null) return null
  const restoreResult = await ssh.exec(restoreCommand, EXEC_OPTS)
  return restoreResult.code === 0
    ? null
    : failedCommand(
        `[${MOUNT_PRESENT}: ${path}] failed to restore previous live mount after fstab update failure`,
        restoreResult
      )
}

export async function restoreLiveMountAfterFstabFailure(
  ssh: SshConnection,
  path: string,
  previousLive: LiveMount
): Promise<ModuleResult | null> {
  const restoreCommand = buildRestoreMountCommand(previousLive, path)
  if (restoreCommand == null) {
    return failed(
      `[${MOUNT_ABSENT}: ${path}] live mount was not restored after fstab update failure ` +
        `(previous FSROOT ${previousLive.fsroot} is not /)`
    )
  }
  const restoreResult = await ssh.exec(restoreCommand, EXEC_OPTS)
  return restoreResult.code === 0
    ? null
    : failedCommand(
        `[${MOUNT_ABSENT}: ${path}] failed to restore live mount after fstab update failure`,
        restoreResult
      )
}
