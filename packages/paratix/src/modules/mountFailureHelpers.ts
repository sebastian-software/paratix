import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

type ExecResult = Awaited<ReturnType<SshConnection["exec"]>>

/**
 * Report a failed replacement mount after the previous mount was already
 * unmounted, restoring the previous mount first when that is possible.
 *
 * @param parameters - Failure inputs.
 * @param parameters.moduleName - Module label for the message prefix (e.g. `"mount.present"`).
 * @param parameters.mountFailure - The failed replacement mount result.
 * @param parameters.path - The mountpoint path.
 * @param parameters.restoreCommand - The command that recreates the previous
 *   mount, or `null` when it cannot be recreated automatically (e.g. a
 *   previous mount whose FSROOT is not `/`); the failure then states that the
 *   previous mount was not restored.
 * @param parameters.ssh - Active SSH connection.
 * @returns The failed ModuleResult.
 */
export async function restorePreviousMountAfterFailure(parameters: {
  moduleName: string
  mountFailure: ExecResult
  path: string
  restoreCommand: null | string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const prefix = `[${parameters.moduleName}: ${parameters.path}]`
  if (parameters.restoreCommand == null) {
    return failedCommand(
      `${prefix} mount after umount failed; previous mount was not restored ` +
        `(previous mount could not be restored automatically)`,
      parameters.mountFailure
    )
  }

  const restoreResult = await parameters.ssh.exec(parameters.restoreCommand, EXEC_OPTS)
  if (restoreResult.code === 0) {
    return failedCommand(
      `${prefix} mount failed, previous mount was restored`,
      parameters.mountFailure
    )
  }

  const restoreDetail = restoreResult.stderr.trim() || restoreResult.stdout.trim()
  const restoreSummary = restoreDetail.length > 0 ? `; restore failure: ${restoreDetail}` : ""
  const originalDetail =
    parameters.mountFailure.stderr.trim() || parameters.mountFailure.stdout.trim()
  const originalSummary =
    originalDetail.length > 0 ? `; original mount failure: ${originalDetail}` : ""
  return failedCommand(
    `${prefix} mount after umount failed and ` +
      `restoring previous mount failed (restore exit code ${String(restoreResult.code)})` +
      `${restoreSummary}${originalSummary}`,
    parameters.mountFailure
  )
}
