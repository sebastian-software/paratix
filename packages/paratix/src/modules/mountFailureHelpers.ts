import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

type ExecResult = Awaited<ReturnType<SshConnection["exec"]>>

export async function restorePreviousMountAfterFailure(parameters: {
  mountFailure: ExecResult
  path: string
  restoreCommand: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const restoreResult = await parameters.ssh.exec(parameters.restoreCommand, EXEC_OPTS)
  if (restoreResult.code === 0) {
    return failedCommand(
      `[mount.present: ${parameters.path}] mount after umount failed`,
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
    `[mount.present: ${parameters.path}] mount after umount failed and ` +
      `restoring previous mount failed (restore exit code ${String(restoreResult.code)})` +
      `${restoreSummary}${originalSummary}`,
    parameters.mountFailure
  )
}
