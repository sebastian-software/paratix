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

  const replacementDetail =
    parameters.mountFailure.stderr.trim() || parameters.mountFailure.stdout.trim()
  const replacementSummary =
    replacementDetail.length > 0 ? `; replacement failure: ${replacementDetail}` : ""
  return failedCommand(
    `[mount.present: ${parameters.path}] mount after umount failed and ` +
      `restoring previous mount failed${replacementSummary}`,
    restoreResult
  )
}
