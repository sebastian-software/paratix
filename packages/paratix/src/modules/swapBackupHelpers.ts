import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

export async function moveSwapToBackup(
  ssh: SshConnection,
  path: string,
  backupPath: string
): Promise<ModuleResult | true> {
  const backupResult = await ssh.exec(
    `mv -T -n ${shellQuote(path)} ${shellQuote(backupPath)}`,
    EXEC_OPTS
  )
  if (backupResult.code !== 0) {
    return failedCommand(`[swap.file: ${path}] swap backup failed`, backupResult)
  }

  const result = await ssh.exec(
    `[ ! -e ${shellQuote(path)} ] && [ -f ${shellQuote(backupPath)} ] && swaplabel ${shellQuote(backupPath)} >/dev/null 2>&1`,
    EXEC_OPTS
  )
  return result.code === 0
    ? true
    : failedCommand(`[swap.file: ${path}] swap backup verification failed`, result)
}
