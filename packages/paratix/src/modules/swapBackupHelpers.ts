import type { ModuleResult, SshConnection } from "../types.js"
import type { NormalizedSwapFileOptions } from "./swapFileHelpers.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { disableSwap, enableSwap } from "./swapAbsentRollbackHelpers.js"

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

export async function restoreSwapBackup(
  ssh: SshConnection,
  path: string,
  backupPath: string
): Promise<ModuleResult | true> {
  // R-0000246: the restore path intentionally allows overwriting the
  // current target. We are recovering from a publish/replace failure where
  // a partial new swap file may have been written at `path`; the goal is
  // to put the operator-managed backup back in place and restart swap.
  // This is the inverse of the backup creation (which uses `mv -T -n` to
  // refuse overwriting a stale backup).
  const restoreResult = await ssh.exec(
    `mv -T -- ${shellQuote(backupPath)} ${shellQuote(path)}`,
    EXEC_OPTS
  )
  return restoreResult.code === 0
    ? true
    : failedCommand(`[swap.file: ${path}] swap restore failed`, restoreResult)
}

async function removeSwapBackup(ssh: SshConnection, backupPath: string): Promise<void> {
  await ssh.exec(`rm -f ${shellQuote(backupPath)}`, EXEC_OPTS)
}

export async function rollbackManagedSwapBackup(
  ssh: SshConnection,
  parameters: {
    backupPath: string
    failureResult: ModuleResult
    options: NormalizedSwapFileOptions
  }
): Promise<ModuleResult> {
  const { backupPath, failureResult, options } = parameters
  // Best-effort rollback: stop the (possibly active) swap on the new file,
  // restore the backup, and try to re-enable swap on it. A failure inside
  // the rollback is surfaced because operators must know if the host is
  // left in a divergent state.
  const disableResult = await disableSwap(ssh, options.path)
  if (typeof disableResult !== "boolean") return disableResult
  const restoreResult = await restoreSwapBackup(ssh, options.path, backupPath)
  if (restoreResult !== true) return restoreResult
  const reEnable = await enableSwap(ssh, options.path)
  if (typeof reEnable !== "boolean") return reEnable
  return failureResult
}

export async function finalizeManagedSwapBackup(
  ssh: SshConnection,
  backupPath: string
): Promise<void> {
  await removeSwapBackup(ssh, backupPath)
}
