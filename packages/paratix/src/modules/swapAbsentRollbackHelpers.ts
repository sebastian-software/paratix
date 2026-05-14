import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { isSwapActive } from "./swapFileHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

export async function enableSwap(
  ssh: SshConnection,
  path: string
): Promise<boolean | ModuleResult> {
  if (await isSwapActive(ssh, path)) return false
  const result = await ssh.exec(`swapon ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapon failed`, result)
}

async function reactivateSwap(ssh: SshConnection, path: string): Promise<ModuleResult | true> {
  const result = await ssh.exec(`swapon ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapon failed`, result)
}

export async function handleAbsentSwapRemovalFailure(
  ssh: SshConnection,
  parameters: { disabledSwap: boolean; path: string; removeFailure: ModuleResult }
): Promise<ModuleResult> {
  const { disabledSwap, path, removeFailure } = parameters
  if (!disabledSwap) return removeFailure

  const reenableResult = await reactivateSwap(ssh, path)
  if (reenableResult === true) return removeFailure

  return failed(
    `${removeFailure.error?.message ?? "swap file removal failed"}; rollback swapon failed: ${
      reenableResult.error?.message ?? "unknown error"
    }`
  )
}
