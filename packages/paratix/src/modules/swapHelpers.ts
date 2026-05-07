import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  classifySwapFilePath,
  cleanupSwapTemporaryFile,
  createInitializedSwapTemporaryFile,
  ensureSwapFilePresent,
  ensureSwapFstabState,
  hasNoSwapFstabEntry,
  hasSwapFstabEntry,
  isSwapActive,
  needsSwapRecreation,
  type NormalizedSwapFileOptions,
  publishInitializedSwapTemporaryFile,
  swapFileModeMatches,
} from "./swapFileHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

async function ensureSafeSwapRemoval(
  ssh: SshConnection,
  path: string
): Promise<"missing" | "ok" | ModuleResult> {
  const classification = await classifySwapFilePath(ssh, path)
  if (classification.state === "missing") return "missing"
  if (classification.state === "managed-swap-file") return "ok"
  return failed(`[swap.file: ${path}] refusing to remove unsafe path: ${classification.reason}`)
}

async function disableSwap(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (!(await isSwapActive(ssh, path))) return false
  const result = await ssh.exec(`swapoff ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapoff failed`, result)
}

async function removeSwapFile(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (!(await ssh.exists(path))) return false
  const result = await ssh.exec(`rm -f ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] rm failed`, result)
}

async function createMissingSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"changed" | ModuleResult> {
  const createResult = await ensureSwapFilePresent({
    mode: options.mode,
    path: options.path,
    size: options.sizeForCommand,
    sizeBytes: options.sizeBytes,
    ssh,
  })
  return createResult === true ? "changed" : createResult
}

async function disableAndRemoveSwapForReplacement(
  ssh: SshConnection,
  path: string,
  temporaryPath: string
): Promise<{ backupPath: string; disabledSwap: boolean } | ModuleResult> {
  const disableResult = await disableSwap(ssh, path)
  if (typeof disableResult !== "boolean") {
    await cleanupSwapTemporaryFile(ssh, temporaryPath)
    return disableResult
  }

  const backupPath = `${path}.paratix-backup`
  const backupResult = await ssh.exec(
    `[ ! -e ${shellQuote(backupPath)} ] && mv -T -- ${shellQuote(path)} ${shellQuote(backupPath)}`,
    EXEC_OPTS
  )
  if (backupResult.code !== 0) {
    await cleanupSwapTemporaryFile(ssh, temporaryPath)
    if (disableResult) {
      const enableResult = await enableSwap(ssh, path)
      if (typeof enableResult !== "boolean") return enableResult
    }
    return failedCommand(`[swap.file: ${path}] swap backup failed`, backupResult)
  }
  return { backupPath, disabledSwap: disableResult }
}

async function restoreSwapBackup(
  ssh: SshConnection,
  path: string,
  backupPath: string
): Promise<ModuleResult | true> {
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

async function replaceManagedSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"changed" | ModuleResult> {
  const replacementFile = await createInitializedSwapTemporaryFile({
    mode: options.mode,
    path: options.path,
    size: options.sizeForCommand,
    sizeBytes: options.sizeBytes,
    ssh,
  })
  if ("status" in replacementFile) return replacementFile

  const replacementState = await disableAndRemoveSwapForReplacement(
    ssh,
    options.path,
    replacementFile.temporaryPath
  )
  if ("status" in replacementState) return replacementState

  const publishResult = await publishInitializedSwapTemporaryFile(
    {
      mode: options.mode,
      path: options.path,
      size: options.sizeForCommand,
      sizeBytes: options.sizeBytes,
      ssh,
    },
    replacementFile
  )
  if (publishResult !== true) {
    const restoreResult = await restoreSwapBackup(ssh, options.path, replacementState.backupPath)
    if (restoreResult !== true) return restoreResult
    if (replacementState.disabledSwap) {
      const enableResult = await enableSwap(ssh, options.path)
      if (typeof enableResult !== "boolean") return enableResult
    }
    return publishResult
  }
  await removeSwapBackup(ssh, replacementState.backupPath)
  return "changed"
}

async function recreateSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"changed" | "ok" | ModuleResult> {
  if (!(await needsSwapRecreation(ssh, options))) return "ok"

  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return safeRemoval

  return safeRemoval === "ok"
    ? replaceManagedSwapFile(ssh, options)
    : createMissingSwapFile(ssh, options)
}

async function enableSwap(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (await isSwapActive(ssh, path)) return false
  const result = await ssh.exec(`swapon ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapon failed`, result)
}

async function applyAbsentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  let swapChanged = false
  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return safeRemoval
  const disableResult = await disableSwap(ssh, options.path)
  if (typeof disableResult !== "boolean") return disableResult
  if (disableResult) swapChanged = true
  if (await ensureSwapFstabState({ desiredLine: null, path: options.path, ssh })) swapChanged = true
  if (safeRemoval === "ok") {
    const removeResult = await removeSwapFile(ssh, options.path)
    if (typeof removeResult !== "boolean") return removeResult
    if (removeResult) swapChanged = true
  }
  return { status: swapChanged ? "changed" : "ok" }
}

async function applyPresentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  let swapChanged = false
  const recreateResult = await recreateSwapFile(ssh, options)
  if (typeof recreateResult !== "string") return recreateResult
  if (recreateResult === "changed") swapChanged = true
  const enableResult = await enableSwap(ssh, options.path)
  if (typeof enableResult !== "boolean") return enableResult
  if (enableResult) swapChanged = true
  if (
    await ensureSwapFstabState({ desiredLine: options.expectedFstabLine, path: options.path, ssh })
  ) {
    swapChanged = true
  }
  return { status: swapChanged ? "changed" : "ok" }
}

export async function applySwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  return options.state === "absent"
    ? applyAbsentSwapFile(ssh, options)
    : applyPresentSwapFile(ssh, options)
}

async function checkAbsent(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"needs-apply" | "ok"> {
  if (await ssh.exists(options.path)) return NEEDS_APPLY
  if (await isSwapActive(ssh, options.path)) return NEEDS_APPLY
  return (await hasNoSwapFstabEntry(ssh, options.path)) ? "ok" : NEEDS_APPLY
}

async function checkPresent(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"needs-apply" | "ok"> {
  if (await needsSwapRecreation(ssh, options)) return NEEDS_APPLY
  if (!(await isSwapActive(ssh, options.path))) return NEEDS_APPLY
  if (!(await hasSwapFstabEntry(ssh, options))) return NEEDS_APPLY
  return (await swapFileModeMatches(ssh, options)) ? "ok" : NEEDS_APPLY
}

export async function checkSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<"needs-apply" | "ok"> {
  return options.state === "absent" ? checkAbsent(ssh, options) : checkPresent(ssh, options)
}
