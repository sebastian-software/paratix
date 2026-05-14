import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { moveSwapToBackup } from "./swapBackupHelpers.js"
import {
  classifySwapFilePath,
  cleanupSwapTemporaryFile,
  createInitializedSwapTemporaryFile,
  ensureSwapFileMode,
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
  const backupResult = await moveSwapToBackup(ssh, path, backupPath)
  if (backupResult !== true) {
    await cleanupSwapTemporaryFile(ssh, temporaryPath)
    if (disableResult) await enableSwap(ssh, path)
    return backupResult
  }
  return { backupPath, disabledSwap: disableResult }
}

async function restoreSwapBackup(
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

type ManagedReplacementOutcome =
  | { backupPath: string; kind: "changed" }
  | ({ kind: "result" } & ModuleResult)

async function replaceManagedSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ManagedReplacementOutcome> {
  const replacementFile = await createInitializedSwapTemporaryFile({
    mode: options.mode,
    path: options.path,
    size: options.sizeForCommand,
    sizeBytes: options.sizeBytes,
    ssh,
  })
  if ("status" in replacementFile) return { kind: "result", ...replacementFile }

  const replacementState = await disableAndRemoveSwapForReplacement(
    ssh,
    options.path,
    replacementFile.temporaryPath
  )
  if ("status" in replacementState) return { kind: "result", ...replacementState }

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
    if (restoreResult !== true) return { kind: "result", ...restoreResult }
    if (replacementState.disabledSwap) {
      const enableResult = await enableSwap(ssh, options.path)
      if (typeof enableResult !== "boolean") return { kind: "result", ...enableResult }
    }
    return { kind: "result", ...publishResult }
  }
  // R-0000175: keep the backup until the entire apply pipeline (mode + enable
  // + fstab update) finishes. The caller is responsible for invoking
  // {@link finalizeManagedSwapBackup} or {@link rollbackManagedSwapBackup}.
  return { backupPath: replacementState.backupPath, kind: "changed" }
}

async function rollbackManagedSwapBackup(
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

async function finalizeManagedSwapBackup(ssh: SshConnection, backupPath: string): Promise<void> {
  await removeSwapBackup(ssh, backupPath)
}

type RecreateOutcome =
  | "ok"
  | { backupPath: null | string; kind: "changed" }
  | ({ kind: "result" } & ModuleResult)

async function recreateSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<RecreateOutcome> {
  if (!(await needsSwapRecreation(ssh, options))) return "ok"

  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return { kind: "result", ...safeRemoval }

  if (safeRemoval === "ok") {
    const replaced = await replaceManagedSwapFile(ssh, options)
    if (replaced.kind === "changed") return { backupPath: replaced.backupPath, kind: "changed" }
    return replaced
  }
  const created = await createMissingSwapFile(ssh, options)
  if (created === "changed") return { backupPath: null, kind: "changed" }
  return { kind: "result", ...created }
}

async function enableSwap(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  if (await isSwapActive(ssh, path)) return false
  const result = await ssh.exec(`swapon ${shellQuote(path)}`, EXEC_OPTS)
  return result.code === 0 ? true : failedCommand(`[swap.file: ${path}] swapon failed`, result)
}

async function reactivateSwap(ssh: SshConnection, path: string): Promise<ModuleResult | true> {
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
  // R-0000287: remove the swap file before pruning the fstab entry. If the
  // file removal fails (permission, busy), the previous order left the
  // fstab line gone but the swap file orphaned on disk — the next mount run
  // would no longer activate it but it still consumed space. Removing the
  // file first means a failed rm aborts the apply with the fstab entry
  // intact, preserving the chance to recover state on the next run.
  if (safeRemoval === "ok") {
    const removeResult = await removeSwapFile(ssh, options.path)
    if (typeof removeResult !== "boolean") {
      if (!disableResult) return removeResult
      const reenableResult = await reactivateSwap(ssh, options.path)
      if (reenableResult !== true) {
        return failed(
          `${removeResult.error?.message ?? "swap file removal failed"}; rollback swapon failed: ${
            reenableResult.error?.message ?? "unknown error"
          }`
        )
      }
      return removeResult
    }
    if (removeResult) swapChanged = true
  }
  const fstabResult = await ensureSwapFstabState({ desiredLine: null, path: options.path, ssh })
  if (typeof fstabResult !== "boolean") return fstabResult
  swapChanged ||= fstabResult
  return { status: swapChanged ? "changed" : "ok" }
}

async function ensureExistingSwapFileMode(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions,
  recreated: boolean
): Promise<boolean | ModuleResult> {
  if (recreated) return false
  return ensureSwapFileMode(ssh, options)
}

type PendingFinalization = {
  backupPath: null | string
  recreated: boolean
}

async function rollbackOrFail(
  ssh: SshConnection,
  parameters: {
    failure: ModuleResult
    options: NormalizedSwapFileOptions
    pending: PendingFinalization
  }
): Promise<ModuleResult> {
  const { failure, options, pending } = parameters
  if (pending.backupPath != null) {
    return rollbackManagedSwapBackup(ssh, {
      backupPath: pending.backupPath,
      failureResult: failure,
      options,
    })
  }
  return failure
}

async function runApplyPresentPipeline(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions,
  pending: PendingFinalization
): Promise<ModuleResult> {
  let swapChanged = pending.recreated
  const modeResult = await ensureExistingSwapFileMode(ssh, options, pending.recreated)
  if (typeof modeResult !== "boolean")
    return rollbackOrFail(ssh, { failure: modeResult, options, pending })
  if (modeResult) swapChanged = true
  const enableResult = await enableSwap(ssh, options.path)
  if (typeof enableResult !== "boolean")
    return rollbackOrFail(ssh, { failure: enableResult, options, pending })
  if (enableResult) swapChanged = true
  const fstabResult = await ensureSwapFstabState({
    desiredLine: options.expectedFstabLine,
    path: options.path,
    ssh,
  })
  if (typeof fstabResult !== "boolean")
    return rollbackOrFail(ssh, { failure: fstabResult, options, pending })
  if (fstabResult) swapChanged = true
  // R-0000175: every step succeeded — only now is it safe to discard the
  // backup created by replaceManagedSwapFile.
  if (pending.backupPath != null) await finalizeManagedSwapBackup(ssh, pending.backupPath)
  return { status: swapChanged ? "changed" : "ok" }
}

async function applyPresentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  const recreateResult = await recreateSwapFile(ssh, options)
  if (recreateResult === "ok") {
    return runApplyPresentPipeline(ssh, options, { backupPath: null, recreated: false })
  }
  if (recreateResult.kind === "result") return recreateResult
  return runApplyPresentPipeline(ssh, options, {
    backupPath: recreateResult.backupPath,
    recreated: true,
  })
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
