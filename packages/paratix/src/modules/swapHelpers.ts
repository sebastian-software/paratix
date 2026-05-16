import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  disableSwap,
  enableSwap,
  handleAbsentSwapRemovalFailure,
} from "./swapAbsentRollbackHelpers.js"
import {
  finalizeManagedSwapBackup,
  handleSwapPublishFailure,
  moveSwapToBackup,
  rollbackManagedSwapBackup,
} from "./swapBackupHelpers.js"
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

// R-0000548: surface enableSwap rollback failures so operators know
// the host is now without an active swap area. Merge the rollback
// failure into the original backup failure message so both causes
// remain attributable in a single ModuleResult.
async function handleSwapBackupFailure(
  ssh: SshConnection,
  parameters: {
    backupResult: ModuleResult
    disabledSwap: boolean
    path: string
    temporaryPath: string
  }
): Promise<ModuleResult> {
  const { backupResult, disabledSwap, path, temporaryPath } = parameters
  await cleanupSwapTemporaryFile(ssh, temporaryPath)
  if (!disabledSwap) return backupResult
  const reEnableResult = await enableSwap(ssh, path)
  if (typeof reEnableResult === "boolean") return backupResult
  const backupMessage = backupResult.error?.message ?? "swap backup failed"
  const reEnableMessage = reEnableResult.error?.message ?? "unknown error"
  return failed(`${backupMessage}; rollback enableSwap failed: ${reEnableMessage}`)
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
    return handleSwapBackupFailure(ssh, {
      backupResult,
      disabledSwap: disableResult,
      path,
      temporaryPath,
    })
  }
  return { backupPath, disabledSwap: disableResult }
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
    const rollbackResult = await handleSwapPublishFailure(ssh, {
      backupPath: replacementState.backupPath,
      disabledSwap: replacementState.disabledSwap,
      path: options.path,
      publishResult,
    })
    return { kind: "result", ...rollbackResult }
  }
  // R-0000175: keep the backup until the entire apply pipeline (mode + enable
  // + fstab update) finishes. The caller is responsible for invoking
  // {@link finalizeManagedSwapBackup} or {@link rollbackManagedSwapBackup}.
  return { backupPath: replacementState.backupPath, kind: "changed" }
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

async function applyAbsentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  // R-0000547: this pipeline is intentionally transactional:
  //
  //   1. ensureSafeSwapRemoval — refuse to touch unmanaged paths.
  //   2. disableSwap — `swapoff` first so the kernel releases the file.
  //      If this fails we return immediately *without* touching fstab so
  //      the persistence entry is preserved for the next recovery run
  //      (the operator can still re-mount swap from fstab on reboot).
  //   3. removeSwapFile (only when the file actually exists). A failure
  //      here re-enables swap via handleAbsentSwapRemovalFailure and
  //      again leaves fstab untouched.
  //   4. ensureSwapFstabState — only reached when the file is either
  //      gone (safeRemoval === "missing") or has been successfully
  //      removed. Pruning the fstab entry at this point is safe because
  //      no swap file remains that the entry could refer to.
  //
  // Document carefully so future edits do not accidentally hoist the
  // fstab mutation before the disable/remove steps.
  let swapChanged = false
  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return safeRemoval
  const disableResult = await disableSwap(ssh, options.path)
  if (typeof disableResult !== "boolean") return disableResult
  if (disableResult) swapChanged = true
  // Remove the swap file before pruning fstab so failed removal leaves
  // persistence intact for the next recovery run.
  if (safeRemoval === "ok") {
    const removeResult = await removeSwapFile(ssh, options.path)
    if (typeof removeResult !== "boolean") {
      return handleAbsentSwapRemovalFailure(ssh, {
        disabledSwap: disableResult,
        path: options.path,
        removeFailure: removeResult,
      })
    }
    if (removeResult) swapChanged = true
  }
  // Only reached on the happy paths (file already missing OR successfully
  // removed). It is therefore safe to prune the fstab entry — there is no
  // live swap file the entry could still reference. A guardedWriteFile
  // failure inside ensureSwapFstabState propagates as a regular failed
  // result; fstab itself remains consistent because guardedWriteFile
  // writes atomically via the SSH-layer temp-file finalize.
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
