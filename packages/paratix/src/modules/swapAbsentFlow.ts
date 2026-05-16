import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  disableSwap,
  enableSwap,
  handleAbsentSwapRemovalFailure,
} from "./swapAbsentRollbackHelpers.js"
import { restoreSwapBackup, snapshotSwapFileForAbsentFlow } from "./swapBackupHelpers.js"
import {
  classifySwapFilePath,
  ensureSwapFstabState,
  type NormalizedSwapFileOptions,
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

// R-0000618: roll back from a fstab-write failure that happened after the
// swap file was already removed. Restore the swap file from the hardlink
// snapshot, re-enable swap if we had previously called `swapoff`, and
// surface a chained failure message so the operator knows that both the
// fstab edit and the recovery state are visible.
async function rollbackAbsentSwapAfterFstabFailure(
  ssh: SshConnection,
  parameters: {
    disabledSwap: boolean
    fstabFailure: ModuleResult
    path: string
    snapshotPath: string
  }
): Promise<ModuleResult> {
  const { disabledSwap, fstabFailure, path, snapshotPath } = parameters
  const fstabMessage = fstabFailure.error?.message ?? "swap fstab update failed"
  const restoreResult = await restoreSwapBackup(ssh, path, snapshotPath)
  if (restoreResult !== true) {
    const restoreMessage = restoreResult.error?.message ?? "unknown error"
    return failed(
      `${fstabMessage}; swap file already removed and rollback restoreSwapBackup failed: ${restoreMessage}; operator must reconcile ${path} and /etc/fstab manually`
    )
  }
  if (disabledSwap) {
    const enableResult = await enableSwap(ssh, path)
    if (typeof enableResult !== "boolean") {
      const enableMessage = enableResult.error?.message ?? "unknown error"
      return failed(
        `${fstabMessage}; swap file restored from snapshot but rollback swapon failed: ${enableMessage}`
      )
    }
  }
  return failed(`${fstabMessage}; swap file restored from snapshot, /etc/fstab left unchanged`)
}

type AbsentRemovalOutcome =
  | { fstabFailure: null; kind: "continue"; snapshotCreated: boolean; swapChangedDelta: boolean }
  | { kind: "done"; result: ModuleResult }

async function performAbsentSwapRemoval(
  ssh: SshConnection,
  parameters: {
    disableResult: boolean
    options: NormalizedSwapFileOptions
    safeRemoval: "missing" | "ok"
    snapshotPath: string
  }
): Promise<AbsentRemovalOutcome> {
  const { disableResult, options, safeRemoval, snapshotPath } = parameters
  if (safeRemoval !== "ok") {
    return {
      fstabFailure: null,
      kind: "continue",
      snapshotCreated: false,
      swapChangedDelta: false,
    }
  }
  const snapshotResult = await snapshotSwapFileForAbsentFlow(ssh, options.path, snapshotPath)
  if (snapshotResult !== true) return { kind: "done", result: snapshotResult }
  const removeResult = await removeSwapFile(ssh, options.path)
  if (typeof removeResult !== "boolean") {
    return {
      kind: "done",
      result: await handleAbsentSwapRemovalFailure(ssh, {
        disabledSwap: disableResult,
        path: options.path,
        removeFailure: removeResult,
      }),
    }
  }
  return {
    fstabFailure: null,
    kind: "continue",
    snapshotCreated: true,
    swapChangedDelta: removeResult,
  }
}

// Only reached on the happy paths (file already missing OR successfully
// removed). It is therefore safe to prune the fstab entry — there is no
// live swap file the entry could still reference. A guardedWriteFile
// failure inside ensureSwapFstabState propagates as a regular failed
// result; fstab itself remains consistent because guardedWriteFile
// writes atomically via the SSH-layer temp-file finalize. If the
// fstab write fails *after* the swap file has been removed, restore
// the swap file from the hardlink snapshot via
// `rollbackAbsentSwapAfterFstabFailure` so the host is not left with
// a stale fstab entry pointing at a missing file.
async function pruneSwapFstabAndRollbackOnFailure(
  ssh: SshConnection,
  parameters: {
    disableResult: boolean
    options: NormalizedSwapFileOptions
    snapshotCreated: boolean
    snapshotPath: string
  }
): Promise<boolean | ModuleResult> {
  const { disableResult, options, snapshotCreated, snapshotPath } = parameters
  const fstabResult = await ensureSwapFstabState({
    desiredLine: null,
    path: options.path,
    ssh,
  })
  if (typeof fstabResult === "boolean") return fstabResult
  if (!snapshotCreated) return fstabResult
  return rollbackAbsentSwapAfterFstabFailure(ssh, {
    disabledSwap: disableResult,
    fstabFailure: fstabResult,
    path: options.path,
    snapshotPath,
  })
}

// R-0000618: clean up the hardlink snapshot. Use `rm -f --` so the call is
// idempotent even when the rollback path already restored (and thus
// consumed) the snapshot via `mv -T --`.
async function cleanupAbsentSwapSnapshot(ssh: SshConnection, snapshotPath: string): Promise<void> {
  await ssh.exec(`rm -f -- ${shellQuote(snapshotPath)}`, EXEC_OPTS)
}

export async function applyAbsentSwapFile(
  ssh: SshConnection,
  options: NormalizedSwapFileOptions
): Promise<ModuleResult> {
  // R-0000547: this pipeline is intentionally transactional:
  //
  //   1. ensureSafeSwapRemoval — refuse to touch unmanaged paths.
  //   2. disableSwap — `swapoff` first so the kernel releases the file.
  //      If this fails we return immediately *without* touching fstab so
  //      the persistence entry is preserved for the next recovery run.
  //   3. snapshotSwapFileForAbsentFlow — R-0000618: hardlink the swap file
  //      to a sibling backup path so a fstab-write failure after the
  //      following `rm` is recoverable.
  //   4. removeSwapFile (only when the file actually exists).
  //   5. ensureSwapFstabState — pruning the fstab entry is safe here.
  //      On failure the snapshot is restored via
  //      `rollbackAbsentSwapAfterFstabFailure`.
  //   6. On success, the hardlink snapshot is removed in the cleanup
  //      finally block.
  const safeRemoval = await ensureSafeSwapRemoval(ssh, options.path)
  if (typeof safeRemoval !== "string") return safeRemoval
  const disableResult = await disableSwap(ssh, options.path)
  if (typeof disableResult !== "boolean") return disableResult
  const snapshotPath = `${options.path}.paratix-absent-backup`
  let snapshotCreated = false
  try {
    const removalOutcome = await performAbsentSwapRemoval(ssh, {
      disableResult,
      options,
      safeRemoval,
      snapshotPath,
    })
    if (removalOutcome.kind === "done") return removalOutcome.result
    snapshotCreated = removalOutcome.snapshotCreated
    const fstabResult = await pruneSwapFstabAndRollbackOnFailure(ssh, {
      disableResult,
      options,
      snapshotCreated,
      snapshotPath,
    })
    if (typeof fstabResult !== "boolean") return fstabResult
    const swapChanged = disableResult || removalOutcome.swapChangedDelta || fstabResult
    return { status: swapChanged ? "changed" : "ok" }
  } finally {
    if (snapshotCreated) await cleanupAbsentSwapSnapshot(ssh, snapshotPath)
  }
}
