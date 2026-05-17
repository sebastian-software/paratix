import type { ModuleResult, SshConnection } from "../types.js"
import type { NormalizedSwapFileOptions } from "./swapFileHelpers.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { disableSwap, enableSwap } from "./swapAbsentRollbackHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

export async function moveSwapToBackup(
  ssh: SshConnection,
  path: string,
  backupPath: string
): Promise<ModuleResult | true> {
  // R-0000647: `mv -T -n` itself does not follow symlinks on the destination,
  // but a symlink that materializes at `$backupPath` between an earlier probe
  // and the rename would still let an attacker steer the swap content onto an
  // operator-controlled target (e.g. `/etc/shadow`). Guard both `$path` and
  // `$backupPath` with a `[ ! -L ]` check inside the same shell statement so
  // the renaming kernel call only ever runs when neither side is a symlink,
  // and pass `--` to terminate option parsing for `mv`. Mirrors the doubled
  // symlink probe in restoreSwapBackup / snapshotSwapFileForAbsentFlow.
  const quotedPath = shellQuote(path)
  const quotedBackup = shellQuote(backupPath)
  const backupResult = await ssh.exec(
    `[ ! -L ${quotedBackup} ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; [ ! -L ${quotedPath} ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; mv -T -n -- ${quotedPath} ${quotedBackup}`,
    EXEC_OPTS
  )
  if (backupResult.code !== 0) {
    return failedCommand(`[swap.file: ${path}] swap backup failed`, backupResult)
  }

  const result = await ssh.exec(
    `[ ! -e ${quotedPath} ] && [ -f ${quotedBackup} ] && swaplabel ${quotedBackup} >/dev/null 2>&1`,
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
  // R-0000624: refuse the restore if either `$path` or `$backupPath` has
  // been turned into a symlink while the absent flow was running. Without
  // these guards an attacker with write access to the parent directory
  // could replace the hardlink backup with a symlink to e.g.
  // `/etc/shadow`; `mv -T --` would then rename that symlink onto
  // `$path`, leaving the host with a swap-managed path that follows an
  // attacker-controlled target on the next `swapon`.
  const quotedPath = shellQuote(path)
  const quotedBackup = shellQuote(backupPath)
  const restoreResult = await ssh.exec(
    `[ ! -L ${quotedBackup} ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; [ ! -L ${quotedPath} ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; mv -T -- ${quotedBackup} ${quotedPath}`,
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

// R-0000618: hardlink-based snapshot for the absent flow. The absent
// pipeline removes the swap file *before* it updates fstab, so a failing
// fstab write would otherwise leave the host with a stale fstab entry
// pointing at a swap file that no longer exists — `swapon -a` on the next
// boot would then fail with `swapon: cannot stat <path>` and miss this
// swap area entirely. A hardlink under `<path>.paratix-absent-backup`
// preserves the original inode (and therefore the file mode and the swap
// header) at near-zero cost, so we can restore the original file via a
// single atomic rename if a later step fails.
export async function snapshotSwapFileForAbsentFlow(
  ssh: SshConnection,
  path: string,
  backupPath: string
): Promise<ModuleResult | true> {
  // Remove any leftover backup from a prior aborted run before the link.
  // `mv -T --` (used by the restore path) refuses to overwrite the
  // destination otherwise.
  await ssh.exec(`rm -f -- ${shellQuote(backupPath)}`, EXEC_OPTS)
  // R-0000624: build the snapshot inside a single shell statement that
  // re-checks `[ ! -L ]` on both `$path` and `$backupPath` immediately
  // before the link and uses `ln -P --` (no-deref) so a last-instant
  // symlink swap on either path cannot produce a hardlink that points at
  // an attacker-controlled target outside the swap parent directory.
  // `swap.file({ path: "/home/foo/swap" })` is a realistic configuration
  // where the parent directory is writable by an unprivileged user, so
  // the plain `ln --` previously here would have followed a freshly
  // planted symlink and created the backup as a hardlink to e.g.
  // `/etc/shadow`. The doubled `[ ! -L ]` guard collapses the TOCTOU
  // window between the `rm -f` above and the link below.
  const quotedPath = shellQuote(path)
  const quotedBackup = shellQuote(backupPath)
  const result = await ssh.exec(
    `[ ! -L ${quotedPath} ] || { echo 'swap path must not be a symlink' >&2; exit 1; }; [ ! -L ${quotedBackup} ] || { echo 'swap backup must not be a symlink' >&2; exit 1; }; ln -P -- ${quotedPath} ${quotedBackup}`,
    EXEC_OPTS
  )
  return result.code === 0
    ? true
    : failedCommand(`[swap.file: ${path}] swap absent snapshot hardlink failed`, result)
}

// R-0000611: chain the publish failure with any rollback failures so the
// original cause stays attributable. Mirrors handleSwapBackupFailure
// (R-0000548), which already chains backup + re-enable failures into a
// single ModuleResult instead of letting the later rollback failure
// shadow the original publish error.
export async function handleSwapPublishFailure(
  ssh: SshConnection,
  parameters: {
    backupPath: string
    disabledSwap: boolean
    path: string
    publishResult: ModuleResult
  }
): Promise<ModuleResult> {
  const { backupPath, disabledSwap, path, publishResult } = parameters
  const publishMessage = publishResult.error?.message ?? "swap publish failed"
  const restoreResult = await restoreSwapBackup(ssh, path, backupPath)
  if (restoreResult !== true) {
    const restoreMessage = restoreResult.error?.message ?? "unknown error"
    return failed(`${publishMessage}; rollback restoreSwapBackup failed: ${restoreMessage}`)
  }
  if (disabledSwap) {
    const enableResult = await enableSwap(ssh, path)
    if (typeof enableResult !== "boolean") {
      const enableMessage = enableResult.error?.message ?? "unknown error"
      return failed(`${publishMessage}; rollback enableSwap failed: ${enableMessage}`)
    }
  }
  return publishResult
}
