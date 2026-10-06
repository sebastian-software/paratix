/**
 * Operations on the existing containment entries of `archive.extract`: clear the entries a fully
 * successful apply verified, the `check` test that no entry exists, the hint how to clear them by
 * hand, and the record a failed apply writes into its own entry.
 */

import type { ModuleResult, SshConnection } from "../types.js"
import type { ContainmentLedger } from "./archiveContainmentEstablish.js"
import type { MutexLockLostReason } from "./mutexLock.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  containmentFlagBody,
  type ContainmentFlagRecord,
  type ContainmentPaths,
} from "./archiveContainmentFlag.js"
import {
  ARCHIVE_EXTRACT_LOCK_LOST_EXIT,
  archiveExtractLockLostReason,
} from "./archiveExtractLock.js"
import { buildFlagLockRefreshGuard } from "./flagLockScripts.js"

const CONTAINMENT_ENTRY_MODE = "0644"

/**
 * Issue #219: exit statuses of the clear exec, see
 * {@link buildContainmentClearScript}.
 */
export const CONTAINMENT_CLEAR_EXIT = {
  arguments: 64,
  claimFailed: 5,
  claimTaken: 3,
  claimUnremovable: 4,
  /** Issue #224: the embedded refresh guard refused; nothing was removed. */
  lockLost: ARCHIVE_EXTRACT_LOCK_LOST_EXIT,
  ownEntry: 6,
} as const

/**
 * Issue #224: the lock the clear exec guards itself with: the holder token and
 * the guard threshold of the destination's extract lock (see
 * `archiveExtractLock.ts`).
 */
export type ContainmentClearLock = {
  /** Guard age in seconds; a holder marker older than this refuses the clear. */
  guardSeconds: number
  /** The unquoted lock directory path. */
  lockPath: string
  /** Issue #224: why the lock handle was latched as lost, if it was. */
  lostReason?: () => MutexLockLostReason | undefined
  /** The holder token on marker line 1. */
  token: string
}

/**
 * Issue #219: the clear script. Positional parameters: `$1` the lock
 * directory and `$2` the holder token of the destination's extract lock
 * (issue #224), `$3` the own entry, then one `<path> <sha256>` pair per
 * removable entry.
 *
 * Issue #224: before anything else, the embedded refresh guard checks that
 * the lock still belongs to this apply — the lock directory exists, its
 * holder marker carries the token on line 1 and is not older than the guard
 * threshold — and refreshes the marker. When it refuses, the script exits
 * {@link CONTAINMENT_CLEAR_EXIT}.lockLost before it renames or removes
 * anything: another apply may hold the lock by now and rely on every entry it
 * read.
 *
 * For the n-th pair it claims the entry by renaming it to `$own-claim-<n>`
 * (inside the entry directory, so the claim is still an entry), which is
 * atomic: a concurrent rewrite (a rename onto the path) after that point
 * creates a new entry that is never touched. The claim is removed only when
 * it is a regular file whose sha256 still equals the one read before;
 * otherwise it stays, and `check` and the next apply see it. An entry that is
 * already gone is fine. A claim name that is taken exits 3, a claim that
 * cannot be removed 4, an entry that is still there but cannot be claimed 5,
 * an odd number of arguments 64. The own entry is removed last (exit 6 when
 * that fails), so a failure before it can still rewrite the own entry.
 *
 * @param guardSeconds - Issue #224: the guard threshold in seconds.
 * @returns The script, identical for every destination.
 */
export function buildContainmentClearScript(guardSeconds: number): string {
  const exit = CONTAINMENT_CLEAR_EXIT
  const guard = buildFlagLockRefreshGuard({
    guardSeconds,
    lockDirectory: { kind: "parameter", name: "1" },
    token: { kind: "parameter", name: "2" },
  })
  return [
    String.raw`LC_ALL=C; export LC_ALL; `,
    `${guard} || exit ${String(exit.lockLost)}; shift 2; `,
    String.raw`own=$1; shift; n=0; `,
    String.raw`while [ "$#" -ge 2 ]; do `,
    String.raw`p=$1; h=$2; shift 2; c="$own-claim-$n"; n=$((n + 1)); `,
    `if [ -e "$c" ] || [ -L "$c" ]; then printf 'claim %s exists\\n' "$c" >&2; exit ${String(exit.claimTaken)}; fi; `,
    String.raw`if mv -- "$p" "$c" 2>/dev/null; then `,
    String.raw`if [ -f "$c" ] && [ ! -L "$c" ] && [ "$(sha256sum < "$c" | cut -c1-64)" = "$h" ]; then `,
    `rm -f -- "$c" || exit ${String(exit.claimUnremovable)}; `,
    String.raw`fi; `,
    `elif [ -e "$p" ] || [ -L "$p" ]; then printf 'cannot claim %s\\n' "$p" >&2; exit ${String(exit.claimFailed)}; `,
    String.raw`fi; `,
    String.raw`done; `,
    `[ "$#" -eq 0 ] || exit ${String(exit.arguments)}; `,
    `rm -f -- "$own" || exit ${String(exit.ownEntry)}`,
  ].join("")
}

/**
 * Issue #219: the clear exec as an explicit `sh -c` command, see
 * {@link buildContainmentClearScript}.
 *
 * @param ledger - The own entry and the entries it may remove.
 * @param lock - Issue #224: the extract lock the clear guards itself with.
 * @returns The `sh -c` command line with the quoted script and parameters.
 */
export function buildContainmentClearCommand(
  ledger: Pick<ContainmentLedger, "ownEntry" | "removable">,
  lock: ContainmentClearLock
): string {
  return [
    "sh -c",
    shellQuote(buildContainmentClearScript(lock.guardSeconds)),
    "sh",
    shellQuote(lock.lockPath),
    shellQuote(lock.token),
    shellQuote(ledger.ownEntry),
    ...ledger.removable.flatMap(({ path, sha256 }) => [shellQuote(path), sha256]),
  ].join(" ")
}

/**
 * Issue #224: the failure of a clear that removed nothing because the
 * destination's extract lock is no longer this apply's.
 *
 * @param ownEntry - The own entry's absolute path.
 * @param lock - The lock the apply took.
 * @returns The failure.
 */
export function clearRefusedForLostLock(
  ownEntry: string,
  lock: Pick<ContainmentClearLock, "guardSeconds" | "lockPath" | "lostReason">
): ModuleResult {
  return failed(
    `[archive.extract] refusing to remove containment entry ${ownEntry} and the entries it verified: ${archiveExtractLockLostReason(lock)}; no entry was removed, so check stays at needs-apply until a later apply verifies and clears them`
  )
}

/**
 * Issue #219: after a fully successful apply — its post-merge backstop
 * re-verified every carried link, and the whole destination when an entry
 * held no usable list — remove, in ONE exec, every entry it read that is
 * still unchanged, then its own entry. A failure fails the apply: an entry
 * left behind would keep `check` at needs-apply.
 *
 * Issue #224: the exec first checks that the destination's extract lock is
 * still this apply's. When it is not, nothing is removed and the failure
 * names the lost lock; the caller records an empty `failed` list in the own
 * entry, which is safe because this apply's own backstop already passed.
 *
 * @param conn - The SSH connection.
 * @param ledger - What the establish exec read, see {@link ContainmentLedger}.
 * @param lock - Issue #224: the extract lock the clear guards itself with.
 * @returns Null when the own entry is gone, otherwise a structured failure.
 */
export async function clearContainmentEntries(
  conn: SshConnection,
  ledger: Pick<ContainmentLedger, "ownEntry" | "removable">,
  lock: ContainmentClearLock
): Promise<ModuleResult | null> {
  const result = await conn.exec(buildContainmentClearCommand(ledger, lock), {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
  if (result.code === CONTAINMENT_CLEAR_EXIT.lockLost) {
    return clearRefusedForLostLock(ledger.ownEntry, lock)
  }
  return failedCommand(
    `[archive.extract] failed to remove containment entry ${ledger.ownEntry} and the entries it verified`,
    result
  )
}

/**
 * Issue #219: the `check` script that passes only when the entry directory
 * `$1` holds no entry: it is absent, or a real directory that is readable and
 * searchable and in which `run-*` matches nothing, a dangling symlink
 * included. A symlink, a non-directory or an unreadable directory fails.
 *
 * @returns The POSIX `sh` script, which exits 0 only without any entry.
 */
export function buildContainmentCheckScript(): string {
  return [
    String.raw`if [ -L "$1" ]; then exit 1; fi; `,
    String.raw`if [ ! -e "$1" ]; then exit 0; fi; `,
    String.raw`[ -d "$1" ] && [ -r "$1" ] && [ -x "$1" ] || exit 1; `,
    String.raw`for e in "$1"/run-*; do if [ -e "$e" ] || [ -L "$e" ]; then exit 1; fi; done; `,
    String.raw`exit 0`,
  ].join("")
}

/**
 * Issue #219: the part of the `check` test that passes only when neither the
 * old flag file (not even a dangling symlink) nor any entry exists; to be
 * joined with `&&` to the marker test so the exec count of `check` stays
 * unchanged.
 *
 * @param paths - Where the destination's containment state lives.
 * @param paths.entryDirectory - The destination's entry directory.
 * @param paths.legacyFlag - The old single flag file.
 * @returns The shell test.
 */
export function noContainmentEntriesCommand(
  paths: Pick<ContainmentPaths, "entryDirectory" | "legacyFlag">
): string {
  const legacy = shellQuote(paths.legacyFlag)
  return [
    `test ! -e ${legacy} && test ! -L ${legacy} &&`,
    "sh -c",
    shellQuote(buildContainmentCheckScript()),
    "sh",
    shellQuote(paths.entryDirectory),
  ].join(" ")
}

/**
 * Issue #219: the way out when the offending links are intended, for example
 * a virtualenv interpreter link that points into `/usr/bin` after an
 * interrupted apply forced a whole-destination check. Such a link fails every
 * later check, so the operator first has to stop or wait for all applies to
 * this destination to finish, with no new applies until inspection and state
 * clearing are complete. No apply may be active when inspection begins: the
 * tree must stay unchanged while it is checked, and clearing state must not
 * remove a live apply's in-progress entry. The operator can then check the
 * tree, clear the destination's containment entries and legacy flag, and
 * retry. This hint is offered only when the current archive's normal scope
 * passes without that state. Naming both concrete paths keeps the step
 * copyable; it is not a recommendation to clear entries blindly.
 *
 * Issue #224: applies to one destination are serialized by its extract lock,
 * so the hint names the lock directory: while it exists an apply runs or was
 * interrupted. A lock an interrupted apply left is reclaimed by the next
 * apply once its holder marker is stale; removing it by hand is safe only
 * when no apply for the destination runs anywhere, because a live holder
 * would then lose its lock to the next apply.
 *
 * @param paths - The destination's containment state paths.
 * @param paths.entryDirectory - The destination's containment entry directory.
 * @param paths.legacyFlag - The destination's containment flag from older versions.
 * @param paths.lockPath - Issue #224: the destination's extract lock directory;
 *   omitted, the hint does not name it.
 * @returns The sentence appended to a post-merge violation message.
 */
export function intendedLinksHint(paths: {
  entryDirectory: string
  legacyFlag: string
  lockPath?: string
}): string {
  const { entryDirectory, legacyFlag, lockPath } = paths
  const holder = lockPath === undefined ? "" : shellQuote(`${lockPath}/holder`)
  const lock =
    lockPath === undefined
      ? ""
      : ` (while the extract lock ${shellQuote(lockPath)} exists, an apply to this destination runs or was interrupted; the next apply reclaims an interrupted apply's lock once it is stale, and removing it by hand with rm -f -- ${holder} && rmdir -- ${shellQuote(lockPath)} is safe only when no apply for this destination runs anywhere)`
  return `if the offending symlinks are intended (for example a virtualenv's interpreter link), they keep failing this check: first stop or wait for all archive.extract applies to this destination to finish and prevent new applies until inspection and state clearing are complete${lock}; then check the destination yourself and, before retrying, clear its containment state with rm -f -- ${shellQuote(entryDirectory)}/run-* ${shellQuote(legacyFlag)}`
}

/**
 * Issue #219: rewrite the own entry through the guarded `writeFile`, which
 * stages a temp file and renames it onto the entry, refusing to finalize onto
 * a symlink or a directory. An own entry another apply removed in the
 * meantime is created again.
 *
 * @param conn - The SSH connection.
 * @param ownEntry - The own entry's absolute path.
 * @param record - What to record.
 * @returns Null when the record is in place, otherwise why it could not be written.
 */
async function writeOwnEntry(
  conn: SshConnection,
  ownEntry: string,
  record: ContainmentFlagRecord
): Promise<null | string> {
  try {
    await conn.writeFile(ownEntry, containmentFlagBody(record), { mode: CONTAINMENT_ENTRY_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return `failed to write containment entry ${ownEntry}: ${reason}`
  }
  return null
}

/**
 * Issue #219: record a failed apply's outcome in its own entry, best effort;
 * other entries are never touched. When the write fails, the `in-progress`
 * body stays (if the entry still exists), so the next apply verifies the
 * whole destination, or (Issue #227) every link this archive can affect when
 * it extracts the same archive; the write failure is appended to the
 * apply's failure. The message says so conditionally: a concurrent apply may
 * have verified the destination and removed the entry meanwhile (race 1).
 *
 * @param conn - The SSH connection.
 * @param parameters - Record inputs.
 * @param parameters.failure - The apply's failure.
 * @param parameters.ownEntry - The own entry's absolute path.
 * @param parameters.record - What to record.
 * @returns The failure, extended by a record failure if there was one.
 */
export async function recordContainmentFailure(
  conn: SshConnection,
  parameters: { failure: ModuleResult; ownEntry: string; record: ContainmentFlagRecord }
): Promise<ModuleResult> {
  const { failure, ownEntry, record } = parameters
  const recordFailure = await writeOwnEntry(conn, ownEntry, record)
  if (recordFailure === null) return failure
  const message = failure.error?.message ?? "[archive.extract] apply failed"
  return failed(
    `${message}; [archive.extract] ${recordFailure}; the entry still marks the apply as unfinished, so the next apply verifies the whole destination, or every link this archive can affect when it extracts the same archive, unless another apply removed it after verifying the destination`
  )
}

/**
 * Issue #219: record a failed apply's outcome after a thrown error, ignoring
 * any failure of the write itself; the caller rethrows the error.
 *
 * @param conn - The SSH connection.
 * @param ownEntry - The own entry's absolute path.
 * @param record - What to record.
 */
export async function recordContainmentFailureAfterThrow(
  conn: SshConnection,
  ownEntry: string,
  record: ContainmentFlagRecord
): Promise<void> {
  await writeOwnEntry(conn, ownEntry, record)
}
