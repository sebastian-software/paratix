/**
 * Operations on the existing containment entries of `archive.extract`: clear the entries a fully
 * successful apply verified, the `check` test that no entry exists, and the record a failed apply
 * writes into its own entry.
 */

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  containmentFlagBody,
  type ContainmentFlagRecord,
  type ContainmentLedger,
  type ContainmentPaths,
} from "./archiveContainmentFlag.js"

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
  ownEntry: 6,
} as const

/**
 * Issue #219: the clear script. Positional parameters: `$1` the own entry,
 * then one `<path> <sha256>` pair per removable entry.
 *
 * For the n-th pair it claims the entry by renaming it to `$1-claim-<n>`
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
 * @returns The script, identical for every destination.
 */
export function buildContainmentClearScript(): string {
  const exit = CONTAINMENT_CLEAR_EXIT
  return [
    String.raw`LC_ALL=C; export LC_ALL; `,
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
 * @returns The `sh -c` command line with the quoted script and parameters.
 */
export function buildContainmentClearCommand(
  ledger: Pick<ContainmentLedger, "ownEntry" | "removable">
): string {
  return [
    "sh -c",
    shellQuote(buildContainmentClearScript()),
    "sh",
    shellQuote(ledger.ownEntry),
    ...ledger.removable.flatMap(({ path, sha256 }) => [shellQuote(path), sha256]),
  ].join(" ")
}

/**
 * Issue #219: after a fully successful apply — its post-merge backstop
 * re-verified every carried link, and the whole destination when an entry
 * held no usable list — remove, in ONE exec, every entry it read that is
 * still unchanged, then its own entry. A failure fails the apply: an entry
 * left behind would keep `check` at needs-apply.
 *
 * @param conn - The SSH connection.
 * @param ledger - What the establish exec read, see {@link ContainmentLedger}.
 * @returns Null when the own entry is gone, otherwise a structured failure.
 */
export async function clearContainmentEntries(
  conn: SshConnection,
  ledger: Pick<ContainmentLedger, "ownEntry" | "removable">
): Promise<ModuleResult | null> {
  const result = await conn.exec(buildContainmentClearCommand(ledger), {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
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
 * body stays (if the entry still exists), which reads as unknown, so the next
 * apply verifies the whole destination; the write failure is appended to the
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
    `${message}; [archive.extract] ${recordFailure}; the entry still marks the apply as unfinished, so the next apply verifies the whole destination, unless another apply removed it after verifying the destination`
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
