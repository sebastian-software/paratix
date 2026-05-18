import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { isSymlink } from "./remoteFileChecks.js"

const SILENT_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const DEFAULT_UNIT_MODE = "0644"

/**
 * Snapshot of a systemd unit file taken before write/rollback boundaries.
 *
 * Captures whether the file exists, its current content and mode, or a
 * structured failure when the read itself could not complete. Mirrors the
 * swap snapshot contract from R-0000648 (sysctl moved to the same shape
 * in R-0000682) and replaces the implicit `throw` that previously bubbled
 * out of `ssh.readFile` when transient SFTP errors hit.
 */
export type UnitFileSnapshot =
  | {
      content: string
      exists: true
      mode: string
    }
  | { exists: false }
  | { kind: "failed"; reason: string }

/**
 * Render a caught error value as a string for inclusion in user-visible
 * failure messages, without losing the message of an `Error` instance.
 *
 * @param error - The thrown value, typically caught from a Promise or
 *   synchronous block.
 * @returns The error message when `error` is an `Error`, the coerced
 *   string otherwise.
 */
export const formatCaughtError = (error: unknown): string =>
  error instanceof Error ? error.message : String(error)

/**
 * Capture a structured snapshot of `filePath` so a later rollback can
 * decide whether to restore content, restore the original mode, or remove
 * the file entirely.
 *
 * @param ssh - The active SSH connection.
 * @param filePath - Absolute path of the unit file to snapshot.
 * @returns A snapshot describing the file's current state.
 */
export async function snapshotUnitFile(
  ssh: SshConnection,
  filePath: string
): Promise<UnitFileSnapshot> {
  if (!(await ssh.exists(filePath))) return { exists: false }
  // R-0000683: `ssh.readFile` can throw on transient SFTP errors or after a
  // permission denial. Convert the throw into a structured failure so
  // `applySystemdUnit` can return a failed ModuleResult instead of bubbling
  // a raw exception out of the module — matches the swap snapshot contract
  // established in R-0000648.
  let content: string
  try {
    content = await ssh.readFile(filePath)
  } catch (error) {
    return { kind: "failed", reason: formatCaughtError(error) }
  }
  const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(filePath)}`, SILENT_EXEC_OPTS)
  return {
    content,
    exists: true,
    mode:
      modeResult.code === 0 && modeResult.stdout.trim() !== ""
        ? modeResult.stdout.trim()
        : DEFAULT_UNIT_MODE,
  }
}

/**
 * Restore the unit file to the state captured in `snapshot`.
 *
 * @param ssh - The active SSH connection.
 * @param filePath - Absolute path of the unit file to restore.
 * @param snapshot - The snapshot captured by `snapshotUnitFile`.
 * @throws {Error} When the live path is a symlink at restore time.
 */
export async function restoreUnitFileSnapshot(
  ssh: SshConnection,
  filePath: string,
  snapshot: UnitFileSnapshot
): Promise<void> {
  if ("kind" in snapshot) {
    // R-0000683: defensive guard — the apply path refuses to proceed when
    // the snapshot capture failed, so the rollback should never observe
    // this branch. If a future caller routes a failed snapshot here we
    // intentionally do nothing rather than touch the live file on a
    // partially-known state.
    return
  }
  if (snapshot.exists) {
    // R-0000683: refuse to write back through a symlink. Without the
    // `[ -L ]` probe a swap between the snapshot read and the rollback
    // would let `ssh.writeFile` follow the planted link to its target.
    // Mirrors the swap restore guard added in R-0000647.
    if (await isSymlink(ssh, filePath)) {
      throw new Error(`refusing to restore through symlink at ${filePath}`)
    }
    await ssh.writeFile(filePath, snapshot.content, { mode: snapshot.mode })
    return
  }
  await ssh.exec(`rm -f ${shellQuote(filePath)}`, SILENT_EXEC_OPTS)
}

/**
 * Outcome of {@link restoreUnitFileSnapshotIfCurrentMatches}.
 *
 * - `restored`: the live file matched the expected pre-restore content and
 *   was rewritten to the snapshot state.
 * - `skipped`: the live file is either missing or its content diverged from
 *   the expected pre-restore content; the rollback intentionally left the
 *   file untouched.
 * - `failed`: the conditional read itself could not complete (typically a
 *   transient SFTP error or permission denial). Callers must surface this
 *   alongside the original failure instead of treating it as `skipped` —
 *   otherwise a probe error would silently shadow the primary error that
 *   triggered the rollback in the first place.
 */
export type RestoreUnitFileIfCurrentMatchesResult =
  | { kind: "failed"; reason: string }
  | { kind: "restored" }
  | { kind: "skipped" }

/**
 * Restore the unit file only when the current on-disk content still matches
 * `expectedCurrentContent`. Used by rollback paths that must avoid
 * clobbering edits applied after the snapshot was captured.
 *
 * @param parameters - Restore inputs (snapshot, expected pre-restore content, ssh, filePath).
 * @param parameters.expectedCurrentContent - The content that must currently be on disk for the restore to run.
 * @param parameters.filePath - Absolute path of the unit file to restore.
 * @param parameters.snapshot - The captured snapshot to restore from.
 * @param parameters.ssh - The active SSH connection.
 * @returns A structured outcome describing whether the rollback ran,
 *   skipped (file missing or content diverged), or failed because the
 *   live-content read itself could not complete.
 */
export async function restoreUnitFileSnapshotIfCurrentMatches(parameters: {
  expectedCurrentContent: string
  filePath: string
  snapshot: UnitFileSnapshot
  ssh: SshConnection
}): Promise<RestoreUnitFileIfCurrentMatchesResult> {
  const { expectedCurrentContent, filePath, snapshot, ssh } = parameters
  if (!(await ssh.exists(filePath))) return { kind: "skipped" }
  // R-0000721: `ssh.readFile` throws on transient SFTP errors or after a
  // permission denial. Without this catch the rollback path would bubble
  // an unstructured exception out of the module and the original failure
  // (daemon-reload / flag persistence) that triggered the rollback would
  // be lost. Mirror the snapshot-capture contract from R-0000683 and
  // surface a structured failure so callers can chain both errors into
  // a single user-visible message.
  let currentContent: string
  try {
    currentContent = await ssh.readFile(filePath)
  } catch (error) {
    return { kind: "failed", reason: formatCaughtError(error) }
  }
  if (currentContent !== expectedCurrentContent) return { kind: "skipped" }
  await restoreUnitFileSnapshot(ssh, filePath, snapshot)
  return { kind: "restored" }
}
