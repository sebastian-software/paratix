import type { SshConnection } from "../types.js"
import type { TimerPaths } from "./timerHelpers.js"

import { shellQuote } from "../ssh.js"

const UNIT_FILE_MODE = "0644"
const OCTAL_MODE_LENGTH_WITHOUT_LEADING_ZERO = 3

/**
 * Snapshot of a timer unit file taken before write/rollback boundaries.
 *
 * Captures whether the file exists, its current content and mode, or a
 * structured failure when the read itself could not complete. Mirrors the
 * unit snapshot contract added in R-0000683 (and now R-0000721 for the
 * conditional restore path). Without the `kind: "failed"` variant a
 * transient SFTP error during the pre-write read would bubble out of the
 * module as an unstructured exception instead of producing a failed
 * ModuleResult.
 */
export type FileSnapshot =
  | { content: string; exists: true; mode: string }
  | { exists: false }
  | { kind: "failed"; reason: string }

function formatCaughtError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

// R-0000217: Capture the file mode in the snapshot so the rollback can
// restore the exact mode the operator had configured. The previous
// implementation hardcoded `0644` on restore and would silently overwrite
// a manual `chmod 0600` (e.g. for a unit that contains an EnvironmentFile
// path). Mirrors the snapshotting in `quadlet.ts` and `systemd.ts`.
//
// R-0000720: convert a `ssh.readFile` throw into a structured failed
// snapshot. Callers in `timer.ts` refuse to continue when a snapshot
// captured for rollback could not be read, mirroring the
// `UnitFileSnapshot` contract from R-0000683.
export async function readFileSnapshot(ssh: SshConnection, path: string): Promise<FileSnapshot> {
  if (!(await ssh.exists(path))) return { exists: false }
  let content: string
  try {
    content = await ssh.readFile(path)
  } catch (error) {
    return { kind: "failed", reason: formatCaughtError(error) }
  }
  const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(path)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  const rawMode =
    modeResult.code === 0 && modeResult.stdout.trim() !== ""
      ? modeResult.stdout.trim()
      : UNIT_FILE_MODE
  const mode = rawMode.length === OCTAL_MODE_LENGTH_WITHOUT_LEADING_ZERO ? `0${rawMode}` : rawMode
  return { content, exists: true, mode }
}

async function restoreFileSnapshot(
  ssh: SshConnection,
  path: string,
  snapshot: FileSnapshot
): Promise<void> {
  if ("kind" in snapshot) {
    // R-0000720: defensive guard — callers refuse to proceed when the
    // snapshot capture failed, so the rollback should never observe this
    // branch. If a future caller routes a failed snapshot here we
    // intentionally do nothing rather than touch the live file on a
    // partially-known state. Mirrors the same guard in
    // `systemdUnitSnapshot.ts` (R-0000683).
    return
  }
  if (snapshot.exists) {
    await ssh.writeFile(path, snapshot.content, { mode: snapshot.mode })
    return
  }
  await ssh.exec(`rm -f ${shellQuote(path)}`, { ignoreExitCode: true, silent: true })
}

export async function restoreUnitFileSnapshots(
  ssh: SshConnection,
  paths: Pick<TimerPaths, "servicePath" | "timerPath">,
  snapshots: { service?: FileSnapshot; timer?: FileSnapshot }
): Promise<void> {
  if (snapshots.service != null)
    await restoreFileSnapshot(ssh, paths.servicePath, snapshots.service)
  if (snapshots.timer != null) await restoreFileSnapshot(ssh, paths.timerPath, snapshots.timer)
}
