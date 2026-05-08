import type { SshConnection } from "../types.js"
import type { TimerPaths } from "./timerHelpers.js"

import { shellQuote } from "../ssh.js"

const UNIT_FILE_MODE = "0644"
const OCTAL_MODE_LENGTH_WITHOUT_LEADING_ZERO = 3

type FileSnapshot = { content: string; exists: true; mode: string } | { exists: false }

// R-0000217: Capture the file mode in the snapshot so the rollback can
// restore the exact mode the operator had configured. The previous
// implementation hardcoded `0644` on restore and would silently overwrite
// a manual `chmod 0600` (e.g. for a unit that contains an EnvironmentFile
// path). Mirrors the snapshotting in `quadlet.ts` and `systemd.ts`.
export async function readFileSnapshot(ssh: SshConnection, path: string): Promise<FileSnapshot> {
  if (!(await ssh.exists(path))) return { exists: false }
  const content = await ssh.readFile(path)
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
