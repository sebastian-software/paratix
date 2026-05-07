import type { SshConnection } from "../types.js"
import type { TimerPaths } from "./timerHelpers.js"

import { shellQuote } from "../ssh.js"

const UNIT_FILE_MODE = "0644"

type FileSnapshot = { content: string; exists: true } | { exists: false }

export async function readFileSnapshot(ssh: SshConnection, path: string): Promise<FileSnapshot> {
  if (!(await ssh.exists(path))) return { exists: false }
  return { content: await ssh.readFile(path), exists: true }
}

async function restoreFileSnapshot(
  ssh: SshConnection,
  path: string,
  snapshot: FileSnapshot
): Promise<void> {
  if (snapshot.exists) {
    await ssh.writeFile(path, snapshot.content, { mode: UNIT_FILE_MODE })
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
