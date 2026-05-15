import { failed, failedCommand, withRollbackFailure } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const CONTAINERS_SYSTEMD_DIRECTORY_COMMAND = "mkdir -p '/etc/containers/systemd'"
const QUADLET_FILE_MODE = "0644"
const SYSTEMCTL = "systemctl"

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

type QuadletFileSnapshot =
  | {
      content: string
      exists: true
      mode: string
    }
  | { exists: false }

async function snapshotQuadletFile(
  ssh: SshConnection,
  filePath: string
): Promise<QuadletFileSnapshot> {
  if (!(await ssh.exists(filePath))) return { exists: false }
  const content = await ssh.readFile(filePath)
  const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(filePath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  return {
    content,
    exists: true,
    mode:
      modeResult.code === 0 && modeResult.stdout.trim() !== ""
        ? modeResult.stdout.trim()
        : QUADLET_FILE_MODE,
  }
}

async function restoreQuadletFileSnapshot(
  ssh: SshConnection,
  filePath: string,
  snapshot: QuadletFileSnapshot
): Promise<void> {
  if (snapshot.exists) {
    await ssh.writeFile(filePath, snapshot.content, { mode: snapshot.mode })
    return
  }
  await ssh.exec(`rm -f ${shellQuote(filePath)}`, { ignoreExitCode: true, silent: true })
}

export async function applyQuadletFile(parameters: {
  content: string
  filePath: string
  name: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const mkdirResult = await parameters.ssh.exec(CONTAINERS_SYSTEMD_DIRECTORY_COMMAND, {
    ignoreExitCode: true,
    silent: true,
  })
  if (mkdirResult.code !== 0) {
    return failedCommand(
      `[quadlet.container: ${parameters.name}] failed to create quadlet directory`,
      mkdirResult
    )
  }

  const snapshot = await snapshotQuadletFile(parameters.ssh, parameters.filePath)
  const restoreSnapshot = async (): Promise<void> => {
    await restoreQuadletFileSnapshot(parameters.ssh, parameters.filePath, snapshot)
  }
  try {
    await parameters.ssh.writeFile(parameters.filePath, parameters.content, {
      mode: QUADLET_FILE_MODE,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return withRollbackFailure(
      failed(`[quadlet.container: ${parameters.name}] failed to write quadlet file: ${reason}`),
      restoreSnapshot,
      "quadlet apply failed"
    )
  }

  const daemonReload = await parameters.ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (daemonReload.code === 0) return { status: "changed" }
  return withRollbackFailure(
    failedCommand(
      `[quadlet.container: ${parameters.name}] systemctl daemon-reload failed`,
      daemonReload
    ),
    restoreSnapshot,
    "quadlet apply failed"
  )
}

export async function checkQuadletFile(parameters: {
  content: string
  filePath: string
  ssh: SshConnection
}): Promise<"needs-apply" | "ok"> {
  const exists = await parameters.ssh.exists(parameters.filePath)
  if (!exists) return NEEDS_APPLY
  const remoteContent = await parameters.ssh.readFile(parameters.filePath)
  if (remoteContent.trim() !== parameters.content.trim()) return NEEDS_APPLY
  const modeResult = await parameters.ssh.exec(`stat -c '%a' ${shellQuote(parameters.filePath)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (modeResult.code !== 0) return NEEDS_APPLY
  const currentMode = modeResult.stdout.trim()
  if (currentMode === "") return NEEDS_APPLY
  return normalizeMode(currentMode) === normalizeMode(QUADLET_FILE_MODE) ? "ok" : NEEDS_APPLY
}
