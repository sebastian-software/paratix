import { failed, failedCommand, withRollbackFailure } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { isSymlink } from "./remoteFileChecks.js"

const CONTAINERS_SYSTEMD_DIRECTORY_COMMAND = "mkdir -p '/etc/containers/systemd'"
const QUADLET_FILE_MODE = "0644"
const SYSTEMCTL = "systemctl"

const CANONICAL_OCTAL_MODE_LENGTH = 4

/**
 * R-0000604: normalize a raw `stat -c '%a'` octal mode to the four-digit form
 * that `ssh.writeFile` and downstream SFTP backends interpret consistently.
 * `stat -c '%a'` emits the mode without a leading zero (e.g. `"644"`), but
 * some SFTP backends treat the raw three-digit string as decimal rather than
 * octal. Always returning the canonical four-digit form keeps snapshots,
 * rollbacks and mode-drift comparisons deterministic across backends.
 *
 * Analogous to `normalizeSourcesFileMode` in releaseUpgradeSources.ts.
 *
 * R-0000763: pad to the canonical four-digit length unconditionally so
 * shorter modes (e.g. world-readable `"4"` from a `0004`-only file) also
 * compare deterministically rather than being passed through unchanged.
 *
 * @param raw - Trimmed stdout from a `stat -c '%a'` invocation.
 * @returns The four-digit octal mode, or {@link QUADLET_FILE_MODE} when the
 *   input is empty.
 */
function normalizeQuadletMode(raw: string): string {
  if (raw.length === 0) return QUADLET_FILE_MODE
  return raw.padStart(CANONICAL_OCTAL_MODE_LENGTH, "0")
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
  // R-0000604: `stat -c '%a'` emits 3-digit modes like "644" without a
  // leading zero; normalize to the canonical 4-digit form so the snapshot
  // (and any later rollback) writes through `ssh.writeFile` deterministically
  // regardless of the SFTP backend's octal/decimal handling.
  const rawMode = modeResult.code === 0 ? modeResult.stdout.trim() : ""
  return {
    content,
    exists: true,
    mode: normalizeQuadletMode(rawMode),
  }
}

async function restoreQuadletFileSnapshot(
  ssh: SshConnection,
  filePath: string,
  snapshot: QuadletFileSnapshot
): Promise<void> {
  if (snapshot.exists) {
    // R-0000603: defense in depth — refuse to restore through a symlink that
    // may have appeared between the apply-time guard and rollback. The apply
    // guard runs once before the snapshot; a symlink that materializes
    // afterwards must not let `ssh.writeFile` follow it to an arbitrary
    // target during rollback.
    if (await isSymlink(ssh, filePath)) {
      throw new Error(`[quadlet.container] refuses to restore through symlink at ${filePath}`)
    }
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

  // R-0000603: refuse to apply through a symlinked quadlet file. Both
  // `snapshotQuadletFile` (via `ssh.exists`/`ssh.readFile`) and
  // `ssh.writeFile` follow symlinks; a planted symlink would otherwise let
  // apply mutate an arbitrary file outside `/etc/containers/systemd/`.
  // Mirrors the apt.repository (R-0000235) and net.dropin (R-0000526)
  // hardening pattern.
  if (await isSymlink(parameters.ssh, parameters.filePath)) {
    return failed(
      `[quadlet.container: ${parameters.name}] refuses to write through symlink at ${parameters.filePath}`
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
  // R-0000762: a symlinked unit file is not in convergence even when its
  // resolved target matches `content` and `0644` — apply must rewrite it as a
  // regular file so the apply-time symlink guard in `applyQuadletFile` and the
  // rollback-time guard in `restoreQuadletFileSnapshot` see a deterministic
  // regular file. Treating a symlink as `ok` would skip apply and leave the
  // attack surface in place.
  if (await isSymlink(parameters.ssh, parameters.filePath)) return NEEDS_APPLY
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
  // R-0000604: normalize the on-disk mode to the same canonical 4-digit form
  // we write so a `stat`-emitted "644" compares equal to the canonical
  // "0644" without relying on the unsafe `^0+` strip-and-compare hack.
  return normalizeQuadletMode(currentMode) === QUADLET_FILE_MODE ? "ok" : NEEDS_APPLY
}
