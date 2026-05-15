import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecResult,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { sha256String } from "./fileHelpers.js"
import { hasFlag, setVersionedFlag } from "./moduleHelpers.js"

const SYSTEMCTL = "systemctl"
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v
const SYSTEMD_UNIT_MODE = "0644"
const SYSTEMD_UNIT_RELOAD_HASH_LENGTH = 16

function validateUnitName(name: string): string {
  if (!name || name.startsWith("-") || !UNIT_NAME_PATTERN.test(name)) {
    throw new Error(`Invalid systemd unit name: ${name}`)
  }
  return name
}

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

function buildSystemdUnitReloadFlag(
  name: string,
  content: string
): {
  flagName: string
  flagPrefix: string
} {
  const flagPrefix = `systemd-unit-${sha256String(name).slice(0, SYSTEMD_UNIT_RELOAD_HASH_LENGTH)}-`
  return {
    flagName: `${flagPrefix}${sha256String(content).slice(0, SYSTEMD_UNIT_RELOAD_HASH_LENGTH)}`,
    flagPrefix,
  }
}

type UnitFileSnapshot =
  | {
      content: string
      exists: true
      mode: string
    }
  | { exists: false }

const formatCaughtError = (error: unknown): string =>
  error instanceof Error ? error.message : String(error)

function failedWithRollbackFailure(message: string, rollbackError: unknown): ModuleResult {
  return failed(`${message}\nrollback failed: ${formatCaughtError(rollbackError)}`)
}

async function snapshotUnitFile(ssh: SshConnection, filePath: string): Promise<UnitFileSnapshot> {
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
        : SYSTEMD_UNIT_MODE,
  }
}

async function restoreUnitFileSnapshot(
  ssh: SshConnection,
  filePath: string,
  snapshot: UnitFileSnapshot
): Promise<void> {
  if (snapshot.exists) {
    await ssh.writeFile(filePath, snapshot.content, { mode: snapshot.mode })
    return
  }
  await ssh.exec(`rm -f ${shellQuote(filePath)}`, { ignoreExitCode: true, silent: true })
}

async function restoreUnitFileSnapshotIfCurrentMatches(parameters: {
  expectedCurrentContent: string
  filePath: string
  snapshot: UnitFileSnapshot
  ssh: SshConnection
}): Promise<boolean> {
  const { expectedCurrentContent, filePath, snapshot, ssh } = parameters
  if (!(await ssh.exists(filePath))) return false
  const currentContent = await ssh.readFile(filePath)
  if (currentContent !== expectedCurrentContent) return false
  await restoreUnitFileSnapshot(ssh, filePath, snapshot)
  return true
}

/**
 * Write a systemd unit file with rollback on writeFile failure.
 *
 * @param parameters - Unit-file write context.
 * @param parameters.content - The full unit file content to write.
 * @param parameters.filePath - Absolute remote path of the unit file.
 * @param parameters.name - Unit name used in failure messages.
 * @param parameters.snapshot - Pre-write snapshot used to roll back on failure.
 * @param parameters.ssh - The active SSH connection.
 * @returns A failed `ModuleResult` when writeFile failed, otherwise `null`.
 */
async function writeSystemdUnitFile(parameters: {
  content: string
  filePath: string
  name: string
  snapshot: UnitFileSnapshot
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { content, filePath, name, snapshot, ssh } = parameters
  // R-0000211: writeFile can throw (SFTP error after a partial write,
  // permission denied, network drop). Without this guard the unit file
  // would stay half-written while the original snapshot is discarded
  // unrestored. Mirrors the quadlet pattern from R-0000182.
  try {
    await ssh.writeFile(filePath, content, { mode: SYSTEMD_UNIT_MODE })
    return null
  } catch (error) {
    const message = `[systemd.unit: ${name}] failed to write unit file: ${formatCaughtError(error)}`
    try {
      await restoreUnitFileSnapshot(ssh, filePath, snapshot)
    } catch (rollbackError) {
      return failedWithRollbackFailure(message, rollbackError)
    }
    return failed(message)
  }
}

async function reloadSystemdDaemon(ssh: SshConnection): Promise<ExecResult> {
  return ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
}

async function rollbackUnitAfterFlagPersistenceFailure(parameters: {
  content: string
  filePath: string
  flagFailure: ModuleResult
  name: string
  snapshot: UnitFileSnapshot
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { content, filePath, flagFailure, name, snapshot, ssh } = parameters
  const didRollback = await restoreUnitFileSnapshotIfCurrentMatches({
    expectedCurrentContent: content,
    filePath,
    snapshot,
    ssh,
  })
  if (!didRollback) return flagFailure
  const rollbackReload = await reloadSystemdDaemon(ssh)
  if (rollbackReload.code !== 0) {
    return failedCommand(
      `[systemd.unit: ${name}] rollback systemctl daemon-reload failed after flag persistence failure`,
      rollbackReload
    )
  }
  return flagFailure
}

async function rollbackUnitAfterDaemonReloadFailure(parameters: {
  content: string
  filePath: string
  name: string
  reloadFailure: ExecResult
  snapshot: UnitFileSnapshot
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { content, filePath, name, reloadFailure, snapshot, ssh } = parameters
  const result = failedCommand(
    `[systemd.unit: ${name}] systemctl daemon-reload failed`,
    reloadFailure
  )
  try {
    await restoreUnitFileSnapshotIfCurrentMatches({
      expectedCurrentContent: content,
      filePath,
      snapshot,
      ssh,
    })
  } catch (error) {
    return failedWithRollbackFailure(
      result.error?.message ?? "systemctl daemon-reload failed",
      error
    )
  }
  return result
}

/**
 * Apply a systemd unit file write + daemon-reload pipeline with rollback on
 * any intermediate failure (write, reload, flag persist).
 *
 * @param parameters - Unit deployment context.
 * @param parameters.content - The full unit file content.
 * @param parameters.filePath - Absolute remote path of the unit file.
 * @param parameters.name - Unit name used in failure messages.
 * @param parameters.reloadFlag - Flag descriptor used to mark reload completion.
 * @param parameters.reloadFlag.flagName - Versioned flag file name written on success.
 * @param parameters.reloadFlag.flagPrefix - Flag prefix used to evict older versions.
 * @param parameters.ssh - The active SSH connection.
 * @returns The module result for the apply operation.
 */
async function applySystemdUnit(parameters: {
  content: string
  filePath: string
  name: string
  reloadFlag: { flagName: string; flagPrefix: string }
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { content, filePath, name, reloadFlag, ssh } = parameters
  const snapshot = await snapshotUnitFile(ssh, filePath)
  const writeFailure = await writeSystemdUnitFile({ content, filePath, name, snapshot, ssh })
  if (writeFailure) return writeFailure
  const result = await reloadSystemdDaemon(ssh)
  if (result.code !== 0) {
    return rollbackUnitAfterDaemonReloadFailure({
      content,
      filePath,
      name,
      reloadFailure: result,
      snapshot,
      ssh,
    })
  }
  // R-0000273: surface flag-persist failures (EROFS/EPERM/ENOSPC) through
  // the failedCommand path; the helper no longer throws.
  const flagFailure = await setVersionedFlag(ssh, reloadFlag.flagName, reloadFlag.flagPrefix)
  if (flagFailure) {
    return rollbackUnitAfterFlagPersistenceFailure({
      content,
      filePath,
      flagFailure,
      name,
      snapshot,
      ssh,
    })
  }
  return { status: "changed" }
}

/**
 * Modules for managing systemd unit files and unit masking.
 *
 * The `unit` method writes unit files with idempotent checks and triggers a daemon-reload
 * on change. `masked` and `unmasked` control unit masking state.
 * `daemonReload` is a signal-style method that always applies.
 */
export const systemd = {
  /**
   * Reload the systemd manager configuration. Intended as a recipe signal --
   * always applies.
   * @returns A Module that runs `systemctl daemon-reload`.
   */
  daemonReload(): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[systemd.daemonReload] SSH connection is required")
        const result = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand("[systemd.daemonReload] systemctl daemon-reload failed", result)
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(): Promise<"needs-apply" | "ok"> {
        // Signal: always needs apply
        return NEEDS_APPLY
      },
      name: "systemd.daemonReload",
    }
  },

  /**
   * Ensure a systemd unit is masked and cannot be started.
   * @param name - The systemd unit name (e.g. `"apt-daily.timer"`).
   * @returns A Module that ensures the unit is masked.
   */
  masked(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[systemd.masked: ${name}] SSH connection is required`)
        // R-0000490: short-circuit when the unit is already masked. Mirrors
        // the `is-enabled` probe used in the check function so apply does
        // not emit `changed` for a converged state.
        const probe = await ssh.exec(`${SYSTEMCTL} is-enabled -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (probe.stdout.trim().includes("masked")) return { status: "ok" }
        const result = await ssh.exec(`${SYSTEMCTL} mask -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[systemd.masked: ${name}] systemctl mask failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const result = await ssh.exec(`${SYSTEMCTL} is-enabled -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.stdout.trim().includes("masked") ? "ok" : NEEDS_APPLY
      },
      name: `systemd.masked: ${name}`,
    }
  },

  /**
   * Write a systemd unit file to `/etc/systemd/system/` and reload the
   * daemon configuration when the content changes.
   *
   * The check phase compares the remote file content with the desired
   * content string. Apply writes the file and runs `systemctl daemon-reload`.
   *
   * @param name - Unit file name (e.g. `"my-app.service"` or `"backup.timer"`).
   * @param content - The full unit file content.
   * @returns A Module that ensures the unit file is present with the given content.
   */
  unit(name: string, content: string): Module {
    const unitName = validateUnitName(name)
    const filePath = `/etc/systemd/system/${unitName}`
    const reloadFlag = buildSystemdUnitReloadFlag(unitName, content)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[systemd.unit: ${name}] SSH connection is required`)
        return applySystemdUnit({ content, filePath, name, reloadFlag, ssh })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const exists = await ssh.exists(filePath)
        if (!exists) return NEEDS_APPLY
        const remoteContent = await ssh.readFile(filePath)
        if (remoteContent.trim() !== content.trim()) return NEEDS_APPLY
        const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(filePath)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (modeResult.code !== 0) return NEEDS_APPLY
        const currentMode = modeResult.stdout.trim()
        if (currentMode === "") return NEEDS_APPLY
        if (normalizeMode(currentMode) !== normalizeMode(SYSTEMD_UNIT_MODE)) return NEEDS_APPLY
        return (await hasFlag(ssh, reloadFlag.flagName)) ? "ok" : NEEDS_APPLY
      },
      name: `systemd.unit: ${name}`,
    }
  },

  /**
   * Ensure a systemd unit is unmasked and can be started normally.
   * @param name - The systemd unit name (e.g. `"apt-daily.timer"`).
   * @returns A Module that ensures the unit is unmasked.
   */
  unmasked(name: string): Module {
    const unitName = validateUnitName(name)
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[systemd.unmasked: ${name}] SSH connection is required`)
        // R-0000490: short-circuit when the unit is already unmasked. Mirrors
        // the `is-enabled` probe used in the check function so apply does
        // not emit `changed` for a converged state.
        const probe = await ssh.exec(`${SYSTEMCTL} is-enabled -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (!probe.stdout.trim().includes("masked")) return { status: "ok" }
        const result = await ssh.exec(`${SYSTEMCTL} unmask -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[systemd.unmasked: ${name}] systemctl unmask failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        const result = await ssh.exec(`${SYSTEMCTL} is-enabled -- ${shellQuote(unitName)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        return result.stdout.trim().includes("masked") ? NEEDS_APPLY : "ok"
      },
      name: `systemd.unmasked: ${name}`,
    }
  },
}
