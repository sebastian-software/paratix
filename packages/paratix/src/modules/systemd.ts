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
import {
  formatCaughtError,
  restoreUnitFileSnapshot,
  restoreUnitFileSnapshotIfCurrentMatches,
  snapshotUnitFile,
  type UnitFileSnapshot,
} from "./systemdUnitSnapshot.js"
// `isSymlink` is no longer imported here: the symlink guard moved into
// `restoreUnitFileSnapshot` together with the snapshot helpers.

const SYSTEMCTL = "systemctl"
const UNIT_NAME_PATTERN = /^[\w@.\-]+$/v
const SYSTEMD_UNIT_MODE = "0644"
const SYSTEMD_UNIT_RELOAD_HASH_LENGTH = 16
const SILENT_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

function validateUnitName(name: string): string {
  // R-0000659: the unit-name pattern `^[\w@.\-]+$` lets `.` and `..` slip
  // through because both are non-empty matches of `[\w@.\-]+`. When used
  // as `${unitName}` inside paths like `/etc/systemd/system/${unitName}`
  // they would resolve to the unit directory itself (`/etc/systemd/system/`
  // or `/etc/systemd/`), turning an `ssh.writeFile` into a write to a
  // directory and an `rm -f` into a no-op on the parent dir. Reject the
  // two values up front, before the regex check, to keep the path
  // interpolation safe.
  if (name === "." || name === "..") {
    throw new Error(`Invalid systemd unit name: ${name}`)
  }
  if (!name || name.startsWith("-") || !UNIT_NAME_PATTERN.test(name)) {
    throw new Error(`Invalid systemd unit name: ${name}`)
  }
  return name
}

// R-0000772: surface toolchain failures of the `systemctl is-enabled`
// probe as a structured ModuleResult instead of blindly returning `false`.
// Without this, an inaccessible systemd bus or a `systemctl` binary that
// failed to launch (PATH issue, missing binary, transient sandbox error)
// would render the unit as "not masked" — even though the real state is
// unknown. The apply path would then either run `mask` against a
// possibly-already-masked unit (harmless) or skip `unmask` for a unit
// that is actually masked (silent regression). Mirrors the structured
// probe shape introduced for `isSwapActive` (R-0000722).
async function isUnitMasked(ssh: SshConnection, unitName: string): Promise<boolean | ModuleResult> {
  const probe = await ssh.exec(
    `${SYSTEMCTL} is-enabled -- ${shellQuote(unitName)}`,
    SILENT_EXEC_OPTS
  )
  const stdout = probe.stdout.trim()
  if (probe.code !== 0 && stdout === "") {
    return failedCommand(
      `[systemd: ${unitName}] systemctl is-enabled failed while probing masked state`,
      probe
    )
  }
  return stdout.includes("masked")
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

function failedWithRollbackFailure(message: string, rollbackError: unknown): ModuleResult {
  return failed(`${message}\nrollback failed: ${formatCaughtError(rollbackError)}`)
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
  return ssh.exec(`${SYSTEMCTL} daemon-reload`, SILENT_EXEC_OPTS)
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
  const rollback = await restoreUnitFileSnapshotIfCurrentMatches({
    expectedCurrentContent: content,
    filePath,
    snapshot,
    ssh,
  })
  // R-0000721: surface a probe-read failure alongside the primary flag
  // persistence failure. Without the chained message the readFile error
  // (e.g. transient SFTP) would shadow the user-visible reason that
  // triggered the rollback in the first place.
  if (rollback.kind === "failed") {
    return failedWithRollbackFailure(
      flagFailure.error?.message ?? "flag persistence failed",
      new Error(`rollback read of ${filePath} failed: ${rollback.reason}`)
    )
  }
  if (rollback.kind === "skipped") return flagFailure
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
    const rollback = await restoreUnitFileSnapshotIfCurrentMatches({
      expectedCurrentContent: content,
      filePath,
      snapshot,
      ssh,
    })
    // R-0000721: a soft read failure must surface alongside the original
    // daemon-reload failure — the writeFile step inside
    // `restoreUnitFileSnapshot` (still throws on symlink) keeps the
    // surrounding try/catch in place for the restore branch.
    if (rollback.kind === "failed") {
      return failedWithRollbackFailure(
        result.error?.message ?? "systemctl daemon-reload failed",
        new Error(`rollback read of ${filePath} failed: ${rollback.reason}`)
      )
    }
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
  // R-0000683: refuse to proceed when the pre-write snapshot capture failed.
  // Without this guard the writeFile path would overwrite the existing unit
  // file while the rollback would have nothing to restore — a regression of
  // the recovery contract documented in R-0000211.
  if ("kind" in snapshot) {
    return failed(
      `[systemd.unit: ${name}] failed to snapshot unit file at ${filePath}: ${snapshot.reason}`
    )
  }
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
        const result = await ssh.exec(`${SYSTEMCTL} daemon-reload`, SILENT_EXEC_OPTS)
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
        // R-0000490: skip the mask call when the unit is already masked.
        // R-0000772: a structured probe failure must short-circuit the apply
        // so the operator sees the real toolchain error instead of a
        // misleading `mask` attempt.
        const maskedProbe = await isUnitMasked(ssh, unitName)
        if (typeof maskedProbe !== "boolean") return maskedProbe
        if (maskedProbe) return { status: "ok" }
        const result = await ssh.exec(
          `${SYSTEMCTL} mask -- ${shellQuote(unitName)}`,
          SILENT_EXEC_OPTS
        )
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[systemd.masked: ${name}] systemctl mask failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        // R-0000772: a probe-toolchain failure is treated as `needs-apply`
        // so the apply phase has a chance to surface the structured error;
        // a check call has no failure channel of its own.
        const maskedProbe = await isUnitMasked(ssh, unitName)
        if (typeof maskedProbe !== "boolean") return NEEDS_APPLY
        return maskedProbe ? "ok" : NEEDS_APPLY
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
        const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(filePath)}`, SILENT_EXEC_OPTS)
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
        // R-0000490: skip the unmask call when the unit is not currently masked.
        // R-0000772: a structured probe failure short-circuits the apply
        // so the operator sees the toolchain error rather than silently
        // skipping `unmask` for a unit whose state could not be probed.
        const maskedProbe = await isUnitMasked(ssh, unitName)
        if (typeof maskedProbe !== "boolean") return maskedProbe
        if (!maskedProbe) return { status: "ok" }
        const result = await ssh.exec(
          `${SYSTEMCTL} unmask -- ${shellQuote(unitName)}`,
          SILENT_EXEC_OPTS
        )
        return result.code === 0
          ? { status: "changed" }
          : failedCommand(`[systemd.unmasked: ${name}] systemctl unmask failed`, result)
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        // R-0000772: see masked.check; a probe failure routes to NEEDS_APPLY
        // so apply can resurface the error structurally.
        const maskedProbe = await isUnitMasked(ssh, unitName)
        if (typeof maskedProbe !== "boolean") return NEEDS_APPLY
        return maskedProbe ? NEEDS_APPLY : "ok"
      },
      name: `systemd.unmasked: ${name}`,
    }
  },
}
