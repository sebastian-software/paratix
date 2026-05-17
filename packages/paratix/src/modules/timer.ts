/* eslint-disable max-lines -- timer module keeps related lifecycle helpers (sync, restart, absent) together for cohesion */
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecResult,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { readFileSnapshot, restoreUnitFileSnapshots } from "./timerFileSnapshots.js"
import {
  assertTimerName,
  buildTimerLocations,
  buildTimerPaths,
  type TimerLocations,
  type TimerPaths,
  type TimerScheduledOptions,
  validatePresentOptions,
} from "./timerHelpers.js"

const SYSTEMCTL = "systemctl"
const UNIT_FILE_MODE = "0644"

function normalizeMode(mode: string): string {
  return mode.replace(/^0+/v, "")
}

type FileMatchSpec = {
  expected: string
  expectedMode?: string
  path: string
}

// When `apply` runs after a `check` that already inspected the same paths,
// this issues another `exists`/`readFile` round-trip. The extra calls are
// accepted because the check phase only reports `needs-apply`/`ok` and does
// not propagate read results to apply, and re-reading right before writing
// avoids acting on stale data when the remote state changes between phases.
//
// When `expectedMode` is supplied, the file's current mode is read via
// `stat -c '%a'` and compared after normalizing leading zeros so that values
// like `"644"` and `"0644"` compare equal. Any failure to obtain a mode --
// missing file, stat failure, or empty output -- counts as a mismatch so the
// caller treats the file as needing apply.
async function fileMatches(ssh: SshConnection, spec: FileMatchSpec): Promise<boolean> {
  if (!(await ssh.exists(spec.path))) return false
  const remote = await ssh.readFile(spec.path)
  if (remote.trim() !== spec.expected.trim()) return false
  if (spec.expectedMode === undefined) return true
  const modeResult = await ssh.exec(`stat -c '%a' ${shellQuote(spec.path)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (modeResult.code !== 0) return false
  const currentMode = modeResult.stdout.trim()
  if (currentMode === "") return false
  return normalizeMode(currentMode) === normalizeMode(spec.expectedMode)
}

async function checkPresent(ssh: SshConnection, paths: TimerPaths): Promise<"needs-apply" | "ok"> {
  const serviceMatched = await fileMatches(ssh, {
    expected: paths.serviceContent,
    expectedMode: UNIT_FILE_MODE,
    path: paths.servicePath,
  })
  if (!serviceMatched) return NEEDS_APPLY
  const timerMatched = await fileMatches(ssh, {
    expected: paths.timerContent,
    expectedMode: UNIT_FILE_MODE,
    path: paths.timerPath,
  })
  if (!timerMatched) return NEEDS_APPLY
  const enabled = await ssh.test(
    `${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(paths.timerUnit)}`
  )
  if (!enabled) return NEEDS_APPLY
  const active = await ssh.test(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(paths.timerUnit)}`)
  return active ? "ok" : NEEDS_APPLY
}

async function checkAbsent(
  ssh: SshConnection,
  locations: TimerLocations
): Promise<"needs-apply" | "ok"> {
  if (await ssh.exists(locations.servicePath)) return NEEDS_APPLY
  if (await ssh.exists(locations.timerPath)) return NEEDS_APPLY
  return (await hasResidualTimerState(ssh, locations.timerUnit)) ? NEEDS_APPLY : "ok"
}

type SyncOutcome =
  | { failure: ModuleResult; ok: false }
  | { ok: true; serviceMatched: boolean; timerMatched: boolean }

type SnapshotPair = Parameters<typeof restoreUnitFileSnapshots>[2]

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function describeExecResult(result: ExecResult): string {
  const detail = result.stderr.trim() || result.stdout.trim()
  return detail === "" ? `exit code ${String(result.code)}` : detail
}

// R-0000655: optional activation context. When present, after a successful
// `restoreUnitFileSnapshots` the helper additionally performs a second
// `systemctl daemon-reload` (so systemd picks up the restored unit files
// on disk) and replays the pre-apply enable/active state through
// `restoreTimerActivationForAbsent`. Without these two steps the absent
// path could leave the timer in "files present but disabled" — the unit
// files would be back on disk but systemd would still believe they had
// been removed and the timer would no longer fire.
type ReloadFailureRollbackActivationContext = {
  context: AbsentContext
  snapshot: TimerActivationSnapshot
}

async function restoreUnitFileSnapshotsAfterReloadFailure(
  ssh: SshConnection,
  parameters: {
    activation?: ReloadFailureRollbackActivationContext
    message: string
    paths: Pick<TimerPaths, "servicePath" | "timerPath">
    reload: ExecResult
    snapshots: SnapshotPair
  }
): Promise<ModuleResult> {
  try {
    await restoreUnitFileSnapshots(ssh, parameters.paths, parameters.snapshots)
  } catch (error) {
    return failed(
      `${parameters.message}; rollback of timer unit files also failed: ${describeError(error)}; original daemon-reload failure: ${describeExecResult(parameters.reload)}`
    )
  }
  // R-0000655: when invoked from the absent path, additionally tell
  // systemd about the restored files (mirrors the post-rollback
  // daemon-reload in `handleAbsentUnitRemovalFailure` lines 428-439)
  // and replay the pre-apply enable/active state so the timer ends up
  // in its original state, not "files present but disabled". The
  // present path leaves `activation` undefined and keeps the historic
  // failedCommand behaviour.
  const baseFailure = failedCommand(parameters.message, parameters.reload)
  const { activation } = parameters
  if (activation == null) return baseFailure
  const reloadAfterRestore = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (reloadAfterRestore.code !== 0) {
    return failed(
      `${parameters.message}: ${describeExecResult(
        parameters.reload
      )}; daemon-reload after unit-file rollback also failed: ${describeExecResult(
        reloadAfterRestore
      )}`
    )
  }
  const activationFailure = await restoreTimerActivationForAbsent(
    ssh,
    activation.context,
    activation.snapshot
  )
  if (activationFailure == null) return baseFailure
  const baseMessage = baseFailure.error?.message ?? parameters.message
  const restoreMessage = activationFailure.error?.message ?? "timer activation rollback failed"
  return failed(`${baseMessage}; ${restoreMessage}`)
}

async function restoreUnitFileSnapshotsAfterWriteFailure(
  ssh: SshConnection,
  parameters: {
    message: string
    paths: Pick<TimerPaths, "servicePath" | "timerPath">
    snapshots: SnapshotPair
    writeError: unknown
  }
): Promise<ModuleResult> {
  try {
    await restoreUnitFileSnapshots(ssh, parameters.paths, parameters.snapshots)
  } catch (restoreError) {
    return failed(
      `${parameters.message}: ${describeError(
        parameters.writeError
      )}; rollback of timer unit files also failed: ${describeError(restoreError)}`
    )
  }
  return failed(`${parameters.message}: ${describeError(parameters.writeError)}`)
}

// R-0000216: writeFile can throw (SFTP error after a partial write,
// permission denied, network drop). Wrap both writes in a shared
// try/catch so a throw on the second writeFile cannot leave the first
// file modified — the captured snapshots restore both back to the
// pre-apply state, and the caller surfaces a failed result.
async function writeTimerUnitFiles(
  ssh: SshConnection,
  parameters: {
    name: string
    paths: TimerPaths
    serviceMatched: boolean
    snapshots: SnapshotPair
    timerMatched: boolean
  }
): Promise<ModuleResult | null> {
  const { name, paths, serviceMatched, snapshots, timerMatched } = parameters
  try {
    if (!serviceMatched) {
      await ssh.writeFile(paths.servicePath, paths.serviceContent, { mode: UNIT_FILE_MODE })
    }
    if (!timerMatched) {
      await ssh.writeFile(paths.timerPath, paths.timerContent, { mode: UNIT_FILE_MODE })
    }
    return null
  } catch (error) {
    return restoreUnitFileSnapshotsAfterWriteFailure(ssh, {
      message: `[timer.scheduled: ${name}] failed to write timer unit files`,
      paths,
      snapshots,
      writeError: error,
    })
  }
}

async function reloadDaemonAfterTimerSync(
  ssh: SshConnection,
  parameters: { name: string; paths: TimerPaths; snapshots: SnapshotPair }
): Promise<ModuleResult | null> {
  const reload = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (reload.code === 0) return null
  return restoreUnitFileSnapshotsAfterReloadFailure(ssh, {
    message: `[timer.scheduled: ${parameters.name}] systemctl daemon-reload failed`,
    paths: parameters.paths,
    reload,
    snapshots: parameters.snapshots,
  })
}

async function syncUnitFiles(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<SyncOutcome> {
  const serviceMatched = await fileMatches(ssh, {
    expected: paths.serviceContent,
    expectedMode: UNIT_FILE_MODE,
    path: paths.servicePath,
  })
  const timerMatched = await fileMatches(ssh, {
    expected: paths.timerContent,
    expectedMode: UNIT_FILE_MODE,
    path: paths.timerPath,
  })
  const snapshots: SnapshotPair = {
    service: serviceMatched ? undefined : await readFileSnapshot(ssh, paths.servicePath),
    timer: timerMatched ? undefined : await readFileSnapshot(ssh, paths.timerPath),
  }

  const writeFailure = await writeTimerUnitFiles(ssh, {
    name,
    paths,
    serviceMatched,
    snapshots,
    timerMatched,
  })
  if (writeFailure != null) return { failure: writeFailure, ok: false }

  if (serviceMatched && timerMatched) return { ok: true, serviceMatched, timerMatched }

  const reloadFailure = await reloadDaemonAfterTimerSync(ssh, { name, paths, snapshots })
  if (reloadFailure != null) return { failure: reloadFailure, ok: false }
  return { ok: true, serviceMatched, timerMatched }
}

async function isTimerFullyActive(ssh: SshConnection, timerUnit: string): Promise<boolean> {
  const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(timerUnit)}`)
  if (!enabled) return false
  return ssh.test(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(timerUnit)}`)
}

async function hasResidualTimerState(ssh: SshConnection, timerUnit: string): Promise<boolean> {
  const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(timerUnit)}`)
  if (enabled) return true
  return ssh.test(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(timerUnit)}`)
}

function isMissingUnitDisableResult(result: { stderr?: string; stdout?: string }): boolean {
  const output = `${result.stderr ?? ""}\n${result.stdout ?? ""}`.toLowerCase()
  return (
    output.includes("no such unit") ||
    (output.includes("unit file") && output.includes("does not exist"))
  )
}

type RestartContext = {
  name: string
  needsRestartForContentChange: boolean
  needsRestartForStaleState: boolean
  paths: TimerPaths
}

// Restart the timer in two situations:
//   1. The timer unit content changed -- restart re-reads the schedule.
//   2. The unit files match on disk but the timer was not fully active
//      (stale RAM state, e.g. after a `systemctl edit` override that was
//      reverted). `enable --now` does not pick up such drift, so we force a
//      `daemon-reload` plus `restart` to reset the in-memory state.
// Without a content change and a healthy active state, `enable --now`
// already started it and restarting would just abort an in-flight oneshot
// job.
async function restartTimerIfNeeded(
  ssh: SshConnection,
  context: RestartContext
): Promise<ModuleResult | null> {
  const { name, needsRestartForContentChange, needsRestartForStaleState, paths } = context
  if (!needsRestartForContentChange && !needsRestartForStaleState) return null

  if (needsRestartForStaleState) {
    const reload = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (reload.code !== 0) {
      return failedCommand(`[timer.scheduled: ${name}] systemctl daemon-reload failed`, reload)
    }
  }
  const restart = await ssh.exec(`${SYSTEMCTL} restart -- ${shellQuote(paths.timerUnit)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (restart.code !== 0) {
    return failedCommand(`[timer.scheduled: ${name}] systemctl restart failed`, restart)
  }
  return null
}

async function applyPresent(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<ModuleResult> {
  const sync = await syncUnitFiles(ssh, name, paths)
  if (!sync.ok) return sync.failure

  const filesMatched = sync.serviceMatched && sync.timerMatched
  const fullyActive = filesMatched ? await isTimerFullyActive(ssh, paths.timerUnit) : false

  // If both files matched and the timer is already enabled and active, nothing
  // needs to change. Reporting `ok` here keeps direct apply calls (e.g. inside
  // recipes) from triggering spurious change signals.
  if (filesMatched && fullyActive) {
    return { status: "ok" }
  }

  const enable = await ssh.exec(`${SYSTEMCTL} enable --now -- ${shellQuote(paths.timerUnit)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (enable.code !== 0) {
    return failedCommand(`[timer.scheduled: ${name}] systemctl enable --now failed`, enable)
  }

  const restartFailure = await restartTimerIfNeeded(ssh, {
    name,
    needsRestartForContentChange: !sync.timerMatched,
    needsRestartForStaleState: filesMatched && !fullyActive,
    paths,
  })
  if (restartFailure) return restartFailure

  return { status: "changed" }
}

type AbsentContext = { locations: TimerLocations; module: string; name: string }

type TimerActivationSnapshot = {
  active: boolean
  enabled: boolean
}

async function readTimerActivationSnapshot(
  ssh: SshConnection,
  timerUnit: string
): Promise<TimerActivationSnapshot> {
  const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(timerUnit)}`)
  const active = await ssh.test(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(timerUnit)}`)
  return { active, enabled }
}

async function runTimerActivationRollback(
  ssh: SshConnection,
  context: AbsentContext,
  parameters: { action: string; command: string }
): Promise<ModuleResult | null> {
  const restore = await ssh.exec(parameters.command, {
    ignoreExitCode: true,
    silent: true,
  })
  if (restore.code === 0) return null
  return failedCommand(
    `[${context.module}: ${context.name}] systemctl ${parameters.action} rollback failed`,
    restore
  )
}

async function restoreTimerActivationForAbsent(
  ssh: SshConnection,
  context: AbsentContext,
  snapshot: TimerActivationSnapshot
): Promise<ModuleResult | null> {
  const { locations } = context
  if (snapshot.enabled && snapshot.active) {
    return runTimerActivationRollback(ssh, context, {
      action: "enable --now",
      command: `${SYSTEMCTL} enable --now -- ${shellQuote(locations.timerUnit)}`,
    })
  }
  if (snapshot.enabled) {
    return runTimerActivationRollback(ssh, context, {
      action: "enable",
      command: `${SYSTEMCTL} enable -- ${shellQuote(locations.timerUnit)}`,
    })
  }
  if (snapshot.active) {
    return runTimerActivationRollback(ssh, context, {
      action: "start",
      command: `${SYSTEMCTL} start -- ${shellQuote(locations.timerUnit)}`,
    })
  }
  return null
}

async function disableTimerForAbsent(
  ssh: SshConnection,
  context: AbsentContext
): Promise<ModuleResult | undefined> {
  const { locations, module, name } = context
  // Run before deleting files so `disable --now` can remove the wants/ symlink.
  // Only tolerate missing-unit races; real disable failures may leave active state.
  const disable = await ssh.exec(
    `${SYSTEMCTL} disable --now -- ${shellQuote(locations.timerUnit)}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  if (disable.code === 0 || isMissingUnitDisableResult(disable)) return undefined
  return failedCommand(`[${module}: ${name}] systemctl disable --now failed`, disable)
}

async function handleAbsentUnitRemovalFailure(
  ssh: SshConnection,
  parameters: {
    message: string
    paths: Pick<TimerPaths, "servicePath" | "timerPath">
    remove: ExecResult
    snapshots: SnapshotPair
  }
): Promise<ModuleResult> {
  const { message, paths, remove, snapshots } = parameters
  try {
    await restoreUnitFileSnapshots(ssh, paths, snapshots)
  } catch (error) {
    return failed(
      `${message}: ${describeExecResult(
        remove
      )}; rollback of timer unit files also failed: ${describeError(error)}`
    )
  }
  const reloadAfterRestore = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (reloadAfterRestore.code === 0) return failedCommand(message, remove)
  return failed(
    `${message}: ${describeExecResult(
      remove
    )}; daemon-reload after unit-file rollback also failed: ${describeExecResult(
      reloadAfterRestore
    )}`
  )
}

async function removeAbsentUnitFiles(
  ssh: SshConnection,
  context: AbsentContext,
  parameters: {
    activationSnapshot: TimerActivationSnapshot
    existing: { service: boolean; timer: boolean }
  }
): Promise<ModuleResult | null> {
  const { locations, module, name } = context
  const { activationSnapshot, existing } = parameters
  const snapshots = {
    service: existing.service ? await readFileSnapshot(ssh, locations.servicePath) : undefined,
    timer: existing.timer ? await readFileSnapshot(ssh, locations.timerPath) : undefined,
  }
  if (existing.service || existing.timer) {
    const remove = await ssh.exec(
      `rm -f ${shellQuote(locations.timerPath)} ${shellQuote(locations.servicePath)}`,
      { ignoreExitCode: true, silent: true }
    )
    if (remove.code !== 0) {
      return handleAbsentUnitRemovalFailure(ssh, {
        message: `[${module}: ${name}] failed to remove unit files`,
        paths: locations,
        remove,
        snapshots,
      })
    }
  }
  const reload = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (reload.code === 0) return null
  // R-0000655: when the post-rm daemon-reload fails, restoring the unit
  // files must be followed by another daemon-reload (so systemd
  // re-reads them) and by `restoreTimerActivationForAbsent` (so the
  // pre-apply enable/active state comes back). Without the second
  // step the timer would end up in "files present but disabled".
  return restoreUnitFileSnapshotsAfterReloadFailure(ssh, {
    activation: { context, snapshot: activationSnapshot },
    message: `[${module}: ${name}] systemctl daemon-reload failed`,
    paths: locations,
    reload,
    snapshots,
  })
}

// R-0000552: previously the `??` fallback caused a rollback failure to
// completely shadow the original `removeFailure` message. Chain both
// errors instead so the primary failure (unit-file removal) stays
// visible alongside the follow-up rollback failure.
async function handleAbsentRemoveFailure(
  ssh: SshConnection,
  context: AbsentContext,
  parameters: {
    activationSnapshot: TimerActivationSnapshot
    removeFailure: ModuleResult
  }
): Promise<ModuleResult> {
  const { activationSnapshot, removeFailure } = parameters
  const activationRestoreFailure = await restoreTimerActivationForAbsent(
    ssh,
    context,
    activationSnapshot
  )
  if (!activationRestoreFailure) return removeFailure
  const removeMessage = removeFailure.error?.message ?? "timer unit-file removal failed"
  const restoreMessage =
    activationRestoreFailure.error?.message ?? "timer activation rollback failed"
  return failed(`${removeMessage}; rollback enable failed: ${restoreMessage}`)
}

async function applyAbsent(ssh: SshConnection, context: AbsentContext): Promise<ModuleResult> {
  const { locations } = context

  // Idempotent no-op: if neither unit file exists, there is nothing to clean
  // up unless systemd still has residual active/enabled state for the timer.
  const serviceExists = await ssh.exists(locations.servicePath)
  const timerExists = await ssh.exists(locations.timerPath)
  const activationSnapshot = await readTimerActivationSnapshot(ssh, locations.timerUnit)
  const residualState = activationSnapshot.enabled || activationSnapshot.active
  if (!serviceExists && !timerExists && !residualState) return { status: "ok" }

  const disableFailure = await disableTimerForAbsent(ssh, context)
  if (disableFailure) return disableFailure

  const removeFailure = await removeAbsentUnitFiles(ssh, context, {
    activationSnapshot,
    existing: { service: serviceExists, timer: timerExists },
  })
  if (removeFailure) {
    return handleAbsentRemoveFailure(ssh, context, { activationSnapshot, removeFailure })
  }
  return { status: "changed" }
}

/**
 * Modules for managing systemd timer-driven scheduled tasks.
 *
 * `scheduled(name, options)` is the timer-based equivalent of `cron.job`: it
 * generates a `.service` and `.timer` unit pair under `/etc/systemd/system/`,
 * reloads systemd, and enables and starts the timer in a single idempotent
 * step. Compared to cron, this gives you `Persistent=` for catch-up runs,
 * journald logging, and richer scheduling expressions.
 */
export const timer = {
  /**
   * Ensure a systemd timer-driven scheduled task does not exist.
   *
   * Disables and stops `<name>.timer`, removes both `<name>.service` and
   * `<name>.timer` from `/etc/systemd/system/`, and reloads systemd. The
   * `disable --now` step also removes the timer's `wants/` symlink. Failure
   * to disable a unit that does not exist is ignored, so this method is
   * safe to apply repeatedly.
   *
   * Behaves like `timer.scheduled(name, { exec: "<unused>", onCalendar: "<unused>", state: "absent" })`,
   * but does not require placeholder values for `exec` or `onCalendar` and
   * reports failures with a `timer.absent` prefix instead of `timer.scheduled`.
   *
   * @param name - Base unit name without extension. Must match
   *   `^[A-Za-z0-9_\-]+$`.
   * @returns A Module that ensures the timer-driven scheduled task is absent.
   */
  absent(name: string): Module {
    assertTimerName(name)
    const locations = buildTimerLocations(name)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[timer.absent: ${name}] SSH connection is required`)
        return applyAbsent(ssh, { locations, module: "timer.absent", name })
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return checkAbsent(ssh, locations)
      },
      name: `timer.absent: ${name}`,
    }
  },

  /**
   * Ensure a systemd timer-driven scheduled task is present (or absent).
   *
   * Generates `<name>.service` (`Type=oneshot`, no `[Install]` section since
   * it is triggered exclusively by the timer) and `<name>.timer` under
   * `/etc/systemd/system/`, reloads systemd, and runs
   * `systemctl enable --now <name>.timer`. When the timer unit content
   * changed, the timer is restarted so a new `OnCalendar=` schedule is picked
   * up immediately. With `state: "absent"`, the timer is disabled and
   * stopped, both unit files are removed, and systemd is reloaded.
   *
   * Validation of `exec`, `description`, `user`, `group`, `workingDirectory`,
   * `environment` and `onCalendar` only runs when `state` is `"present"`,
   * so callers can pass placeholder values when removing a timer.
   *
   * @param name - Base unit name without extension. Used as `<name>.service`
   *   and `<name>.timer`. Must match `^[A-Za-z0-9_\-]+$`.
   * @param options - Schedule, command, optional service hardening, and state.
   * @returns A Module that manages the timer-driven scheduled task.
   */
  scheduled(name: string, options: TimerScheduledOptions): Module {
    assertTimerName(name)

    const state = options.state ?? "present"

    if (state === "absent") {
      const locations = buildTimerLocations(name)
      return {
        async apply(ssh: null | SshConnection): Promise<ModuleResult> {
          if (!ssh) return failed(`[timer.scheduled: ${name}] SSH connection is required`)
          return applyAbsent(ssh, { locations, module: "timer.scheduled", name })
        },
        async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
          if (!ssh) return NEEDS_APPLY
          return checkAbsent(ssh, locations)
        },
        name: `timer.scheduled: ${name}`,
      }
    }

    validatePresentOptions(options)
    const paths = buildTimerPaths(name, options)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[timer.scheduled: ${name}] SSH connection is required`)
        return applyPresent(ssh, name, paths)
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY
        return checkPresent(ssh, paths)
      },

      name: `timer.scheduled: ${name}`,
    }
  },
}
