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
const TIMER_ACTIVATION_ROLLBACK_FAILED = "timer activation rollback failed"
const TIMER_SCHEDULED_MODULE_PATH = "timer.scheduled"

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
  locations: TimerLocations,
  context: { name: string; path: string }
): Promise<"needs-apply" | "ok"> {
  if (await ssh.exists(locations.servicePath)) return NEEDS_APPLY
  if (await ssh.exists(locations.timerPath)) return NEEDS_APPLY
  // R-0000773: a structured probe failure has no failure channel in the
  // check phase. Treat it as `needs-apply` so the apply phase can
  // re-issue the probe and surface the toolchain error structurally;
  // this mirrors the systemd.masked check handling (R-0000772).
  const residual = await hasResidualTimerState(ssh, locations.timerUnit, context)
  if (typeof residual !== "boolean") return NEEDS_APPLY
  return residual ? NEEDS_APPLY : "ok"
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
  const restoreMessage = activationFailure.error?.message ?? TIMER_ACTIVATION_ROLLBACK_FAILED
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

  // R-0000720: refuse to proceed when a pre-write snapshot capture failed.
  // Without this guard `writeTimerUnitFiles` would overwrite the on-disk
  // unit file while the rollback would have no usable snapshot to restore.
  // Matches the systemd.unit snapshot contract from R-0000683.
  const snapshotFailure = describeSnapshotPairFailure(name, paths, snapshots)
  if (snapshotFailure != null) return { failure: snapshotFailure, ok: false }

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

// R-0000720: surface a failed snapshot capture as a structured ModuleResult
// so neither the present-apply nor the absent-apply path mutates the live
// unit files when the pre-write read could not complete. Returns `null`
// when both snapshots are either healthy or skipped.
function describeSnapshotPairFailure(
  name: string,
  paths: Pick<TimerPaths, "servicePath" | "timerPath">,
  snapshots: SnapshotPair
): ModuleResult | null {
  if (snapshots.service != null && "kind" in snapshots.service) {
    return failed(
      `[timer.scheduled: ${name}] failed to snapshot timer unit file at ${paths.servicePath}: ${snapshots.service.reason}`
    )
  }
  if (snapshots.timer != null && "kind" in snapshots.timer) {
    return failed(
      `[timer.scheduled: ${name}] failed to snapshot timer unit file at ${paths.timerPath}: ${snapshots.timer.reason}`
    )
  }
  return null
}

// R-0000773: distinguish toolchain failures from disabled/inactive state.
// `ssh.test` collapses every non-zero exit (including failures of the
// `systemctl` binary itself or a missing dbus session) into `false`, so a
// transient probe error would look identical to "the timer is disabled".
// Route both probes through `ssh.exec({ ignoreExitCode, silent })` and
// classify the standardised systemctl exit codes:
//   * `is-enabled --quiet`: 0 == enabled, 1 == disabled/masked/linked
//     (well-formed disabled-class answer). Codes >= 4 are toolchain errors
//     ("no such unit", "internal error"), `2` and `3` are reserved by
//     systemctl as alias indicators. Treat anything outside the known
//     well-formed set as a structured failure so a missing systemctl
//     binary or a dbus outage no longer renders as "disabled".
//   * `is-active --quiet`: 0 == active, 3 == inactive (well-formed). Any
//     other code is a toolchain error.
// Mirror the `isSwapActive` contract from R-0000722 by routing the
// failure case through `failedCommand`. With `--quiet` systemctl emits
// nothing on stdout, so the classification leans entirely on the exit
// code rather than stdout content.
// Treat 0..3 as well-formed answers from systemctl:
//   * 0: enabled / active
//   * 1: disabled / masked / linked (is-enabled), or `inactive` on older
//        systemctl builds that do not emit the modern code 3
//   * 2: alias of `linked-runtime`/`enabled-runtime` (is-enabled)
//   * 3: inactive / failed (is-active)
// Higher codes (e.g. 4 == "no such unit", 5 == "internal error") are
// reserved for genuine problems that should surface as a structured
// failure rather than be quietly downgraded to "disabled/inactive".
const SYSTEMCTL_STATE_OK = 0
const SYSTEMCTL_STATE_DISABLED_LIKE = 1
const SYSTEMCTL_STATE_RUNTIME_LIKE = 2
const SYSTEMCTL_STATE_INACTIVE_LIKE = 3
const WELL_FORMED_IS_ENABLED_CODES = new Set([
  SYSTEMCTL_STATE_DISABLED_LIKE,
  SYSTEMCTL_STATE_INACTIVE_LIKE,
  SYSTEMCTL_STATE_OK,
  SYSTEMCTL_STATE_RUNTIME_LIKE,
])
const WELL_FORMED_IS_ACTIVE_CODES = new Set([
  SYSTEMCTL_STATE_DISABLED_LIKE,
  SYSTEMCTL_STATE_INACTIVE_LIKE,
  SYSTEMCTL_STATE_OK,
  SYSTEMCTL_STATE_RUNTIME_LIKE,
])

async function probeUnitEnabled(
  ssh: SshConnection,
  timerUnit: string,
  context: { name: string; path: string }
): Promise<boolean | ModuleResult> {
  const result = await ssh.exec(`${SYSTEMCTL} is-enabled --quiet -- ${shellQuote(timerUnit)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (!WELL_FORMED_IS_ENABLED_CODES.has(result.code)) {
    return failedCommand(
      `[${context.path}: ${context.name}] systemctl is-enabled failed while probing timer state`,
      result
    )
  }
  return result.code === 0
}

async function probeUnitActive(
  ssh: SshConnection,
  timerUnit: string,
  context: { name: string; path: string }
): Promise<boolean | ModuleResult> {
  const result = await ssh.exec(`${SYSTEMCTL} is-active --quiet -- ${shellQuote(timerUnit)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (!WELL_FORMED_IS_ACTIVE_CODES.has(result.code)) {
    return failedCommand(
      `[${context.path}: ${context.name}] systemctl is-active failed while probing timer state`,
      result
    )
  }
  return result.code === 0
}

async function isTimerFullyActive(
  ssh: SshConnection,
  timerUnit: string,
  context: { name: string; path: string }
): Promise<boolean | ModuleResult> {
  const enabled = await probeUnitEnabled(ssh, timerUnit, context)
  if (typeof enabled !== "boolean") return enabled
  if (!enabled) return false
  return probeUnitActive(ssh, timerUnit, context)
}

async function hasResidualTimerState(
  ssh: SshConnection,
  timerUnit: string,
  context: { name: string; path: string }
): Promise<boolean | ModuleResult> {
  const enabled = await probeUnitEnabled(ssh, timerUnit, context)
  if (typeof enabled !== "boolean") return enabled
  if (enabled) return true
  return probeUnitActive(ssh, timerUnit, context)
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

// R-0000773: probe whether a freshly-synced timer is already fully
// active before deciding whether `enable --now` is required. Extracted
// from applyPresent to keep the dispatcher below the max-statements
// ceiling (oxlint).
async function probeFullyActiveForPresent(
  ssh: SshConnection,
  parameters: { filesMatched: boolean; name: string; paths: TimerPaths }
): Promise<boolean | ModuleResult> {
  if (!parameters.filesMatched) return false
  return isTimerFullyActive(ssh, parameters.paths.timerUnit, {
    name: parameters.name,
    path: TIMER_SCHEDULED_MODULE_PATH,
  })
}

async function applyPresent(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<ModuleResult> {
  const sync = await syncUnitFiles(ssh, name, paths)
  if (!sync.ok) return sync.failure

  const filesMatched = sync.serviceMatched && sync.timerMatched
  const fullyActiveProbe = await probeFullyActiveForPresent(ssh, { filesMatched, name, paths })
  if (typeof fullyActiveProbe !== "boolean") return fullyActiveProbe
  const fullyActive = fullyActiveProbe

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

// R-0000858: the activation snapshot drives the post-apply rollback in
// `restoreTimerActivationForAbsent`. The previous implementation used
// `ssh.test`, which coerces any non-zero exit (including toolchain
// failures such as a missing or broken `systemctl` binary returning
// exit code 127) to `false`. A toolchain failure would therefore
// produce a snapshot that reports the timer as disabled+inactive,
// leading the apply path to skip the rollback and silently leave a
// previously-enabled timer disabled on failure. Mirror the structured
// probe helpers (`probeUnitEnabled`, `probeUnitActive`) so toolchain
// failures surface as a ModuleResult and abort apply instead of
// corrupting the rollback decision.
async function readTimerActivationSnapshot(
  ssh: SshConnection,
  timerUnit: string,
  context: { name: string; path: string }
): Promise<ModuleResult | TimerActivationSnapshot> {
  const enabled = await probeUnitEnabled(ssh, timerUnit, context)
  if (typeof enabled !== "boolean") return enabled
  const active = await probeUnitActive(ssh, timerUnit, context)
  if (typeof active !== "boolean") return active
  return { active, enabled }
}

function isTimerActivationSnapshot(
  value: ModuleResult | TimerActivationSnapshot
): value is TimerActivationSnapshot {
  return typeof (value as TimerActivationSnapshot).enabled === "boolean"
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

// R-0000819: distinguish two failure shapes from `disableTimerForAbsent`:
//   - `kind: "disable"` covers an actual `systemctl disable --now` failure;
//     systemd may have mutated the timer's activation, so the apply path
//     must replay `restoreTimerActivationForAbsent` afterwards.
//   - `kind: "probe"` covers the missing-unit branch where the residual
//     toolchain probe itself failed or where systemd contradicts the
//     "no such unit" diagnostic with residual state. `disable --now`
//     reported nothing-to-do in this case, so the apply path must surface
//     the diagnostic verbatim without an activation rollback that could
//     itself fail and obscure the real cause.
type DisableAbsentFailure =
  | { kind: "disable"; result: ModuleResult }
  | { kind: "probe"; result: ModuleResult }

async function disableTimerForAbsent(
  ssh: SshConnection,
  context: AbsentContext
): Promise<DisableAbsentFailure | undefined> {
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
  if (disable.code === 0) return undefined
  if (isMissingUnitDisableResult(disable)) {
    // R-0000780: a "no such unit" diagnostic from `disable --now` can
    // mask a real stop failure — systemd may report the unit file as
    // missing (e.g. after the wants/ symlink was already pruned) while
    // the timer itself is still enabled or active in RAM. Without an
    // additional residual-state probe the apply path would silently
    // skip the disable and proceed to `rm -f` the unit files, leaving
    // a still-active timer pointing at a non-existent service. Probe
    // the live state and surface a structured failure when the unit
    // is in fact still enabled or active. A toolchain failure of the
    // probe (R-0000773) propagates through unchanged.
    const residualOrFailure = await hasResidualTimerState(ssh, locations.timerUnit, {
      name,
      path: module,
    })
    // R-0000819: a structured probe failure is not a disable failure —
    // `disable --now` already reported missing-unit, so tagging the
    // outcome as `kind: "probe"` lets the apply path skip the
    // activation rollback and surface the toolchain diagnostic
    // verbatim.
    if (typeof residualOrFailure !== "boolean") {
      return { kind: "probe", result: residualOrFailure }
    }
    if (residualOrFailure) {
      // R-0000819: residual state contradicts the "no such unit"
      // diagnostic but `disable --now` itself did not mutate
      // activation — also a probe-side conclusion.
      return {
        kind: "probe",
        result: failedCommand(
          `[${module}: ${name}] systemctl disable --now reported missing unit but the timer is still enabled or active`,
          disable
        ),
      }
    }
    return undefined
  }
  return {
    kind: "disable",
    result: failedCommand(`[${module}: ${name}] systemctl disable --now failed`, disable),
  }
}

async function handleAbsentUnitRemovalFailure(
  ssh: SshConnection,
  parameters: {
    activation?: ReloadFailureRollbackActivationContext
    message: string
    paths: Pick<TimerPaths, "servicePath" | "timerPath">
    remove: ExecResult
    snapshots: SnapshotPair
  }
): Promise<ModuleResult> {
  const { activation, message, paths, remove, snapshots } = parameters
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
  if (reloadAfterRestore.code !== 0) {
    return failed(
      `${message}: ${describeExecResult(
        remove
      )}; daemon-reload after unit-file rollback also failed: ${describeExecResult(
        reloadAfterRestore
      )}`
    )
  }
  const baseFailure = failedCommand(message, remove)
  // R-0000818: after restoring the snapshotted unit files and re-running
  // `daemon-reload`, additionally replay the pre-apply enable/active state
  // via `restoreTimerActivationForAbsent`. The disable step in
  // `disableTimerForAbsent` already mutated the timer's activation, so a
  // bare snapshot restore would otherwise leave the timer in
  // "files present but disabled" — mirrors the post-rm reload failure path
  // (R-0000655).
  if (activation == null) return baseFailure
  const activationFailure = await restoreTimerActivationForAbsent(
    ssh,
    activation.context,
    activation.snapshot
  )
  if (activationFailure == null) return baseFailure
  const baseMessage = baseFailure.error?.message ?? message
  const restoreMessage = activationFailure.error?.message ?? TIMER_ACTIVATION_ROLLBACK_FAILED
  return failed(`${baseMessage}; ${restoreMessage}`)
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
  // R-0000720: refuse to delete the unit files when a pre-rm snapshot could
  // not be captured. The disable step above already changed the timer's
  // enable/active state, so a failed snapshot must trigger
  // `restoreTimerActivationForAbsent` to re-establish the pre-apply state
  // before bubbling the failure up. Otherwise the timer would be silently
  // left disabled while the unit files remain on disk.
  const snapshotFailure = await handleAbsentSnapshotFailure(ssh, context, {
    activationSnapshot,
    locations,
    module,
    name,
    snapshots,
  })
  if (snapshotFailure != null) return snapshotFailure
  if (existing.service || existing.timer) {
    const remove = await ssh.exec(
      `rm -f ${shellQuote(locations.timerPath)} ${shellQuote(locations.servicePath)}`,
      { ignoreExitCode: true, silent: true }
    )
    if (remove.code !== 0) {
      return handleAbsentUnitRemovalFailure(ssh, {
        // R-0000818: hand the pre-apply activation snapshot through so that
        // after the unit-file rollback and `daemon-reload` the timer's
        // enable/active state is also restored. Without this context the
        // helper would leave the timer in "files present but disabled".
        activation: { context, snapshot: activationSnapshot },
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

// R-0000720: when a pre-rm snapshot read failed, the disable step from
// `disableTimerForAbsent` already mutated the timer's enable/active state.
// Replay `restoreTimerActivationForAbsent` so the pre-apply state comes
// back, and chain a possible activation rollback failure into the final
// ModuleResult so neither failure is silently dropped.
async function handleAbsentSnapshotFailure(
  ssh: SshConnection,
  context: AbsentContext,
  parameters: {
    activationSnapshot: TimerActivationSnapshot
    locations: TimerLocations
    module: string
    name: string
    snapshots: SnapshotPair
  }
): Promise<ModuleResult | null> {
  const { activationSnapshot, locations, module, name, snapshots } = parameters
  const failedSnapshotPath = describeFailedSnapshotPath(locations, snapshots)
  if (failedSnapshotPath == null) return null
  const baseMessage = `[${module}: ${name}] failed to snapshot timer unit file at ${failedSnapshotPath.path}: ${failedSnapshotPath.reason}`
  const activationRestoreFailure = await restoreTimerActivationForAbsent(
    ssh,
    context,
    activationSnapshot
  )
  if (activationRestoreFailure == null) return failed(baseMessage)
  const restoreMessage = activationRestoreFailure.error?.message ?? TIMER_ACTIVATION_ROLLBACK_FAILED
  return failed(`${baseMessage}; rollback enable failed: ${restoreMessage}`)
}

function describeFailedSnapshotPath(
  locations: Pick<TimerLocations, "servicePath" | "timerPath">,
  snapshots: SnapshotPair
): { path: string; reason: string } | null {
  if (snapshots.service != null && "kind" in snapshots.service) {
    return { path: locations.servicePath, reason: snapshots.service.reason }
  }
  if (snapshots.timer != null && "kind" in snapshots.timer) {
    return { path: locations.timerPath, reason: snapshots.timer.reason }
  }
  return null
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
  const restoreMessage = activationRestoreFailure.error?.message ?? TIMER_ACTIVATION_ROLLBACK_FAILED
  return failed(`${removeMessage}; rollback enable failed: ${restoreMessage}`)
}

// R-0000774: chain a disable-time failure with the activation-snapshot
// rollback so neither failure is silently dropped. Extracted from
// applyAbsent to keep the dispatcher below the complexity ceiling
// (oxlint complexity rule).
async function handleAbsentDisableFailure(
  ssh: SshConnection,
  context: AbsentContext,
  parameters: {
    activationSnapshot: TimerActivationSnapshot
    disableFailure: ModuleResult
  }
): Promise<ModuleResult> {
  const { activationSnapshot, disableFailure } = parameters
  const activationRestoreFailure = await restoreTimerActivationForAbsent(
    ssh,
    context,
    activationSnapshot
  )
  if (activationRestoreFailure == null) return disableFailure
  const disableMessage = disableFailure.error?.message ?? "systemctl disable --now failed"
  const restoreMessage = activationRestoreFailure.error?.message ?? TIMER_ACTIVATION_ROLLBACK_FAILED
  return failed(`${disableMessage}; rollback enable failed: ${restoreMessage}`)
}

async function applyAbsent(ssh: SshConnection, context: AbsentContext): Promise<ModuleResult> {
  const { locations, module, name } = context

  // Idempotent no-op: if neither unit file exists, there is nothing to clean
  // up unless systemd still has residual active/enabled state for the timer.
  const serviceExists = await ssh.exists(locations.servicePath)
  const timerExists = await ssh.exists(locations.timerPath)
  // R-0000858: surface toolchain failures from the activation probes as
  // a structured ModuleResult instead of silently coercing them to
  // disabled+inactive. The snapshot helper now mirrors the
  // probeUnitEnabled/probeUnitActive contract.
  const activationProbe = await readTimerActivationSnapshot(ssh, locations.timerUnit, {
    name,
    path: module,
  })
  if (!isTimerActivationSnapshot(activationProbe)) return activationProbe
  const activationSnapshot = activationProbe
  const residualState = activationSnapshot.enabled || activationSnapshot.active
  if (!serviceExists && !timerExists && !residualState) return { status: "ok" }

  const disableFailure = await disableTimerForAbsent(ssh, context)
  if (disableFailure) {
    // R-0000819: `disable --now` returns a tagged failure. A probe-side
    // failure (toolchain failure of `hasResidualTimerState` or contradictory
    // residual state after a "no such unit" diagnostic) is forwarded
    // without an activation rollback because `disable --now` reported
    // nothing-to-do; running the rollback regardless would either fail
    // because the unit truly is gone or obscure the original diagnostic.
    // Only an actual disable failure routes through
    // `handleAbsentDisableFailure`.
    if (disableFailure.kind === "probe") return disableFailure.result
    return handleAbsentDisableFailure(ssh, context, {
      activationSnapshot,
      disableFailure: disableFailure.result,
    })
  }

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
        return checkAbsent(ssh, locations, { name, path: "timer.absent" })
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
          return applyAbsent(ssh, { locations, module: TIMER_SCHEDULED_MODULE_PATH, name })
        },
        async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
          if (!ssh) return NEEDS_APPLY
          return checkAbsent(ssh, locations, { name, path: TIMER_SCHEDULED_MODULE_PATH })
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
