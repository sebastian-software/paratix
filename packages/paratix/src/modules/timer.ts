import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
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

type FileSnapshot = { content: string; exists: true } | { exists: false }

async function readFileSnapshot(ssh: SshConnection, path: string): Promise<FileSnapshot> {
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

async function restoreUnitFileSnapshots(
  ssh: SshConnection,
  paths: TimerPaths,
  snapshots: { service?: FileSnapshot; timer?: FileSnapshot }
): Promise<void> {
  if (snapshots.service != null)
    await restoreFileSnapshot(ssh, paths.servicePath, snapshots.service)
  if (snapshots.timer != null) await restoreFileSnapshot(ssh, paths.timerPath, snapshots.timer)
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
  const snapshots = {
    service: serviceMatched ? undefined : await readFileSnapshot(ssh, paths.servicePath),
    timer: timerMatched ? undefined : await readFileSnapshot(ssh, paths.timerPath),
  }

  if (!serviceMatched) {
    await ssh.writeFile(paths.servicePath, paths.serviceContent, { mode: UNIT_FILE_MODE })
  }
  if (!timerMatched) {
    await ssh.writeFile(paths.timerPath, paths.timerContent, { mode: UNIT_FILE_MODE })
  }

  if (!serviceMatched || !timerMatched) {
    const reload = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (reload.code !== 0) {
      await restoreUnitFileSnapshots(ssh, paths, snapshots)
      return {
        failure: failedCommand(`[timer.scheduled: ${name}] systemctl daemon-reload failed`, reload),
        ok: false,
      }
    }
  }
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

type AbsentContext = {
  locations: TimerLocations
  module: string
  name: string
}

async function disableTimerForAbsent(
  ssh: SshConnection,
  context: AbsentContext
): Promise<ModuleResult | undefined> {
  const { locations, module, name } = context
  // `disable --now` removes the wants/ symlink, so run it before deleting
  // unit files. Only tolerate the expected missing-unit race; real stop or
  // disable failures mean the timer may still be active or enabled.
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

async function applyAbsent(ssh: SshConnection, context: AbsentContext): Promise<ModuleResult> {
  const { locations, module, name } = context

  // Idempotent no-op: if neither unit file exists, there is nothing to clean
  // up unless systemd still has residual active/enabled state for the timer.
  const serviceExists = await ssh.exists(locations.servicePath)
  const timerExists = await ssh.exists(locations.timerPath)
  const residualState = await hasResidualTimerState(ssh, locations.timerUnit)
  if (!serviceExists && !timerExists && !residualState) return { status: "ok" }

  const disableFailure = await disableTimerForAbsent(ssh, context)
  if (disableFailure) return disableFailure

  if (serviceExists || timerExists) {
    const remove = await ssh.exec(
      `rm -f ${shellQuote(locations.timerPath)} ${shellQuote(locations.servicePath)}`,
      { ignoreExitCode: true, silent: true }
    )
    if (remove.code !== 0) {
      return failedCommand(`[${module}: ${name}] failed to remove unit files`, remove)
    }
  }

  const reload = await ssh.exec(`${SYSTEMCTL} daemon-reload`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (reload.code !== 0) {
    return failedCommand(`[${module}: ${name}] systemctl daemon-reload failed`, reload)
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
