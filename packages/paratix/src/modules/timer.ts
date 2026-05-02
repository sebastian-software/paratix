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

// When `apply` runs after a `check` that already inspected the same paths,
// this issues another `exists`/`readFile` round-trip. The extra calls are
// accepted because the check phase only reports `needs-apply`/`ok` and does
// not propagate read results to apply, and re-reading right before writing
// avoids acting on stale data when the remote state changes between phases.
async function fileMatches(ssh: SshConnection, path: string, expected: string): Promise<boolean> {
  if (!(await ssh.exists(path))) return false
  const remote = await ssh.readFile(path)
  return remote.trim() === expected.trim()
}

async function checkPresent(ssh: SshConnection, paths: TimerPaths): Promise<"needs-apply" | "ok"> {
  if (!(await fileMatches(ssh, paths.servicePath, paths.serviceContent))) return NEEDS_APPLY
  if (!(await fileMatches(ssh, paths.timerPath, paths.timerContent))) return NEEDS_APPLY
  const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet ${shellQuote(paths.timerUnit)}`)
  if (!enabled) return NEEDS_APPLY
  const active = await ssh.test(`${SYSTEMCTL} is-active --quiet ${shellQuote(paths.timerUnit)}`)
  return active ? "ok" : NEEDS_APPLY
}

async function checkAbsent(
  ssh: SshConnection,
  locations: TimerLocations
): Promise<"needs-apply" | "ok"> {
  if (await ssh.exists(locations.servicePath)) return NEEDS_APPLY
  if (await ssh.exists(locations.timerPath)) return NEEDS_APPLY
  return "ok"
}

type SyncOutcome =
  | { failure: ModuleResult; ok: false }
  | { ok: true; serviceMatched: boolean; timerMatched: boolean }

async function syncUnitFiles(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<SyncOutcome> {
  const serviceMatched = await fileMatches(ssh, paths.servicePath, paths.serviceContent)
  const timerMatched = await fileMatches(ssh, paths.timerPath, paths.timerContent)

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
      return {
        failure: failedCommand(`[timer.scheduled: ${name}] systemctl daemon-reload failed`, reload),
        ok: false,
      }
    }
  }
  return { ok: true, serviceMatched, timerMatched }
}

async function isTimerFullyActive(ssh: SshConnection, timerUnit: string): Promise<boolean> {
  const enabled = await ssh.test(`${SYSTEMCTL} is-enabled --quiet ${shellQuote(timerUnit)}`)
  if (!enabled) return false
  return ssh.test(`${SYSTEMCTL} is-active --quiet ${shellQuote(timerUnit)}`)
}

async function applyPresent(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<ModuleResult> {
  const sync = await syncUnitFiles(ssh, name, paths)
  if (!sync.ok) return sync.failure

  // If both files matched and the timer is already enabled and active, nothing
  // needs to change. Reporting `ok` here keeps direct apply calls (e.g. inside
  // recipes) from triggering spurious change signals.
  if (
    sync.serviceMatched &&
    sync.timerMatched &&
    (await isTimerFullyActive(ssh, paths.timerUnit))
  ) {
    return { status: "ok" }
  }

  const enable = await ssh.exec(`${SYSTEMCTL} enable --now ${shellQuote(paths.timerUnit)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (enable.code !== 0) {
    return failedCommand(`[timer.scheduled: ${name}] systemctl enable --now failed`, enable)
  }

  // Only restart when the timer unit content changed; restart re-reads the
  // schedule. Without a content change `enable --now` already started it and
  // restarting would just abort an in-flight oneshot job.
  if (!sync.timerMatched) {
    const restart = await ssh.exec(`${SYSTEMCTL} restart ${shellQuote(paths.timerUnit)}`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (restart.code !== 0) {
      return failedCommand(`[timer.scheduled: ${name}] systemctl restart failed`, restart)
    }
  }

  return { status: "changed" }
}

type AbsentContext = {
  locations: TimerLocations
  module: string
  name: string
}

async function applyAbsent(ssh: SshConnection, context: AbsentContext): Promise<ModuleResult> {
  const { locations, module, name } = context

  // Idempotent no-op: if neither unit file exists, there is nothing to clean
  // up. Skipping the systemctl/rm sequence avoids a spurious daemon-reload.
  const serviceExists = await ssh.exists(locations.servicePath)
  const timerExists = await ssh.exists(locations.timerPath)
  if (!serviceExists && !timerExists) return { status: "ok" }

  // Best-effort disable; ignore failure (unit may already be gone). `disable
  // --now` also removes the wants/ symlink, which is why we run it before
  // deleting the unit files.
  await ssh.exec(`${SYSTEMCTL} disable --now ${shellQuote(locations.timerUnit)}`, {
    ignoreExitCode: true,
    silent: true,
  })

  const remove = await ssh.exec(
    `rm -f ${shellQuote(locations.timerPath)} ${shellQuote(locations.servicePath)}`,
    { ignoreExitCode: true, silent: true }
  )
  if (remove.code !== 0) {
    return failedCommand(`[${module}: ${name}] failed to remove unit files`, remove)
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
