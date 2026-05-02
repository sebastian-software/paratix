import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"

const SYSTEMCTL = "systemctl"
const SYSTEMD_DIRECTORY = "/etc/systemd/system"
const UNIT_FILE_MODE = "0644"
const TIMER_NAME_PATTERN = /^[\w\-]+$/v
const ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_]\w*$/v
const ENVIRONMENT_VALUE_NEEDS_QUOTING = /[\s"\\]/v

/** Options for `timer.scheduled`. */
type TimerScheduledOptions = {
  /** Optional `AccuracySec=` for the `[Timer]` section. */
  accuracySec?: number | string
  /** Description used in both unit `[Unit]` sections. Defaults to `Paratix scheduled task: <name>`. */
  description?: string
  /** Extra environment variables rendered as `Environment=KEY=VAL` lines in `[Service]`. */
  environment?: Record<string, string>
  /** The single command line written as `ExecStart=` in the generated `.service`. */
  exec: string
  /** Optional `Group=` for the `[Service]` section. */
  group?: string
  /** Calendar specification(s) written as one or more `OnCalendar=` lines. */
  onCalendar: string | string[]
  /** Whether `Persistent=true` is written into the `[Timer]` section. Defaults to `true`. */
  persistent?: boolean
  /** Optional `RandomizedDelaySec=` for the `[Timer]` section. */
  randomizedDelaySec?: number | string
  /** Whether the timer should be `"present"` or `"absent"`. Defaults to `"present"`. */
  state?: "absent" | "present"
  /** Optional `User=` for the `[Service]` section. */
  user?: string
  /** Optional `WorkingDirectory=` for the `[Service]` section. */
  workingDirectory?: string
}

function assertNoNewline(field: string, value: string): void {
  if (/[\n\r]/v.test(value)) {
    throw new Error(`timer.scheduled: ${field} must not contain newlines: ${JSON.stringify(value)}`)
  }
}

function normalizeOnCalendar(onCalendar: string | string[]): string[] {
  const entries = Array.isArray(onCalendar) ? onCalendar : [onCalendar]
  if (entries.length === 0) {
    throw new Error("timer.scheduled: onCalendar must contain at least one entry")
  }
  for (const entry of entries) {
    assertNoNewline("onCalendar entry", entry)
    if (entry.trim().length === 0) {
      throw new Error("timer.scheduled: onCalendar entries must not be empty")
    }
  }
  return entries
}

function quoteEnvironmentValue(value: string): string {
  if (!ENVIRONMENT_VALUE_NEEDS_QUOTING.test(value)) return value
  const escaped = value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')
  return `"${escaped}"`
}

function renderServiceUnit(name: string, options: TimerScheduledOptions): string {
  const description = options.description ?? `Paratix scheduled task: ${name}`
  const lines: string[] = ["[Unit]", `Description=${description}`, "", "[Service]", "Type=oneshot"]

  if (options.user != null) lines.push(`User=${options.user}`)
  if (options.group != null) lines.push(`Group=${options.group}`)
  if (options.workingDirectory != null) {
    lines.push(`WorkingDirectory=${options.workingDirectory}`)
  }
  if (options.environment) {
    for (const [key, value] of Object.entries(options.environment)) {
      lines.push(`Environment=${key}=${quoteEnvironmentValue(value)}`)
    }
  }
  lines.push(`ExecStart=${options.exec}`)
  return `${lines.join("\n")}\n`
}

function renderTimerUnit(name: string, options: TimerScheduledOptions): string {
  const description = options.description ?? `Paratix scheduled task: ${name}`
  const persistent = options.persistent ?? true

  const lines: string[] = ["[Unit]", `Description=${description} (timer)`, "", "[Timer]"]
  for (const entry of normalizeOnCalendar(options.onCalendar)) {
    lines.push(`OnCalendar=${entry}`)
  }
  if (persistent) lines.push("Persistent=true")
  if (options.randomizedDelaySec != null) {
    lines.push(`RandomizedDelaySec=${String(options.randomizedDelaySec)}`)
  }
  if (options.accuracySec != null) lines.push(`AccuracySec=${String(options.accuracySec)}`)
  lines.push(`Unit=${name}.service`, "", "[Install]", "WantedBy=timers.target")
  return `${lines.join("\n")}\n`
}

function validateEnvironment(environment: Record<string, string>): void {
  for (const [key, value] of Object.entries(environment)) {
    if (!ENVIRONMENT_KEY_PATTERN.test(key)) {
      throw new Error(
        `timer.scheduled: environment key must match ${String(ENVIRONMENT_KEY_PATTERN)}, got: ${JSON.stringify(key)}`
      )
    }
    assertNoNewline(`environment[${key}]`, value)
  }
}

function validatePresentOptions(options: TimerScheduledOptions): void {
  assertNoNewline("exec", options.exec)
  if (options.exec.trim().length === 0) {
    throw new Error("timer.scheduled: exec must not be empty")
  }
  const optionalStringFields: ReadonlyArray<readonly [string, string | undefined]> = [
    ["description", options.description],
    ["user", options.user],
    ["group", options.group],
    ["workingDirectory", options.workingDirectory],
  ]
  for (const [field, value] of optionalStringFields) {
    if (value != null) assertNoNewline(field, value)
  }
  if (options.environment) validateEnvironment(options.environment)
  // Also validates onCalendar entries for newlines / empty values.
  normalizeOnCalendar(options.onCalendar)
}

type TimerLocations = {
  servicePath: string
  timerPath: string
  timerUnit: string
}

type TimerPaths = {
  serviceContent: string
  timerContent: string
} & TimerLocations

function buildTimerLocations(name: string): TimerLocations {
  return {
    servicePath: `${SYSTEMD_DIRECTORY}/${name}.service`,
    timerPath: `${SYSTEMD_DIRECTORY}/${name}.timer`,
    timerUnit: `${name}.timer`,
  }
}

function buildTimerPaths(name: string, options: TimerScheduledOptions): TimerPaths {
  return {
    ...buildTimerLocations(name),
    serviceContent: renderServiceUnit(name, options),
    timerContent: renderTimerUnit(name, options),
  }
}

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

async function syncUnitFiles(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<{ serviceMatched: boolean; timerMatched: boolean } | ModuleResult> {
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
      return failedCommand(`[timer.scheduled: ${name}] systemctl daemon-reload failed`, reload)
    }
  }
  return { serviceMatched, timerMatched }
}

async function applyPresent(
  ssh: SshConnection,
  name: string,
  paths: TimerPaths
): Promise<ModuleResult> {
  const sync = await syncUnitFiles(ssh, name, paths)
  if ("status" in sync) return sync

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

function assertTimerName(name: string): void {
  if (!TIMER_NAME_PATTERN.test(name)) {
    throw new Error(
      `timer: name must match ${String(TIMER_NAME_PATTERN)}, got: ${JSON.stringify(name)}`
    )
  }
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
   * Equivalent to `timer.scheduled(name, { exec: "<unused>", onCalendar: "<unused>", state: "absent" })`,
   * but does not require placeholder values for `exec` or `onCalendar`.
   *
   * @param name - Base unit name without extension. Must match
   *   `^[\w\-]+$`.
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
   *   and `<name>.timer`. Must match `^[\w\-]+$`.
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
