const SYSTEMD_DIRECTORY = "/etc/systemd/system"
// eslint-disable-next-line regexp/prefer-w -- explicit ASCII intent, do not collapse to \w
export const TIMER_NAME_PATTERN = /^[A-Za-z0-9_\-]+$/v
const ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_]\w*$/v
const ENVIRONMENT_VALUE_NEEDS_QUOTING = /[\s"\\]/v

/** Options for `timer.scheduled`. */
export type TimerScheduledOptions = {
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

export type TimerLocations = {
  servicePath: string
  timerPath: string
  timerUnit: string
}

export type TimerPaths = {
  serviceContent: string
  timerContent: string
} & TimerLocations

function assertNoNewline(field: string, value: string): void {
  if (/[\n\r]/v.test(value)) {
    throw new Error(`timer.scheduled: ${field} must not contain newlines: ${JSON.stringify(value)}`)
  }
}

function assertNotBlank(field: string, value: string): void {
  if (value.trim().length === 0) {
    throw new Error(`timer.scheduled: ${field} must not be empty: ${JSON.stringify(value)}`)
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

export function validatePresentOptions(options: TimerScheduledOptions): void {
  assertNoNewline("exec", options.exec)
  assertNotBlank("exec", options.exec)
  const optionalStringFields: ReadonlyArray<readonly [string, string | undefined]> = [
    ["description", options.description],
    ["user", options.user],
    ["group", options.group],
    ["workingDirectory", options.workingDirectory],
  ]
  for (const [field, value] of optionalStringFields) {
    if (value != null) {
      assertNoNewline(field, value)
      assertNotBlank(field, value)
    }
  }
  if (options.randomizedDelaySec != null) {
    assertNoNewline("randomizedDelaySec", String(options.randomizedDelaySec))
  }
  if (options.accuracySec != null) {
    assertNoNewline("accuracySec", String(options.accuracySec))
  }
  if (options.environment) validateEnvironment(options.environment)
  // Also validates onCalendar entries for newlines / empty values.
  normalizeOnCalendar(options.onCalendar)
}

export function assertTimerName(name: string): void {
  if (!TIMER_NAME_PATTERN.test(name)) {
    throw new Error(
      `timer: name must match ${String(TIMER_NAME_PATTERN)}, got: ${JSON.stringify(name)}`
    )
  }
}

export function buildTimerLocations(name: string): TimerLocations {
  return {
    servicePath: `${SYSTEMD_DIRECTORY}/${name}.service`,
    timerPath: `${SYSTEMD_DIRECTORY}/${name}.timer`,
    timerUnit: `${name}.timer`,
  }
}

export function buildTimerPaths(name: string, options: TimerScheduledOptions): TimerPaths {
  return {
    ...buildTimerLocations(name),
    serviceContent: renderServiceUnit(name, options),
    timerContent: renderTimerUnit(name, options),
  }
}
