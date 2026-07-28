import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommandWithDiagnostic } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

const SYSTEMCTL = "systemctl"
const JOURNALCTL = "journalctl"

/** Maximum number of journal lines carried into a restart failure message. */
const JOURNAL_LINE_LIMIT = 20
/** Byte ceiling for the journal excerpt, independent of the line limit. */
const JOURNAL_BYTE_LIMIT = 4000
/** Appended when the line or byte budget dropped part of the excerpt. */
const JOURNAL_TRUNCATION_MARKER = "… (journal excerpt truncated)"

/**
 * `date` output shape passed to `journalctl --since`. Validated before use so a
 * host whose `date` prints something unexpected cannot turn into a nonsensical
 * journal query -- in that case the excerpt falls back to the recent lines.
 */
const HOST_TIMESTAMP_PATTERN =
  /^(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2}) (?<hour>\d{2}):(?<minute>\d{2}):(?<second>\d{2})$/v

/** Extra seconds added to the measured attempt duration when sizing the window. */
const JOURNAL_WINDOW_SLACK_SECONDS = 3
/** Smallest journal window, so a fast failure still catches its own lines. */
const JOURNAL_WINDOW_MIN_SECONDS = 5
const MILLISECONDS_PER_SECOND = 1000

type JournalExcerpt = {
  /** Whether the excerpt is provably from the failing attempt. */
  attributable: boolean
  text: string
}

function pad(part: number): string {
  return String(part).padStart(2, "0")
}

function formatHostTimestamp(value: Date): string {
  return [
    `${String(value.getUTCFullYear())}-${pad(value.getUTCMonth() + 1)}-${pad(value.getUTCDate())}`,
    `${pad(value.getUTCHours())}:${pad(value.getUTCMinutes())}:${pad(value.getUTCSeconds())}`,
  ].join(" ")
}

/**
 * Resolve the `journalctl --since` bound for a restart that just failed.
 *
 * The bound is the target host's own wall clock minus the measured duration of
 * the attempt, so the window is expressed in the host's clock domain and covers
 * exactly that attempt rather than an earlier one. `date` is read only on the
 * failure path -- a successful restart issues no extra command at all.
 *
 * The host string is treated as a wall-clock representation and shifted with UTC
 * arithmetic, because `journalctl` compares it against the same local wall clock
 * that produced it.
 *
 * @param ssh - Connection to the target host.
 * @param elapsedMilliseconds - Measured duration of the failed restart attempt.
 * @returns The `--since` bound in host wall-clock form, or `null` when the host
 *   clock could not be read or parsed.
 */
export async function resolveJournalWindowStart(
  ssh: SshConnection,
  elapsedMilliseconds: number
): Promise<null | string> {
  try {
    const result = await ssh.exec(`date '+%Y-%m-%d %H:%M:%S'`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (result.code !== 0) return null
    const parts = HOST_TIMESTAMP_PATTERN.exec(result.stdout.trim())?.groups
    if (parts == null) return null
    const { day, hour, minute, month, second, year } = parts
    const hostNow = Date.UTC(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second)
    )
    const lookbackSeconds = Math.max(
      JOURNAL_WINDOW_MIN_SECONDS,
      Math.ceil(elapsedMilliseconds / MILLISECONDS_PER_SECOND) + JOURNAL_WINDOW_SLACK_SECONDS
    )
    return formatHostTimestamp(new Date(hostNow - lookbackSeconds * MILLISECONDS_PER_SECOND))
  } catch {
    return null
  }
}

/**
 * Bound a raw journal read by the line and byte budget.
 *
 * @param text - Raw `journalctl` output.
 * @returns The bounded excerpt, or `null` when the output carried no content.
 */
function boundJournalText(text: string): null | string {
  const lines = text.split("\n").filter((line) => line.trim().length > 0)
  if (lines.length === 0) return null
  // Keep the *tail* of the window: the lines closest to the failure carry the
  // cause, while the head is usually unit start-up noise.
  const kept = lines.slice(-JOURNAL_LINE_LIMIT)
  let truncated = kept.length < lines.length
  while (kept.length > 1 && kept.join("\n").length > JOURNAL_BYTE_LIMIT) {
    kept.shift()
    truncated = true
  }
  let excerpt = kept.join("\n")
  if (excerpt.length > JOURNAL_BYTE_LIMIT) {
    excerpt = excerpt.slice(0, JOURNAL_BYTE_LIMIT)
    truncated = true
  }
  return truncated ? `${JOURNAL_TRUNCATION_MARKER}\n${excerpt}` : excerpt
}

/**
 * Run one best-effort journal read.
 *
 * @param ssh - Connection to the target host.
 * @param unit - Unit whose journal is read.
 * @param since - Optional `--since` bound; `null` reads the recent lines.
 * @returns The bounded excerpt, or `null` on any problem.
 */
async function readJournal(
  ssh: SshConnection,
  unit: string,
  since: null | string
): Promise<null | string> {
  const window = since == null ? "" : ` --since ${shellQuote(since)}`
  try {
    const result = await ssh.exec(
      `${JOURNALCTL} -u ${shellQuote(unit)}${window} --no-pager --lines=${String(JOURNAL_LINE_LIMIT)}`,
      { ignoreExitCode: true, silent: true }
    )
    if (result.code !== 0) return null
    return boundJournalText(result.stdout)
  } catch {
    return null
  }
}

/**
 * Read the unit's journal for a failed restart, preferring the window of the
 * failing attempt.
 *
 * A time-bounded read can legitimately come back empty -- the journal may not
 * have flushed yet, or the host clock may have moved. Falling back to the recent
 * lines keeps a diagnostic available, but marks it as not attributable so stale
 * output from an earlier attempt is never presented as this attempt's cause.
 *
 * @param ssh - Connection to the target host.
 * @param unit - Unit whose journal is read.
 * @param since - The attempt's `--since` bound, or `null` when unavailable.
 * @returns The excerpt with its attribution flag, or `null` when the journal
 *   could not be read at all.
 */
async function readJournalExcerpt(
  ssh: SshConnection,
  unit: string,
  since: null | string
): Promise<JournalExcerpt | null> {
  if (since != null) {
    const scoped = await readJournal(ssh, unit, since)
    if (scoped != null) return { attributable: true, text: scoped }
  }
  const recent = await readJournal(ssh, unit, null)
  return recent == null ? null : { attributable: false, text: recent }
}

function formatDiagnostic(
  unit: string,
  since: null | string,
  excerpt: JournalExcerpt | null
): null | string {
  if (excerpt == null) {
    // Even without journal access, naming the unit turns "exit code 1" into
    // something the operator can act on.
    return `unit ${unit} — inspect with: ${JOURNALCTL} -xeu ${unit}`
  }
  const header =
    excerpt.attributable && since != null
      ? `unit ${unit} — journal since ${since}:`
      : `unit ${unit} — last journal lines (not attributable to this attempt):`
  return `${header}\n${excerpt.text}`
}

/**
 * Restart a systemd unit and, on failure, enrich the error with the unit's own
 * journal output.
 *
 * `systemctl restart` reports only `Job for <unit>.service failed …` on stderr;
 * the actual cause -- a container engine refusing to replace a container, a
 * failing `ExecStartPre`, an OOM kill -- exists only in the journal. Without it,
 * the operator gets an exit code and has to reconstruct the cause by hand.
 *
 * The journal read is strictly best-effort and follows the same rule as the
 * other diagnostic probes in this codebase: any problem yields no excerpt rather
 * than a worse failure. A successful restart issues no extra command at all --
 * every probe happens after a non-zero exit.
 *
 * @param parameters - Restart inputs.
 * @param parameters.failureMessage - Message prefix used when the restart fails.
 * @param parameters.secrets - Optional secret strings to mask in the rendered
 *   message, the journal excerpt, and the captured stdout/stderr.
 * @param parameters.ssh - Connection to the target host.
 * @param parameters.unit - The systemd unit to restart.
 * @returns `null` when the restart succeeded, otherwise a failed ModuleResult.
 */
export async function restartSystemdUnit(parameters: {
  failureMessage: string
  secrets?: string[]
  ssh: SshConnection
  unit: string
}): Promise<ModuleResult | null> {
  const { failureMessage, secrets, ssh, unit } = parameters
  const startedAt = Date.now()
  const result = await ssh.exec(`${SYSTEMCTL} restart -- ${shellQuote(unit)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
  const since = await resolveJournalWindowStart(ssh, Date.now() - startedAt)
  const excerpt = await readJournalExcerpt(ssh, unit, since)
  return failedCommandWithDiagnostic({
    diagnostic: formatDiagnostic(unit, since, excerpt),
    message: failureMessage,
    result,
    secrets,
  })
}
