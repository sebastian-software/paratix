import { createHash } from "node:crypto"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecResult,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { computePresentMutation, looksLikeCronJobLine } from "./cronMutation.js"
import { cronJobDigest, selectCronAbsentWarning } from "./cronWarningHelpers.js"
import { withMutexLock } from "./moduleHelpers.js"
import { assertValidUserName } from "./posixNames.js"

/**
 * R-0000272: typed result for {@link readCrontab}. The success arm carries the
 * parsed crontab lines (empty for "no crontab"), while the error arm carries
 * the raw `ExecResult` so apply paths can render `failedCommand("…", result)`
 * with masked stdout/stderr instead of throwing a plain `Error`.
 */
type ReadCrontabResult = { kind: "error"; result: ExecResult } | { kind: "lines"; lines: string[] }

/**
 * Read the current crontab lines for a user.
 *
 * R-0000272: returns a discriminated union instead of throwing on read
 * failures. Apply callers convert the `error` arm into `failedCommand(…)` so
 * the runner sees a structured failure with stdout/stderr; check callers
 * convert it into `NEEDS_APPLY` (mirroring the package.installed.check
 * pattern) so the next apply has a chance to heal the underlying problem.
 *
 * @param ssh - The active SSH connection.
 * @param user - The target user whose crontab is read.
 * @returns A typed result: `{kind:"lines"; lines}` on success (with empty
 *   lines when no crontab exists), or `{kind:"error"; result}` carrying the
 *   raw `ExecResult` when `crontab -l` exited non-zero for any reason other
 *   than "no crontab for <user>".
 */
async function readCrontab(ssh: SshConnection, user: string): Promise<ReadCrontabResult> {
  const result = await ssh.exec(`crontab -u ${shellQuote(user)} -l`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return { kind: "lines", lines: result.stdout.trimEnd().split("\n") }
  if (isMissingCrontabResult(result.stdout, result.stderr, user)) {
    return { kind: "lines", lines: [] }
  }
  return { kind: "error", result }
}

function isMissingCrontabResult(stdout: string, stderr: string, user: string): boolean {
  const output = `${stdout}\n${stderr}`.trim()
  if (output === "") return true
  return output.toLowerCase().includes(`no crontab for ${user.toLowerCase()}`)
}

type WriteCrontabArguments = {
  /** Failure message used when removing an empty crontab fails. */
  failureMessage: string
  /** The crontab lines to write. An empty array removes the crontab. */
  lines: string[]
  /** The active SSH connection. */
  ssh: SshConnection
  /** The target user whose crontab is written. */
  user: string
}

/**
 * Write a new crontab for a user, or remove it entirely when the content is empty.
 *
 * @param input - Crontab write arguments.
 * @returns A failure result when empty-crontab removal fails, otherwise `null`.
 */
async function writeCrontab(input: WriteCrontabArguments): Promise<ModuleResult | null> {
  const { failureMessage, lines, ssh, user } = input

  if (lines.length === 0) {
    const removeResult = await ssh.exec(`crontab -u ${shellQuote(user)} -r`, {
      ignoreExitCode: true,
      silent: true,
    })
    if (removeResult.code === 0) return null
    // R-0000227: `crontab -r` exits non-zero when no crontab exists (typical
    // message: "no crontab for <user>"). The desired state — no crontab —
    // is already satisfied, so treat the missing crontab as success rather
    // than reporting failedCommand. Mirrors the logic in readCrontab.
    if (isMissingCrontabResult(removeResult.stdout, removeResult.stderr, user)) return null
    return failedCommand(failureMessage, removeResult)
  }
  // R-0000157: install non-empty crontabs with ignoreExitCode so invalid
  // crontab syntax, missing target users or permission-denied errors surface
  // as a failedCommand result with maskable stdout/stderr instead of
  // bubbling up as an uncaught CommandError exception that escapes the
  // module's failure-handling contract.
  const content = `${lines.join("\n")}\n`
  const installResult = await ssh.exec(`crontab -u ${shellQuote(user)} -`, {
    ignoreExitCode: true,
    input: content,
    silent: true,
  })
  return installResult.code === 0 ? null : failedCommand(failureMessage, installResult)
}

const MARKER_HASH_TAG = " sha256="
const MARKER_PREFIX = "# paratix: "
const CRONTAB_LOCK_DIGEST_LENGTH = 16

function crontabMutexLockName(user: string): string {
  const digest = createHash("sha256")
    .update(user)
    .digest("hex")
    .slice(0, CRONTAB_LOCK_DIGEST_LENGTH)
  return `cron-crontab-${digest}`
}

/**
 * R-0000168: render the marker comment that precedes a managed cron job.
 * The hash suffix lets `cron.absent` match the line below it as one we
 * wrote ourselves before deleting it.
 *
 * @param name - Logical job name supplied by the caller.
 * @param cronJob - The cron job line written immediately below the marker.
 * @returns The full marker comment to insert into the crontab.
 */
function renderMarkerLine(name: string, cronJob: string): string {
  return `${MARKER_PREFIX}${name}${MARKER_HASH_TAG}${cronJobDigest(cronJob)}`
}

/**
 * R-0000168: extract the recorded sha256 digest from a marker line, or
 * `null` when the marker pre-dates R-0000168 (legacy `# paratix: <name>`).
 *
 * @param markerLine - The full marker line read from the crontab.
 * @returns The recorded digest, or `null` for legacy markers.
 */
function readMarkerDigest(markerLine: string): null | string {
  const tagIndex = markerLine.indexOf(MARKER_HASH_TAG)
  if (tagIndex === -1) return null
  const digest = markerLine.slice(tagIndex + MARKER_HASH_TAG.length).trim()
  return /^[\da-f]{64}$/v.test(digest) ? digest : null
}

/**
 * R-0000168: locate the marker for `name` in the crontab. Both the legacy
 * (no hash) and the hash-tagged forms are matched so existing crontabs keep
 * working through a paratix upgrade.
 *
 * @param lines - The crontab lines to search.
 * @param name - Logical job name.
 * @returns The marker index, or `-1` when no marker is present.
 */
function findMarkerIndex(lines: string[], name: string): number {
  const legacyMarker = `${MARKER_PREFIX}${name}`
  const taggedPrefix = `${legacyMarker}${MARKER_HASH_TAG}`
  return lines.findIndex((line) => line === legacyMarker || line.startsWith(taggedPrefix))
}

/**
 * Check whether a marker-job pair is correctly present in crontab lines.
 *
 * @param lines - The crontab lines to inspect.
 * @param name - The logical name written into the marker comment.
 * @param cronJob - The expected job line after the marker.
 * @returns `true` if the marker exists and is followed by the expected job line.
 */
function hasMarkedJob(lines: string[], name: string, cronJob: string): boolean {
  const index = findMarkerIndex(lines, name)
  return index !== -1 && index + 1 < lines.length && lines[index + 1] === cronJob
}

/**
 * R-0000760: find an exact-match `cronJob` line that is NOT the managed
 * follow-up of the active marker. Such a line is an orphan-job duplicate
 * (typically left behind by a legacy-marker `cron.absent`) and must
 * trigger NEEDS_APPLY so the present-state mutation can consolidate the
 * crontab back to a single managed entry.
 *
 * The managed-follow-up index is excluded from the scan because the
 * marker pair always carries one byte-identical `cronJob` line by design.
 *
 * @param lines - The current crontab lines.
 * @param cronJob - The desired job line to compare against.
 * @param markerIndex - The index of the active marker, or `-1` when no marker exists.
 * @returns The index of the orphan duplicate, or `-1` when none is present.
 */
function findOrphanDuplicateIndex(lines: string[], cronJob: string, markerIndex: number): number {
  const managedJobIndex = markerIndex === -1 ? -1 : markerIndex + 1
  return lines.findIndex((line, index) => index !== managedJobIndex && line === cronJob)
}

/**
 * R-0000760: compute the `check()` verdict for `cron.job(state="present")`.
 * Reports `needs-apply` when the marker is missing, predates the hash tag,
 * or when an orphan-job duplicate sits outside the managed pair.
 *
 * @param parameters - The check inputs.
 * @param parameters.lines - The current crontab lines.
 * @param parameters.markerIndex - The index of the active marker, or `-1`.
 * @param parameters.cronJob - The desired job line.
 * @param parameters.marker - The hash-tagged marker comment.
 * @param parameters.found - Whether `hasMarkedJob` returned true.
 * @returns `"ok"` when the crontab matches, otherwise `"needs-apply"`.
 */
function computeCronJobPresentVerdict(parameters: {
  cronJob: string
  found: boolean
  lines: string[]
  marker: string
  markerIndex: number
}): "needs-apply" | "ok" {
  const { cronJob, found, lines, marker, markerIndex } = parameters
  if (!found) return NEEDS_APPLY
  if (markerIndex === -1) return NEEDS_APPLY
  if (lines[markerIndex] !== marker) return NEEDS_APPLY
  return findOrphanDuplicateIndex(lines, cronJob, markerIndex) === -1 ? "ok" : NEEDS_APPLY
}

/** Options for `cron.job`. */
type CronJobOptions = {
  /**
   * R-0000697: opt-in to splicing the marker in front of an existing
   * crontab line that exactly matches `job` when no marker is present.
   * Without this flag, `state="present"` appends a fresh marker + job
   * and never silently adopts an identical user-authored line. Set this
   * to `true` only when knowingly recovering from a `cron.absent` on a
   * legacy marker that left the original job line as an orphan
   * (R-0000567/R-0000676). Defaults to `false`.
   */
  adoptOrphans?: boolean
  /** The crontab line to manage (e.g. `"0 * * * * /usr/bin/backup"`). */
  job: string
  /** Whether the job should be `"present"` or `"absent"`. Defaults to `"present"`. */
  state?: "absent" | "present"
}

// R-0000532: restrict cron marker names to a strict pattern so values
// containing whitespace, `:`, `=` or the literal ` sha256=` segment cannot
// collide with the marker format `# paratix: <name> sha256=<digest>`. Without
// this, a crafted name could cause `findMarkerIndex` to match a foreign
// marker and `cron.absent` to delete an unrelated managed job. Mirrors the
// strict resource-name validation used by `validateAptResourceName`.
//
// R-0000561: explicitly reject `..` so traversal-style names cannot slip
// through the character-class form `[\w.\-]+`. Mirrors the explicit `..`
// reject in `validateAptResourceName` (apt.ts) so cron names follow the
// same hardening contract.
const CRON_NAME_PATTERN = /^[\w.\-]+$/v

function assertCronName(name: string): void {
  if (name.length === 0 || name.includes("..") || !CRON_NAME_PATTERN.test(name)) {
    throw new Error(
      `cron: name must match ${String(CRON_NAME_PATTERN)} and must not contain '..', got: ${JSON.stringify(name)}`
    )
  }
}

/**
 * Compute the mutated crontab lines for `cron.job.apply`.
 *
 * @param parameters - The mutation context.
 * @param parameters.adoptOrphans - R-0000697 opt-in: when `true`, an existing
 *   crontab line that exactly matches `cronJob` is adopted by splicing the
 *   marker in front of it. When `false`, a duplicate is appended instead.
 * @param parameters.cronJob - The desired cron job line.
 * @param parameters.lines - The current crontab lines.
 * @param parameters.marker - The hash-tagged marker comment to write.
 * @param parameters.markerIndex - The current marker index, or `-1`.
 * @param parameters.state - The desired `"present"` / `"absent"` state.
 * @returns The new crontab lines, or `null` when no write is needed.
 */
function computeCronJobMutation(parameters: {
  adoptOrphans: boolean
  cronJob: string
  lines: string[]
  marker: string
  markerIndex: number
  state: "absent" | "present"
}): null | string[] {
  const { adoptOrphans, cronJob, lines, marker, markerIndex, state } = parameters
  if (state === "present") {
    return computePresentMutation({ adoptOrphans, cronJob, lines, marker, markerIndex })
  }
  if (markerIndex === -1) return null
  // R-0000047: only remove the line after the marker when it exactly
  // matches the expected job. If the user has already deleted the job
  // line, or replaced it with something different, drop only the marker
  // and keep the surrounding content untouched.
  const removeCount = lines[markerIndex + 1] === cronJob ? 2 : 1
  const nextLines = [...lines]
  nextLines.splice(markerIndex, removeCount)
  return nextLines
}

async function applyCronJobState(parameters: {
  adoptOrphans: boolean
  cronJob: string
  marker: string
  name: string
  ssh: SshConnection
  state: "absent" | "present"
  user: string
}): Promise<ModuleResult> {
  const { adoptOrphans, cronJob, marker, name, ssh, state, user } = parameters

  // R-0000757: `withMutexLock` now returns a structured result; the outer
  // try/catch is replaced with a `kind === "failed"` branch so lock failures
  // and unexpected section throws surface as typed ModuleResults.
  const lockResult = await withMutexLock(ssh, {
    failureMessage: `[cron.job: ${name} (${user})] aborted`,
    lockName: crontabMutexLockName(user),
    async section(): Promise<ModuleResult> {
      const readResult = await readCrontab(ssh, user)
      // R-0000272: surface crontab-read failures as a structured
      // failedCommand result instead of throwing — see the matching
      // change in cron.absent.apply for the full rationale.
      if (readResult.kind === "error") {
        return failedCommand(`[cron.job: ${name} (${user})] crontab read failed`, readResult.result)
      }
      const lines = readResult.lines
      const markerIndex = findMarkerIndex(lines, name)

      const nextLines = computeCronJobMutation({
        adoptOrphans,
        cronJob,
        lines,
        marker,
        markerIndex,
        state,
      })
      if (nextLines === null) return { status: "ok" }

      const failure = await writeCrontab({
        failureMessage: `[cron.job: ${name} (${user})] crontab removal failed`,
        lines: nextLines,
        ssh,
        user,
      })
      if (failure) return failure
      return { status: "changed" }
    },
  })
  return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
}

/**
 * Apply the cron.absent mutation against an already-read crontab.
 *
 * Extracted out of the `cron.absent.apply` closure so the surrounding
 * function stays inside the lint statement budget.
 *
 * @param parameters - The mutation context.
 * @param parameters.lines - The crontab lines read on entry to apply.
 * @param parameters.markerIndex - The marker index inside `lines`.
 * @param parameters.name - Logical job name (used in failure messages).
 * @param parameters.ssh - The active SSH connection.
 * @param parameters.user - The target user whose crontab is managed.
 * @returns The module result for the apply operation.
 */
async function applyCronAbsentMutation(parameters: {
  lines: string[]
  markerIndex: number
  name: string
  ssh: SshConnection
  user: string
}): Promise<ModuleResult> {
  const { lines, markerIndex, name, ssh, user } = parameters
  // R-0000168: prefer the recorded hash tag — only delete the follow-up
  // line when its sha256 matches the value paratix wrote when the cron
  // job was last installed. If a user replaced the managed job with
  // their own (and the marker still carries the old hash), we leave
  // their line untouched and only drop the marker.
  // R-0000567: when the marker is a legacy marker without a recorded
  // hash (pre-R-0000168), we cannot prove the follow-up line was the one
  // paratix wrote. Keeping the legacy guess ("looks like a cron job
  // line") would blindly delete the user's own cron line if it happened
  // to sit below the marker. Be conservative instead: only remove the
  // marker and preserve any follow-up content. Operators get a heads-up
  // on stderr so they can clean up the orphaned job line manually.
  // R-0000699: the managed-job decision compares the follow-up line's
  // sha256 against the digest paratix recorded in the marker — that
  // comparison is byte-exact and intentionally does NOT normalize
  // whitespace (tabs vs spaces, trailing spaces, run-length differences).
  // Whitespace differences would otherwise change the digest and a
  // hand-edited follow-up line would be silently mistaken for a foreign
  // user line. Operators who reformat managed job lines are expected to
  // re-run `cron.job(state="present")` so paratix rewrites the marker
  // with the new digest.
  const recordedDigest = readMarkerDigest(lines[markerIndex] ?? "")
  const followLine = lines[markerIndex + 1] ?? ""
  const followLooksLikeJob = looksLikeCronJobLine(lines, markerIndex + 1)
  const followIsManagedJob =
    recordedDigest === null
      ? false
      : followLooksLikeJob && cronJobDigest(followLine) === recordedDigest
  // R-0000635: surface the legacy-marker warning through the returned
  // ModuleResult so the runner can render and mask it consistently. The
  // previous direct write to `process.stderr` bypassed the secret-masking
  // pipeline and never appeared in structured logs.
  // R-0000699: when a recorded digest exists but the follow-up line does
  // not match byte-exactly, `selectCronAbsentWarning` also emits a
  // whitespace-normalized near-miss hint so the divergence does not vanish
  // silently. The decision itself stays byte-exact (see above).
  const legacyMarkerWarning = selectCronAbsentWarning({
    followIsManagedJob,
    followLine,
    followLooksLikeJob,
    recordedDigest,
  })
  const removeCount = followIsManagedJob ? 2 : 1
  const nextLines = [...lines]
  nextLines.splice(markerIndex, removeCount)
  const failure = await writeCrontab({
    failureMessage: `[cron.absent: ${name} (${user})] crontab removal failed`,
    lines: nextLines,
    ssh,
    user,
  })
  if (failure) return failure
  return legacyMarkerWarning === null
    ? { status: "changed" }
    : { detail: legacyMarkerWarning, status: "changed" }
}

/**
 * Modules for managing cron jobs in user crontabs.
 *
 * Each managed entry is identified by a `# paratix: <name>` marker comment
 * written on the line directly above the job line, making all changes
 * idempotent and safely repeatable.
 */
export const cron = {
  /**
   * Ensure a cron job is absent from a user's crontab.
   *
   * Removes the `# paratix: <name>` marker comment and the crontab line
   * directly below it. If the marker is not found, the module reports `ok`
   * without writing the crontab. When the crontab becomes empty after the
   * removal, it is deleted entirely via `crontab -r`.
   *
   * Equivalent to `cron.job(user, name, { job: "<unused>", state: "absent" })`,
   * but does not require a placeholder `job` argument.
   *
   * @param user - The target user whose crontab is managed.
   * @param name - Unique identifier of the cron job marker to remove.
   * @returns A Module that ensures the cron job entry is absent.
   */
  absent(user: string, name: string): Module {
    // R-0000748: validate `user` against the posix name pattern before any
    // command is issued. `user` is shell-quoted by `crontabMutexLockName` /
    // `readCrontab`, so quoting itself is safe — the assertion still rejects
    // invalid identifiers (whitespace, newlines, leading dashes) up-front so
    // callers never see a half-applied mutex acquired against a bogus user.
    assertValidUserName(user)
    assertCronName(name)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[cron.absent: ${name} (${user})] SSH connection is required`)

        // R-0000757: `withMutexLock` now returns a structured result; the
        // outer try/catch becomes a kind branch so lock failures and section
        // throws surface as typed ModuleResults.
        const lockResult = await withMutexLock(ssh, {
          failureMessage: `[cron.absent: ${name} (${user})] aborted`,
          lockName: crontabMutexLockName(user),
          async section(): Promise<ModuleResult> {
            const readResult = await readCrontab(ssh, user)
            // R-0000272: surface crontab-read failures as a structured
            // failedCommand result instead of throwing — the runner can then
            // render masked stdout/stderr through CommandError like every
            // other apply failure path.
            if (readResult.kind === "error") {
              return failedCommand(
                `[cron.absent: ${name} (${user})] crontab read failed`,
                readResult.result
              )
            }
            const lines = readResult.lines
            const markerIndex = findMarkerIndex(lines, name)
            if (markerIndex === -1) return { status: "ok" }

            return applyCronAbsentMutation({ lines, markerIndex, name, ssh, user })
          },
        })
        return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const readResult = await readCrontab(ssh, user)
        // R-0000272: a transient read error must not throw out of `check`
        // — defer to apply so the runner can heal itself, mirroring the
        // package.installed.check needs-apply-on-error pattern.
        if (readResult.kind === "error") return NEEDS_APPLY
        return findMarkerIndex(readResult.lines, name) === -1 ? "ok" : NEEDS_APPLY
      },

      name: `cron.absent: ${name} (${user})`,
    }
  },

  /**
   * Ensure a cron job is present in (or absent from) a user's crontab.
   *
   * Each managed entry is tracked via a `# paratix: <name>` marker comment
   * placed on the line directly above the job line. When the marker already
   * exists, the job line is updated in place. When `state` is `"absent"`,
   * both the marker and the job line are removed.
   *
   * @param user - The target user whose crontab is managed.
   * @param name - Unique identifier for this cron job, used in the marker line.
   * @param options - Job content and desired state.
   * @param options.job - The crontab line to manage (e.g. `"0 * * * * /usr/bin/backup"`).
   * @param options.state - Whether the job should be `"present"` or `"absent"`. Defaults to `"present"`.
   * @param options.adoptOrphans - R-0000697: opt-in to splicing the marker
   *   in front of an existing crontab line that exactly matches `job` when
   *   no marker is present. Defaults to `false`. Set to `true` only when
   *   knowingly recovering from a `cron.absent` on a legacy marker.
   *
   * R-0000804: concurrency semantics.
   *
   * Each `cron.job` / `cron.absent` apply is serialised by the per-user
   * mutex `crontab-<user>` (see `crontabMutexLockName`). All cron modules
   * targeting the same user therefore share the same flag-lock directory:
   * only one apply can hold the mutex at a time and writers never
   * interleave their `crontab -u <user> -` calls.
   *
   * `check` does NOT take the mutex — it issues a plain `crontab -u <user>
   * -l` and inspects the output, which is safe because cron's own crontab
   * file is read atomically. As a result, `check` may briefly observe a
   * snapshot that does not yet reflect a concurrent apply on the same
   * user. The verdict in that case is `NEEDS_APPLY`, and the subsequent
   * apply re-runs under the mutex against the current crontab state, so a
   * stale `check` cannot cause a divergent write.
   *
   * @returns A Module that manages the cron job entry.
   */
  job(user: string, name: string, options: CronJobOptions): Module {
    // R-0000748: validate `user` against the posix name pattern before any
    // command is issued, mirroring `cron.absent`. Prevents invalid identifiers
    // from reaching `crontabMutexLockName` / `readCrontab`.
    assertValidUserName(user)
    assertCronName(name)
    if (/[\n\r]/v.test(options.job)) {
      throw new Error(`cron.job: job must not contain newlines: ${JSON.stringify(options.job)}`)
    }

    const state = options.state ?? "present"
    const cronJob = options.job
    // R-0000697: only adopt an identical existing crontab line when the
    // caller opts in. Defaults to `false` so a user-authored line that
    // happens to match `job` is never silently taken over.
    const adoptOrphans = options.adoptOrphans ?? false
    // R-0000168: marker carries the sha256 of the cron job so cron.absent
    // (and `cron.job(state="absent")`) can match the line they wrote
    // and avoid deleting user-replaced follow-up content.
    const marker = renderMarkerLine(name, cronJob)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[cron.job: ${name} (${user})] SSH connection is required`)

        return applyCronJobState({ adoptOrphans, cronJob, marker, name, ssh, state, user })
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const readResult = await readCrontab(ssh, user)
        // R-0000272: a transient read error becomes NEEDS_APPLY so apply
        // gets a chance to heal the underlying problem, matching the
        // package.installed.check pattern.
        if (readResult.kind === "error") return NEEDS_APPLY
        const lines = readResult.lines
        const markerIndex = findMarkerIndex(lines, name)
        const found = hasMarkedJob(lines, name, cronJob)

        if (state === "present") {
          // R-0000168: also re-apply when the marker exists but predates
          // the hash tag, so the upgraded marker lands on disk.
          // R-0000760: detect orphan-job duplicates that sit outside the
          // marker pair so the consolidation in `computePresentMutation`
          // is scheduled. The full verdict matrix lives in
          // `computeCronJobPresentVerdict` to keep this function's
          // cognitive complexity in check.
          return computeCronJobPresentVerdict({ cronJob, found, lines, marker, markerIndex })
        }

        // state === "absent": ok when marker is not found
        return markerIndex === -1 ? "ok" : NEEDS_APPLY
      },

      name: `cron.job: ${name} (${user})`,
    }
  },
}
