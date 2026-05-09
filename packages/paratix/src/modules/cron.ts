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

/**
 * R-0000168: derive a stable digest of a cron job line so the marker
 * comment can carry the hash of the last managed job. `cron.absent` reads
 * the digest back from the marker and only removes a follow-up line whose
 * hash matches, preventing user-authored replacement jobs from being
 * deleted.
 *
 * @param cronJob - The cron job line to hash.
 * @returns The 64-character lowercase hex sha256 digest.
 */
function cronJobDigest(cronJob: string): string {
  return createHash("sha256").update(cronJob).digest("hex")
}

const MARKER_HASH_TAG = " sha256="
const MARKER_PREFIX = "# paratix: "

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
 * Decide whether the line at `index` looks like a previously managed cron
 * job that may safely be overwritten.
 *
 * "Safely overwritable" means: the line is not a comment (starts with `#`),
 * not empty, and not another paratix marker. This protects user-authored
 * lines that ended up between the marker and the original job from being
 * silently overwritten by `present` apply.
 *
 * @param lines - The full crontab line array.
 * @param index - The index of the line to inspect.
 * @returns `true` when the line at `index` is a real cron job line.
 */
function looksLikeCronJobLine(lines: string[], index: number): boolean {
  if (index < 0 || index >= lines.length) return false
  const line = lines[index] ?? ""
  const trimmed = line.trim()
  if (trimmed.length === 0) return false
  if (trimmed.startsWith("#")) return false
  return true
}

/** Arguments for {@link computePresentMutation}. */
type PresentMutationArguments = {
  /** The desired cron job line. */
  cronJob: string
  /** The current crontab lines (not mutated). */
  lines: string[]
  /** The paratix marker comment with hash tag. */
  marker: string
  /** The current index of the marker, or `-1`. */
  markerIndex: number
}

/**
 * Compute the new crontab lines required to make the `present` state hold.
 *
 * Returns `null` when no mutation is required (the marker already exists,
 * carries the matching hash tag, and is followed by the desired job line),
 * allowing the caller to short-circuit without writing the crontab.
 *
 * @param mutation - The mutation inputs (see {@link PresentMutationArguments}).
 * @returns The new crontab lines, or `null` when no write is needed.
 */
function computePresentMutation(mutation: PresentMutationArguments): null | string[] {
  const { cronJob, lines, marker, markerIndex } = mutation

  // R-0000081: short-circuit when the marker already carries the desired
  // hash tag and the following line already matches the cron job. Without
  // this, apply would overwrite the line with the same value and re-write
  // the crontab, reporting "changed" on every run when invoked directly
  // (e.g. as a signal target). Mirrors the no-op returns that R-0000075
  // added to file.replace.apply and R-0000077 added to user.absent.apply.
  // R-0000168: legacy markers (no hash tag) drop into the rewrite path
  // below so the upgraded tagged marker lands on disk.
  if (markerIndex !== -1 && lines[markerIndex] === marker && lines[markerIndex + 1] === cronJob) {
    return null
  }

  const next = [...lines]

  if (markerIndex === -1) {
    // No marker yet — append at the end.
    next.push(marker, cronJob)
  } else if (looksLikeCronJobLine(next, markerIndex + 1)) {
    // R-0000047: only overwrite the next line when it actually looks
    // like a managed cron job. This prevents user-authored comments /
    // blanks that ended up between marker and previous job from being
    // silently destroyed by a re-apply.
    // R-0000168: refresh the marker line itself so it gains (or updates)
    // the hash tag for the new cron job.
    next[markerIndex] = marker
    next[markerIndex + 1] = cronJob
  } else {
    // Marker is the last line, or the next line is a comment / blank
    // that the user inserted — splice the new job in instead of
    // overwriting unrelated content. R-0000168: refresh the marker line
    // so the recorded hash tag reflects the cron job we splice in.
    next[markerIndex] = marker
    next.splice(markerIndex + 1, 0, cronJob)
  }

  return next
}

/** Options for `cron.job`. */
type CronJobOptions = {
  /** The crontab line to manage (e.g. `"0 * * * * /usr/bin/backup"`). */
  job: string
  /** Whether the job should be `"present"` or `"absent"`. Defaults to `"present"`. */
  state?: "absent" | "present"
}

function assertCronName(name: string): void {
  if (/[\n\r]/v.test(name)) {
    throw new Error(`cron: name must not contain newlines: ${JSON.stringify(name)}`)
  }
}

/**
 * Compute the mutated crontab lines for `cron.job.apply`.
 *
 * @param parameters - The mutation context.
 * @param parameters.cronJob - The desired cron job line.
 * @param parameters.lines - The current crontab lines.
 * @param parameters.marker - The hash-tagged marker comment to write.
 * @param parameters.markerIndex - The current marker index, or `-1`.
 * @param parameters.state - The desired `"present"` / `"absent"` state.
 * @returns The new crontab lines, or `null` when no write is needed.
 */
function computeCronJobMutation(parameters: {
  cronJob: string
  lines: string[]
  marker: string
  markerIndex: number
  state: "absent" | "present"
}): null | string[] {
  const { cronJob, lines, marker, markerIndex, state } = parameters
  if (state === "present") {
    return computePresentMutation({ cronJob, lines, marker, markerIndex })
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
  // R-0000047: legacy markers (pre-R-0000168) have no recorded hash;
  // fall back to the conservative "looks like a cron job line" rule so
  // unrelated user content next to the marker is preserved.
  const recordedDigest = readMarkerDigest(lines[markerIndex] ?? "")
  const followLine = lines[markerIndex + 1] ?? ""
  const followLooksLikeJob = looksLikeCronJobLine(lines, markerIndex + 1)
  const followIsManagedJob =
    recordedDigest === null
      ? followLooksLikeJob
      : followLooksLikeJob && cronJobDigest(followLine) === recordedDigest
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
  return { status: "changed" }
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
    assertCronName(name)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[cron.absent: ${name} (${user})] SSH connection is required`)

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
   * @returns A Module that manages the cron job entry.
   */
  job(user: string, name: string, options: CronJobOptions): Module {
    assertCronName(name)
    if (/[\n\r]/v.test(options.job)) {
      throw new Error(`cron.job: job must not contain newlines: ${JSON.stringify(options.job)}`)
    }

    const state = options.state ?? "present"
    const cronJob = options.job
    // R-0000168: marker carries the sha256 of the cron job so cron.absent
    // (and `cron.job(state="absent")`) can match the line they wrote
    // and avoid deleting user-replaced follow-up content.
    const marker = renderMarkerLine(name, cronJob)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[cron.job: ${name} (${user})] SSH connection is required`)

        const readResult = await readCrontab(ssh, user)
        // R-0000272: surface crontab-read failures as a structured
        // failedCommand result instead of throwing — see the matching
        // change in cron.absent.apply for the full rationale.
        if (readResult.kind === "error") {
          return failedCommand(
            `[cron.job: ${name} (${user})] crontab read failed`,
            readResult.result
          )
        }
        const lines = readResult.lines
        const markerIndex = findMarkerIndex(lines, name)

        const nextLines = computeCronJobMutation({ cronJob, lines, marker, markerIndex, state })
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
          if (!found) return NEEDS_APPLY
          if (markerIndex === -1) return NEEDS_APPLY
          return lines[markerIndex] === marker ? "ok" : NEEDS_APPLY
        }

        // state === "absent": ok when marker is not found
        return markerIndex === -1 ? "ok" : NEEDS_APPLY
      },

      name: `cron.job: ${name} (${user})`,
    }
  },
}
