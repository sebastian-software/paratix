import { createHash } from "node:crypto"

/**
 * R-0000168 / R-0000699: derive a stable digest of a cron job line so the
 * marker comment can carry the hash of the last managed job. `cron.absent`
 * reads the digest back from the marker and only removes a follow-up line
 * whose hash matches, preventing user-authored replacement jobs from being
 * deleted. Re-exported via `cronWarningHelpers` so the diagnostic helpers
 * here can compute a whitespace-normalized digest without importing back
 * into `cron.ts`.
 *
 * @param cronJob - The cron job line to hash.
 * @returns The 64-character lowercase hex sha256 digest.
 */
export function cronJobDigest(cronJob: string): string {
  return createHash("sha256").update(cronJob).digest("hex")
}

/**
 * R-0000699: collapse interior whitespace runs and strip leading / trailing
 * whitespace so a near-match check can distinguish a real foreign line from
 * an editor-reformatted managed line.
 *
 * Used only for diagnostic hints — the actual managed-line decision stays
 * byte-exact via {@link cronJobDigest} (see commentary in
 * `applyCronAbsentMutation` and `computePresentMutation`).
 *
 * @param line - The crontab line to normalize.
 * @returns The whitespace-normalized form of the input line.
 */
export function normalizeCronWhitespace(line: string): string {
  return line.replaceAll(/[\t ]+/gv, " ").trim()
}

/**
 * R-0000699: build a structured operator hint when the recorded digest does
 * not match a follow-up line byte-exactly but would match after whitespace
 * normalization. Returns `null` when no near-match is detected so the caller
 * can fall back to the silent path.
 *
 * @param followLine - The follow-up line as read from the crontab.
 * @param recordedDigest - The sha256 digest captured in the marker comment.
 * @returns A hint string suitable for `ModuleResult.detail`, or `null`.
 */
export function buildWhitespaceMismatchHint(
  followLine: string,
  recordedDigest: string
): null | string {
  const normalized = normalizeCronWhitespace(followLine)
  if (normalized === followLine) return null
  if (cronJobDigest(normalized) !== recordedDigest) return null
  return (
    `follow-up line differs from the recorded digest only in whitespace — ` +
    `keeping the user's line untouched. Re-run cron.job(state="present") if the ` +
    `reformatted line should become managed again.`
  )
}

/** Context for {@link selectCronAbsentWarning}. */
export type CronAbsentWarningContext = {
  followIsManagedJob: boolean
  followLine: string
  followLooksLikeJob: boolean
  recordedDigest: null | string
}

/**
 * R-0000699: pick the right operator-facing warning for `cron.absent` apply
 * based on whether the marker carries a recorded digest, whether the
 * follow-up line looks like a cron job and whether a whitespace-normalized
 * compare hits a near-miss. Returning `null` means the result detail stays
 * empty.
 *
 * @param context - Diagnostic inputs derived from the crontab snapshot.
 * @returns The warning detail string, or `null` when no hint applies.
 */
export function selectCronAbsentWarning(context: CronAbsentWarningContext): null | string {
  const { followIsManagedJob, followLine, followLooksLikeJob, recordedDigest } = context
  if (!followLooksLikeJob) return null
  if (recordedDigest === null) {
    return `legacy marker without recorded digest — keeping follow-up line and removing only the marker`
  }
  if (!followIsManagedJob) {
    return buildWhitespaceMismatchHint(followLine, recordedDigest)
  }
  return null
}
