/**
 * Helpers that compute the new crontab line array for `cron.job` apply.
 *
 * Extracted out of `cron.ts` so the present-mutation logic — including the
 * R-0000676 / R-0000697 commentary about orphan adoption — does not push
 * `cron.ts` over the file-length budget.
 */

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
export function looksLikeCronJobLine(lines: string[], index: number): boolean {
  if (index < 0 || index >= lines.length) return false
  const line = lines[index] ?? ""
  const trimmed = line.trim()
  if (trimmed.length === 0) return false
  if (trimmed.startsWith("#")) return false
  return true
}

/** Arguments for {@link computePresentMutation}. */
export type PresentMutationArguments = {
  /**
   * Whether an existing job line that exactly matches `cronJob` should be
   * adopted by splicing the marker directly in front of it (R-0000676).
   * Defaults to `false` (R-0000697): without this opt-in, an identical
   * user-authored line that paratix never managed would otherwise be
   * silently taken over. When `false`, the marker + job pair is appended
   * at the end of the crontab, which may produce a duplicate line if the
   * existing match was a previously orphaned legacy-marker follow-up.
   */
  adoptOrphans: boolean
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
export function computePresentMutation(mutation: PresentMutationArguments): null | string[] {
  const { adoptOrphans, cronJob, lines, marker, markerIndex } = mutation

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
    // R-0000676: cron.absent on a legacy marker preserves the follow-up
    // line as an orphan (see R-0000567). Without duplicate detection, a
    // later `state="present"` apply would append a fresh marker + job at
    // the end, leaving the orphan line behind and resulting in two
    // identical cron entries running side by side. Re-adopt an existing
    // exact match instead: splice the marker directly in front of the
    // first line that equals `cronJob`, so the line becomes managed
    // again and no duplicate is created.
    //
    // R-0000697: the re-adoption silently vereinnahmt any identical
    // user-authored line that paratix never managed. Gate it behind the
    // opt-in `adoptOrphans` flag (default `false`): callers that knowingly
    // recover from a legacy-marker absent → present cycle must set the
    // flag explicitly. Without the flag, append a fresh marker + job and
    // accept the (visible) duplicate over silently grabbing a user line.
    const orphanIndex = adoptOrphans ? lines.indexOf(cronJob) : -1
    if (orphanIndex === -1) {
      next.push(marker, cronJob)
    } else {
      next.splice(orphanIndex, 0, marker)
    }
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
