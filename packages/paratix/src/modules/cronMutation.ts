/**
 * Helpers that compute the new crontab line array for `cron.job` apply.
 *
 * Extracted out of `cron.ts` so the present-mutation logic — including the
 * R-0000676 / R-0000697 / R-0000699 commentary about orphan adoption and
 * whitespace handling — does not push `cron.ts` over the file-length budget.
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
  // R-0000760: `adoptOrphans` no longer changes the marker-less code path
  // (we always splice instead of producing a duplicate). It is consumed
  // here only to keep the destructured signature stable for callers; the
  // type field is still exported so future opt-ins can hook back in.
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
    //
    // R-0000760: even without `adoptOrphans`, refuse to write a fresh
    // marker + job pair when an exact-match line already exists in the
    // crontab. The previous append-anyway behaviour produced two
    // byte-identical job lines running side by side — a duplicate that
    // a subsequent `check()` could not detect (the marker pair matched,
    // the orphan elsewhere was invisible). The conservative remediation
    // is to splice the marker in front of the existing line so the
    // crontab ends up with a single managed entry: this differs from
    // R-0000697 only in that the duplicate would have been *paratix's
    // own work*, not a user-authored line — the line was already there
    // before apply ran, so adopting it cannot delete user content that
    // the previous behaviour would not also have left behind.
    //
    // R-0000699: the orphan match uses a strict exact-string compare
    // (`lines.indexOf(cronJob)`) and intentionally does NOT normalize
    // whitespace, tabs vs spaces, leading/trailing spaces or interior
    // run-length differences. Two reasons:
    //   1) Crontab uses whitespace as the column separator — collapsing
    //      runs of spaces could re-interpret a different schedule field
    //      layout as "the same job".
    //   2) Any normalization that changes semantics (e.g. tab ↔ space)
    //      would couple the adoption decision to crond's specific tokenizer
    //      version, which differs across distros.
    // The trade-off: an orphan whose exact bytes differ from the desired
    // `cronJob` (e.g. an extra trailing space saved by an editor) is NOT
    // re-adopted and the append path runs instead, producing a visible
    // duplicate. Operators can fix the orphan manually after the visible
    // duplicate flags the divergence in their crontab review.
    const orphanIndex = lines.indexOf(cronJob)
    if (orphanIndex === -1) {
      next.push(marker, cronJob)
    } else {
      // R-0000760: splice the marker in front of the existing exact
      // match instead of appending a fresh pair. The previous append
      // path produced two byte-identical job lines that ran in
      // parallel — and the duplicate could not be detected by a later
      // `check()` because the appended marker + job pair always passed
      // its own integrity probe. Adopting the existing line (the same
      // operation R-0000697 gated behind `adoptOrphans`) is now
      // unconditional: the line was already present before apply, so
      // the duplicate would have been paratix's own residue from a
      // legacy-marker `cron.absent` cycle.
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

  // R-0000760: strip any remaining exact-match orphan that sits outside
  // the managed pair so the resulting crontab has a single instance of
  // `cronJob`. Without this, a legacy-marker cron.absent followed by a
  // present-state re-apply would leave the original line behind (R-0000567
  // preserved it as an orphan) and the present apply would keep adding
  // duplicate copies on every run.
  return removeOrphanDuplicates(next, cronJob, marker)
}

/**
 * R-0000760: remove every `cronJob` line that is not the managed
 * follow-up of `marker`. The managed pair is identified by the marker
 * line that exactly equals `marker` in the supplied `lines`. Any other
 * line that exactly equals `cronJob` is an orphan duplicate and is
 * pruned so the crontab carries a single instance of the managed job.
 *
 * @param lines - The candidate next-state crontab lines.
 * @param cronJob - The desired job line. Equality is byte-exact (see R-0000699).
 * @param marker - The hash-tagged marker comment whose follow-up must survive.
 * @returns A copy of `lines` with orphan duplicates removed.
 */
function removeOrphanDuplicates(
  lines: readonly string[],
  cronJob: string,
  marker: string
): string[] {
  const result: string[] = []
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ""
    if (line !== cronJob) {
      result.push(line)
      continue
    }
    // Keep the line when it is the managed follow-up — i.e. when the
    // previous line is the active marker. Drop every other exact match.
    if (index > 0 && lines[index - 1] === marker) {
      result.push(line)
    }
  }
  return result
}
