/**
 * The post-merge symlink containment backstop of `archive.extract`.
 *
 * Issue #219: after the staging merge, {@link enforceSymlinkContainment} lists
 * every link below the destination as it actually is, judges the set with the
 * resolver the pre-merge check uses, lets the host kernel confirm the
 * resolver's location of every link judged inside, removes each violating
 * link without following it, re-checks and repeats while the removal makes
 * progress, and fails the run.
 */
import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { runKernelCrossCheck } from "./archiveKernelCrossCheck.js"
import {
  type MergedSymlink,
  mergedSymlinkResolutions,
  type MergedSymlinkViolation,
  variantDescription,
} from "./archiveLinkValidation.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES } from "./archiveMemberValidation.js"
import {
  buildSymlinkListingProbeScript,
  encodeSymlinkListingEntry,
  removeEscapingSymlinks,
  runBatchedProbe,
  type SymlinkRemovalReport,
} from "./archiveProbe.js"
import { hostStateFromListing } from "./archiveSymlinkListing.js"

const CHECKED_AFTER_MERGE =
  "every symlink under the destination is checked after the merge, including links this archive did not ship"

/**
 * Issue #219: a link the backstop cannot show to stay inside: a violation of
 * the lexical resolver, or a `kernel-mismatch` where the host kernel does not
 * confirm the location the resolver computed (`expected`, absolute).
 */
export type PostMergeViolation =
  { expected: string; key: string; kind: "kernel-mismatch" } | MergedSymlinkViolation

/**
 * Issue #219: every symlink below the destination after the merge, keyed by
 * destination-relative path, with the links that cannot be shown to stay
 * inside.
 */
type PostMergeSymlinks = {
  kind: "ok"
  links: ReadonlyMap<string, MergedSymlink>
  violations: PostMergeViolation[]
}

/** Issue #219: a post-merge listing, or why it cannot be trusted. */
type PostMergeSymlinkReading = { detail: string; kind: "failed" } | PostMergeSymlinks

/**
 * Issue #219: read every symlink below the destination as it is now, judge
 * the whole set with the pre-merge resolver and let the kernel confirm it.
 *
 * One batched exec of `buildSymlinkListingProbeScript` with the destination as
 * its only `r` entry lists each link with its stored target; nothing on the
 * host resolves a link in user space, so a self-extending loop such as
 * `b -> b/..` cannot hang the probe. The pairs are decoded by the same
 * {@link hostStateFromListing} the pre-merge check uses, with no requested
 * member paths, so any directory hit counts as broken framing. The listing
 * grows with the number of links on the host, not with violations, so it gets
 * the archive capture cap; truncation still fails closed.
 *
 * Issue #219: the resolver alone is lexical. Every link it judges inside is
 * then handed to {@link runKernelCrossCheck} in one more batched exec, which
 * compares the link with the location the resolver computed by device and
 * inode. A link the kernel resolves elsewhere is a `kernel-mismatch`
 * violation; a cross-check that cannot be completed fails the reading like a
 * failed listing. Without links judged inside, no cross-check runs.
 *
 * @param conn - The SSH connection.
 * @param destination - The validated, canonical destination directory.
 * @returns The listed links with their violations, or why the reading cannot
 *   be trusted.
 */
async function readPostMergeSymlinks(
  conn: SshConnection,
  destination: string
): Promise<PostMergeSymlinkReading> {
  const outcome = await runBatchedProbe(conn, {
    entries: [encodeSymlinkListingEntry("r", destination)],
    maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
    script: buildSymlinkListingProbeScript(),
  })
  if (outcome.kind === "failed") return outcome
  const host = hostStateFromListing(destination, outcome.fields, new Map())
  if (typeof host === "string") return { detail: host, kind: "failed" }
  const { inside, violations } = mergedSymlinkResolutions(host.links)
  if (inside.size === 0) return { kind: "ok", links: host.links, violations }
  const kernel = await runKernelCrossCheck(conn, { destination, inside })
  if (kernel.kind === "failed") {
    return { detail: `kernel cross-check could not be completed: ${kernel.detail}`, kind: "failed" }
  }
  const mismatches = kernel.mismatches.map(({ expected, key }): PostMergeViolation => ({
    expected,
    key,
    kind: "kernel-mismatch",
  }))
  return { kind: "ok", links: host.links, violations: [...violations, ...mismatches] }
}

/**
 * Describe one violation of the post-merge link set by absolute link path and
 * stored target.
 *
 * @param destination - The validated, canonical destination directory.
 * @param reading - The listing the violation comes from.
 * @param violation - The violation to describe.
 * @returns The description, without a trailing count.
 */
function postMergeViolationDescription(
  destination: string,
  reading: PostMergeSymlinks,
  violation: PostMergeViolation
): string {
  const stored = reading.links.get(violation.key)?.stored ?? ""
  const linkPath = `${destination}/${violation.key}`
  const link = `symlink ${JSON.stringify(linkPath)} -> ${JSON.stringify(stored)}`
  switch (violation.kind) {
    case "escape": {
      return `${link} resolves outside destination ${JSON.stringify(destination)}`
    }
    case "kernel-mismatch": {
      return `${link} resolves on the host to a different location than the containment check computed (${JSON.stringify(violation.expected)})`
    }
    case "limit": {
      return `${link} cannot be resolved within the symlink resolution limit`
    }
    case "variant": {
      return `${link} ${variantDescription(violation)}`
    }
  }
}

/**
 * Describe the first violation the post-merge check found.
 *
 * @param destination - The validated, canonical destination directory.
 * @param reading - The first post-merge listing, with at least one violation.
 * @returns The violation text without the `[archive.extract]` prefix, with the
 *   `(and N more)` suffix when there are more.
 */
function containmentViolationMessage(destination: string, reading: PostMergeSymlinks): string {
  const [first] = reading.violations
  const more = reading.violations.length - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return `${postMergeViolationDescription(destination, reading, first)}; ${CHECKED_AFTER_MERGE}${suffix}`
}

/**
 * Issue #219: what the removal rounds of {@link enforceSymlinkContainment}
 * did in total, and the last re-check.
 */
type RemovalRounds = {
  /** Links still in place after the rounds, with the latest reason. */
  kept: ReadonlyMap<string, string>
  /** Notes on removed links, e.g. a quarantine directory left behind. */
  notes: ReadonlyMap<string, string>
  /** The listing taken after the last round. */
  recheck: PostMergeSymlinkReading
  /** Every link removed in any round, in removal order, without duplicates. */
  removed: readonly string[]
}

/** Issue #219: the running totals of the removal rounds. */
type RemovalTotals = {
  kept: Map<string, string>
  notes: Map<string, string>
  removed: Set<string>
}

/**
 * Fold one removal report into the totals across rounds: a removed link is no
 * longer reported as kept, a kept link carries its latest reason.
 *
 * @param totals - The accumulated totals, updated in place.
 * @param report - The report of the latest removal round.
 */
function recordRemovalRound(totals: RemovalTotals, report: SymlinkRemovalReport): void {
  for (const link of report.removed) {
    totals.removed.add(link)
    totals.kept.delete(link)
  }
  for (const [link, reason] of report.kept) totals.kept.set(link, reason)
  for (const [link, note] of report.notes) totals.notes.set(link, note)
}

/**
 * Issue #219: remove the violating links, re-list and repeat while the
 * removal makes progress.
 *
 * Removing a link changes how every link whose target passes through its path
 * resolves: the walk then continues lexically through the missing path. The
 * resolver already reports a link that follows a violating link as a
 * violation itself, so on an unchanged tree one round removes them together.
 * The tree can still change while the rounds run — the host may create or
 * redirect links, and a link the removal script refused stays in place — so
 * each round removes whatever the latest listing reports, then re-lists. The
 * rounds stop when the re-check is clean, when it failed, or when a round
 * removed nothing. There are at most as many rounds as the first listing had
 * links (at least one), which caps the work even when the host keeps creating
 * new links. Each round costs one removal exec and one re-check, which is one
 * listing exec plus one kernel cross-check exec when the listing has a link
 * judged inside.
 *
 * @param conn - The SSH connection.
 * @param destination - The validated, canonical destination directory.
 * @param first - The first post-merge listing, with at least one violation.
 * @returns The accumulated removal outcome and the last re-check.
 */
async function removeViolatingSymlinks(
  conn: SshConnection,
  destination: string,
  first: PostMergeSymlinks
): Promise<RemovalRounds> {
  const totals: RemovalTotals = { kept: new Map(), notes: new Map(), removed: new Set() }
  const maxRounds = Math.max(1, first.links.size)
  let current = first
  let recheck: PostMergeSymlinkReading = first
  for (let round = 0; round < maxRounds; round += 1) {
    const links = current.violations.map(({ key }) => `${destination}/${key}`)
    // Rounds depend on each other: each one removes what the previous
    // re-check reported, so they cannot run concurrently.
    // eslint-disable-next-line no-await-in-loop -- sequential by design
    const report = await removeEscapingSymlinks(conn, destination, links)
    recordRemovalRound(totals, report)
    // eslint-disable-next-line no-await-in-loop -- sequential by design
    recheck = await readPostMergeSymlinks(conn, destination)
    if (recheck.kind === "failed" || recheck.violations.length === 0) break
    if (report.removed.length === 0) break
    current = recheck
  }
  return { kept: totals.kept, notes: totals.notes, recheck, removed: [...totals.removed] }
}

/**
 * Describe what the removal rounds did and what the last re-check found.
 *
 * @param destination - The validated, canonical destination directory.
 * @param rounds - The accumulated outcome of {@link removeViolatingSymlinks}.
 * @returns The message tail, starting with `; `.
 */
function enforcementSummary(destination: string, rounds: RemovalRounds): string {
  const { kept, notes, recheck, removed } = rounds
  const parts: string[] = []
  if (removed.length > 0) {
    parts.push(
      `removed escaping symlinks: ${removed.map((link) => JSON.stringify(link)).join(", ")}`
    )
  }
  if (notes.size > 0) {
    const details = [...notes].map(([link, note]) => `${JSON.stringify(link)} (${note})`)
    parts.push(`removal notes: ${details.join(", ")}`)
  }
  if (kept.size > 0) {
    const reasons = [...kept].map(([link, reason]) => `${JSON.stringify(link)} (${reason})`)
    parts.push(`could not remove: ${reasons.join(", ")}`)
  }
  if (recheck.kind === "failed") parts.push(`re-check failed: ${recheck.detail}`)
  else if (recheck.violations.length === 0) parts.push("re-check found no escaping symlinks")
  else {
    const remaining = recheck.violations.map((violation) =>
      postMergeViolationDescription(destination, recheck, violation)
    )
    parts.push(`re-check still reports ${remaining.join(", ")}`)
  }
  return parts.map((part) => `; ${part}`).join("")
}

/**
 * Issue #219: the post-merge backstop. List every symlink below the
 * destination as it actually is, judge the set with the resolver the pre-merge
 * model uses, let the host kernel confirm every link judged inside, remove
 * each violating link and fail the run.
 *
 * This runs after every merge that started, even a failed one, because a
 * merge that failed half-way may already have published links. It covers
 * links this archive did not ship and host changes between the pre-merge
 * listing and the merge. It never asks the host to resolve a link in user
 * space: the host only lists links with their stored targets (see
 * `buildSymlinkListingProbeScript`), {@link mergedSymlinkResolutions} resolves
 * them in TypeScript with its hop limit and cycle detection, and the kernel
 * cross-check only compares files with `test -ef`. GNU `realpath`, which the
 * backstop used before, never terminates on a self-extending loop such as
 * `b -> b/..` or `x -> y/..` with `y -> x`, and the remote process outlived
 * the client's timeout.
 *
 * Decision: a link the resolver reports as `limit` (hop limit or cycle) is
 * treated like an escaping link and removed. It cannot be shown to stay
 * inside, the pre-merge model counts it as a violation as well, and the
 * previous backstop removed links it could not resolve; the run fails and
 * names it either way. The same holds for a `variant` link and for a
 * `kernel-mismatch`.
 *
 * On a violation it removes the reported links, re-lists and repeats while a
 * round makes progress (see {@link removeViolatingSymlinks}). The run still
 * fails after a removal, so the containment flag the caller wrote before the
 * merge stays set. The message names the first violation, every link removed
 * in any round, every link that could not be removed with its reason, and the
 * last re-check: every link it still reports, or why it failed.
 *
 * Cost: a converged tree costs one listing exec plus one kernel cross-check
 * exec when the destination holds at least one symlink (one exec when it holds
 * none), regardless of member or link count; each removal round adds one
 * removal exec and one re-check of the same shape.
 *
 * A listing that failed (including a missing or unusable `readlink`, a `find`
 * traversal error, a truncated capture and output that is not valid UTF-8),
 * returned broken framing or a duplicate link, or whose kernel cross-check
 * could not be completed removes nothing and fails the run.
 *
 * @param conn - The SSH connection.
 * @param parameters - Enforcement inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.source - The archive source, for the failure message.
 * @returns Null when every symlink stays inside, otherwise a failure naming the
 *   violation, the removal outcome and the re-check result.
 */
export async function enforceSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const { destination, source } = parameters
  const prefix = `[archive.extract] refusing to complete extraction of ${source}`
  const reading = await readPostMergeSymlinks(conn, destination)
  if (reading.kind === "failed") {
    return failed(`${prefix}: symlink containment check failed: ${reading.detail}`)
  }
  if (reading.violations.length === 0) return null
  const rounds = await removeViolatingSymlinks(conn, destination, reading)
  const violation = containmentViolationMessage(destination, reading)
  return failed(`${prefix}: ${violation}${enforcementSummary(destination, rounds)}`)
}
