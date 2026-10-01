/**
 * The post-merge symlink containment backstop of `archive.extract`.
 *
 * Issue #219: after the staging merge, {@link enforceSymlinkContainment} lists
 * every link below the destination as it actually is, judges the links this
 * archive can affect with the resolver the pre-merge check uses and lets the
 * host kernel confirm the resolver's location of every such link judged
 * inside. It only detects and reports: on a violation it names the offending
 * links and fails the run, and it never removes, moves or changes anything on
 * the host.
 *
 * Issue #219: it also re-verifies the links an earlier failed apply recorded
 * in their containment entries (see `archiveContainmentFlag.ts`), and reports
 * the offending link keys so the caller can record them in turn. When an
 * entry held no usable list, it judges every symlink under the destination from
 * the same listing instead (see {@link runSymlinkContainmentBackstop}).
 */
import type { ModuleResult, SshConnection } from "../types.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { archiveHasSymlinks } from "./archiveContainmentScope.js"
import { type KernelMismatchPoint, runKernelCrossCheck } from "./archiveKernelCrossCheck.js"
import { type MergedSymlink, variantDescription } from "./archiveLinkValidation.js"
import {
  inListingOrder,
  listingViolations,
  type PostMergeReadingInputs,
  type PostMergeViolation,
  UNREADABLE_DIRECTORY,
  UNREADABLE_MEMBER,
} from "./archivePostMergeJudgement.js"
import { encodeSymlinkListingEntry } from "./archiveProbe.js"
import {
  hostStateFromListing,
  quotedHostPath,
  runSymlinkListing,
  symlinkDescription,
  unverifiableLinkReason,
} from "./archiveSymlinkListing.js"

const CHECKED_AFTER_MERGE =
  "after the merge, the archive's symlinks and every symlink under the destination whose resolution passes through a path the archive writes are checked, including links it did not ship"

/**
 * Issue #219: what the backstop checked when a containment entry held no
 * usable list of offending links.
 */
const CHECKED_WHOLE_DESTINATION_AFTER_MERGE =
  "after the merge, every symlink under the destination is checked, because a containment entry does not say which links need verification (an unfinished or concurrent apply, an older paratix version's flag file, or too many entries)"

/**
 * Issue #219: what an operator has to do after a post-merge violation. The
 * backstop only reports, so the offending links stay in place until someone
 * removes them or points them inside the destination; that manual step is
 * needed only while they remain. This apply's containment entry records
 * them, or `unknown` when it cannot, and a later apply of any source verifies
 * them again — every symlink under the destination for an `unknown` entry —
 * and only when they pass removes the entries it read that are still
 * unchanged.
 */
const NOTHING_CHANGED_AFTER_MERGE =
  "nothing was removed or changed; while the offending symlinks remain, remove them or point them inside the destination manually; this apply's containment entry records them and keeps check at needs-apply, and a later apply of any source verifies them again (every symlink under the destination when the entry could not record them) and, only when they pass, removes the entries it read that are still unchanged"

/**
 * Issue #219: the way out when the offending links are intended, for example
 * a virtualenv interpreter link that points into `/usr/bin` after an
 * interrupted apply forced a whole-destination check. Such a link fails every
 * later check, so the operator first has to stop or wait for all applies to
 * this destination to finish, with no new applies until inspection and state
 * clearing are complete. No apply may be active when inspection begins: the
 * tree must stay unchanged while it is checked, and clearing state must not
 * remove a live apply's in-progress entry. The operator can then check the
 * tree, clear the destination's containment entries and legacy flag, and
 * retry. This hint is offered only when the current archive's normal scope
 * passes without that state. Naming both concrete paths keeps the step
 * copyable; it is not a recommendation to clear entries blindly.
 *
 * @param entryDirectory - The destination's containment entry directory.
 * @param legacyFlag - The destination's containment flag from older versions.
 * @returns The sentence appended to a post-merge violation message.
 */
function intendedLinksHint(entryDirectory: string, legacyFlag: string): string {
  return `if the offending symlinks are intended (for example a virtualenv's interpreter link), they keep failing this check: first stop or wait for all archive.extract applies to this destination to finish and prevent new applies until inspection and state clearing are complete; then check the destination yourself and, before retrying, clear its containment state with rm -f -- ${shellQuote(entryDirectory)}/run-* ${shellQuote(legacyFlag)}`
}

/** Issue #219: how a violation names a link an earlier failed apply recorded. */
const RECORDED_NOTE = ", recorded by an earlier failed apply,"

/** Issue #219: the offending links when the backstop could not identify them. */
const UNIDENTIFIED = "unidentified"

/**
 * Issue #219: how many violations the failure message names before it
 * summarizes the rest as `(and N more)`, so a tree with many offending links
 * cannot inflate the message without bound.
 */
export const POST_MERGE_VIOLATION_REPORT_LIMIT = 10

/**
 * Issue #219: every symlink below the destination after the merge, keyed by
 * destination-relative path, with the links this archive can affect that
 * cannot be shown to stay inside.
 */
type PostMergeSymlinks = {
  /** The current archive's scope passes after clearing all containment state. */
  clearingStateWouldPass: boolean
  kind: "ok"
  links: ReadonlyMap<string, MergedSymlink>
  /** Issue #219: the links an earlier failed apply recorded. */
  recorded: ReadonlySet<string>
  violations: PostMergeViolation[]
  /** Issue #219: every listed symlink was judged, see `PostMergeReadingInputs`. */
  wholeDestination: boolean
}

/**
 * Issue #219: a violation for a path the listing could not show, because it
 * lies at or below an unreadable directory.
 */
type UnlistedViolation = Extract<
  PostMergeViolation,
  { kind: "unreadable-directory" | "unreadable-member" | "unreadable-recorded" }
>

/** Issue #219: a post-merge listing, or why it cannot be trusted. */
type PostMergeSymlinkReading = { detail: string; kind: "failed" } | PostMergeSymlinks

/**
 * Reuse the decoded listing to check whether state clearing would recover
 * the current archive. An unreadable directory cannot establish that the
 * offending links are intended, even when it lies outside archive scope.
 *
 * @param inputs - The original backstop reading inputs.
 * @param host - The decoded host listing.
 * @param host.links - Every symlink in the listing.
 * @param host.unreadable - Directories whose links could not be listed.
 * @returns The archive-scope judgement without recorded state, or undefined
 *   unless whole-destination verification has a readable listing.
 */
function originalArchiveScope(
  inputs: PostMergeReadingInputs,
  host: { links: ReadonlyMap<string, MergedSymlink>; unreadable?: ReadonlySet<string> }
): ReturnType<typeof listingViolations> | undefined {
  if (!inputs.wholeDestination || (host.unreadable?.size ?? 0) > 0) return undefined
  return listingViolations({ ...inputs, recorded: new Set(), wholeDestination: false }, host)
}

/**
 * Issue #219: read every symlink below the destination as it is now, judge
 * the links this archive can affect with the pre-merge resolver and let the
 * kernel confirm them.
 *
 * One batched exec of `buildSymlinkListingProbeScript` with the destination as
 * its only `r` entry lists each link with its stored target; nothing on the
 * host resolves a link in user space, so a self-extending loop such as
 * `b -> b/..` cannot hang the probe. The records are decoded by the same
 * {@link hostStateFromListing} the pre-merge check uses, with no requested
 * member paths, so any directory hit counts as broken framing. The listing
 * grows with the number of links on the host, not with violations, so it gets
 * its own capture cap; truncation still fails closed.
 *
 * Issue #219: only the links this archive can affect are judged, exactly as
 * before the merge (see `mergedSymlinkResolutions`): the archive's symlinks
 * that are present now and every link whose resolution touches a path the
 * archive writes. An archive member path at or below a directory the listing
 * could not read is a violation as well, because the links there are
 * unknown.
 *
 * Issue #219: the links an earlier failed apply recorded are judged from the
 * same listing, as if the archive shipped them (see `postMergeScope` in
 * `archivePostMergeJudgement.ts`).
 * A recorded link the listing no longer reports is gone and passes; one at or
 * below an unreadable directory is a violation.
 *
 * Issue #219: the resolver alone is lexical. Every judged link it places
 * inside is then handed to {@link runKernelCrossCheck} in one more batched
 * exec, which compares the link with the location the resolver computed by
 * device and inode, and, for a link that reaches nothing, the nearest
 * existing point of its target path with the resolver's location of that
 * point. A link the kernel resolves elsewhere, or whose nearest existing
 * point differs, is a `kernel-mismatch` violation; a cross-check that cannot
 * be completed fails the reading like a failed listing. Without judged links
 * inside, no cross-check runs.
 *
 * Issue #219: in a destination-wide verification every listed link is judged
 * from the same listing, every one judged inside rides in the same single
 * cross-check, and every directory the listing could not read is a violation
 * that leaves the offending links unidentified. The violations of listed
 * links are then reported in listing order.
 *
 * @param conn - The SSH connection.
 * @param inputs - Reading inputs, see {@link PostMergeReadingInputs}.
 * @returns The listed links with the violations of the judged ones, or why
 *   the reading cannot be trusted.
 */
async function readPostMergeSymlinks(
  conn: SshConnection,
  inputs: PostMergeReadingInputs
): Promise<PostMergeSymlinkReading> {
  const { destination, recorded, wholeDestination } = inputs
  const outcome = await runSymlinkListing(conn, [encodeSymlinkListingEntry("r", destination)])
  if (outcome.kind === "failed") return outcome
  const host = hostStateFromListing(destination, outcome.fields, new Map())
  if (typeof host === "string") return { detail: host, kind: "failed" }
  const { resolutions, violations } = listingViolations(inputs, host)
  const scoped = originalArchiveScope(inputs, host)
  const reading = {
    clearingStateWouldPass: scoped?.violations.length === 0,
    kind: "ok",
    links: host.links,
    recorded,
    wholeDestination,
  } as const
  const ordered = (all: PostMergeViolation[]): PostMergeViolation[] =>
    wholeDestination ? inListingOrder(all, host.links) : all
  if (resolutions.inside.size === 0) return { ...reading, violations: ordered(violations) }
  const kernel = await runKernelCrossCheck(conn, {
    destination,
    links: resolutions.inside.keys(),
    trail: resolutions.trail,
  })
  if (kernel.kind === "failed") {
    return { detail: `kernel cross-check could not be completed: ${kernel.detail}`, kind: "failed" }
  }
  const mismatches = kernel.mismatches.map(({ at, expected, key }): PostMergeViolation => ({
    at,
    expected,
    key,
    kind: "kernel-mismatch",
  }))
  return {
    ...reading,
    clearingStateWouldPass:
      reading.clearingStateWouldPass &&
      !kernel.mismatches.some(({ key }) => scoped?.resolutions.inside.has(key)),
    violations: ordered([...violations, ...mismatches]),
  }
}

/**
 * Issue #219: describe where the host kernel disagrees with the containment
 * check for one link.
 *
 * @param mismatch - A `kernel-mismatch` violation.
 * @param mismatch.at - Where the kernel and the check disagree.
 * @param mismatch.expected - The absolute location the check computed.
 * @returns The description, starting after the link it is about.
 */
function kernelMismatchDescription(mismatch: {
  at: KernelMismatchPoint
  expected: string
}): string {
  const { at, expected } = mismatch
  switch (at.kind) {
    case "link": {
      return `resolves on the host to a different location than the containment check computed (${JSON.stringify(expected)})`
    }
    case "none": {
      return `reaches nothing on the host, and no point of its target path exists on the host or where the containment check computed it, so its location (${JSON.stringify(expected)}) cannot be confirmed`
    }
    case "point": {
      return `reaches nothing on the host, and the nearest existing point of its target path, ${JSON.stringify(at.host)} on the host, is not the location the containment check computed for it (${JSON.stringify(at.location)})`
    }
  }
}

/**
 * Issue #219: describe a violation for a path the listing could not show,
 * because it lies at or below an unreadable directory.
 *
 * @param destination - The validated, canonical destination directory.
 * @param violation - An `unreadable-member`, `unreadable-recorded` or
 *   `unreadable-directory` violation.
 * @returns The path and the unreadable directory it lies in, as message text.
 */
function unlistedPathDescription(destination: string, violation: UnlistedViolation): string {
  if (violation.kind === UNREADABLE_DIRECTORY) {
    return `directory ${quotedHostPath(destination, violation.directory)} is not readable, so the symlinks below it cannot be checked`
  }
  const path = quotedHostPath(destination, violation.key)
  const subject =
    violation.kind === UNREADABLE_MEMBER
      ? `archive member path ${path}`
      : `symlink ${path}${RECORDED_NOTE}`
  return `${subject} cannot be checked: directory ${quotedHostPath(destination, violation.directory)} is not readable`
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
  if (
    violation.kind === UNREADABLE_MEMBER ||
    violation.kind === "unreadable-recorded" ||
    violation.kind === UNREADABLE_DIRECTORY
  ) {
    return unlistedPathDescription(destination, violation)
  }
  const stored = reading.links.get(violation.key)?.stored ?? ""
  // Issue #219: name a link an earlier failed apply recorded as such, so the
  // operator sees why a source that never touches it still fails.
  const recorded = reading.recorded.has(violation.key) ? RECORDED_NOTE : ""
  const link = `${symlinkDescription(destination, violation.key, stored)}${recorded}`
  return `${link} ${linkViolationReason(destination, violation)}`
}

/**
 * Describe why a listed link violates containment.
 *
 * @param destination - The validated, canonical destination directory.
 * @param violation - The violation of a listed link.
 * @returns The reason, following the link description.
 */
function linkViolationReason(
  destination: string,
  violation: Exclude<PostMergeViolation, UnlistedViolation>
): string {
  switch (violation.kind) {
    case "escape": {
      return `resolves outside destination ${JSON.stringify(destination)}`
    }
    case "kernel-mismatch": {
      return kernelMismatchDescription(violation)
    }
    case "limit": {
      return "cannot be resolved within the symlink resolution limit"
    }
    case "unmappable":
    case "unreadable": {
      return unverifiableLinkReason(destination, violation)
    }
    case "variant": {
      return variantDescription(violation)
    }
  }
}

/**
 * Issue #219: describe the violations the post-merge check found, at most
 * {@link POST_MERGE_VIOLATION_REPORT_LIMIT} of them, and say that nothing was
 * changed.
 *
 * @param destination - The validated, canonical destination directory.
 * @param reading - The post-merge listing, with at least one violation.
 * @param paths - The destination's containment state paths.
 * @param paths.entryDirectory - Issue #219: the destination's containment entry
 *   directory, needed for a complete {@link intendedLinksHint}.
 * @param paths.legacyFlag - The destination's old containment flag; the hint needs
 *   both paths and a passing current archive scope after clearing state.
 * @returns The violation text without the `[archive.extract]` prefix, with the
 *   `(and N more)` suffix after the listed links when there are more.
 */
function containmentViolationMessage(
  destination: string,
  reading: PostMergeSymlinks,
  paths: { entryDirectory?: string; legacyFlag?: string }
): string {
  const { entryDirectory, legacyFlag } = paths
  const listed = reading.violations
    .slice(0, POST_MERGE_VIOLATION_REPORT_LIMIT)
    .map((violation) => postMergeViolationDescription(destination, reading, violation))
  const more = reading.violations.length - listed.length
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  const checked = reading.wholeDestination
    ? CHECKED_WHOLE_DESTINATION_AFTER_MERGE
    : CHECKED_AFTER_MERGE
  const hint =
    reading.clearingStateWouldPass && entryDirectory !== undefined && legacyFlag !== undefined
      ? `; ${intendedLinksHint(entryDirectory, legacyFlag)}`
      : ""
  return `${listed.join("; ")}${suffix}; ${checked}; ${NOTHING_CHANGED_AFTER_MERGE}${hint}`
}

/**
 * Issue #219: what the post-merge backstop found: its failure, if any, and
 * the offending link keys to record in the own containment entry — every violating
 * link, or `unidentified` when the reading failed or an archive member lies
 * in a directory the listing could not read, so links there are unknown. In a
 * destination-wide verification any directory the listing could not read
 * leaves the links `unidentified`.
 */
export type ContainmentBackstopOutcome = {
  failure: ModuleResult | null
  offendingLinks: readonly string[] | typeof UNIDENTIFIED
}

/**
 * Issue #219: the offending link keys of the violations, see
 * {@link ContainmentBackstopOutcome}.
 *
 * @param violations - The post-merge violations.
 * @returns The distinct link keys, or `unidentified`.
 */
function offendingLinkKeys(
  violations: readonly PostMergeViolation[]
): ContainmentBackstopOutcome["offendingLinks"] {
  if (
    violations.some(
      (violation) => violation.kind === UNREADABLE_MEMBER || violation.kind === UNREADABLE_DIRECTORY
    )
  ) {
    return UNIDENTIFIED
  }
  return [...new Set(violations.map((violation) => violation.key))]
}

/**
 * Issue #219: the post-merge backstop. List every symlink below the
 * destination as it actually is, judge the links this archive can affect with
 * the resolver the pre-merge model uses, let the host kernel confirm every
 * such link judged inside, and fail the run on any violation.
 *
 * This runs after every merge that started, even a failed one, because a
 * merge that failed half-way may already have published links. It covers
 * links this archive did not ship whose resolution passes through a path it
 * writes, and host changes between the pre-merge listing and the merge. A
 * link elsewhere in the destination is not judged, even when it points
 * outside; the merge cannot have changed where it resolves (Issue #219:
 * unless the whole destination has to be verified, see below). An archive
 * without symlink members runs no exec here at all, for the reason
 * `validateMergedSymlinkContainment` gives (Issue #219: unless links are
 * recorded or the whole destination has to be verified, see below). It never asks the host to resolve
 * a link in user space: the host only lists links with their stored targets (see
 * `buildSymlinkListingProbeScript`), `mergedSymlinkResolutions` resolves
 * them in TypeScript with its hop limit and cycle detection, and the kernel
 * cross-check only compares files with `test -ef`. GNU `realpath`, which the
 * backstop used before, never terminates on a self-extending loop such as
 * `b -> b/..` or `x -> y/..` with `y -> x`, and the remote process outlived
 * the client's timeout.
 *
 * Decision: a link the resolver reports as `limit` (hop limit or cycle) is
 * treated like an escaping link. It cannot be shown to stay inside, and the
 * pre-merge model counts it as a violation as well; the run fails and names
 * it. The same holds for a `variant` link and for a `kernel-mismatch`.
 *
 * Issue #219: the backstop only detects and reports. It never removes, moves
 * or rewrites a link, because another writer can change the tree between any
 * check and any change the backstop could make. On a violation the run fails,
 * so the containment entry the caller created before the merge stays and
 * `check` keeps reporting needs-apply. The caller records the offending links
 * in that entry, and a later apply of any source removes it only after this
 * backstop re-verified them — or, when the entry could not record them, after
 * it verified the whole destination. The message
 * names the first {@link POST_MERGE_VIOLATION_REPORT_LIMIT} violations by
 * absolute link path, stored target and reason, adds `(and N more)` for the
 * rest, and states that nothing was removed or changed, so the offending links
 * must be removed or pointed inside manually while they remain.
 *
 * Cost: a converged tree costs one listing exec plus one kernel cross-check
 * exec when a judged symlink is placed inside, one exec otherwise, and none
 * for an archive without symlink members, regardless of member or link
 * count. A violation adds no further exec. Issue #219: recorded links ride in
 * the same listing and cross-check; for an archive without symlink members
 * they cost that listing (and the cross-check when one is judged inside)
 * instead of nothing.
 *
 * Issue #219: with `verifyWholeDestination` — a containment entry held no
 * usable list of offending links, so any link under the destination may be
 * one an unfinished or unrecorded apply published — every symlink the same
 * listing reports is judged, not only those this archive can affect, and
 * every one judged inside rides in the same single cross-check. Any directory
 * the listing could not read, anywhere below the destination, makes the
 * verification incomplete, as does a failed, truncated or throwing listing or
 * an incomplete cross-check; the offending links are then `unidentified`. The
 * listing runs even for an archive without symlink members, so this mode costs
 * such an archive one listing exec more than an absent flag, plus the
 * cross-check when a link is judged inside, and an archive with symlink
 * members nothing more; the cost stays constant in the member count.
 *
 * A listing that failed (including a missing or unusable `readlink`, a `find`
 * traversal error other than an unreadable directory with GNU find, and a
 * truncated capture), returned broken framing or a duplicate link, or whose
 * kernel cross-check could not be completed fails the run as well.
 *
 * @param conn - The SSH connection.
 * @param parameters - Backstop inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.entryDirectory - Issue #219: the destination's
 *   containment entry directory. Together with `legacyFlag`, a violation
 *   message names how to clear state only when whole-destination verification
 *   fails but the current archive's normal scope would pass after clearing it.
 *   Omitted, the message stays without that hint.
 * @param parameters.legacyFlag - The destination's old containment flag;
 *   omitted, the message stays without the state-clearing hint.
 * @param parameters.members - The validated archive members; they decide
 *   which links are judged.
 * @param parameters.recordedLinks - Issue #219: the links earlier failed
 *   applies recorded in their containment entries; they are judged as well.
 * @param parameters.source - The archive source, for the failure message.
 * @param parameters.verifyWholeDestination - Issue #219: judge every symlink
 *   under the destination, because a containment entry held no usable list
 *   of offending links; off when omitted.
 * @returns The failure (null when every judged symlink stays inside) and the
 *   offending link keys, see {@link ContainmentBackstopOutcome}.
 */
export async function runSymlinkContainmentBackstop(
  conn: SshConnection,
  parameters: {
    destination: string
    entryDirectory?: string
    legacyFlag?: string
    members: readonly ArchiveMember[]
    recordedLinks?: readonly string[]
    source: string
    verifyWholeDestination?: boolean
  }
): Promise<ContainmentBackstopOutcome> {
  const { destination, members, source } = parameters
  const recorded = new Set(parameters.recordedLinks ?? [])
  const wholeDestination = parameters.verifyWholeDestination === true
  if (!wholeDestination && !archiveHasSymlinks(members) && recorded.size === 0) {
    return { failure: null, offendingLinks: [] }
  }
  const prefix = `[archive.extract] refusing to complete extraction of ${source}`
  const reading = await readPostMergeSymlinks(conn, {
    destination,
    members,
    recorded,
    wholeDestination,
  })
  if (reading.kind === "failed") {
    return {
      failure: failed(`${prefix}: symlink containment check failed: ${reading.detail}`),
      offendingLinks: UNIDENTIFIED,
    }
  }
  if (reading.violations.length === 0) return { failure: null, offendingLinks: [] }
  return {
    failure: failed(`${prefix}: ${containmentViolationMessage(destination, reading, parameters)}`),
    offendingLinks: offendingLinkKeys(reading.violations),
  }
}

/**
 * Issue #219: the post-merge backstop without the offending link keys, see
 * {@link runSymlinkContainmentBackstop}.
 *
 * @param conn - The SSH connection.
 * @param parameters - Backstop inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.members - The validated archive members; they decide
 *   which links are judged.
 * @param parameters.recordedLinks - Issue #219: links an earlier failed apply
 *   recorded; none when omitted.
 * @param parameters.source - The archive source, for the failure message.
 * @param parameters.verifyWholeDestination - Issue #219: judge every symlink
 *   under the destination; off when omitted.
 * @returns Null when every judged symlink stays inside, otherwise a failure
 *   naming the offending links, or why the check could not run.
 */
export async function enforceSymlinkContainment(
  conn: SshConnection,
  parameters: {
    destination: string
    members: readonly ArchiveMember[]
    recordedLinks?: readonly string[]
    source: string
    verifyWholeDestination?: boolean
  }
): Promise<ModuleResult | null> {
  const outcome = await runSymlinkContainmentBackstop(conn, parameters)
  return outcome.failure
}
