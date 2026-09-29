/**
 * Symlink containment around the staging merge of `archive.extract`.
 *
 * Issue #219: whether a relative link stays inside the destination depends on
 * the links its target passes through, and those can come from an earlier run
 * or the host. Two checks bracket the merge:
 *
 * - before it, {@link validateMergedSymlinkContainment} lists the host's links
 *   and the host directories at the archive's non-directory member paths in one
 *   exec, models the post-merge link set and refuses an escaping combination
 *   or a merge whose outcome the model cannot predict, before anything is
 *   copied;
 * - after it, {@link enforceSymlinkContainment} lists every link below the
 *   destination as it actually is with the same probe, judges the set with the
 *   same resolver, removes each violating link without following it, re-checks
 *   and repeats while the removal makes progress, and fails the run.
 *
 * Neither check asks the host to resolve a link; the host only reports stored
 * targets, and the resolver in `archiveLinkValidation.ts` bounds every walk.
 */
import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import {
  ARCHIVE_MEMBER_KIND_LABELS,
  nonDirectoryMemberPaths,
} from "./archiveDestinationValidation.js"
import {
  type MergedArchiveSymlinks,
  mergedArchiveSymlinks,
  type MergedSymlink,
  type MergedSymlinkViolation,
  mergedSymlinkViolations,
  type MergeHostState,
  type SymlinkWalkTarget,
} from "./archiveLinkValidation.js"
import { ARCHIVE_CAPTURE_LIMIT_BYTES, type ArchiveMember } from "./archiveMemberValidation.js"
import {
  buildSymlinkListingProbeScript,
  encodeSymlinkListingEntry,
  removeEscapingSymlinks,
  runBatchedProbe,
  type SymlinkRemovalReport,
} from "./archiveProbe.js"

export { removeEscapingSymlinks } from "./archiveProbe.js"

const CHECKED_AFTER_MERGE =
  "every symlink under the destination is checked after the merge, including links this archive did not ship"

/**
 * Issue #219: the pre-merge model's verdict for one archive, see
 * {@link preMergeContainmentVerdict}.
 *
 * - `invalid`: the listing output cannot be trusted (broken framing or a path
 *   that is not below the destination); `reason` says why.
 * - `conflict`: a member whose merge is not the modelled replacement (see
 *   {@link mergedArchiveSymlinks}).
 * - `violations`: the combined link set has links that escape or exceed the
 *   resolution limit.
 * - `ok`: the combined link set stays inside the destination.
 */
export type PreMergeContainmentVerdict =
  | { kind: "invalid"; reason: string }
  | { kind: "ok"; links: ReadonlyMap<string, MergedSymlink> }
  | {
      kind: "violations"
      links: ReadonlyMap<string, MergedSymlink>
      violations: MergedSymlinkViolation[]
    }
  | Extract<MergedArchiveSymlinks, { kind: "conflict" }>

/**
 * Issue #219: every symlink below the destination after the merge, keyed by
 * destination-relative path, with the links the resolver cannot show to stay
 * inside.
 */
type PostMergeSymlinks = {
  kind: "ok"
  links: ReadonlyMap<string, MergedSymlink>
  violations: MergedSymlinkViolation[]
}

/** Issue #219: a post-merge listing, or why it cannot be trusted. */
type PostMergeSymlinkReading = { detail: string; kind: "failed" } | PostMergeSymlinks

/**
 * Classify a raw host symlink target for the resolver.
 *
 * A relative target is walked from the link's parent. An absolute target equal
 * to or below the canonical destination restarts at the destination root; any
 * other absolute target counts as escaping, a fail-closed stance on
 * pre-existing links that point outside that both the pre-merge and the
 * post-merge check share. The
 * prefix comparison is literal, so an absolute target that reaches the
 * destination through a non-canonical spelling is judged conservatively as
 * outside.
 *
 * @param destination - The validated, canonical destination directory.
 * @param target - The target exactly as `readlink` reported it.
 * @returns How the resolver walks the target: from the link's parent, from the
 *   destination root, or not at all because it lies outside.
 */
function hostSymlinkWalkTarget(destination: string, target: string): SymlinkWalkTarget {
  if (!target.startsWith("/")) return { anchor: "parent", path: target }
  if (target === destination) return { anchor: "root", path: "" }
  if (target.startsWith(`${destination}/`)) {
    return { anchor: "root", path: target.slice(destination.length + 1) }
  }
  return { anchor: "outside" }
}

/**
 * Issue #219: the entries of the pre-merge listing probe (see
 * {@link buildSymlinkListingProbeScript}): one `r` entry for the destination,
 * then one `n` entry per non-directory member path below it.
 *
 * @param destination - The validated, canonical destination directory.
 * @param members - The validated archive members.
 * @returns The encoded entries (see {@link encodeSymlinkListingEntry}).
 */
export function symlinkListingEntries(
  destination: string,
  members: readonly ArchiveMember[]
): string[] {
  const directoryChecks = [...nonDirectoryMemberPaths(destination, members).keys()]
  return [
    encodeSymlinkListingEntry("r", destination),
    ...directoryChecks.map((path) => encodeSymlinkListingEntry("n", path)),
  ]
}

/**
 * Add one decoded listing pair to the host state.
 *
 * @param state - The host state being built, with the requested directory paths.
 * @param state.destination - The validated, canonical destination directory.
 * @param state.directories - Collector for directory hits by member key.
 * @param state.links - Collector for host links by destination-relative path.
 * @param state.requested - The `n` entry paths that were sent, mapped to their key.
 * @param pair - The `(link, target)` or `("", directory)` pair.
 * @returns Null when the pair was added, otherwise why the output cannot be trusted.
 */
function addListingPair(
  state: {
    destination: string
    directories: Set<string>
    links: Map<string, MergedSymlink>
    requested: ReadonlyMap<string, string>
  },
  pair: readonly [string, string]
): null | string {
  const [first, second] = pair
  if (first === "") {
    const key = state.requested.get(second)
    if (key === undefined) {
      return `probe reported directory ${JSON.stringify(second)}, which is not a requested member path below the destination`
    }
    state.directories.add(key)
    return null
  }
  const prefix = `${state.destination}/`
  if (!first.startsWith(prefix) || first.length === prefix.length) {
    return `probe reported ${JSON.stringify(first)}, which is not below the destination`
  }
  // Issue #219: Linux cannot store an empty symlink target, so an empty one
  // means `readlink` succeeded without printing the target. The resolver would
  // walk it as the link's parent directory, i.e. as contained, so an unusable
  // `readlink` fails the listing instead.
  if (second === "") {
    return `probe reported an empty target for symlink ${JSON.stringify(first)}; readlink output is unusable`
  }
  state.links.set(first.slice(prefix.length), {
    stored: second,
    target: hostSymlinkWalkTarget(state.destination, second),
  })
  return null
}

/**
 * Turn the decoded listing fields into the host state the link model needs,
 * or explain why the output cannot be trusted.
 *
 * Issue #219: the post-merge backstop passes an empty `requested` map, because
 * it sends no `n` entries; any directory hit is then broken framing.
 *
 * @param destination - The validated, canonical destination directory.
 * @param fields - The decoded probe fields.
 * @param requested - The `n` entry paths that were sent, mapped to their key.
 * @returns The host state, or a reason the framing is broken.
 */
function hostStateFromListing(
  destination: string,
  fields: readonly string[],
  requested: ReadonlyMap<string, string>
): MergeHostState | string {
  // An odd field count means the pair framing broke somewhere; pairing the
  // rest anyway could attach a target to the wrong link.
  if (fields.length % 2 !== 0) {
    return `probe returned ${String(fields.length)} fields, expected (link, target) or ("", directory) pairs`
  }
  const state = {
    destination,
    directories: new Set<string>(),
    links: new Map<string, MergedSymlink>(),
    requested,
  }
  for (let index = 0; index < fields.length; index += 2) {
    const broken = addListingPair(state, [fields[index], fields[index + 1]])
    if (broken !== null) return broken
  }
  return { directories: state.directories, links: state.links }
}

/**
 * Issue #219: judge an archive against the decoded output of the pre-merge
 * listing probe, without any I/O.
 *
 * The listing must be the output of {@link buildSymlinkListingProbeScript} for
 * the entries of {@link symlinkListingEntries} with the same destination and
 * members. The verdict is `invalid` when the framing is broken or a reported
 * path is not below the destination (or, for a directory hit, not one of the
 * requested member paths), `conflict` when a member's merge is not the
 * modelled replacement, `violations` when the combined link set escapes or
 * exceeds the resolution limit, and `ok` otherwise.
 *
 * @param destination - The validated, canonical destination directory.
 * @param fields - The decoded listing probe fields.
 * @param members - The validated archive members, in listing order.
 * @returns The model verdict.
 */
export function preMergeContainmentVerdict(
  destination: string,
  fields: readonly string[],
  members: readonly ArchiveMember[]
): PreMergeContainmentVerdict {
  const requested = nonDirectoryMemberPaths(destination, members)
  const host = hostStateFromListing(destination, fields, requested)
  if (typeof host === "string") return { kind: "invalid", reason: host }
  const merged = mergedArchiveSymlinks(host, members)
  if (merged.kind === "conflict") return merged
  const violations = mergedSymlinkViolations(merged.links)
  if (violations.length === 0) return { kind: "ok", links: merged.links }
  return { kind: "violations", links: merged.links, violations }
}

/**
 * Describe a merge conflict of the pre-merge model.
 *
 * @param destination - The validated, canonical destination directory.
 * @param conflict - The conflict the model reported.
 * @returns The refusal reason without the `[archive.extract]` prefix.
 */
function mergeConflictRefusal(
  destination: string,
  conflict: Extract<MergedArchiveSymlinks, { kind: "conflict" }>
): string {
  const member = `archive member ${JSON.stringify(conflict.member.path)}`
  const kind = ARCHIVE_MEMBER_KIND_LABELS[conflict.member.kind]
  const path = JSON.stringify(`${destination}/${conflict.key}`)
  const detail = {
    "below-host-symlink": `${member} lies below existing host symlink ${path}`,
    "host-directory": `${member} is a ${kind} but destination path ${path} is an existing directory`,
    "host-symlink": `${member} is a ${kind} but destination path ${path} is an existing symlink`,
  }[conflict.reason]
  return `${detail}; the merge could not put this member in place as the symlink containment check models it, so nothing is copied`
}

/**
 * Describe the first violation of the combined link set, naming the link by
 * absolute path with its stored target, plus how many more there are.
 *
 * @param parameters - Refusal inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.links - The combined post-merge link set.
 * @param parameters.violations - The non-empty violations of `links`.
 * @returns The refusal reason without the `[archive.extract]` prefix.
 */
function mergedSymlinkRefusal(parameters: {
  destination: string
  links: ReadonlyMap<string, MergedSymlink>
  violations: readonly MergedSymlinkViolation[]
}): string {
  const { destination, links, violations } = parameters
  const [{ key, kind }] = violations
  const linkPath = `${destination}/${key}`
  const link = `symlink ${JSON.stringify(linkPath)} -> ${JSON.stringify(links.get(key)?.stored ?? "")}`
  const violation =
    kind === "escape"
      ? `${link} would resolve outside destination ${JSON.stringify(destination)}`
      : `${link} would exceed the symlink resolution limit`
  const more = violations.length - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return `${violation} once this archive is merged; existing symlinks under the destination are checked together with the archive's links before anything is copied${suffix}`
}

/**
 * Refuse an extraction before the staging merge when the links already under
 * the destination and the links this archive ships would, together, resolve
 * outside the destination, or when a member's merge is not the replacement
 * the link model assumes.
 *
 * Issue #219: whether a relative link stays inside depends on the links its
 * target passes through, and those can come from an earlier run. Run 1 may
 * ship `a/esc -> up/..` (inside while `a/up` is missing) and run 2
 * `a/up -> ..` (inside on its own); merged, `a/esc` resolves above the
 * destination. This check lists every existing symlink with its stored target,
 * and every non-directory member path that is an existing real directory, in
 * one batched exec ({@link buildSymlinkListingProbeScript}), judges the result
 * with {@link preMergeContainmentVerdict} and refuses a conflict or a
 * violation, so nothing is copied into the destination.
 * {@link enforceSymlinkContainment} stays in place after the merge as the
 * backstop for host changes that land between this listing and the merge.
 *
 * Host link paths and targets are split on `/` only, so spaces and newlines in
 * them are handled faithfully. A probe failure (including a `find` traversal
 * error or an unreadable link), a truncated capture and output that is not
 * made of pairs with paths below the destination all fail closed.
 *
 * @param conn - The SSH connection.
 * @param parameters - Check inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.members - The validated archive members.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when the merge would publish an escaping link, cannot be
 *   modelled, or the check could not run, otherwise null.
 */
export async function validateMergedSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; members: readonly ArchiveMember[]; source: string }
): Promise<ModuleResult | null> {
  const { destination, members, source } = parameters
  const prefix = `[archive.extract] refusing to extract ${source}`
  // The listing grows with the number of links on the host (a `node_modules`
  // tree has many), not with violations, so it gets the archive capture cap
  // instead of the 1 MiB default. Truncation still fails closed.
  const outcome = await runBatchedProbe(conn, {
    entries: symlinkListingEntries(destination, members),
    maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
    script: buildSymlinkListingProbeScript(),
  })
  if (outcome.kind === "failed") {
    return failed(`${prefix}: symlink listing before the merge failed: ${outcome.detail}`)
  }
  const verdict = preMergeContainmentVerdict(destination, outcome.fields, members)
  switch (verdict.kind) {
    case "conflict": {
      return failed(`${prefix}: ${mergeConflictRefusal(destination, verdict)}`)
    }
    case "invalid": {
      return failed(`${prefix}: symlink listing before the merge failed: ${verdict.reason}`)
    }
    case "ok": {
      return null
    }
    case "violations": {
      return failed(`${prefix}: ${mergedSymlinkRefusal({ destination, ...verdict })}`)
    }
  }
}

/**
 * Issue #219: read every symlink below the destination as it is now and judge
 * the whole set with the pre-merge resolver.
 *
 * One batched exec of {@link buildSymlinkListingProbeScript} with the
 * destination as its only `r` entry lists each link with its stored target;
 * nothing on the host resolves a link, so a self-extending loop such as
 * `b -> b/..` cannot hang the probe. The pairs are decoded by the same
 * {@link hostStateFromListing} the pre-merge check uses, with no requested
 * member paths, so any directory hit counts as broken framing. The listing
 * grows with the number of links on the host, not with violations, so it gets
 * the archive capture cap; truncation still fails closed.
 *
 * @param conn - The SSH connection.
 * @param destination - The validated, canonical destination directory.
 * @returns The listed links with their violations (see
 *   {@link mergedSymlinkViolations}), or why the listing cannot be trusted.
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
  return { kind: "ok", links: host.links, violations: mergedSymlinkViolations(host.links) }
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
  violation: MergedSymlinkViolation
): string {
  const { key, kind } = violation
  const stored = reading.links.get(key)?.stored ?? ""
  const linkPath = `${destination}/${key}`
  const link = `symlink ${JSON.stringify(linkPath)} -> ${JSON.stringify(stored)}`
  return kind === "escape"
    ? `${link} resolves outside destination ${JSON.stringify(destination)}`
    : `${link} cannot be resolved within the symlink resolution limit`
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
  /** The listing taken after the last round. */
  recheck: PostMergeSymlinkReading
  /** Every link removed in any round, in removal order, without duplicates. */
  removed: readonly string[]
}

/**
 * Fold one removal report into the totals across rounds: a removed link is no
 * longer reported as kept, a kept link carries its latest reason.
 *
 * @param totals - The accumulated totals, updated in place.
 * @param totals.kept - Links still in place, with the latest reason.
 * @param totals.removed - Links removed in any round, in removal order.
 * @param report - The report of the latest removal round.
 */
function recordRemovalRound(
  totals: { kept: Map<string, string>; removed: Set<string> },
  report: SymlinkRemovalReport
): void {
  for (const link of report.removed) {
    totals.removed.add(link)
    totals.kept.delete(link)
  }
  for (const [link, reason] of report.kept) totals.kept.set(link, reason)
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
 * new links. Each round costs one removal exec and one listing exec.
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
  const totals = { kept: new Map<string, string>(), removed: new Set<string>() }
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
  return { kept: totals.kept, recheck, removed: [...totals.removed] }
}

/**
 * Describe what the removal rounds did and what the last re-check found.
 *
 * @param destination - The validated, canonical destination directory.
 * @param rounds - The accumulated outcome of {@link removeViolatingSymlinks}.
 * @returns The message tail, starting with `; `.
 */
function enforcementSummary(destination: string, rounds: RemovalRounds): string {
  const { kept, recheck, removed } = rounds
  const parts: string[] = []
  if (removed.length > 0) {
    parts.push(
      `removed escaping symlinks: ${removed.map((link) => JSON.stringify(link)).join(", ")}`
    )
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
 * model uses, remove each violating link and fail the run.
 *
 * This runs after every merge that started, even a failed one, because a
 * merge that failed half-way may already have published links. It covers
 * links this archive did not ship and host changes between the pre-merge
 * listing and the merge. It never asks the host to resolve a link: the host
 * only lists links with their stored targets (see
 * {@link buildSymlinkListingProbeScript}), and {@link mergedSymlinkViolations}
 * resolves them in TypeScript with its hop limit and cycle detection. GNU
 * `realpath`, which the backstop used before, never terminates on a
 * self-extending loop such as `b -> b/..` or `x -> y/..` with `y -> x`, and the
 * remote process outlived the client's timeout.
 *
 * Decision: a link the resolver reports as `limit` (hop limit or cycle) is
 * treated like an escaping link and removed. It cannot be shown to stay
 * inside, the pre-merge model counts it as a violation as well, and the
 * previous backstop removed links it could not resolve; the run fails and
 * names it either way.
 *
 * On a violation it removes the reported links, re-lists and repeats while a
 * round makes progress (see {@link removeViolatingSymlinks}). The run still
 * fails after a removal, so the containment flag the caller wrote before the
 * merge stays set. The message names the first violation, every link removed
 * in any round, every link that could not be removed with its reason, and the
 * last re-check: every link it still reports, or why it failed.
 *
 * Cost: a converged tree costs exactly one listing exec regardless of member
 * count; each removal round adds one removal exec and one listing exec.
 *
 * A listing that failed (including a missing or unusable `readlink`, a `find`
 * traversal error and a truncated capture) or returned broken framing removes
 * nothing and fails the run.
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
