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
 * - after it, {@link enforceSymlinkContainment} resolves every link below the
 *   destination as it actually is, removes each escaping link it reports
 *   without following it, re-checks once and fails the run.
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
  buildSymlinkContainmentProbeScript,
  buildSymlinkListingProbeScript,
  buildSymlinkRemovalScript,
  encodeSymlinkListingEntry,
  escapingSymlinkRemovalRefusal,
  runBatchedProbe,
  type SymlinkRemovalReport,
  symlinkRemovalReport,
} from "./archiveProbe.js"

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

type EscapingSymlinkReading =
  { detail: string; kind: "failed" } | { kind: "ok"; pairs: Array<readonly [string, string]> }

/**
 * Classify a raw host symlink target for the resolver.
 *
 * A relative target is walked from the link's parent. An absolute target equal
 * to or below the canonical destination restarts at the destination root; any
 * other absolute target counts as escaping, consistent with the post-merge
 * check's fail-closed stance on pre-existing links that point outside. The
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
 * Run the post-merge containment probe once and decode its `(link, resolved)`
 * pairs.
 *
 * @param conn - The SSH connection.
 * @param destination - The validated, canonical destination directory.
 * @returns The escaping links with their resolved paths, or why the probe failed.
 */
async function readEscapingSymlinks(
  conn: SshConnection,
  destination: string
): Promise<EscapingSymlinkReading> {
  const outcome = await runBatchedProbe(conn, {
    entries: [destination],
    script: buildSymlinkContainmentProbeScript(),
  })
  if (outcome.kind === "failed") return outcome
  const { fields } = outcome
  // An odd field count means the pair framing broke somewhere; pairing the
  // rest anyway could attach a resolved path to the wrong link.
  if (fields.length % 2 !== 0) {
    return {
      detail: `probe returned ${String(fields.length)} fields, expected (link, resolved) pairs`,
      kind: "failed",
    }
  }
  const pairs: Array<readonly [string, string]> = []
  for (let index = 0; index < fields.length; index += 2) {
    pairs.push([fields[index], fields[index + 1]])
  }
  return { kind: "ok", pairs }
}

/**
 * Describe one escaping link and how many more there are.
 *
 * @param destination - The validated, canonical destination directory.
 * @param pairs - The non-empty `(link, resolved)` pairs; an empty resolved path
 *   means the link could not be resolved.
 * @returns The description of the first pair with the `(and N more)` suffix.
 */
function escapingSymlinkDescription(
  destination: string,
  pairs: ReadonlyArray<readonly [string, string]>
): string {
  const [[link, resolved]] = pairs
  const more = pairs.length - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  const violation =
    resolved === ""
      ? `symlink ${JSON.stringify(link)} could not be resolved`
      : `symlink ${JSON.stringify(link)} resolves to ${JSON.stringify(resolved)}, outside destination ${JSON.stringify(destination)}`
  return `${violation}${suffix}`
}

/**
 * Describe the first escaping link the post-merge probe reported.
 *
 * @param destination - The validated, canonical destination directory.
 * @param pairs - The non-empty `(link, resolved)` pairs.
 * @returns The violation text without the `[archive.extract]` prefix.
 */
function containmentViolationMessage(
  destination: string,
  pairs: ReadonlyArray<readonly [string, string]>
): string {
  const [first] = pairs
  const more = pairs.length - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return `${escapingSymlinkDescription(destination, [first])}; ${CHECKED_AFTER_MERGE}${suffix}`
}

/**
 * Refuse to complete an extraction when any symlink below the destination
 * resolves outside it, with one batched probe over the whole tree.
 *
 * Issue #219: this is the check-only form of {@link enforceSymlinkContainment}:
 * it reports, but never removes. A probe failure, an output that is not made
 * of `(link, resolved)` pairs, or a link that could not be resolved all fail
 * closed.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when a symlink escapes the destination or the check could not run, otherwise null.
 */
export async function validateSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const { destination, source } = parameters
  const prefix = `[archive.extract] refusing to complete extraction of ${source}`
  const reading = await readEscapingSymlinks(conn, destination)
  if (reading.kind === "failed") {
    return failed(`${prefix}: symlink containment check failed: ${reading.detail}`)
  }
  if (reading.pairs.length === 0) return null
  return failed(`${prefix}: ${containmentViolationMessage(destination, reading.pairs)}`)
}

/**
 * Issue #219: remove the given escaping links with one batched exec, never
 * following them.
 *
 * Each link is first vetted by {@link escapingSymlinkRemovalRefusal}; only the
 * vetted ones reach {@link buildSymlinkRemovalScript}, which re-checks every
 * ancestor and the link itself on the host before a no-follow `rm -f`.
 *
 * @param conn - The SSH connection.
 * @param destination - The validated, canonical destination directory.
 * @param links - The link paths the containment probe reported.
 * @returns Which links were removed and which were kept, with reasons.
 */
export async function removeEscapingSymlinks(
  conn: SshConnection,
  destination: string,
  links: readonly string[]
): Promise<SymlinkRemovalReport> {
  const refused: Array<readonly [string, string]> = []
  const vetted: string[] = []
  for (const link of new Set(links)) {
    const refusal = escapingSymlinkRemovalRefusal(destination, link)
    if (refusal === null) vetted.push(link)
    else refused.push([link, refusal])
  }
  const outcome = await runBatchedProbe(conn, {
    entries: vetted,
    script: buildSymlinkRemovalScript(destination),
  })
  const report = symlinkRemovalReport(vetted, outcome)
  return { kept: [...refused, ...report.kept], removed: report.removed }
}

/**
 * Describe what the removal did and what the re-check found.
 *
 * @param destination - The validated, canonical destination directory.
 * @param report - The removal report.
 * @param recheck - The containment probe run after the removal.
 * @returns The message tail, starting with `; `.
 */
function enforcementSummary(
  destination: string,
  report: SymlinkRemovalReport,
  recheck: EscapingSymlinkReading
): string {
  const parts: string[] = []
  if (report.removed.length > 0) {
    parts.push(
      `removed escaping symlinks: ${report.removed.map((link) => JSON.stringify(link)).join(", ")}`
    )
  }
  if (report.kept.length > 0) {
    const kept = report.kept.map(([link, reason]) => `${JSON.stringify(link)} (${reason})`)
    parts.push(`could not remove: ${kept.join(", ")}`)
  }
  if (recheck.kind === "failed") parts.push(`re-check failed: ${recheck.detail}`)
  else if (recheck.pairs.length === 0) parts.push("re-check found no escaping symlinks")
  else
    parts.push(`re-check still reports ${escapingSymlinkDescription(destination, recheck.pairs)}`)
  return parts.map((part) => `; ${part}`).join("")
}

/**
 * Issue #219: the post-merge backstop. Resolve every symlink below the
 * destination as it actually is, remove each one that escapes, re-check once
 * and fail the run.
 *
 * This runs after every merge that started, even a failed one, because a
 * merge that failed half-way may already have published links. It covers
 * links this archive did not ship and host changes between the pre-merge
 * listing and the merge. The links the containment probe reports — including
 * links it could not resolve — are the only candidates for removal; see
 * {@link removeEscapingSymlinks}. The run still fails after a removal, so the
 * containment flag the caller wrote before the merge stays set.
 *
 * A probe that failed or returned broken framing removes nothing and fails the
 * run as {@link validateSymlinkContainment} does.
 *
 * @param conn - The SSH connection.
 * @param parameters - Enforcement inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.source - The archive source, for the failure message.
 * @returns Null when no symlink escapes, otherwise a failure naming the
 *   violation, the removal outcome and the re-check result.
 */
export async function enforceSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const { destination, source } = parameters
  const prefix = `[archive.extract] refusing to complete extraction of ${source}`
  const reading = await readEscapingSymlinks(conn, destination)
  if (reading.kind === "failed") {
    return failed(`${prefix}: symlink containment check failed: ${reading.detail}`)
  }
  if (reading.pairs.length === 0) return null
  const links = reading.pairs.map(([link]) => link)
  const report = await removeEscapingSymlinks(conn, destination, links)
  const recheck = await readEscapingSymlinks(conn, destination)
  const violation = containmentViolationMessage(destination, reading.pairs)
  return failed(`${prefix}: ${violation}${enforcementSummary(destination, report, recheck)}`)
}
