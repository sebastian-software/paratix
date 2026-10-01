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
 * - after it, `enforceSymlinkContainment` (in `archiveContainmentBackstop.ts`)
 *   lists every link below the destination as it actually is with the same
 *   probe, judges the links the archive can affect with the same resolver,
 *   lets the host kernel confirm every such link judged inside and, on a
 *   violation, only reports the offending links and fails the run; it removes
 *   and changes nothing on the host.
 *
 * Issue #219: both checks judge only the links this archive can affect: its
 * own symlinks and every link whose resolution passes through a path the
 * archive writes, directly or through another link (see
 * `mergedSymlinkResolutions` in `archiveLinkValidation.ts`). A link elsewhere
 * in the destination — the `bin/python3 -> /usr/bin/python3` of a Python
 * virtual environment, say — is never judged and never changed, even when it
 * points outside. An archive
 * without symlink members cannot change how any path resolves, so for it both
 * checks run no exec at all.
 *
 * Neither check asks the host to resolve a link in user space; the host only
 * reports stored targets, and the resolver in `archiveSymlinkResolver.ts`
 * bounds every walk. The listing is decoded by `hostStateFromListing` in
 * `archiveSymlinkListing.ts`, shared by both checks.
 */
import type { ModuleResult, SshConnection } from "../types.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { failed } from "../moduleFailure.js"
import { archiveContainmentScope, archiveHasSymlinks } from "./archiveContainmentScope.js"
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
  variantDescription,
} from "./archiveLinkValidation.js"
import {
  hostStateFromListing,
  quotedHostPath,
  runSymlinkListing,
  symlinkDescription,
  symlinkListingEntries,
  unverifiableLinkReason,
} from "./archiveSymlinkListing.js"

export { enforceSymlinkContainment } from "./archiveContainmentBackstop.js"
export { symlinkListingEntries } from "./archiveSymlinkListing.js"

/**
 * Issue #219: the pre-merge model's verdict for one archive, see
 * {@link preMergeContainmentVerdict}.
 *
 * - `invalid`: the listing output cannot be trusted (broken framing or a path
 *   that is not below the destination); `reason` says why.
 * - `conflict`: a member whose merge is not the modelled replacement (see
 *   {@link mergedArchiveSymlinks}), including a member at or below a host
 *   directory the listing could not read.
 * - `violations`: links of the combined set that this archive can affect
 *   escape, exceed the resolution limit, pass through a name that differs from
 *   a symlink only by letter case or Unicode normalization, are or follow a
 *   host link whose name or target is not valid UTF-8, or reach a host
 *   directory the listing could not read.
 * - `ok`: every link of the combined set this archive can affect stays inside
 *   the destination.
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
 * Issue #219: judge an archive against the decoded output of the pre-merge
 * listing probe, without any I/O.
 *
 * The listing must be the output of `buildSymlinkListingProbeScript` for
 * the entries of {@link symlinkListingEntries} with the same destination and
 * members. The verdict is `invalid` when the framing is broken or a reported
 * path is not below the destination (or, for a directory hit, not one of the
 * requested member paths), `conflict` when a member's merge is not the
 * modelled replacement, `violations` when a link this archive can affect
 * cannot be shown to stay inside, and `ok` otherwise.
 *
 * Issue #219: only the links this archive can affect are judged (see
 * `mergedSymlinkResolutions`): its own symlinks and every link whose
 * resolution touches a path it writes. Every other listed link is ignored.
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
  const violations = mergedSymlinkViolations(merged.links, {
    ...archiveContainmentScope(members),
    unreadable: host.unreadable,
  })
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
    "unreadable-directory": `${member} cannot be checked: directory ${quotedHostPath(destination, conflict.key)} is not readable`,
  }[conflict.reason]
  return `${detail}; the merge could not put this member in place as the symlink containment check models it, so nothing is copied`
}

/**
 * Issue #219: why one link of the combined set cannot be shown to stay inside.
 *
 * @param destination - The validated, canonical destination directory.
 * @param violation - The link's violation of the combined set.
 * @returns The reason, following the link description.
 */
function mergedViolationReason(destination: string, violation: MergedSymlinkViolation): string {
  switch (violation.kind) {
    case "escape": {
      return `would resolve outside destination ${JSON.stringify(destination)} once this archive is merged`
    }
    case "limit": {
      return "would exceed the symlink resolution limit once this archive is merged"
    }
    case "unmappable":
    case "unreadable": {
      return unverifiableLinkReason(destination, violation)
    }
    case "variant": {
      return `${variantDescription(violation)} once this archive is merged`
    }
  }
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
  const [first] = violations
  const link = symlinkDescription(destination, first.key, links.get(first.key)?.stored ?? "")
  const violation = `${link} ${mergedViolationReason(destination, first)}`
  const more = violations.length - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return `${violation}; the archive's symlinks and the existing symlinks whose resolution passes through a path it writes are checked together before anything is copied${suffix}`
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
 * one batched exec (`buildSymlinkListingProbeScript`), judges the result
 * with {@link preMergeContainmentVerdict} and refuses a conflict or a
 * violation, so nothing is copied into the destination.
 * `enforceSymlinkContainment` stays in place after the merge as the
 * backstop for host changes that land between this listing and the merge.
 *
 * Issue #219: an archive without symlink members skips the listing and runs
 * no exec. Without an archive symlink the merge cannot change how any path
 * resolves: a new file or directory matches the lexical model the resolver
 * already uses (a path the archive does not ship is walked as whatever is
 * there), a directory member merges into a host directory and keeps its
 * links, and a non-symlink member over a host symlink, or below one, is
 * refused by the pre-staging probe and the merge guard. Such archives — every
 * zip among them — save the listing exec here and the listing and kernel
 * cross-check execs of the backstop.
 *
 * The listing itself stays complete for archives with symlinks: a link the
 * archive can affect may live anywhere below the destination (host
 * `x/esc -> ../a/up/..` next to archive `a/up -> ..`), and pruning the
 * listing by target shape would be unsound because a host link on a relevant
 * walk can move the walk elsewhere. Which links are judged is decided in
 * {@link preMergeContainmentVerdict}.
 *
 * Host link paths and targets are split on `/` only, so spaces and newlines in
 * them are handled faithfully; names outside printable ASCII travel
 * hex-encoded. A probe failure (including a `find` traversal error other than
 * an unreadable directory with GNU find, or an unreadable target of an
 * existing link), a truncated capture (the destination holds too many
 * symlinks to check) and output that is not made of well-formed records all
 * fail closed.
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
  if (!archiveHasSymlinks(members)) return null
  const prefix = `[archive.extract] refusing to extract ${source}`
  // The listing grows with the number of links on the host (a `node_modules`
  // tree has many), not with violations, so it gets its own capture cap
  // instead of the 1 MiB default. Truncation still fails closed.
  const outcome = await runSymlinkListing(conn, symlinkListingEntries(destination, members))
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
