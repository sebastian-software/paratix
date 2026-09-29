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
 */
import type { ModuleResult, SshConnection } from "../types.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { failed } from "../moduleFailure.js"
import {
  archiveContainmentScope,
  archiveHasSymlinks,
  normalizedMemberKeys,
  unreadableDirectoryAt,
  unreadableDirectoryIndex,
} from "./archiveContainmentScope.js"
import { runKernelCrossCheck } from "./archiveKernelCrossCheck.js"
import {
  type MergedSymlink,
  mergedSymlinkResolutions,
  type MergedSymlinkViolation,
  variantDescription,
} from "./archiveLinkValidation.js"
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
 * Issue #219: what an operator has to do after a post-merge violation. The
 * backstop only reports, so the offending links stay in place until someone
 * removes them or points them inside the destination.
 */
const NOTHING_CHANGED_AFTER_MERGE =
  "nothing was removed or changed; remove the offending symlinks under the destination or point them inside it manually before the next run, the containment flag keeps check at needs-apply until an apply succeeds"

/**
 * Issue #219: how many violations the failure message names before it
 * summarizes the rest as `(and N more)`, so a tree with many offending links
 * cannot inflate the message without bound.
 */
export const POST_MERGE_VIOLATION_REPORT_LIMIT = 10

/**
 * Issue #219: a link the backstop cannot show to stay inside: a violation of
 * the lexical resolver, a `kernel-mismatch` where the host kernel does not
 * confirm the location the resolver computed (`expected`, absolute), or an
 * `unreadable-member`: an archive member path (`key`) at or below a host
 * directory the listing could not read, whose links the backstop cannot see.
 */
export type PostMergeViolation =
  | { directory: string; key: string; kind: "unreadable-member" }
  | { expected: string; key: string; kind: "kernel-mismatch" }
  | MergedSymlinkViolation

/**
 * Issue #219: every symlink below the destination after the merge, keyed by
 * destination-relative path, with the links this archive can affect that
 * cannot be shown to stay inside.
 */
type PostMergeSymlinks = {
  kind: "ok"
  links: ReadonlyMap<string, MergedSymlink>
  violations: PostMergeViolation[]
}

/** Issue #219: a post-merge listing, or why it cannot be trusted. */
type PostMergeSymlinkReading = { detail: string; kind: "failed" } | PostMergeSymlinks

/**
 * Issue #219: the archive member paths at or below a host directory the
 * listing could not read. The backstop cannot see the links there, so each is
 * a violation.
 *
 * @param members - The validated archive members.
 * @param unreadable - The unreadable host directories.
 * @returns One violation per such member path, in listing order.
 */
function unreadableMemberViolations(
  members: readonly ArchiveMember[],
  unreadable: ReadonlySet<string> | undefined
): PostMergeViolation[] {
  const index = unreadableDirectoryIndex(unreadable)
  if (index.size === 0) return []
  const violations: PostMergeViolation[] = []
  for (const key of normalizedMemberKeys(members)) {
    const directory = unreadableDirectoryAt(key, index)
    if (directory !== undefined) violations.push({ directory, key, kind: "unreadable-member" })
  }
  return violations
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
 * Issue #219: the resolver alone is lexical. Every judged link it places
 * inside is then handed to {@link runKernelCrossCheck} in one more batched
 * exec, which compares the link with the location the resolver computed by
 * device and inode. A link the kernel resolves elsewhere is a
 * `kernel-mismatch` violation; a cross-check that cannot be completed fails
 * the reading like a failed listing. Without judged links inside, no
 * cross-check runs.
 *
 * @param conn - The SSH connection.
 * @param parameters - Reading inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.members - The validated archive members.
 * @returns The listed links with the violations of the judged ones, or why
 *   the reading cannot be trusted.
 */
async function readPostMergeSymlinks(
  conn: SshConnection,
  parameters: { destination: string; members: readonly ArchiveMember[] }
): Promise<PostMergeSymlinkReading> {
  const { destination, members } = parameters
  const outcome = await runSymlinkListing(conn, [encodeSymlinkListingEntry("r", destination)])
  if (outcome.kind === "failed") return outcome
  const host = hostStateFromListing(destination, outcome.fields, new Map())
  if (typeof host === "string") return { detail: host, kind: "failed" }
  const resolutions = mergedSymlinkResolutions(host.links, {
    ...archiveContainmentScope(members),
    unreadable: host.unreadable,
  })
  const { inside } = resolutions
  const violations = [
    ...unreadableMemberViolations(members, host.unreadable),
    ...resolutions.violations,
  ]
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
  if (violation.kind === "unreadable-member") {
    return `archive member path ${quotedHostPath(destination, violation.key)} cannot be checked: directory ${quotedHostPath(destination, violation.directory)} is not readable`
  }
  const stored = reading.links.get(violation.key)?.stored ?? ""
  const link = symlinkDescription(destination, violation.key, stored)
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
    case "unmappable":
    case "unreadable": {
      return `${link} ${unverifiableLinkReason(destination, violation)}`
    }
    case "variant": {
      return `${link} ${variantDescription(violation)}`
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
 * @returns The violation text without the `[archive.extract]` prefix, with the
 *   `(and N more)` suffix after the listed links when there are more.
 */
function containmentViolationMessage(destination: string, reading: PostMergeSymlinks): string {
  const listed = reading.violations
    .slice(0, POST_MERGE_VIOLATION_REPORT_LIMIT)
    .map((violation) => postMergeViolationDescription(destination, reading, violation))
  const more = reading.violations.length - listed.length
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return `${listed.join("; ")}${suffix}; ${CHECKED_AFTER_MERGE}; ${NOTHING_CHANGED_AFTER_MERGE}`
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
 * outside; the merge cannot have changed where it resolves. An archive
 * without symlink members runs no exec here at all, for the reason
 * `validateMergedSymlinkContainment` gives. It never asks the host to resolve
 * a link in user space: the host only lists links with their stored targets (see
 * `buildSymlinkListingProbeScript`), {@link mergedSymlinkResolutions} resolves
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
 * so the containment flag the caller wrote before the merge stays set and
 * `check` keeps reporting needs-apply until an apply succeeds. The message
 * names the first {@link POST_MERGE_VIOLATION_REPORT_LIMIT} violations by
 * absolute link path, stored target and reason, adds `(and N more)` for the
 * rest, and states that nothing was removed or changed, so the offending links
 * must be removed or pointed inside manually before the next run.
 *
 * Cost: a converged tree costs one listing exec plus one kernel cross-check
 * exec when a judged symlink is placed inside, one exec otherwise, and none
 * for an archive without symlink members, regardless of member or link
 * count. A violation adds no further exec.
 *
 * A listing that failed (including a missing or unusable `readlink`, a `find`
 * traversal error other than an unreadable directory with GNU find, and a
 * truncated capture), returned broken framing or a duplicate link, or whose
 * kernel cross-check could not be completed fails the run as well.
 *
 * @param conn - The SSH connection.
 * @param parameters - Backstop inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.members - The validated archive members; they decide
 *   which links are judged.
 * @param parameters.source - The archive source, for the failure message.
 * @returns Null when every judged symlink stays inside, otherwise a failure
 *   naming the offending links, or why the check could not run.
 */
export async function enforceSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; members: readonly ArchiveMember[]; source: string }
): Promise<ModuleResult | null> {
  const { destination, members, source } = parameters
  if (!archiveHasSymlinks(members)) return null
  const prefix = `[archive.extract] refusing to complete extraction of ${source}`
  const reading = await readPostMergeSymlinks(conn, { destination, members })
  if (reading.kind === "failed") {
    return failed(`${prefix}: symlink containment check failed: ${reading.detail}`)
  }
  if (reading.violations.length === 0) return null
  return failed(`${prefix}: ${containmentViolationMessage(destination, reading)}`)
}
