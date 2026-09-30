/**
 * Which links the post-merge symlink containment backstop of `archive.extract`
 * judges, and the violations its listing alone shows.
 *
 * Issue #219: split out of `archiveContainmentBackstop.ts`. The backstop
 * judges the links the archive can affect and the links earlier failed
 * applies recorded in their containment entries; when an entry held no usable
 * list,
 * it judges every listed link instead, and any directory the listing could not
 * read makes that destination-wide verification incomplete.
 */
import type { KernelMismatchPoint } from "./archiveKernelCrossCheck.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import {
  type ArchiveContainmentScope,
  archiveContainmentScope,
  archiveHasSymlinks,
  normalizedMemberKeys,
  unreadableDirectoryAt,
  unreadableDirectoryIndex,
} from "./archiveContainmentScope.js"
import {
  type MergedSymlink,
  mergedSymlinkResolutions,
  type MergedSymlinkViolation,
} from "./archiveLinkValidation.js"
import { pathNameVariantKey } from "./archiveSymlinkResolver.js"

/**
 * Issue #219: a link the backstop cannot show to stay inside: a violation of
 * the lexical resolver, a `kernel-mismatch` where the host kernel does not
 * confirm the location the resolver computed (`expected`, absolute; `at`
 * says where the two disagree, see `KernelMismatchPoint`), or an
 * `unreadable-member`: an archive member path (`key`) at or below a host
 * directory the listing could not read, whose links the backstop cannot see.
 * Issue #219: an `unreadable-recorded` violation is a link an earlier failed
 * apply recorded (`key`) at or below such a directory, which the backstop
 * cannot see either. An `unreadable-directory` violation is a directory the
 * listing could not read while the whole destination has to be verified;
 * its `key` is the directory itself.
 */
export type PostMergeViolation =
  | { at: KernelMismatchPoint; expected: string; key: string; kind: "kernel-mismatch" }
  | { directory: string; key: string; kind: "unreadable-directory" }
  | { directory: string; key: string; kind: "unreadable-member" }
  | { directory: string; key: string; kind: "unreadable-recorded" }
  | MergedSymlinkViolation

/** Issue #219: the kind of an archive member path the listing could not show. */
export const UNREADABLE_MEMBER = "unreadable-member"

/** Issue #219: the kind of an unreadable directory in a destination-wide verification. */
export const UNREADABLE_DIRECTORY = "unreadable-directory"

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
    if (directory !== undefined) violations.push({ directory, key, kind: UNREADABLE_MEMBER })
  }
  return violations
}

/**
 * Issue #219: the recorded links at or below a host directory the listing
 * could not read. The listing cannot show them, so they are not gone but
 * unverifiable.
 *
 * @param recorded - The links an earlier failed apply recorded.
 * @param unreadable - The unreadable host directories.
 * @returns One violation per such link.
 */
function unreadableRecordedViolations(
  recorded: ReadonlySet<string>,
  unreadable: ReadonlySet<string> | undefined
): PostMergeViolation[] {
  const index = unreadableDirectoryIndex(unreadable)
  if (index.size === 0) return []
  const violations: PostMergeViolation[] = []
  for (const key of recorded) {
    const directory = unreadableDirectoryAt(key, index)
    if (directory !== undefined) violations.push({ directory, key, kind: "unreadable-recorded" })
  }
  return violations
}

/**
 * Issue #219: the links the backstop judges: those the archive can affect and
 * the recorded ones. The recorded links join the archive's links under
 * {@link pathNameVariantKey}, so the resolver judges them from the same
 * listing. An archive without symlinks cannot change how any path resolves,
 * so for it only the recorded links are judged.
 *
 * @param members - The validated archive members.
 * @param recorded - The links an earlier failed apply recorded.
 * @returns The scope for `mergedSymlinkResolutions`.
 */
function postMergeScope(
  members: readonly ArchiveMember[],
  recorded: ReadonlySet<string>
): ArchiveContainmentScope {
  const recordedKeys = [...recorded].map((key) => pathNameVariantKey(key))
  if (!archiveHasSymlinks(members)) {
    return { archiveLinks: new Set(recordedKeys), written: new Set() }
  }
  const scope = archiveContainmentScope(members)
  return { archiveLinks: new Set([...scope.archiveLinks, ...recordedKeys]), written: scope.written }
}

/**
 * Issue #219: the scope of a destination-wide verification: every listed
 * link is judged as if the archive shipped it.
 *
 * @param links - Every symlink the post-merge listing reported.
 * @returns The scope for `mergedSymlinkResolutions`.
 */
function wholeDestinationScope(links: ReadonlyMap<string, MergedSymlink>): ArchiveContainmentScope {
  return {
    archiveLinks: new Set([...links.keys()].map((key) => pathNameVariantKey(key))),
    written: new Set(),
  }
}

/**
 * Issue #219: every directory the listing could not read, as violations of a
 * destination-wide verification: the links below it are unknown, so the
 * verification is incomplete however few archive members lie there.
 *
 * @param unreadable - The unreadable host directories.
 * @returns One violation per directory, keyed by the directory.
 */
function unreadableDirectoryViolations(
  unreadable: ReadonlySet<string> | undefined
): PostMergeViolation[] {
  return [...(unreadable ?? [])].map((directory) => ({
    directory,
    key: directory,
    kind: UNREADABLE_DIRECTORY,
  }))
}

/**
 * Issue #219: sort the violations of listed links into listing order, so a
 * destination-wide verification records the offending links in the order the
 * host listed them; violations of unlisted paths keep their place in front.
 *
 * @param violations - The violations to sort; the input stays unchanged.
 * @param links - The listed links, in listing order.
 * @returns The violations in listing order.
 */
export function inListingOrder(
  violations: readonly PostMergeViolation[],
  links: ReadonlyMap<string, MergedSymlink>
): PostMergeViolation[] {
  const position = new Map([...links.keys()].map((key, index) => [key, index]))
  const rank = (violation: PostMergeViolation): number => position.get(violation.key) ?? -1
  return violations.toSorted((left, right) => rank(left) - rank(right))
}

/** Issue #219: the inputs of `readPostMergeSymlinks` in `archiveContainmentBackstop.ts`. */
export type PostMergeReadingInputs = {
  /** The validated, canonical destination directory. */
  destination: string
  /** The validated archive members. */
  members: readonly ArchiveMember[]
  /** The links an earlier failed apply recorded. */
  recorded: ReadonlySet<string>
  /**
   * Judge every listed symlink, not only the ones the archive can affect or
   * an earlier apply recorded; any unreadable directory is a violation.
   */
  wholeDestination: boolean
}

/**
 * Issue #219: the violations the listing alone shows: paths below unreadable
 * directories and the resolver's findings for the judged links.
 *
 * @param inputs - The reading inputs.
 * @param host - The decoded listing.
 * @param host.links - Every listed symlink.
 * @param host.unreadable - The unreadable host directories.
 * @returns The resolutions and the violations without the kernel's.
 */
export function listingViolations(
  inputs: PostMergeReadingInputs,
  host: { links: ReadonlyMap<string, MergedSymlink>; unreadable?: ReadonlySet<string> }
): { resolutions: ReturnType<typeof mergedSymlinkResolutions>; violations: PostMergeViolation[] } {
  const { members, recorded, wholeDestination } = inputs
  const scope = wholeDestination
    ? wholeDestinationScope(host.links)
    : postMergeScope(members, recorded)
  const resolutions = mergedSymlinkResolutions(host.links, {
    ...scope,
    unreadable: host.unreadable,
  })
  if (wholeDestination) {
    return {
      resolutions,
      violations: [...unreadableDirectoryViolations(host.unreadable), ...resolutions.violations],
    }
  }
  const violations = [
    ...(archiveHasSymlinks(members) ? unreadableMemberViolations(members, host.unreadable) : []),
    ...unreadableRecordedViolations(recorded, host.unreadable),
    ...resolutions.violations,
  ]
  return { resolutions, violations }
}
