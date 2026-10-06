/**
 * Issue #219: the resolver over an archive's own symlink members, shared per
 * member list by the archive-level link rules and the pre-staging prefix model
 * in `archiveLinkValidation.ts`.
 */
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { type KeyedMember, keyedMembers } from "./archiveContainmentScope.js"
import { ArchiveSymlinkResolver, type SymlinkWalkTarget } from "./archiveSymlinkResolver.js"

/**
 * The keyed members of one archive and the resolver over its own symlinks,
 * shared by `archiveLinkUnsafeReason` and `archiveSymlinkTargetPrefixes`.
 */
export type ArchiveLinkAnalysis = { entries: KeyedMember[]; resolver: ArchiveSymlinkResolver }

/**
 * Build a resolver over an archive's own symlink members, each walked from its
 * parent directory.
 *
 * @param entries - The members with their normalized paths.
 * @returns A resolver whose known paths are exactly the archive members.
 */
function archiveResolver(entries: readonly KeyedMember[]): ArchiveSymlinkResolver {
  const targets = new Map<string, SymlinkWalkTarget>()
  for (const { key, member } of entries) {
    if (member.kind === "symlink") {
      targets.set(key, { anchor: "parent", path: member.linkTarget ?? "" })
    }
  }
  return new ArchiveSymlinkResolver(targets, new Set(entries.map(({ key }) => key)))
}

/**
 * One {@link ArchiveLinkAnalysis} per member array. The archive-level rules
 * and the pre-staging prefix model receive the same array instance from the
 * member validation, so each symlink target is resolved once per archive
 * instead of once per caller. The cache relies on the arrays not changing
 * after validation, which holds for every caller; a weak key lets the analysis
 * go with the array.
 */
const archiveLinkAnalyses = new WeakMap<readonly ArchiveMember[], ArchiveLinkAnalysis>()

/**
 * The shared analysis of a member array, built on first use.
 *
 * @param members - All parsed members of the archive, in listing order.
 * @returns The keyed members and the resolver over the archive's symlinks.
 */
export function archiveLinkAnalysis(members: readonly ArchiveMember[]): ArchiveLinkAnalysis {
  const known = archiveLinkAnalyses.get(members)
  if (known !== undefined) return known
  const entries = keyedMembers(members)
  const analysis = { entries, resolver: archiveResolver(entries) }
  archiveLinkAnalyses.set(members, analysis)
  return analysis
}
