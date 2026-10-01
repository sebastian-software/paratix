/**
 * Issue #219: which links the symlink containment checks of `archive.extract`
 * judge.
 *
 * Both checks around the staging merge list every symlink below the
 * destination, but judge only the links the archive can affect: its own
 * symlinks and every link whose resolution passes through a path the archive
 * writes (see `mergedSymlinkResolutions` in `archiveLinkValidation.ts`). The
 * helpers here derive that scope from the archive members and locate member
 * paths inside host directories the listing could not read.
 */
import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"
import { pathNameVariantKey } from "./archiveSymlinkResolver.js"

/** A member paired with its normalized path, the key the link checks compare. */
export type KeyedMember = { key: string; member: ArchiveMember }

/**
 * Pair every member with its normalized path, skipping members whose path
 * does not normalize.
 *
 * @param members - The validated archive members.
 * @returns The members with their normalized paths, in listing order.
 */
export function keyedMembers(members: readonly ArchiveMember[]): KeyedMember[] {
  const keyed: KeyedMember[] = []
  for (const member of members) {
    const key = normalizeArchiveMemberPath(member.path)
    if (key !== null) keyed.push({ key, member })
  }
  return keyed
}

/**
 * Issue #219: which links of a combined link set an archive can affect, see
 * {@link archiveContainmentScope}.
 */
export type ArchiveContainmentScope = {
  /** {@link pathNameVariantKey} of the archive's symlink member paths. */
  archiveLinks: ReadonlySet<string>
  /**
   * {@link pathNameVariantKey} of every non-empty member path and of each of
   * its non-empty proper ancestors: the paths the merge writes.
   */
  written: ReadonlySet<string>
}

/**
 * Issue #219: the distinct non-empty normalized paths of the members, in
 * listing order.
 *
 * @param members - The validated archive members.
 * @returns The normalized member paths.
 */
export function normalizedMemberKeys(members: readonly ArchiveMember[]): string[] {
  return [...new Set(keyedMembers(members).map(({ key }) => key))].filter((key) => key !== "")
}

/**
 * Issue #219: index unreadable host directories by {@link pathNameVariantKey}
 * for {@link unreadableDirectoryAt}.
 *
 * @param unreadable - The unreadable host directories, if any.
 * @returns The directories keyed by their variant key.
 */
export function unreadableDirectoryIndex(
  unreadable: ReadonlySet<string> | undefined
): ReadonlyMap<string, string> {
  return new Map([...(unreadable ?? [])].map((path) => [pathNameVariantKey(path), path]))
}

/**
 * Issue #219: the unreadable host directory a path lies at or below, compared
 * under {@link pathNameVariantKey}.
 *
 * @param key - A normalized destination-relative path.
 * @param index - The unreadable directories, see {@link unreadableDirectoryIndex}.
 * @returns The directory, or undefined when the path is outside all of them.
 */
export function unreadableDirectoryAt(
  key: string,
  index: ReadonlyMap<string, string>
): string | undefined {
  if (index.size === 0 || key === "") return undefined
  const segments = key.split("/")
  for (let length = 1; length <= segments.length; length += 1) {
    const directory = index.get(pathNameVariantKey(segments.slice(0, length).join("/")))
    if (directory !== undefined) return directory
  }
  return undefined
}

/**
 * Issue #219: the links of an archive and the paths it writes, which decide
 * which links of a combined link set the containment checks judge.
 *
 * Every non-empty normalized member path and each of its non-empty proper
 * ancestors is written; they are kept by {@link pathNameVariantKey}, so a
 * host link that walks a differently spelled name of a written path counts
 * as touching it. The archive's symlink member paths are kept by the same
 * key: a host listing can report an archive link under its preserved or
 * canonical spelling, e.g. `A/S` for member `a/s` or the NFD form of an NFC
 * member, and that link must still be judged as the archive's own.
 *
 * @param members - The validated archive members.
 * @returns The variant keys of the archive's symlinks and of written paths.
 */
export function archiveContainmentScope(
  members: readonly ArchiveMember[]
): ArchiveContainmentScope {
  const archiveLinks = new Set<string>()
  const written = new Set<string>()
  for (const { key, member } of keyedMembers(members)) {
    if (key === "") continue
    if (member.kind === "symlink") archiveLinks.add(pathNameVariantKey(key))
    written.add(pathNameVariantKey(key))
    for (let end = key.indexOf("/"); end !== -1; end = key.indexOf("/", end + 1)) {
      written.add(pathNameVariantKey(key.slice(0, end)))
    }
  }
  return { archiveLinks, written }
}

/**
 * Issue #219: whether an archive ships a symlink. Without one, the merge
 * cannot change how any path below the destination resolves, see
 * `validateMergedSymlinkContainment`.
 *
 * @param members - The validated archive members.
 * @returns True when at least one member is a symlink.
 */
export function archiveHasSymlinks(members: readonly ArchiveMember[]): boolean {
  return members.some((member) => member.kind === "symlink")
}

/**
 * Issue #219: what `mergedSymlinkResolutions` judges a link set against:
 * the archive's scope and the unreadable host directories.
 */
export type MergedSymlinkScope = {
  /** Destination-relative paths of host directories the listing could not read. */
  unreadable?: ReadonlySet<string>
} & ArchiveContainmentScope
