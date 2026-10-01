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
import { createHash } from "node:crypto"

import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"
import { pathNameVariantKey } from "./archiveSymlinkResolver.js"

/**
 * Pair every member with its normalized path, skipping members whose path
 * does not normalize.
 *
 * @param members - The validated archive members.
 * @returns The members with their normalized paths, in listing order.
 */
function keyedMembers(
  members: readonly ArchiveMember[]
): Array<{ key: string; member: ArchiveMember }> {
  const keyed: Array<{ key: string; member: ArchiveMember }> = []
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
 * Issue #227: the algorithm ID {@link containmentScopeDigest} hashes first. A
 * change to how the scope is derived or encoded must change this ID, so that a
 * digest an older derivation recorded never matches a newer one.
 */
export const CONTAINMENT_SCOPE_DIGEST_ALGORITHM = "paratix-archive-containment-scope/1"

/**
 * Issue #227: order strings by UTF-16 code unit, independent of the locale.
 *
 * @param left - One string.
 * @param right - The other string.
 * @returns A negative number, zero or a positive number.
 */
function compareCodeUnits(left: string, right: string): number {
  if (left === right) return 0
  return left < right ? -1 : 1
}

/**
 * Issue #227: the digest of an archive's containment scope that the
 * containment entry of an apply records, so a later apply of the same archive
 * can recognize the entry an interrupted apply left.
 *
 * It is the lowercase hex SHA-256 of the JSON array of
 * {@link CONTAINMENT_SCOPE_DIGEST_ALGORITHM}, `process.versions.unicode`, the
 * `archiveLinks` keys and the `written` keys, each set sorted by UTF-16 code
 * unit. The two sets stay separate arrays, so moving a key from one to the
 * other changes the digest; the Unicode version is included because
 * {@link pathNameVariantKey} depends on the engine's Unicode tables, and a key
 * derived under other tables must not match.
 *
 * @param scope - The scope, see {@link archiveContainmentScope}.
 * @returns 64 lowercase hex digits.
 */
export function containmentScopeDigest(scope: ArchiveContainmentScope): string {
  const encoding = JSON.stringify([
    CONTAINMENT_SCOPE_DIGEST_ALGORITHM,
    process.versions.unicode,
    [...scope.archiveLinks].toSorted(compareCodeUnits),
    [...scope.written].toSorted(compareCodeUnits),
  ])
  return createHash("sha256").update(encoding, "utf8").digest("hex")
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
