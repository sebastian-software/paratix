/**
 * Archive-level link validation for `archive.extract`.
 *
 * Issue #219: `archiveMemberUnsafeReason` judges one member at a time, which
 * is enough for paths but not for links. Whether a relative symlink stays
 * inside the destination depends on the other members: `a/up -> ..` is
 * harmless on its own, yet `a/esc -> up/..` next to it resolves above the
 * destination. The rules here therefore see the whole member list. They run
 * after the per-member checks, so every path and target they receive is
 * relative, free of control characters and lexically inside the destination.
 *
 * The rules run in a fixed order and each reports the first offending member
 * in listing order:
 *
 * 1. root link — a symlink or hardlink at the destination root;
 * 2. duplicate — a path that occurs more than once with a symlink among its
 *    occurrences and conflicting kinds or targets, because the later tar entry
 *    wins on disk;
 * 3. ancestor — a member below an archive symlink, or a hardlink whose target
 *    passes through one;
 * 4. hardlink to symlink — `link(2)` does not follow symlinks, so the hardlink
 *    would become a second name for the link and read its relative target from
 *    a different directory;
 * 5. resolution — every symlink target, walked through the archive's own
 *    symlinks, must end inside the destination within the Linux hop limit, and
 *    must not pass through a name that differs from another symlink only by
 *    letter case or Unicode normalization (see `pathNameVariantKey` in `archiveSymlinkResolver.ts`).
 *
 * Rules 3 and 4 make every archive symlink a leaf whose parent contains no
 * archive symlink, which is what lets rule 5 start each walk from the literal
 * parent path. Issue #219: rules 2, 3 and 4 compare paths by
 * `pathNameVariantKey`, because a case-folding or normalizing filesystem
 * stores `x/L` and `x/l` as one entry and tar would write through, or
 * hardlink, the symlink under the other spelling. The comparison is lexical,
 * so it refuses the same archives on case-sensitive hosts; it only ever
 * refuses more. Rule 1 stays literal: a name made only of default-ignorable
 * characters folds to `""` but is not the destination root.
 *
 * The same resolver also judges the combined post-merge link set — the links
 * already on the host plus the links this archive ships — before the staging
 * merge; see {@link mergedArchiveSymlinks} and {@link mergedSymlinkViolations}.
 * That model only covers merges whose outcome is known: a symlink member
 * replacing a host symlink, a member landing on a path the host does not
 * have, and a directory merging into a host directory. Any other type
 * combination at a member path or below a host symlink is reported as a
 * conflict, which refuses the extraction instead of guessing what `cp` does.
 */
import type { KeyedMember, MergedSymlinkScope } from "./archiveContainmentScope.js"

import {
  keyedMembers,
  unreadableDirectoryAt,
  unreadableDirectoryIndex,
} from "./archiveContainmentScope.js"
import { archiveLinkAnalysis } from "./archiveLinkAnalysis.js"
import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"
import {
  ArchiveSymlinkResolver,
  pathNameVariantKey,
  type SymlinkFailure,
  type SymlinkTrailSource,
  SymlinkVariantIndex,
  type SymlinkWalkTarget,
  variantDescription,
} from "./archiveSymlinkResolver.js"

export {
  pathNameVariantKey,
  type SymlinkTrail,
  type SymlinkTrailSource,
  type SymlinkWalkTarget,
  variantDescription,
} from "./archiveSymlinkResolver.js"

/**
 * Issue #219: one symlink of the combined post-merge link set, keyed elsewhere
 * by its normalized destination-relative path.
 */
export type MergedSymlink = {
  /** The target exactly as stored (host) or listed (archive), for messages. */
  stored: string
  /** The target as the resolver walks it. */
  target: SymlinkWalkTarget
  /**
   * Issue #219: set for a host link whose listed path or target is not valid
   * UTF-8. Such a name is mapped to a token no real name can produce, so the
   * model stays exact byte for byte, but name variants of it cannot be
   * modelled and the kernel cross-check cannot carry it; a relevant link of
   * this kind is a violation (see `unmappable` in
   * {@link MergedSymlinkViolation}).
   */
  unmappable?: true
}

/**
 * A link of the combined set that cannot be shown to stay inside the destination.
 *
 * - `escape`: it resolves outside.
 * - `limit`: it exceeds the hop limit or recursion depth.
 * - `variant`: Issue #219: its resolution passes through `prefix`, a name that
 *   differs from the symlink `link` only by letter case or Unicode
 *   normalization, so a case-folding or normalizing filesystem may follow
 *   `link` where the model walks a plain path.
 * - `unmappable`: Issue #219: it is, or its resolution follows, the host link
 *   `link` whose listed path or target is not valid UTF-8.
 * - `unreadable`: Issue #219: its resolution reaches `directory`, a host
 *   directory the listing could not read, or a path below it.
 */
export type MergedSymlinkViolation =
  | {
      /** Destination-relative path of the unreadable directory. */
      directory: string
      /** Normalized destination-relative path of the link. */
      key: string
      kind: "unreadable"
    }
  | {
      /** Normalized destination-relative path of the link. */
      key: string
      kind: "escape" | "limit"
    }
  | {
      /** Normalized destination-relative path of the link. */
      key: string
      kind: "unmappable"
      /** The link whose listed path or target is not valid UTF-8. */
      link: string
    }
  | {
      /** Normalized destination-relative path of the link. */
      key: string
      kind: "variant"
      /** The symlink whose name the visited path matches only after folding. */
      link: string
      /** The visited destination-relative path. */
      prefix: string
    }

/**
 * Issue #219: the combined link set judged by the resolver, see
 * {@link mergedSymlinkResolutions}.
 */
export type MergedSymlinkResolutions = {
  /**
   * Issue #219: the links outside the judged set that the resolution of a
   * judged link placed inside follows, directly or through another followed
   * link, each once in walk order; none for any other key. They are the host
   * links the merge did not touch, so they are never judged on their own, but
   * the kernel cross-check has to confirm their targets as well: a write
   * through the judged link lands wherever the kernel resolves them (see
   * `ArchiveSymlinkResolver.followedLinks`). The same `trail` source serves
   * their trails.
   */
  followed: (key: string) => readonly string[]
  /**
   * Every relevant link that resolves inside the destination, mapped to the
   * normalized destination-relative path it resolves to (`""` for the
   * destination root).
   */
  inside: Map<string, string>
  /**
   * Issue #219: the trail of a link's own target for the kernel cross-check,
   * computed on demand by the same resolver (see `ArchiveSymlinkResolver.trail`).
   */
  trail: SymlinkTrailSource
  /** The relevant links that cannot be shown to stay inside, in iteration order. */
  violations: MergedSymlinkViolation[]
}

/** A non-member path visited while resolving a symlink target. */
export type ArchiveSymlinkTargetPrefix = {
  /** Normalized destination-relative path that is not an archive member. */
  path: string
  /** Raw path of the symlink member whose target resolution visited it. */
  symlink: string
}

function isLink(member: ArchiveMember): boolean {
  return member.kind === "symlink" || member.kind === "hardlink"
}

function hardlinkTargetKey(member: ArchiveMember): null | string {
  if (member.kind !== "hardlink" || member.linkTarget === null) return null
  return normalizeArchiveMemberPath(member.linkTarget)
}

function rootLinkReason(entries: readonly KeyedMember[]): null | string {
  const rootLink = entries.find(({ key, member }) => key === "" && isLink(member))
  if (rootLink === undefined) return null
  return `member ${JSON.stringify(rootLink.member.path)} is a link at the destination root`
}

function conflictingDuplicate(group: readonly KeyedMember[]): KeyedMember | undefined {
  if (group.length < 2) return undefined
  const [first] = group
  if (!group.some(({ member }) => member.kind === "symlink")) return undefined
  const conflicts = group.some(
    ({ member }) =>
      member.kind !== first.member.kind || member.linkTarget !== first.member.linkTarget
  )
  return conflicts ? first : undefined
}

/**
 * Issue #219: members are grouped by `pathNameVariantKey`, so a symlink `Foo`
 * and a file `foo` conflict. Only a group with a symlink can conflict, which
 * keeps plain files like `Makefile` and `makefile` acceptable; link targets
 * are still compared literally.
 *
 * @param entries - The members with their normalized paths.
 * @param symlinks - The archive's symlinks, whose variant keys are memoized.
 * @returns The reason naming the group's first member, or null.
 */
function duplicateReason(
  entries: readonly KeyedMember[],
  symlinks: SymlinkVariantIndex
): null | string {
  const groups = new Map<string, KeyedMember[]>()
  for (const entry of entries) {
    const variantKey = symlinks.variantKey(entry.key)
    const group = groups.get(variantKey)
    if (group === undefined) groups.set(variantKey, [entry])
    else group.push(entry)
  }
  for (const group of groups.values()) {
    const duplicate = conflictingDuplicate(group)
    if (duplicate === undefined) continue
    const other = group.find(({ key }) => key !== duplicate.key)?.member.path
    const spelling = other === undefined ? "" : ` (also spelled ${JSON.stringify(other)})`
    return `member ${JSON.stringify(duplicate.member.path)} occurs more than once with conflicting link types or targets${spelling}`
  }
  return null
}

function ancestorReason(
  entries: readonly KeyedMember[],
  symlinks: SymlinkVariantIndex
): null | string {
  for (const { key, member } of entries) {
    const ancestor = symlinks.symlinkAncestor(key)
    if (ancestor !== undefined) {
      return `member ${JSON.stringify(member.path)} is below archive symlink ${JSON.stringify(ancestor)}`
    }
    const targetKey = hardlinkTargetKey(member)
    const targetAncestor = targetKey === null ? undefined : symlinks.symlinkAncestor(targetKey)
    if (targetAncestor !== undefined) {
      return `member ${JSON.stringify(member.path)} hardlinks to archive symlink ${JSON.stringify(targetAncestor)}`
    }
  }
  return null
}

function hardlinkToSymlinkReason(
  entries: readonly KeyedMember[],
  symlinks: SymlinkVariantIndex
): null | string {
  for (const { member } of entries) {
    const targetKey = hardlinkTargetKey(member)
    // Issue #219: `h link to a/b/s` names the symlink `a/b/S` on a case-folding filesystem.
    const symlink = targetKey === null ? undefined : symlinks.symlinkAt(targetKey)
    if (symlink !== undefined) {
      return `member ${JSON.stringify(member.path)} hardlinks to archive symlink ${JSON.stringify(symlink)}`
    }
  }
  return null
}

function resolutionReason(
  entries: readonly KeyedMember[],
  resolver: ArchiveSymlinkResolver
): null | string {
  for (const { key, member } of entries) {
    if (member.kind !== "symlink") continue
    const resolution = resolver.resolve(key)
    if (resolution.kind === "resolved") continue
    const detail = `member ${JSON.stringify(member.path)} -> ${JSON.stringify(member.linkTarget)}`
    if (resolution.kind === "variant") {
      return `${detail} ${variantDescription(resolution)}`
    }
    return resolution.kind === "escape"
      ? `${detail} would escape destination`
      : `${detail} exceeds the symlink resolution limit`
  }
  return null
}

/**
 * Issue #219: return why the links of an archive are unsafe as a whole, or
 * null when they may be extracted. Runs the root-link, duplicate, ancestor,
 * hardlink-to-symlink and resolution rules in that order and reports the first
 * offending member of the first failing rule.
 *
 * The duplicate, ancestor and hardlink-to-symlink rules compare member paths
 * by `pathNameVariantKey`, because case-folding or normalizing filesystems
 * store variant spellings as one entry. That comparison is lexical, so the
 * same archives are refused on case-sensitive hosts too, which only refuses
 * more. The root-link rule stays literal.
 *
 * Expects members that already passed `archiveMemberUnsafeReason`, so absolute
 * targets, control characters and zip symlinks never reach these rules.
 *
 * @param members - All parsed members of the archive, in listing order.
 * @returns A human-readable unsafe reason, or null.
 */
export function archiveLinkUnsafeReason(members: readonly ArchiveMember[]): null | string {
  const { entries, resolver } = archiveLinkAnalysis(members)
  const symlinks = new SymlinkVariantIndex(
    entries.filter(({ member }) => member.kind === "symlink").map(({ key }) => key)
  )
  return (
    rootLinkReason(entries) ??
    duplicateReason(entries, symlinks) ??
    ancestorReason(entries, symlinks) ??
    hardlinkToSymlinkReason(entries, symlinks) ??
    resolutionReason(entries, resolver)
  )
}

/**
 * Issue #219: list the paths outside the archive's own members that resolving
 * its symlink targets passes through, each with the first symlink member (in
 * listing order) whose resolution visited it. A host symlink at one of these
 * paths would redirect the link even though the archive alone resolves inside
 * the destination, so the pre-extraction probe checks them.
 *
 * Expects members that passed {@link archiveLinkUnsafeReason}; links whose
 * resolution fails contribute nothing.
 *
 * @param members - All parsed members of the archive, in listing order.
 * @returns The visited non-member paths, destination-relative and normalized.
 */
export function archiveSymlinkTargetPrefixes(
  members: readonly ArchiveMember[]
): ArchiveSymlinkTargetPrefix[] {
  const { entries, resolver } = archiveLinkAnalysis(members)
  const visited = new Map<string, string>()
  for (const { key, member } of entries) {
    if (member.kind !== "symlink") continue
    const resolution = resolver.resolve(key)
    if (resolution.kind !== "resolved") continue
    for (const prefix of resolution.prefixes) {
      if (!visited.has(prefix)) visited.set(prefix, member.path)
    }
  }
  return [...visited].map(([path, symlink]) => ({ path, symlink }))
}

/**
 * Issue #219: what the host holds below the destination before the merge, as
 * far as the post-merge link model needs it. Keys are normalized
 * destination-relative paths.
 */
export type MergeHostState = {
  /**
   * Paths of non-directory archive members that are existing real directories
   * (not symlinks) on the host.
   */
  directories: ReadonlySet<string>
  /** Every symlink below the destination with its target. */
  links: ReadonlyMap<string, MergedSymlink>
  /**
   * Issue #219: host directories below the destination the listing could not
   * read; the links inside them are unknown.
   */
  unreadable?: ReadonlySet<string>
}

/**
 * Issue #219: why the merge of one archive member cannot be modelled as an
 * exact-path replacement.
 *
 * - `host-directory`: a non-directory member at a path that is an existing
 *   real directory; `cp` cannot replace a directory with a non-directory.
 * - `host-symlink`: a non-symlink member at a path that is a host symlink; the
 *   merge guard refuses it.
 * - `below-host-symlink`: a member whose proper ancestor is a host symlink;
 *   the merge guard refuses it.
 * - `unreadable-directory`: Issue #219: a member at or below a host directory
 *   the listing could not read, so the links there are unknown.
 */
export type MergeConflictReason =
  "below-host-symlink" | "host-directory" | "host-symlink" | "unreadable-directory"

/**
 * Issue #219: the post-merge link model's verdict for one archive.
 *
 * `merged` carries the combined link set the destination holds once the merge
 * has run. `conflict` names the first member (in listing order) whose merge
 * would not be the modelled replacement: `key` is the host path the conflict
 * is about — the member's own path, or for `below-host-symlink` the host
 * symlink ancestor.
 */
export type MergedArchiveSymlinks =
  | { key: string; kind: "conflict"; member: ArchiveMember; reason: MergeConflictReason }
  | { kind: "merged"; links: Map<string, MergedSymlink> }

type MergeConflict = Extract<MergedArchiveSymlinks, { kind: "conflict" }>

/**
 * Find the proper ancestor of a normalized path that is a host symlink.
 *
 * @param key - A normalized destination-relative path.
 * @param links - The host symlinks by normalized path.
 * @returns The ancestor, or undefined when no proper ancestor is a host symlink.
 */
function hostSymlinkAncestor(
  key: string,
  links: ReadonlyMap<string, MergedSymlink>
): string | undefined {
  for (let end = key.indexOf("/"); end !== -1; end = key.indexOf("/", end + 1)) {
    const ancestor = key.slice(0, end)
    if (links.has(ancestor)) return ancestor
  }
  return undefined
}

/**
 * Decide whether merging one member is the modelled exact-path replacement.
 *
 * @param host - The host state before the merge, with its unreadable directories indexed.
 * @param entry - The member with its normalized path.
 * @returns The conflict, or null when the member merges as modelled.
 */
function mergeConflict(
  host: { unreadableIndex: ReadonlyMap<string, string> } & MergeHostState,
  entry: KeyedMember
): MergeConflict | null {
  const { key, member } = entry
  const conflict = (reason: MergeConflictReason, at = key): MergeConflict => ({
    key: at,
    kind: "conflict",
    member,
    reason,
  })
  const unreadable = unreadableDirectoryAt(key, host.unreadableIndex)
  if (unreadable !== undefined) return conflict("unreadable-directory", unreadable)
  if (member.kind !== "directory" && host.directories.has(key)) return conflict("host-directory")
  if (member.kind !== "symlink" && host.links.has(key)) return conflict("host-symlink")
  const ancestor = hostSymlinkAncestor(key, host.links)
  return ancestor === undefined ? null : conflict("below-host-symlink", ancestor)
}

/**
 * Issue #219: build the symlink set the destination will hold once the staged
 * archive is merged, keyed by normalized destination-relative path, or refuse
 * where the merge would not do what the model assumes.
 *
 * It starts from the links already on the host and applies the archive's
 * members in listing order. The merge copies every staged entry with
 * `cp -aT --no-dereference --remove-destination`. Only the outcomes `cp` and
 * the merge guard actually produce are modelled: an archive symlink replaces a
 * host symlink at the same path and brings its own target, any member lands
 * at a path the host does not have, and a directory member merges into a host
 * directory, keeping the host links below it.
 *
 * Every other combination is a conflict instead of a guessed outcome. A
 * non-directory member over a host directory makes `cp` fail after it may
 * already have copied the rest of that top-level entry, so paths through the
 * member would really run through the host directory and the host links
 * below it. A non-symlink member at a host symlink, or any member below a host
 * symlink, is refused by the merge guard. Modelling any of these as a
 * replacement could let an escaping link pass, so the caller refuses the
 * extraction before anything is copied. Issue #219: a member at or below a
 * host directory the listing could not read is a conflict as well, because the
 * links in there are unknown.
 *
 * @param host - The host state before the merge (see {@link MergeHostState}).
 * @param members - The validated archive members, in listing order.
 * @returns The combined post-merge link set, or the first conflicting member.
 */
export function mergedArchiveSymlinks(
  host: MergeHostState,
  members: readonly ArchiveMember[]
): MergedArchiveSymlinks {
  const links = new Map(host.links)
  const indexed = { ...host, unreadableIndex: unreadableDirectoryIndex(host.unreadable) }
  for (const entry of keyedMembers(members)) {
    const conflict = mergeConflict(indexed, entry)
    if (conflict !== null) return conflict
    const { key, member } = entry
    links.delete(key)
    if (member.kind !== "symlink") continue
    const stored = member.linkTarget ?? ""
    links.set(key, { stored, target: { anchor: "parent", path: stored } })
  }
  return { kind: "merged", links }
}

/**
 * Issue #219: turn a failed resolution into the violation it stands for.
 *
 * @param key - Normalized path of the link.
 * @param failure - The failed resolution.
 * @returns The violation of the matching kind; a `depth` failure counts as
 *   `limit`.
 */
function mergedViolation(key: string, failure: SymlinkFailure): MergedSymlinkViolation {
  switch (failure.kind) {
    case "depth":
    case "limit": {
      return { key, kind: "limit" }
    }
    case "escape": {
      return { key, kind: "escape" }
    }
    case "unmappable": {
      return { key, kind: "unmappable", link: failure.link }
    }
    case "unreadable": {
      return { directory: failure.directory, key, kind: "unreadable" }
    }
    case "variant": {
      return { key, kind: "variant", link: failure.link, prefix: failure.prefix }
    }
  }
}

/**
 * Issue #219: resolve the links of a combined link set with the same resolver
 * the archive-level rules use. A link that escapes the destination, exceeds
 * the resolution limit, passes through a name that differs from a symlink
 * only by case or normalization, is or follows an unmappable link, or reaches
 * an unreadable directory is a violation: it cannot be proven to stay inside.
 * Every other link is reported with the destination-relative path it resolves
 * to; the post-merge backstop asks the host kernel to confirm it, using the
 * returned `trail` source for the points of the link's target path, and to
 * confirm the unjudged links it follows (see `followed`).
 *
 * Issue #219: with a `scope`, only the links the archive can affect are
 * judged: the archive's own symlinks present in `links`, and every link whose
 * walk touched a path the archive writes, directly or through a link it
 * follows (see `TrackedSymlinkResolution`). The archive's own symlinks are
 * matched under `pathNameVariantKey`, like written paths, so a host that
 * lists the archive's link under a case- or normalization-variant spelling
 * still has it judged. On a case-sensitive host this also judges an unrelated
 * host link whose path only folds to an archive link's path, which refuses
 * more, never less. A host link whose resolution
 * passes through an archive link is covered by that archive link's own
 * resolution, which follows it. Every other link is ignored, even one that
 * escapes, loops, is unmappable or reaches an unreadable directory: the merge
 * cannot change where it resolves. Without a `scope`, every link is judged.
 *
 * @param links - The combined link set, e.g. from {@link mergedArchiveSymlinks}.
 * @param scope - The archive's scope and the unreadable host directories; when
 *   omitted, every link is judged.
 * @returns The violations in the iteration order of `links`, and the resolved
 *   path of every other judged link.
 */
export function mergedSymlinkResolutions(
  links: ReadonlyMap<string, MergedSymlink>,
  scope?: MergedSymlinkScope
): MergedSymlinkResolutions {
  const targets = new Map<string, SymlinkWalkTarget>()
  const unmappable = new Set<string>()
  for (const [key, link] of links) {
    targets.set(key, link.target)
    if (link.unmappable === true) unmappable.add(key)
  }
  const resolver = new ArchiveSymlinkResolver(targets, new Set(targets.keys()), {
    unmappable,
    unreadable: scope?.unreadable,
    written: scope?.written,
  })
  const inside = new Map<string, string>()
  const violations: MergedSymlinkViolation[] = []
  for (const key of targets.keys()) {
    const { resolution, touched } = resolver.resolveTracked(key)
    const relevant =
      scope === undefined || touched || scope.archiveLinks.has(pathNameVariantKey(key))
    if (!relevant) continue
    if (resolution.kind === "resolved") inside.set(key, resolution.segments.join("/"))
    else violations.push(mergedViolation(key, resolution))
  }
  return {
    followed: (key) =>
      inside.has(key) ? resolver.followedLinks(key).filter((link) => !inside.has(link)) : [],
    inside,
    trail: (key, maxLength) => resolver.trail(key, maxLength),
    violations,
  }
}

/**
 * Issue #219: the violations of {@link mergedSymlinkResolutions} alone.
 *
 * @param links - The combined link set, e.g. from {@link mergedArchiveSymlinks}.
 * @param scope - The archive's scope; when omitted, every link is judged.
 * @returns The violations in the iteration order of `links`.
 */
export function mergedSymlinkViolations(
  links: ReadonlyMap<string, MergedSymlink>,
  scope?: MergedSymlinkScope
): MergedSymlinkViolation[] {
  return mergedSymlinkResolutions(links, scope).violations
}
