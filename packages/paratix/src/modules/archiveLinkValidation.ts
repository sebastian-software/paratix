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
 *    symlinks, must end inside the destination within the Linux hop limit.
 *
 * Rules 3 and 4 make every archive symlink a leaf whose parent contains no
 * archive symlink, which is what lets rule 5 start each walk from the literal
 * parent path.
 */
import {
  type ArchiveMember,
  archiveMemberParentPath,
  normalizeArchiveMemberPath,
} from "./archiveMemberValidation.js"

/**
 * Issue #219: the maximum number of symlinks one resolution may follow. It
 * mirrors Linux `MAXSYMLINKS` (40): the kernel refuses a lookup with `ELOOP`
 * after that many follows, so a longer chain cannot resolve on the host
 * either. Internal on purpose, not an option.
 */
const SYMLINK_RESOLUTION_LIMIT = 40

/** A member paired with its normalized path, the key every rule compares. */
type KeyedMember = { key: string; member: ArchiveMember }

/** A non-member path visited while resolving a symlink target. */
export type ArchiveSymlinkTargetPrefix = {
  /** Normalized destination-relative path that is not an archive member. */
  path: string
  /** Raw path of the symlink member whose target resolution visited it. */
  symlink: string
}

/**
 * Outcome of resolving one symlink member.
 *
 * `depth` marks a resolution cut off because the stack of links being
 * resolved grew past {@link SYMLINK_RESOLUTION_LIMIT}. Only the link at the
 * bottom of that stack is known to fail, so a `depth` outcome is never
 * memoized for the links above it.
 */
type SymlinkResolution =
  | { hops: number; kind: "resolved"; prefixes: readonly string[]; segments: readonly string[] }
  | { kind: "depth" }
  | { kind: "escape" }
  | { kind: "limit" }

type SymlinkFailure = Exclude<SymlinkResolution, { kind: "resolved" }>

/** The state of one walk: hops spent, visited non-member prefixes, resolved segments. */
type WalkState = { hops: number; prefixes: string[]; segments: readonly string[] }

const ESCAPE: SymlinkFailure = { kind: "escape" }
const LIMIT: SymlinkFailure = { kind: "limit" }
const DEPTH: SymlinkFailure = { kind: "depth" }

function isLink(member: ArchiveMember): boolean {
  return member.kind === "symlink" || member.kind === "hardlink"
}

function keyedMembers(members: readonly ArchiveMember[]): KeyedMember[] {
  const keyed: KeyedMember[] = []
  for (const member of members) {
    const key = normalizeArchiveMemberPath(member.path)
    if (key !== null) keyed.push({ key, member })
  }
  return keyed
}

function hardlinkTargetKey(member: ArchiveMember): null | string {
  if (member.kind !== "hardlink" || member.linkTarget === null) return null
  return normalizeArchiveMemberPath(member.linkTarget)
}

/**
 * Find the outermost proper ancestor of a normalized path that is a symlink
 * member.
 *
 * @param key - A normalized archive path.
 * @param symlinkKeys - Normalized paths of all symlink members.
 * @returns The ancestor, or undefined when no proper ancestor is a symlink.
 */
function symlinkAncestor(key: string, symlinkKeys: ReadonlySet<string>): string | undefined {
  for (let end = key.indexOf("/"); end !== -1; end = key.indexOf("/", end + 1)) {
    const ancestor = key.slice(0, end)
    if (symlinkKeys.has(ancestor)) return ancestor
  }
  return undefined
}

function rootLinkReason(entries: readonly KeyedMember[]): null | string {
  const rootLink = entries.find(({ key, member }) => key === "" && isLink(member))
  if (rootLink === undefined) return null
  return `member ${JSON.stringify(rootLink.member.path)} is a link at the destination root`
}

function conflictingDuplicate(group: readonly ArchiveMember[]): ArchiveMember | undefined {
  if (group.length < 2) return undefined
  const [first] = group
  if (!group.some((member) => member.kind === "symlink")) return undefined
  const conflicts = group.some(
    (member) => member.kind !== first.kind || member.linkTarget !== first.linkTarget
  )
  return conflicts ? first : undefined
}

function duplicateReason(entries: readonly KeyedMember[]): null | string {
  const groups = new Map<string, ArchiveMember[]>()
  for (const { key, member } of entries) {
    const group = groups.get(key)
    if (group === undefined) groups.set(key, [member])
    else group.push(member)
  }
  for (const group of groups.values()) {
    const duplicate = conflictingDuplicate(group)
    if (duplicate !== undefined) {
      return `member ${JSON.stringify(duplicate.path)} occurs more than once with conflicting link types or targets`
    }
  }
  return null
}

function ancestorReason(
  entries: readonly KeyedMember[],
  symlinkKeys: ReadonlySet<string>
): null | string {
  for (const { key, member } of entries) {
    const ancestor = symlinkAncestor(key, symlinkKeys)
    if (ancestor !== undefined) {
      return `member ${JSON.stringify(member.path)} is below archive symlink ${JSON.stringify(ancestor)}`
    }
    const targetKey = hardlinkTargetKey(member)
    const targetAncestor = targetKey === null ? undefined : symlinkAncestor(targetKey, symlinkKeys)
    if (targetAncestor !== undefined) {
      return `member ${JSON.stringify(member.path)} hardlinks to archive symlink ${JSON.stringify(targetAncestor)}`
    }
  }
  return null
}

function hardlinkToSymlinkReason(
  entries: readonly KeyedMember[],
  symlinkKeys: ReadonlySet<string>
): null | string {
  for (const { member } of entries) {
    const targetKey = hardlinkTargetKey(member)
    if (targetKey !== null && symlinkKeys.has(targetKey)) {
      return `member ${JSON.stringify(member.path)} hardlinks to archive symlink ${JSON.stringify(targetKey)}`
    }
  }
  return null
}

/**
 * Issue #219: resolves symlink targets through the archive's own symlinks.
 *
 * A walk starts from the segments of the link's parent and applies the
 * target's segments: `.` is skipped, `..` drops the last resolved segment and
 * escapes when none is left, and every other segment is appended. When the
 * resolved prefix is itself a symlink member, the walk continues from that
 * link's own resolution, which also follows the final component. Following a
 * link costs one hop plus the hops its own resolution needed, so a chain of N
 * links costs N hops from its head, and more than
 * {@link SYMLINK_RESOLUTION_LIMIT} fails, as does a link re-entered while it
 * is still being resolved (a cycle).
 *
 * Results are memoized per link, so every link is walked once and the total
 * work stays linear in the member count. The recursion never nests deeper than
 * the hop limit: a deeper stack means the link at its bottom has already
 * exceeded the limit.
 */
class ArchiveSymlinkResolver {
  private readonly inProgress = new Set<string>()
  private readonly memberKeys: ReadonlySet<string>
  private readonly memo = new Map<string, SymlinkResolution>()
  private readonly targets: ReadonlyMap<string, string>

  /**
   * @param entries - The members with their normalized paths.
   */
  public constructor(entries: readonly KeyedMember[]) {
    const targets = new Map<string, string>()
    for (const { key, member } of entries) {
      if (member.kind === "symlink") targets.set(key, member.linkTarget ?? "")
    }
    this.memberKeys = new Set(entries.map(({ key }) => key))
    this.targets = targets
  }

  /**
   * Resolve the target of the symlink member at `key`.
   *
   * @param key - Normalized path of a symlink member.
   * @returns The resolved path segments and hop count, or the failure kind.
   */
  public resolve(key: string): SymlinkResolution {
    const known = this.memo.get(key)
    if (known !== undefined) return known
    if (this.inProgress.has(key)) return LIMIT
    if (this.inProgress.size >= SYMLINK_RESOLUTION_LIMIT) return DEPTH
    this.inProgress.add(key)
    const resolution = this.walk(key)
    this.inProgress.delete(key)
    if (resolution.kind !== "depth") this.memo.set(key, resolution)
    return resolution
  }

  /**
   * Handle one resolved prefix of a walk.
   *
   * @param prefix - The resolved prefix after appending a segment.
   * @param prefixes - Collector for visited prefixes that are not archive members.
   * @returns The resolution of the archive symlink at `prefix`, or null when it is none.
   */
  private follow(prefix: string, prefixes: string[]): null | SymlinkResolution {
    if (this.targets.has(prefix)) return this.resolve(prefix)
    // Issue #219: a prefix the archive does not ship already exists on the
    // host or is created by nothing; either way the kernel follows whatever is
    // there, so the host probe has to look at it.
    if (!this.memberKeys.has(prefix)) prefixes.push(prefix)
    return null
  }

  /**
   * Apply one target segment to a walk.
   *
   * @param state - The walk so far.
   * @param segment - One `/`-separated segment of the link target.
   * @returns The walk after the segment, or the failure that ends it.
   */
  private step(state: WalkState, segment: string): SymlinkFailure | WalkState {
    if (segment === "" || segment === ".") return state
    if (segment === "..") {
      if (state.segments.length === 0) return ESCAPE
      return { ...state, segments: state.segments.slice(0, -1) }
    }
    const segments = [...state.segments, segment]
    const followed = this.follow(segments.join("/"), state.prefixes)
    if (followed === null) return { ...state, segments }
    if (followed.kind !== "resolved") return followed
    const hops = state.hops + followed.hops
    if (hops > SYMLINK_RESOLUTION_LIMIT) return LIMIT
    return { hops, prefixes: state.prefixes, segments: [...followed.segments] }
  }

  private walk(key: string): SymlinkResolution {
    const parent = archiveMemberParentPath(key)
    let state: WalkState = {
      hops: 1,
      prefixes: [],
      segments: parent === "" ? [] : parent.split("/"),
    }
    for (const segment of (this.targets.get(key) ?? "").split("/")) {
      const next = this.step(state, segment)
      if ("kind" in next) return next
      state = next
    }
    return {
      hops: state.hops,
      kind: "resolved",
      prefixes: state.prefixes,
      segments: state.segments,
    }
  }
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
    return resolution.kind === "escape"
      ? `${detail} would escape destination`
      : `${detail} exceeds the symlink resolution limit`
  }
  return null
}

function symlinkKeySet(entries: readonly KeyedMember[]): Set<string> {
  return new Set(entries.filter(({ member }) => member.kind === "symlink").map(({ key }) => key))
}

/**
 * Issue #219: return why the links of an archive are unsafe as a whole, or
 * null when they may be extracted. Runs the root-link, duplicate, ancestor,
 * hardlink-to-symlink and resolution rules in that order and reports the first
 * offending member of the first failing rule.
 *
 * Expects members that already passed `archiveMemberUnsafeReason`, so absolute
 * targets, control characters and zip symlinks never reach these rules.
 *
 * @param members - All parsed members of the archive, in listing order.
 * @returns A human-readable unsafe reason, or null.
 */
export function archiveLinkUnsafeReason(members: readonly ArchiveMember[]): null | string {
  const entries = keyedMembers(members)
  const symlinkKeys = symlinkKeySet(entries)
  return (
    rootLinkReason(entries) ??
    duplicateReason(entries) ??
    ancestorReason(entries, symlinkKeys) ??
    hardlinkToSymlinkReason(entries, symlinkKeys) ??
    resolutionReason(entries, new ArchiveSymlinkResolver(entries))
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
  const entries = keyedMembers(members)
  const resolver = new ArchiveSymlinkResolver(entries)
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
