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
 *
 * The same resolver also judges the combined post-merge link set — the links
 * already on the host plus the links this archive ships — before the staging
 * merge; see {@link mergedArchiveSymlinks} and {@link mergedSymlinkViolations}.
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

/**
 * Issue #219: a symlink target as the resolver walks it.
 *
 * - `parent`: `path` is resolved from the link's parent directory. Every
 *   archive target is of this kind, and so is a relative host target.
 * - `root`: an absolute host target inside the destination. `path` is the part
 *   below the destination, and the walk restarts at the destination root, as
 *   the kernel restarts an absolute target at `/`. This is deliberately not
 *   rewritten into a `../` chain: `..` after a symlinked prefix lands somewhere
 *   else than an absolute restart does.
 * - `outside`: an absolute host target outside the destination. Resolving or
 *   passing through such a link always escapes.
 */
export type SymlinkWalkTarget = { anchor: "outside" } | { anchor: "parent" | "root"; path: string }

/**
 * Issue #219: one symlink of the combined post-merge link set, keyed elsewhere
 * by its normalized destination-relative path.
 */
export type MergedSymlink = {
  /** The target exactly as stored (host) or listed (archive), for messages. */
  stored: string
  /** The target as the resolver walks it. */
  target: SymlinkWalkTarget
}

/** A link of the combined set that cannot be shown to stay inside the destination. */
export type MergedSymlinkViolation = {
  /** Normalized destination-relative path of the link. */
  key: string
  /** `escape` resolves outside; `limit` exceeds the hop limit or recursion depth. */
  kind: "escape" | "limit"
}

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
 *
 * A `root` target (see {@link SymlinkWalkTarget}) starts its walk at the
 * destination root instead of the link's parent; an `outside` target escapes
 * as soon as it is resolved or followed.
 */
class ArchiveSymlinkResolver {
  private readonly inProgress = new Set<string>()
  private readonly memberKeys: ReadonlySet<string>
  private readonly memo = new Map<string, SymlinkResolution>()
  private readonly targets: ReadonlyMap<string, SymlinkWalkTarget>

  /**
   * @param targets - Every symlink by normalized path, with its walk target.
   * @param memberKeys - Normalized paths that are known to exist; any other
   *   visited prefix is collected for the host probe.
   */
  public constructor(
    targets: ReadonlyMap<string, SymlinkWalkTarget>,
    memberKeys: ReadonlySet<string>
  ) {
    this.memberKeys = memberKeys
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
    const target = this.targets.get(key)
    // Fail closed: `resolve` is only called for known links, and a link whose
    // target lies outside the destination escapes by definition.
    if (target === undefined || target.anchor === "outside") return ESCAPE
    const start = target.anchor === "root" ? "" : archiveMemberParentPath(key)
    let state: WalkState = {
      hops: 1,
      prefixes: [],
      segments: start === "" ? [] : start.split("/"),
    }
    for (const segment of target.path.split("/")) {
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
    resolutionReason(entries, archiveResolver(entries))
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
  const resolver = archiveResolver(entries)
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
 * Issue #219: build the symlink set the destination will hold once the staged
 * archive is merged, keyed by normalized destination-relative path.
 *
 * It starts from the links already on the host and applies the archive's
 * members in listing order. The merge copies every staged entry with
 * `cp -aT --no-dereference --remove-destination`, so an archive member of any
 * kind at a path replaces the host link there: an archive symlink brings its
 * own target, any other member leaves no link at that path. Only this
 * exact-path replacement is modelled. A host link below an archive member path
 * is kept, which is conservative: a non-symlink member at or below a host
 * symlink is already refused by the pre-staging probe and the merge guard, and
 * a directory/non-directory conflict makes `cp` fail.
 *
 * @param hostLinks - The links on the host, keyed by destination-relative path.
 * @param members - The validated archive members, in listing order.
 * @returns The combined post-merge link set.
 */
export function mergedArchiveSymlinks(
  hostLinks: ReadonlyMap<string, MergedSymlink>,
  members: readonly ArchiveMember[]
): Map<string, MergedSymlink> {
  const merged = new Map(hostLinks)
  for (const { key, member } of keyedMembers(members)) {
    merged.delete(key)
    if (member.kind !== "symlink") continue
    const stored = member.linkTarget ?? ""
    merged.set(key, { stored, target: { anchor: "parent", path: stored } })
  }
  return merged
}

/**
 * Issue #219: resolve every link of a combined post-merge link set with the
 * same resolver the archive-level rules use and report each link that escapes
 * the destination or exceeds the resolution limit. A link that cannot be
 * resolved within the limit cannot be proven to stay inside, so it counts as a
 * violation as well.
 *
 * @param links - The combined link set, e.g. from {@link mergedArchiveSymlinks}.
 * @returns The violations in the iteration order of `links`.
 */
export function mergedSymlinkViolations(
  links: ReadonlyMap<string, MergedSymlink>
): MergedSymlinkViolation[] {
  const targets = new Map<string, SymlinkWalkTarget>()
  for (const [key, link] of links) targets.set(key, link.target)
  const resolver = new ArchiveSymlinkResolver(targets, new Set(targets.keys()))
  const violations: MergedSymlinkViolation[] = []
  for (const key of targets.keys()) {
    const resolution = resolver.resolve(key)
    if (resolution.kind === "resolved") continue
    violations.push({ key, kind: resolution.kind === "escape" ? "escape" : "limit" })
  }
  return violations
}
