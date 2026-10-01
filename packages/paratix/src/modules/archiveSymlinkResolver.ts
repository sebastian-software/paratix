/**
 * Issue #219: the bounded, lexical symlink resolver shared by the archive-level
 * link rules, the pre-staging prefix model, the pre-merge model and the
 * post-merge backstop of `archive.extract`. It never asks a host to resolve
 * anything; see {@link ArchiveSymlinkResolver}.
 */
import { archiveMemberParentPath } from "./archiveMemberValidation.js"

/**
 * Issue #219: the maximum number of symlinks one resolution may follow. It
 * mirrors Linux `MAXSYMLINKS` (40): the kernel refuses a lookup with `ELOOP`
 * after that many follows, so a longer chain cannot resolve on the host
 * either. Internal on purpose, not an option.
 */
const SYMLINK_RESOLUTION_LIMIT = 40

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
 * Outcome of resolving one symlink member.
 *
 * `depth` marks a resolution cut off because the stack of links being
 * resolved grew past {@link SYMLINK_RESOLUTION_LIMIT}. Only the link at the
 * bottom of that stack is known to fail, so a `depth` outcome is never
 * memoized for the links above it.
 *
 * Issue #219: `unmappable` names a link (the resolved one or one it follows)
 * whose listed path or target is not valid UTF-8 (see
 * {@link ResolverScope.unmappable}); `unreadable` names an unreadable host
 * directory the walk reached (see {@link ResolverScope.unreadable}).
 */
export type SymlinkResolution =
  | { directory: string; kind: "unreadable" }
  | { hops: number; kind: "resolved"; prefixes: readonly string[]; segments: readonly string[] }
  | { kind: "depth" }
  | { kind: "escape" }
  | { kind: "limit" }
  | { kind: "unmappable"; link: string }
  | { kind: "variant"; link: string; prefix: string }

/** A resolution that did not end inside the destination. */
export type SymlinkFailure = Exclude<SymlinkResolution, { kind: "resolved" }>

/**
 * Issue #219: a resolution together with whether its walk touched a path the
 * archive writes (see {@link ResolverScope.written}).
 */
export type TrackedSymlinkResolution = {
  resolution: SymlinkResolution
  /**
   * True when the walk appended a prefix whose {@link pathNameVariantKey} is
   * in the written set (including the prefix at which a `variant` failure was
   * detected, and an ancestor of the link that names a link only after
   * folding), or followed a link whose own resolution touched it.
   */
  touched: boolean
}

/**
 * Issue #219: what the resolver needs to know beyond the link targets.
 */
export type ResolverScope = {
  /** Link keys whose listed path or target is not valid UTF-8. */
  unmappable?: ReadonlySet<string>
  /** Destination-relative paths of host directories that could not be read. */
  unreadable?: ReadonlySet<string>
  /**
   * {@link pathNameVariantKey} of every path the archive writes: each member
   * path and each of its proper ancestors.
   */
  written?: ReadonlySet<string>
}

/**
 * Issue #219: the trail of one resolved link's own target, for the kernel
 * cross-check: where the resolver places each point of the target path.
 *
 * `segments` are the target's segments without empty and `.` segments (the
 * kernel ignores those), with `..` kept. `locations[j]` is the normalized
 * destination-relative path the resolver reaches after applying the first `j`
 * of them from `base`, following links exactly as the resolution does, so
 * `locations[0]` is `base` and the last entry is the link's resolution
 * (`""` stands for the destination root).
 */
export type SymlinkTrail = {
  /**
   * Where the walk starts, destination-relative: the link's parent, or `""`
   * for a top-level link and for a `root` target.
   */
  base: string
  /** One location per applied segment count, `segments.length + 1` in all. */
  locations: readonly string[]
  /** The kept target segments. */
  segments: readonly string[]
}

/**
 * Issue #219: computes the {@link SymlinkTrail} of a resolved link on demand,
 * see `ArchiveSymlinkResolver.trail`.
 */
export type SymlinkTrailSource = (
  key: string,
  maxLength: number
) => "oversized" | null | SymlinkTrail

/** The state of one walk: hops spent, visited non-member prefixes, resolved segments. */
type WalkState = { hops: number; prefixes: string[]; segments: readonly string[] }

const ESCAPE: SymlinkFailure = { kind: "escape" }
const LIMIT: SymlinkFailure = { kind: "limit" }
const DEPTH: SymlinkFailure = { kind: "depth" }
const EMPTY_SET: ReadonlySet<string> = new Set()

/**
 * Issue #219: characters with the Unicode property
 * `Default_Ignorable_Code_Point` (zero-width joiners and non-joiners, the
 * byte order mark, the soft hyphen and similar). Some case-folding
 * implementations ignore them when they compare names.
 */
const DEFAULT_IGNORABLE_CODE_POINTS = /\p{Default_Ignorable_Code_Point}/gv

/**
 * Issue #219: how often {@link pathNameVariantKey} applies its folding round
 * at most. One round is not idempotent for every input: U+1E9E (capital
 * sharp s) lower-cases to `ß`, which only the next round upper-cases to `SS`.
 * Every single code point reaches a fixpoint within two rounds (the unit
 * tests check all of them); the bound only keeps a pathological string from
 * looping.
 */
const VARIANT_KEY_ROUND_LIMIT = 4

/**
 * Issue #219: one folding round of {@link pathNameVariantKey}.
 *
 * @param path - The path, or the result of an earlier round.
 * @returns The path without default-ignorable characters, NFKD-decomposed,
 *   upper- and then lower-cased and decomposed again.
 */
function variantKeyRound(path: string): string {
  return path
    .replaceAll(DEFAULT_IGNORABLE_CODE_POINTS, "")
    .normalize("NFKD")
    .toUpperCase()
    .toLowerCase()
    .normalize("NFKD")
}

/**
 * Issue #219: the key under which two path spellings count as the same name.
 *
 * The resolver compares link paths byte for byte, but case-insensitive or
 * normalizing filesystems (APFS, casefold ext4 and f2fs, case-insensitive ZFS,
 * CIFS mounts) resolve a differently spelled name to an existing entry. Two
 * paths with the same key may therefore name the same entry on some host.
 *
 * The key is a conservative superset of those equivalences. One round drops
 * every `Default_Ignorable_Code_Point` character, which some case-folding
 * implementations ignore, then applies NFKD decomposition (covers NFC, NFD
 * and compatibility forms), upper- and lower-casing (covers simple and full
 * case folding, e.g. `ß` and `SS`) and NFKD again because case mapping can
 * produce characters that decompose. Rounds repeat until the result no longer
 * changes, so the key is a fixpoint: `pathNameVariantKey(key) === key`. This
 * matters for U+1E9E, which one round only maps to `ß`, while APFS and Linux
 * casefolding treat it like `ss`. The key may group more spellings than any
 * real filesystem does (dropping default-ignorable characters included); that
 * only makes the containment checks refuse more, never less.
 *
 * @param path - A normalized destination-relative path.
 * @returns The comparison key; equal keys mean the names may collide.
 */
export function pathNameVariantKey(path: string): string {
  let key = variantKeyRound(path)
  for (let round = 1; round < VARIANT_KEY_ROUND_LIMIT; round += 1) {
    const next = variantKeyRound(key)
    if (next === key) return key
    key = next
  }
  return key
}

/**
 * Issue #219: the proper ancestors of a normalized path, outermost first.
 *
 * @param key - A normalized destination-relative path.
 * @returns Every proper, non-empty ancestor.
 */
function properAncestors(key: string): string[] {
  const ancestors: string[] = []
  for (let end = key.indexOf("/"); end !== -1; end = key.indexOf("/", end + 1)) {
    ancestors.push(key.slice(0, end))
  }
  return ancestors
}

/**
 * Issue #219: the archive's symlinks indexed by {@link pathNameVariantKey}, so
 * the archive-level relationship rules can find a symlink under any spelling a
 * case-folding or normalizing filesystem treats as the same name.
 *
 * Meant to live for one `archiveLinkUnsafeReason` call. It memoizes the variant
 * key of every path it is asked about, because the rules ask about every proper
 * ancestor of every member and siblings share those prefixes, and it answers
 * lookups without computing any key while the archive has no symlink.
 */
export class SymlinkVariantIndex {
  private readonly keys = new Map<string, string>()
  private readonly symlinks = new Map<string, string>()

  /**
   * @param symlinkKeys - Normalized destination-relative symlink paths, in
   *   listing order; each variant key keeps the first literal path.
   */
  public constructor(symlinkKeys: Iterable<string>) {
    for (const key of symlinkKeys) {
      const variantKey = this.variantKey(key)
      if (!this.symlinks.has(variantKey)) this.symlinks.set(variantKey, key)
    }
  }

  /**
   * Find the outermost proper ancestor of a path that names an indexed
   * symlink, so `x/l/f` is below the symlink `x/L`.
   *
   * @param key - A normalized destination-relative path.
   * @returns The symlink's literal path, or undefined when no proper ancestor
   *   names a symlink.
   */
  public symlinkAncestor(key: string): string | undefined {
    if (this.symlinks.size === 0) return undefined
    for (const ancestor of properAncestors(key)) {
      const symlink = this.symlinks.get(this.variantKey(ancestor))
      if (symlink !== undefined) return symlink
    }
    return undefined
  }

  /**
   * Find the indexed symlink a path names, so `a/b/s` names the symlink
   * `a/b/S`.
   *
   * @param key - A normalized destination-relative path.
   * @returns The symlink's literal path, or undefined when the path names none.
   */
  public symlinkAt(key: string): string | undefined {
    if (this.symlinks.size === 0) return undefined
    return this.symlinks.get(this.variantKey(key))
  }

  /**
   * {@link pathNameVariantKey}, memoized for the lifetime of this index.
   *
   * @param path - A normalized destination-relative path.
   * @returns The path's variant key.
   */
  public variantKey(path: string): string {
    let variantKey = this.keys.get(path)
    if (variantKey === undefined) {
      variantKey = pathNameVariantKey(path)
      this.keys.set(path, variantKey)
    }
    return variantKey
  }
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
 *
 * Issue #219: every path a walk visits — each ancestor of the link's own
 * parent and each prefix a target segment produces — is also compared with
 * the link keys under {@link pathNameVariantKey}. A visited path that matches
 * a link only after folding, without being that link byte for byte, ends the
 * walk as a `variant` failure: on a case-folding or normalizing filesystem
 * the kernel may follow that link where the model walks a plain path. Only
 * link keys are candidates. A host directory at a member path is refused as a
 * merge conflict before the resolver runs, and a plain directory or file under
 * another spelling cannot redirect a walk, so the link keys are the complete
 * set of names whose spelling matters.
 *
 * Issue #219: the containment checks judge only the links an archive can
 * affect, so every outcome also records whether its walk touched a path the
 * archive writes ({@link ResolverScope.written}); see
 * {@link TrackedSymlinkResolution}. The flag is memoized with the outcome, one
 * boolean per link, so no per-link set of visited paths is kept even for trees
 * with hundreds of thousands of links. A walk that follows a link inherits
 * that link's flag. Two approximations are deliberate: a link re-entered while
 * it is still being resolved (a cycle) contributes only what the walks on the
 * stack saw before the cycle closed, which the link that entered the cycle
 * still sees in full; and a `depth` outcome is not memoized, so its flag is
 * what the walk saw until it was cut off. Both outcomes are failures, so the
 * approximation can only drop a report for a link that follows an already
 * failing chain, never accept a link that resolves.
 *
 * A walk that appends an unreadable host directory, or a path below one, ends
 * as an `unreadable` failure: the listing could not see the links in there.
 * A link whose listed name or target is not valid UTF-8 resolves to an
 * `unmappable` failure after its walk (so its flag is still known), and every
 * link that follows it inherits that failure.
 */
export class ArchiveSymlinkResolver {
  /** Issue #219: the lists `followedLinks` computed so far, by link. */
  private readonly followed = new Map<string, readonly string[]>()
  private readonly inProgress = new Set<string>()
  private readonly memberKeys: ReadonlySet<string>
  private readonly memo = new Map<string, TrackedSymlinkResolution>()
  private readonly targets: ReadonlyMap<string, SymlinkWalkTarget>
  /**
   * Issue #219: one touched flag per walk in progress, innermost last; see
   * {@link TrackedSymlinkResolution}.
   */
  private readonly touches: boolean[] = []
  private readonly unmappable: ReadonlySet<string>
  /** Issue #219: unreadable directories keyed by {@link pathNameVariantKey}. */
  private readonly unreadable = new Map<string, string>()
  /** Issue #219: link keys grouped by {@link pathNameVariantKey}. */
  private readonly variants = new Map<string, string[]>()
  private readonly written: ReadonlySet<string>

  /**
   * @param targets - Every symlink by normalized path, with its walk target.
   * @param memberKeys - Normalized paths that are known to exist; any other
   *   visited prefix is collected for the host probe.
   * @param scope - Issue #219: unmappable links, unreadable directories and
   *   written paths; each defaults to empty.
   */
  public constructor(
    targets: ReadonlyMap<string, SymlinkWalkTarget>,
    memberKeys: ReadonlySet<string>,
    scope: ResolverScope = {}
  ) {
    this.memberKeys = memberKeys
    this.targets = targets
    this.unmappable = scope.unmappable ?? EMPTY_SET
    this.written = scope.written ?? EMPTY_SET
    for (const directory of scope.unreadable ?? []) {
      this.unreadable.set(pathNameVariantKey(directory), directory)
    }
    for (const key of targets.keys()) {
      const variantKey = pathNameVariantKey(key)
      const group = this.variants.get(variantKey)
      if (group === undefined) this.variants.set(variantKey, [key])
      else group.push(key)
    }
  }

  /**
   * Issue #219: the links the resolution of `key` follows, directly or
   * through a link it follows, each once, for the kernel cross-check.
   *
   * A link whose own target dangles leaves no trace in the trail of a link
   * that follows it: the kernel finds nothing at any point past it, so only
   * that link's own trail can confirm where a write through the chain would
   * land. Like {@link trail}, the list is computed on demand from the
   * memoized resolutions; the lists asked for are kept, so a link followed by
   * many others is retraced once. Every link a resolved walk follows resolved
   * itself, within the hop limit, so a list never holds more than
   * {@link SYMLINK_RESOLUTION_LIMIT} links and contains no cycle.
   *
   * @param key - Normalized path of a symlink.
   * @returns The followed links in walk order, or none when the link does not
   *   resolve inside the destination.
   */
  public followedLinks(key: string): readonly string[] {
    const known = this.followed.get(key)
    if (known !== undefined) return known
    const followed = new Set<string>()
    for (const link of this.directlyFollowedLinks(key)) {
      followed.add(link)
      for (const further of this.followedLinks(link)) followed.add(further)
    }
    const links = [...followed]
    this.followed.set(key, links)
    return links
  }

  /**
   * Resolve the target of the symlink member at `key`.
   *
   * @param key - Normalized path of a symlink member.
   * @returns The resolved path segments and hop count, or the failure kind.
   */
  public resolve(key: string): SymlinkResolution {
    return this.resolveTracked(key).resolution
  }

  /**
   * Issue #219: resolve the target of the symlink at `key` and report whether
   * the walk touched a written path.
   *
   * @param key - Normalized path of a symlink.
   * @returns The resolution with its touched flag.
   */
  public resolveTracked(key: string): TrackedSymlinkResolution {
    const known = this.memo.get(key)
    if (known !== undefined) return known
    if (this.inProgress.has(key)) return { resolution: LIMIT, touched: false }
    if (this.inProgress.size >= SYMLINK_RESOLUTION_LIMIT) {
      return { resolution: DEPTH, touched: false }
    }
    this.inProgress.add(key)
    this.touches.push(false)
    const walked = this.walk(key)
    const touched = this.touches.pop() === true
    this.inProgress.delete(key)
    // Issue #219: an unmappable link is walked like any other, so whether it
    // touches a written path is known, but it never counts as resolved.
    const resolution: SymlinkResolution = this.unmappable.has(key)
      ? { kind: "unmappable", link: key }
      : walked
    const tracked = { resolution, touched }
    if (resolution.kind !== "depth") this.memo.set(key, tracked)
    return tracked
  }

  /**
   * Issue #219: the trail of a resolved link's own target, see
   * {@link SymlinkTrail}.
   *
   * It is computed on demand, one link at a time, so no trail is kept for the
   * links that are never cross-checked. The walk repeats the resolution's
   * steps; every link it follows was memoized by that resolution, so it costs
   * no more than one pass over the target. `maxLength` bounds the summed
   * length of the locations, so an oversized trail is refused before it is
   * built in full.
   *
   * @param key - Normalized path of a symlink.
   * @param maxLength - The largest summed length (in UTF-16 code units) of the
   *   locations that is still built.
   * @returns The trail, `"oversized"` when the locations would exceed
   *   `maxLength`, or null when the link does not resolve inside the
   *   destination.
   */
  public trail(
    key: string,
    maxLength = Number.POSITIVE_INFINITY
  ): "oversized" | null | SymlinkTrail {
    const target = this.targets.get(key)
    if (target === undefined || target.anchor === "outside") return null
    if (this.resolve(key).kind !== "resolved") return null
    const base = target.anchor === "root" ? "" : archiveMemberParentPath(key)
    const segments = target.path.split("/").filter((segment) => segment !== "" && segment !== ".")
    // The walk may mark a touch; give it a slot of its own so no tracked
    // resolution is affected.
    this.touches.push(false)
    try {
      const locations = this.trailLocations(base, segments, maxLength)
      if (locations === null || locations === "oversized") return locations
      return { base, locations, segments }
    } finally {
      this.touches.pop()
    }
  }

  /**
   * Issue #219: check the ancestors the kernel walks to reach the link itself,
   * which the target walk below does not visit.
   *
   * @param key - Normalized path of the link.
   * @returns A `variant` failure for the first ancestor that names a link only
   *   after folding, or null.
   */
  private ancestorVariant(key: string): null | SymlinkFailure {
    for (const ancestor of properAncestors(key)) {
      const variantKey = pathNameVariantKey(ancestor)
      const variant = this.variantOf(ancestor, variantKey)
      if (variant !== null) {
        if (this.written.has(variantKey)) this.markTouched()
        return variant
      }
    }
    return null
  }

  /**
   * Issue #219: the links a resolved link's own walk follows, read off its
   * trail: the prefix a non-`..` segment appends is followed exactly when it
   * names a link (see {@link follow}).
   *
   * @param key - Normalized path of a symlink.
   * @returns The directly followed links in walk order; none for a link that
   *   does not resolve inside the destination.
   */
  private directlyFollowedLinks(key: string): string[] {
    const traced = this.trail(key)
    if (traced === null || traced === "oversized") return []
    const links: string[] = []
    for (const [index, segment] of traced.segments.entries()) {
      if (segment === "..") continue
      const before = traced.locations[index]
      const prefix = before === "" ? segment : `${before}/${segment}`
      if (this.targets.has(prefix)) links.push(prefix)
    }
    return links
  }

  /**
   * Handle one resolved prefix of a walk.
   *
   * @param prefix - The resolved prefix after appending a segment.
   * @param prefixes - Collector for visited prefixes that are not archive members.
   * @returns The resolution of the archive symlink at `prefix`, or null when it is none.
   */
  private follow(prefix: string, prefixes: string[]): null | SymlinkResolution {
    const variantKey = pathNameVariantKey(prefix)
    if (this.written.has(variantKey)) this.markTouched()
    const unreadable = this.unreadableAt(prefix, variantKey)
    if (unreadable !== null) return unreadable
    const variant = this.variantOf(prefix, variantKey)
    if (variant !== null) return variant
    if (this.targets.has(prefix)) {
      const followed = this.resolveTracked(prefix)
      if (followed.touched) this.markTouched()
      return followed.resolution
    }
    // Issue #219: a prefix the archive does not ship already exists on the
    // host or is created by nothing; either way the kernel follows whatever is
    // there, so the host probe has to look at it.
    if (!this.memberKeys.has(prefix)) prefixes.push(prefix)
    return null
  }

  /**
   * Issue #219: record that the innermost walk in progress touched a written
   * path.
   */
  private markTouched(): void {
    this.touches[this.touches.length - 1] = true
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

  /**
   * Issue #219: the locations of a trail, see {@link SymlinkTrail}.
   *
   * @param base - Where the walk starts.
   * @param segments - The kept target segments.
   * @param maxLength - The largest summed length of the locations.
   * @returns The locations, `"oversized"`, or null when a step fails, which
   *   cannot happen for a link that resolved.
   */
  private trailLocations(
    base: string,
    segments: readonly string[],
    maxLength: number
  ): "oversized" | null | string[] {
    let state: WalkState = { hops: 1, prefixes: [], segments: base === "" ? [] : base.split("/") }
    const locations = [base]
    let length = base.length
    for (const segment of segments) {
      const next = this.step(state, segment)
      if ("kind" in next) return null
      state = next
      const location = state.segments.join("/")
      length += location.length
      if (length > maxLength) return "oversized"
      locations.push(location)
    }
    return locations
  }

  /**
   * Issue #219: report an appended path that is an unreadable directory or
   * lies below one, compared under {@link pathNameVariantKey}.
   *
   * @param prefix - A visited destination-relative path.
   * @param variantKey - The variant key of `prefix`.
   * @returns An `unreadable` failure naming the directory, or null.
   */
  private unreadableAt(prefix: string, variantKey: string): null | SymlinkFailure {
    if (this.unreadable.size === 0) return null
    const keys = [variantKey, ...properAncestors(prefix).map((path) => pathNameVariantKey(path))]
    for (const key of keys) {
      const directory = this.unreadable.get(key)
      if (directory !== undefined) return { directory, kind: "unreadable" }
    }
    return null
  }

  /**
   * Issue #219: report a visited path that names a link only after folding.
   *
   * @param prefix - A visited destination-relative path.
   * @param variantKey - The variant key of `prefix`.
   * @returns A `variant` failure naming the first such link, or null.
   */
  private variantOf(prefix: string, variantKey: string): null | SymlinkFailure {
    const group = this.variants.get(variantKey)
    const link = group?.find((candidate) => candidate !== prefix)
    return link === undefined ? null : { kind: "variant", link, prefix }
  }

  private walk(key: string): SymlinkResolution {
    const target = this.targets.get(key)
    // Fail closed: `resolve` is only called for known links, and a link whose
    // target lies outside the destination escapes by definition.
    if (target === undefined || target.anchor === "outside") return ESCAPE
    const ancestorVariant = this.ancestorVariant(key)
    if (ancestorVariant !== null) return ancestorVariant
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
 * Issue #219: describe a `variant` resolution for a refusal message.
 *
 * @param variant - The visited path and the symlink it matches after folding.
 * @param variant.link - The symlink whose name matches only after folding.
 * @param variant.prefix - The visited destination-relative path.
 * @returns The description, starting after the link it is about.
 */
export function variantDescription(variant: { link: string; prefix: string }): string {
  return `passes through ${JSON.stringify(variant.prefix)}, a name that differs from existing symlink ${JSON.stringify(variant.link)} only by letter case or Unicode normalization; a case-insensitive or normalizing filesystem may follow that symlink instead`
}
