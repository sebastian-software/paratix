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
 */
export type SymlinkResolution =
  | { hops: number; kind: "resolved"; prefixes: readonly string[]; segments: readonly string[] }
  | { kind: "depth" }
  | { kind: "escape" }
  | { kind: "limit" }
  | { kind: "variant"; link: string; prefix: string }

/** A resolution that did not end inside the destination. */
export type SymlinkFailure = Exclude<SymlinkResolution, { kind: "resolved" }>

/** The state of one walk: hops spent, visited non-member prefixes, resolved segments. */
type WalkState = { hops: number; prefixes: string[]; segments: readonly string[] }

const ESCAPE: SymlinkFailure = { kind: "escape" }
const LIMIT: SymlinkFailure = { kind: "limit" }
const DEPTH: SymlinkFailure = { kind: "depth" }

/**
 * Issue #219: the key under which two path spellings count as the same name.
 *
 * The resolver compares link paths byte for byte, but case-insensitive or
 * normalizing filesystems (APFS, casefold ext4 and f2fs, case-insensitive ZFS,
 * CIFS mounts) resolve a differently spelled name to an existing entry. Two
 * paths with the same key may therefore name the same entry on some host.
 *
 * The key is a conservative superset of those equivalences: NFKD
 * decomposition (covers NFC, NFD and compatibility forms), then upper- and
 * lower-casing (covers simple and full case folding, e.g. `ß` and `SS`), then
 * NFKD again because case mapping can produce characters that decompose. It
 * may group more spellings than any real filesystem does; that only makes the
 * containment checks refuse more, never less.
 *
 * @param path - A normalized destination-relative path.
 * @returns The comparison key; equal keys mean the names may collide.
 */
export function pathNameVariantKey(path: string): string {
  return path.normalize("NFKD").toUpperCase().toLowerCase().normalize("NFKD")
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
 */
export class ArchiveSymlinkResolver {
  private readonly inProgress = new Set<string>()
  private readonly memberKeys: ReadonlySet<string>
  private readonly memo = new Map<string, SymlinkResolution>()
  private readonly targets: ReadonlyMap<string, SymlinkWalkTarget>
  /** Issue #219: link keys grouped by {@link pathNameVariantKey}. */
  private readonly variants = new Map<string, string[]>()

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
    for (const key of targets.keys()) {
      const variantKey = pathNameVariantKey(key)
      const group = this.variants.get(variantKey)
      if (group === undefined) this.variants.set(variantKey, [key])
      else group.push(key)
    }
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
   * Issue #219: check the ancestors the kernel walks to reach the link itself,
   * which the target walk below does not visit.
   *
   * @param key - Normalized path of the link.
   * @returns A `variant` failure for the first ancestor that names a link only
   *   after folding, or null.
   */
  private ancestorVariant(key: string): null | SymlinkFailure {
    for (let end = key.indexOf("/"); end !== -1; end = key.indexOf("/", end + 1)) {
      const variant = this.variantOf(key.slice(0, end))
      if (variant !== null) return variant
    }
    return null
  }

  /**
   * Handle one resolved prefix of a walk.
   *
   * @param prefix - The resolved prefix after appending a segment.
   * @param prefixes - Collector for visited prefixes that are not archive members.
   * @returns The resolution of the archive symlink at `prefix`, or null when it is none.
   */
  private follow(prefix: string, prefixes: string[]): null | SymlinkResolution {
    const variant = this.variantOf(prefix)
    if (variant !== null) return variant
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

  /**
   * Issue #219: report a visited path that names a link only after folding.
   *
   * @param prefix - A visited destination-relative path.
   * @returns A `variant` failure naming the first such link, or null.
   */
  private variantOf(prefix: string): null | SymlinkFailure {
    const group = this.variants.get(pathNameVariantKey(prefix))
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
