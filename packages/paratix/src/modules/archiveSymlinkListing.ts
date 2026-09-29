/**
 * Decoding of the host symlink listing that both containment checks around
 * the staging merge of `archive.extract` read.
 *
 * Issue #219: the pre-merge check and the post-merge backstop list the links
 * below the destination with the same probe
 * (`buildSymlinkListingProbeScript` in `archiveProbe.ts`) and turn its output into the host
 * state the link model needs with {@link hostStateFromListing}, so both share
 * one set of framing and trust rules.
 */
import type { MergedSymlink, MergeHostState, SymlinkWalkTarget } from "./archiveLinkValidation.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { nonDirectoryMemberPaths } from "./archiveDestinationValidation.js"
import { encodeSymlinkListingEntry } from "./archiveProbe.js"

/**
 * Classify a raw host symlink target for the resolver.
 *
 * A relative target is walked from the link's parent. An absolute target equal
 * to or below the canonical destination restarts at the destination root; any
 * other absolute target counts as escaping, a fail-closed stance on
 * pre-existing links that point outside that both the pre-merge and the
 * post-merge check share. The
 * prefix comparison is literal, so an absolute target that reaches the
 * destination through a non-canonical spelling is judged conservatively as
 * outside.
 *
 * @param destination - The validated, canonical destination directory.
 * @param target - The target exactly as `readlink` reported it.
 * @returns How the resolver walks the target: from the link's parent, from the
 *   destination root, or not at all because it lies outside.
 */
function hostSymlinkWalkTarget(destination: string, target: string): SymlinkWalkTarget {
  if (!target.startsWith("/")) return { anchor: "parent", path: target }
  if (target === destination) return { anchor: "root", path: "" }
  if (target.startsWith(`${destination}/`)) {
    return { anchor: "root", path: target.slice(destination.length + 1) }
  }
  return { anchor: "outside" }
}

/**
 * Issue #219: the entries of the pre-merge listing probe (see
 * `buildSymlinkListingProbeScript` in `archiveProbe.ts`): one `r` entry for the destination,
 * then one `n` entry per non-directory member path below it.
 *
 * @param destination - The validated, canonical destination directory.
 * @param members - The validated archive members.
 * @returns The encoded entries (see {@link encodeSymlinkListingEntry}).
 */
export function symlinkListingEntries(
  destination: string,
  members: readonly ArchiveMember[]
): string[] {
  const directoryChecks = [...nonDirectoryMemberPaths(destination, members).keys()]
  return [
    encodeSymlinkListingEntry("r", destination),
    ...directoryChecks.map((path) => encodeSymlinkListingEntry("n", path)),
  ]
}

/** The host state being built from a listing, with the requested directory paths. */
type ListingState = {
  /** The validated, canonical destination directory. */
  destination: string
  /** Collector for directory hits by member key. */
  directories: Set<string>
  /** Collector for host links by destination-relative path. */
  links: Map<string, MergedSymlink>
  /** The `n` entry paths that were sent, mapped to their key. */
  requested: ReadonlyMap<string, string>
}

/**
 * Issue #219: why one listed `(link, target)` pair cannot be trusted, if at all.
 *
 * @param state - The host state built so far.
 * @param link - The absolute link path as listed.
 * @param target - The stored target as listed.
 * @returns The reason, or null when the pair may be added.
 */
function untrustedLinkPair(state: ListingState, link: string, target: string): null | string {
  const prefix = `${state.destination}/`
  if (!link.startsWith(prefix) || link.length === prefix.length) {
    return `probe reported ${JSON.stringify(link)}, which is not below the destination`
  }
  // Issue #219: Linux cannot store an empty symlink target, so an empty one
  // means `readlink` succeeded without printing the target. The resolver would
  // walk it as the link's parent directory, i.e. as contained, so an unusable
  // `readlink` fails the listing instead.
  if (target === "") {
    return `probe reported an empty target for symlink ${JSON.stringify(link)}; readlink output is unusable`
  }
  // Issue #219: the listing is decoded as strict UTF-8, so every string maps
  // back to exactly the host's bytes. A U+FFFD can then only be a literal
  // replacement character in the name, which is where a lossy decode would
  // have hidden a byte it could not decode; refusing it keeps the rule simple.
  if (link.includes("�") || target.includes("�")) {
    return `probe reported symlink ${JSON.stringify(link)} -> ${JSON.stringify(target)} with a U+FFFD replacement character; the listing cannot be mapped to host names reliably`
  }
  // Issue #219: two listed links with the same key would otherwise collapse
  // into one entry, and the model would judge only one of them.
  if (state.links.has(link.slice(prefix.length))) {
    return `probe reported symlink ${JSON.stringify(link)} more than once`
  }
  return null
}

/**
 * Add one decoded listing pair to the host state.
 *
 * @param state - The host state being built, with the requested directory paths.
 * @param pair - The `(link, target)` or `("", directory)` pair.
 * @returns Null when the pair was added, otherwise why the output cannot be trusted.
 */
function addListingPair(state: ListingState, pair: readonly [string, string]): null | string {
  const [first, second] = pair
  if (first === "") {
    const key = state.requested.get(second)
    if (key === undefined) {
      return `probe reported directory ${JSON.stringify(second)}, which is not a requested member path below the destination`
    }
    state.directories.add(key)
    return null
  }
  const untrusted = untrustedLinkPair(state, first, second)
  if (untrusted !== null) return untrusted
  state.links.set(first.slice(state.destination.length + 1), {
    stored: second,
    target: hostSymlinkWalkTarget(state.destination, second),
  })
  return null
}

/**
 * Turn the decoded listing fields into the host state the link model needs,
 * or explain why the output cannot be trusted.
 *
 * Issue #219: the post-merge backstop passes an empty `requested` map, because
 * it sends no `n` entries; any directory hit is then broken framing. A link
 * listed twice, or a link path or target with a U+FFFD replacement character,
 * makes the listing untrusted as well.
 *
 * @param destination - The validated, canonical destination directory.
 * @param fields - The decoded probe fields.
 * @param requested - The `n` entry paths that were sent, mapped to their key.
 * @returns The host state, or a reason the listing cannot be trusted.
 */
export function hostStateFromListing(
  destination: string,
  fields: readonly string[],
  requested: ReadonlyMap<string, string>
): MergeHostState | string {
  // An odd field count means the pair framing broke somewhere; pairing the
  // rest anyway could attach a target to the wrong link.
  if (fields.length % 2 !== 0) {
    return `probe returned ${String(fields.length)} fields, expected (link, target) or ("", directory) pairs`
  }
  const state: ListingState = {
    destination,
    directories: new Set<string>(),
    links: new Map<string, MergedSymlink>(),
    requested,
  }
  for (let index = 0; index < fields.length; index += 2) {
    const broken = addListingPair(state, [fields[index], fields[index + 1]])
    if (broken !== null) return broken
  }
  return { directories: state.directories, links: state.links }
}
