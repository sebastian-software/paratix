/**
 * Decoding of the host symlink listing that both containment checks around
 * the staging merge of `archive.extract` read.
 *
 * Issue #219: the pre-merge check and the post-merge backstop list the links
 * below the destination with the same probe
 * (`buildSymlinkListingProbeScript` in `archiveProbe.ts`), run it with
 * {@link runSymlinkListing} and turn its output into the host state the link
 * model needs with {@link hostStateFromListing}, so both share one set of
 * framing and trust rules.
 */
import type { SshConnection } from "../types.js"
import type {
  MergedSymlink,
  MergedSymlinkViolation,
  MergeHostState,
  SymlinkWalkTarget,
} from "./archiveLinkValidation.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { nonDirectoryMemberPaths } from "./archiveDestinationValidation.js"
import {
  buildSymlinkListingProbeScript,
  encodeSymlinkListingEntry,
  runBatchedProbe,
} from "./archiveProbe.js"

/**
 * Issue #219: the captured-output cap of the containment listing: 64 MiB.
 *
 * The listing grows with the number of symlinks below the destination (a
 * `node_modules` tree has many), not with violations, so it gets its own cap
 * instead of the 1 MiB default or the 16 MiB archive-listing cap. Link paths
 * are sent relative to the destination to keep each record short. A listing
 * that hits the cap is still refused, as a known limit: the destination then
 * holds too many symlinks to check.
 */
export const SYMLINK_LISTING_CAPTURE_LIMIT_BYTES = 67_108_864

/**
 * Issue #219: the byte that starts a hex-encoded field (see
 * `SYMLINK_LISTING_FIELD_FUNCTION` in `archiveProbe.ts`).
 */
const HEX_FIELD_MARKER = "\u0001"

/**
 * Issue #219: a plain listing field: printable ASCII only. Any other field
 * must arrive hex-encoded.
 */
const PLAIN_FIELD_PATTERN = /^[\x20-\x7E]*$/v

/** Issue #219: lowercase hex digits; the even length is checked separately. */
const HEX_DIGITS_PATTERN = /^[0-9a-f]+$/v

const SLASH_BYTE = 0x2f

/**
 * Issue #219: the prefix of a token for a name segment that is not valid
 * UTF-8. No real name contains U+0000, so a token never equals a real name,
 * and the hex after it keeps two different byte strings apart.
 */
const UNMAPPABLE_SEGMENT_PREFIX = "\u0000"

/** Issue #219: a decoded listing field: its text and whether it maps exactly to UTF-8. */
type DecodedField = { mappable: boolean; text: string }

/**
 * Issue #219: decode one name segment strictly as UTF-8.
 *
 * @param bytes - The segment bytes, without `/`.
 * @returns The segment, or a token (see {@link UNMAPPABLE_SEGMENT_PREFIX})
 *   when the bytes are not valid UTF-8.
 */
function decodeSegment(bytes: Buffer): DecodedField {
  try {
    return {
      mappable: true,
      text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes),
    }
  } catch {
    return { mappable: false, text: `${UNMAPPABLE_SEGMENT_PREFIX}${bytes.toString("hex")}` }
  }
}

/**
 * Issue #219: decode the bytes of a hex-encoded field segment by segment, so
 * a segment that is not valid UTF-8 becomes a token and every other segment
 * keeps its exact text.
 *
 * @param bytes - The raw bytes the host reported for one path or target.
 * @returns The decoded text and whether every segment was valid UTF-8.
 */
function decodeFieldBytes(bytes: Buffer): DecodedField {
  const segments: string[] = []
  let mappable = true
  let start = 0
  for (let index = 0; index <= bytes.length; index += 1) {
    if (index < bytes.length && bytes[index] !== SLASH_BYTE) continue
    const segment = decodeSegment(bytes.subarray(start, index))
    mappable &&= segment.mappable
    segments.push(segment.text)
    start = index + 1
  }
  return { mappable, text: segments.join("/") }
}

/**
 * Issue #219: decode one listing field: plain printable ASCII as is, or the
 * hex form after {@link HEX_FIELD_MARKER}.
 *
 * @param field - The raw field.
 * @returns The decoded field, or a string saying why it cannot be trusted.
 */
export function decodeListingField(field: string): DecodedField | string {
  if (!field.startsWith(HEX_FIELD_MARKER)) {
    if (PLAIN_FIELD_PATTERN.test(field)) return { mappable: true, text: field }
    return `probe reported field ${JSON.stringify(field)} with characters outside printable ASCII that were not hex-encoded`
  }
  const hex = field.slice(HEX_FIELD_MARKER.length)
  if (!HEX_DIGITS_PATTERN.test(hex) || hex.length % 2 !== 0) {
    return `probe reported hex field ${JSON.stringify(hex)} that is not well-formed hex`
  }
  return decodeFieldBytes(Buffer.from(hex, "hex"))
}

/**
 * Issue #219: describe a mapped path for a message, spelling each token of a
 * segment that is not valid UTF-8 as `\xNN` escapes.
 *
 * @param path - A path as {@link decodeListingField} maps it.
 * @returns The printable form.
 */
export function listedPathDescription(path: string): string {
  return path
    .split("/")
    .map((segment) =>
      segment.startsWith(UNMAPPABLE_SEGMENT_PREFIX)
        ? segment
            .slice(UNMAPPABLE_SEGMENT_PREFIX.length)
            .replaceAll(/(?<byte>.{2})/gv, "\\x$<byte>")
        : segment
    )
    .join("/")
}

/**
 * Issue #219: an absolute host path below the destination, quoted for a
 * message, with segments that are not valid UTF-8 spelled as `\\xNN` escapes.
 *
 * @param destination - The validated, canonical destination directory.
 * @param key - The destination-relative path as the listing maps it.
 * @returns The JSON-quoted absolute path.
 */
export function quotedHostPath(destination: string, key: string): string {
  const path = `${destination}/${key}`
  return JSON.stringify(listedPathDescription(path))
}

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
  /** Issue #219: collector for unreadable directories, destination-relative. */
  unreadable: Set<string>
}

/**
 * Issue #219: whether a listed path is a normalized, non-empty path relative
 * to the destination: no leading or trailing `/`, no empty, `.` or `..`
 * segment. The containment entries validate their recorded links with it too.
 *
 * @param path - The decoded path.
 * @returns True when the path may be used as a key.
 */
export function isNormalizedRelativePath(path: string): boolean {
  return path.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..")
}

/**
 * Issue #219: why one listed `(link, target)` pair cannot be trusted, if at all.
 *
 * @param state - The host state built so far.
 * @param link - The decoded destination-relative link path.
 * @param target - The decoded stored target.
 * @returns The reason, or null when the pair may be added.
 */
function untrustedLinkPair(state: ListingState, link: string, target: string): null | string {
  if (!isNormalizedRelativePath(link)) {
    return `probe reported symlink ${JSON.stringify(link)}, which is not a normalized path below the destination`
  }
  // Issue #219: Linux cannot store an empty symlink target, so an empty one
  // means `readlink` succeeded without printing the target. The resolver would
  // walk it as the link's parent directory, i.e. as contained, so an unusable
  // `readlink` fails the listing instead.
  if (target === "") {
    return `probe reported an empty target for symlink ${JSON.stringify(link)}; readlink output is unusable`
  }
  // Issue #219: two listed links with the same key would otherwise collapse
  // into one entry, and the model would judge only one of them.
  if (state.links.has(link)) return `probe reported symlink ${JSON.stringify(link)} more than once`
  return null
}

/**
 * Issue #219: add one `l` record to the host state.
 *
 * A path or target that is hex-encoded arrives as bytes and is decoded
 * segment by segment. Every accepted string therefore maps back to exactly
 * the host's bytes: a valid UTF-8 segment is its exact text (a literal U+FFFD
 * in a name included, which strict decoding cannot have produced from other
 * bytes), and a segment that is not valid UTF-8 becomes a token that no real
 * name can produce. A link with such a token is marked `unmappable`.
 *
 * @param state - The host state being built.
 * @param fields - The raw link path and target fields.
 * @returns Null when the link was added, otherwise why the output cannot be trusted.
 */
function addLinkRecord(state: ListingState, fields: readonly [string, string]): null | string {
  const link = decodeListingField(fields[0])
  if (typeof link === "string") return link
  const target = decodeListingField(fields[1])
  if (typeof target === "string") return target
  const untrusted = untrustedLinkPair(state, link.text, target.text)
  if (untrusted !== null) return untrusted
  state.links.set(link.text, {
    stored: target.text,
    target: hostSymlinkWalkTarget(state.destination, target.text),
    ...(link.mappable && target.mappable ? {} : { unmappable: true }),
  })
  return null
}

/**
 * Issue #219: add one `u` record (an unreadable directory) to the host state.
 *
 * @param state - The host state being built.
 * @param field - The raw directory field.
 * @returns Null when the directory was added, otherwise why the output cannot be trusted.
 */
function addUnreadableRecord(state: ListingState, field: string): null | string {
  const directory = decodeListingField(field)
  if (typeof directory === "string") return directory
  if (!isNormalizedRelativePath(directory.text) || state.unreadable.has(directory.text)) {
    return `probe reported unreadable directory ${JSON.stringify(directory.text)}, which is not a normalized path below the destination or was reported more than once`
  }
  state.unreadable.add(directory.text)
  return null
}

/**
 * Issue #219: add one `n` record (a directory hit for a requested member
 * path) to the host state.
 *
 * @param state - The host state being built.
 * @param field - The raw path field.
 * @returns Null when the hit was added, otherwise why the output cannot be trusted.
 */
function addDirectoryRecord(state: ListingState, field: string): null | string {
  const path = decodeListingField(field)
  if (typeof path === "string") return path
  const key = path.mappable ? state.requested.get(path.text) : undefined
  if (key === undefined) {
    return `probe reported directory ${JSON.stringify(path.text)}, which is not a requested member path below the destination`
  }
  state.directories.add(key)
  return null
}

/**
 * Issue #219: how one record kind is read: the number of fields after the
 * kind field, and how those fields are added to the host state.
 */
type RecordReader = {
  add: (state: ListingState, values: readonly string[]) => null | string
  count: number
}

/** Issue #219: the record kinds of the listing, see {@link hostStateFromListing}. */
const RECORD_READERS: ReadonlyMap<string, RecordReader> = new Map([
  ["l", { add: (state, [link, target]) => addLinkRecord(state, [link, target]), count: 2 }],
  ["n", { add: (state, [path]) => addDirectoryRecord(state, path), count: 1 }],
  ["u", { add: (state, [directory]) => addUnreadableRecord(state, directory), count: 1 }],
])

/**
 * Issue #219: add the record that starts at `index`.
 *
 * @param state - The host state being built.
 * @param fields - All decoded probe fields.
 * @param index - The index of the record's kind field.
 * @returns The index of the next record, or why the output cannot be trusted.
 */
function addRecord(state: ListingState, fields: readonly string[], index: number): number | string {
  const kind = fields[index]
  const reader = RECORD_READERS.get(kind)
  if (reader === undefined) return `probe reported unknown record kind ${JSON.stringify(kind)}`
  const end = index + 1 + reader.count
  if (end > fields.length) return `probe output ends inside a ${JSON.stringify(kind)} record`
  return reader.add(state, fields.slice(index + 1, end)) ?? end
}

/**
 * Turn the decoded listing fields into the host state the link model needs,
 * or explain why the output cannot be trusted.
 *
 * Issue #219: the listing is a sequence of records (see
 * `buildSymlinkListingProbeScript`): `l, <link>, <target>`, `u, <directory>`
 * and `n, <path>`. An unknown record kind, a record cut off at the end, a
 * field that is neither plain printable ASCII nor well-formed hex, a link or
 * directory path that is not a normalized relative path, a link or
 * unreadable directory listed twice, and a directory hit for a path that was
 * not requested all make the listing untrusted. The post-merge backstop
 * passes an empty `requested` map, because it sends no `n` entries; any
 * directory hit is then broken framing.
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
  const state: ListingState = {
    destination,
    directories: new Set<string>(),
    links: new Map<string, MergedSymlink>(),
    requested,
    unreadable: new Set<string>(),
  }
  let index = 0
  while (index < fields.length) {
    const next = addRecord(state, fields, index)
    if (typeof next === "string") return next
    index = next
  }
  return { directories: state.directories, links: state.links, unreadable: state.unreadable }
}

/**
 * Issue #219: run the containment listing with its own capture cap and say
 * what a truncated capture means for it.
 *
 * @param conn - The SSH connection.
 * @param entries - The tagged entries, see `encodeSymlinkListingEntry`.
 * @returns The decoded fields, or why the listing failed.
 */
export async function runSymlinkListing(
  conn: SshConnection,
  entries: string[]
): Promise<{ detail: string; kind: "failed" } | { fields: string[]; kind: "ok" }> {
  const outcome = await runBatchedProbe(conn, {
    entries,
    maxOutputBytes: SYMLINK_LISTING_CAPTURE_LIMIT_BYTES,
    script: buildSymlinkListingProbeScript(),
  })
  if (outcome.kind === "ok") return outcome
  if (outcome.truncated !== true) return { detail: outcome.detail, kind: "failed" }
  return {
    detail: `the destination holds too many symlinks to check: the symlink listing exceeded its captured-output cap of ${String(SYMLINK_LISTING_CAPTURE_LIMIT_BYTES)} bytes`,
    kind: "failed",
  }
}

/**
 * Issue #219: describe why one link cannot be shown to stay inside, for the
 * pre-merge refusal and the post-merge report alike.
 *
 * @param destination - The validated, canonical destination directory.
 * @param violation - The violation, other than a name variant or a limit.
 * @returns The reason after the link, without the tense of the caller.
 */
export function unverifiableLinkReason(
  destination: string,
  violation: Extract<MergedSymlinkViolation, { kind: "unmappable" | "unreadable" }>
): string {
  if (violation.kind === "unreadable") {
    return `cannot be checked: directory ${quotedHostPath(destination, violation.directory)} is not readable`
  }
  const through =
    violation.link === violation.key
      ? "its path or target"
      : `the path or target of symlink ${quotedHostPath(destination, violation.link)}, which it resolves through,`
  return `cannot be checked: ${through} is not valid UTF-8; rename or remove that symlink`
}

/**
 * Issue #219: `symlink "<absolute path>" -> "<stored target>"` for messages,
 * with a name that is not valid UTF-8 spelled as `\xNN` escapes.
 *
 * @param destination - The validated, canonical destination directory.
 * @param key - The link's destination-relative path.
 * @param stored - The link's stored target.
 * @returns The link description.
 */
export function symlinkDescription(destination: string, key: string, stored: string): string {
  return `symlink ${quotedHostPath(destination, key)} -> ${JSON.stringify(listedPathDescription(stored))}`
}
