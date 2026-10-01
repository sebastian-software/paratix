/**
 * Parser for the `tar -tv…f` listing that the member validation of
 * `archive.extract` reads.
 *
 * Issue #219: split out of `archiveMemberValidation.ts` when the listing
 * gained its mode line (see `archiveTarListing.ts`): the mode line selects
 * the GNU tar or bsdtar line layout and whether member names are decoded
 * from the escapes of GNU tar and bsdtar.
 */
import type { ArchiveMember } from "./archiveMemberValidation.js"

import {
  decodeTarListingName,
  splitTarListingModeLine,
  tarListingDecodesNames,
  type TarListingFlavor,
  type TarListingMode,
} from "./archiveTarListing.js"

/** The parsed members of an archive listing, or why the listing is refused. */
export type ArchiveListing = { failureReason: string } | { members: ArchiveMember[] }

/** The result of parsing one archive listing line. */
export type ArchiveMemberParseResult =
  | { failureReason: string; status: "invalid" }
  | { member: ArchiveMember; status: "parsed" }
  | { status: "ignored" }

/**
 * Parse a `tar -tv…f` listing line into an {@link ArchiveMember}.
 *
 * The expected line shape is:
 *
 *     mode   user/group   size   date   time   name [-> linktarget]
 *     mode   user/group   size   date   time   name link to linktarget
 *
 * Issue #219: bsdtar prints `ls -l` columns instead
 * (`mode links user group size month day time-or-year name …`); the
 * listing mode line tells the two layouts apart.
 *
 * Blank lines are ignored. Non-empty lines that do not match this shape are
 * rejected so the safety guard fails closed before extraction. Link lines
 * whose remainder contains the link separator (`->` for non-file members,
 * `link to` or `->` for hardlinks) more than once are rejected as ambiguous,
 * because the split between member name and link target cannot be recovered.
 * For the same reason a hardlink line whose remainder contains both `->` and
 * `link to` is rejected (Issue #219).
 *
 * Issue #219: which lines are hardlinks depends on the listing flavor (see
 * {@link tarListingMemberKind}): GNU tar marks every hardlink `h`, bsdtar
 * prints `link to` for every hardlink whatever its mode character, and
 * BusyBox tar lists hardlinks as regular files `name -> target`.
 *
 * @param line - A single line from `tar -tv…f` output.
 * @returns The parsed member, an ignored marker or an invalid-line reason.
 */
const TAR_LINK_ARROW = " -> "
const TAR_HARDLINK_TARGET = " link to "
const TAR_VERBOSE_LINE_PATTERN =
  /^(?<mode>[\-bcdhlps][\-rwxStTs]{9})\s+\S+\s+\S+\s+\S+\s+\S+\s+(?<rest>\S.*)$/v
/**
 * Issue #219: the bsdtar `-tv` layout: mode, link count, user, group, size,
 * month, day, then time or year. The listing runs in a C locale, so the month
 * is a single English abbreviation.
 */
const TAR_BSD_VERBOSE_LINE_PATTERN =
  /^(?<mode>[\-bcdhlps][\-rwxStTs]{9})\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?<rest>\S.*)$/v

/**
 * Infer the member kind from the first character of a symbolic mode string.
 *
 * @param mode - The ten-character symbolic mode string.
 * @returns Directory, symlink, hardlink, special file or regular file.
 */
export function archiveMemberKindFromMode(mode: string): ArchiveMember["kind"] {
  if (mode.startsWith("d")) return "directory"
  if (mode.startsWith("l")) return "symlink"
  if (mode.startsWith("h")) return "hardlink"
  if (!mode.startsWith("-")) return "special"
  return "file"
}

/**
 * Issue #219: the member kind of a listing line, from its mode character and,
 * where the listing flavor requires it, from its link separator.
 *
 * - `gnu`: the mode character alone; GNU tar derives it from the typeflag,
 *   lists every hardlink `h` and prints `link to` only for hardlinks.
 * - `bsd`: bsdtar prints `link to TARGET` for every hardlink but takes the
 *   mode character from the type bits of the mode field (none: `h`, S_IFREG:
 *   `-`, S_IFLNK: `l`, S_IFDIR: `d`). A remainder containing `link to` is
 *   therefore a hardlink whatever that character. A regular file or directory
 *   whose name contains `link to` lists exactly like such a hardlink, so it is
 *   read as that hardlink: the stricter reading, because the name before the
 *   separator must then pass every member-path rule and the rest every
 *   hardlink-target rule (archive-root-relative, not an archive symlink, not
 *   through one). Lines whose split is not unique fail closed in
 *   {@link parseTarLinkRemainder}. Special files stay special, so a device
 *   named with `link to` is still refused as a special file.
 * - `other`: BusyBox tar lists a hardlink as a regular file `name -> target`,
 *   so a `-` line containing `->` or `link to` is a hardlink.
 *
 * @param mode - The ten-character symbolic mode string.
 * @param rest - The listing remainder after the date/time columns.
 * @param flavor - The `tar` implementation reported by the mode line.
 * @returns The member kind the line is validated as.
 */
function tarListingMemberKind(
  mode: string,
  rest: string,
  flavor: TarListingFlavor
): ArchiveMember["kind"] {
  const kind = archiveMemberKindFromMode(mode)
  if (flavor === "bsd" && kind !== "special" && rest.includes(TAR_HARDLINK_TARGET)) {
    return "hardlink"
  }
  const hasSeparator = rest.includes(TAR_LINK_ARROW) || rest.includes(TAR_HARDLINK_TARGET)
  if (flavor === "other" && kind === "file" && hasSeparator) return "hardlink"
  return kind
}

/**
 * Issue #219: `tar -tv` prints `name -> target` (and `name link to target`)
 * without escaping, so a member name or link target that itself contains the
 * separator makes the split ambiguous. Splitting at the first occurrence lets
 * a symlink named `d/a -> b` with target `../../../x` be validated as `d/a`
 * pointing at `b -> ../../../x`, which stays inside the destination although
 * the extracted link escapes it. Such lines therefore fail closed.
 *
 * @param line - The trimmed listing line, quoted in the failure reason.
 * @param detail - Why the split is ambiguous, shown in parentheses.
 * @returns The invalid-line result for the ambiguous listing line.
 */
function ambiguousTarLinkLine(line: string, detail: string): ArchiveMemberParseResult {
  return {
    failureReason: `ambiguous tar listing line (${detail}): ${JSON.stringify(line)}`,
    status: "invalid",
  }
}

/**
 * Split a tar link listing remainder into member path and link target at the
 * given separator.
 *
 * @param parts - The parsed listing line parts.
 * @param parts.kind - The member kind inferred from the mode.
 * @param parts.line - The trimmed listing line, quoted in failure reasons.
 * @param parts.mode - The ten-character symbolic mode string.
 * @param parts.rest - The listing remainder after the date/time columns.
 * @param separator - The link separator (`->` or `link to`, space-padded).
 * @returns The parsed link member, an ambiguous-line failure, or null when
 *   the separator does not occur.
 */
function parseTarLinkMember(
  parts: { kind: ArchiveMember["kind"]; line: string; mode: string; rest: string },
  separator: string
): ArchiveMemberParseResult | null {
  const { kind, line, mode, rest } = parts
  const separatorIndex = rest.indexOf(separator)
  if (separatorIndex === -1) return null
  // Issue #219: see ambiguousTarLinkLine — never guess the name/target split.
  if (rest.includes(separator, separatorIndex + separator.length)) {
    return ambiguousTarLinkLine(
      line,
      `link separator ${JSON.stringify(separator)} occurs more than once`
    )
  }
  return {
    member: {
      format: "tar",
      kind,
      linkTarget: rest.slice(separatorIndex + separator.length),
      mode,
      path: rest.slice(0, separatorIndex),
    },
    status: "parsed",
  }
}

/**
 * Split the listing remainder of a link member according to its kind:
 * symlinks and other non-file members at `->`, hardlinks at `->` or
 * `link to`. Plain files never carry a link target.
 *
 * Issue #219: `kind` is the flavor-aware kind of
 * {@link tarListingMemberKind}, so a bsdtar `link to` line with a `-`, `l` or
 * `d` mode character and a BusyBox `-` line with `->` or `link to` arrive
 * here as hardlinks and meet the hardlink ambiguity rules below.
 *
 * Issue #219: a hardlink remainder that contains both `->` and `link to` is
 * ambiguous. GNU tar prints the hardlink `a -> b` to `d/e/c` as
 * `a -> b link to d/e/c`; splitting at `->` first would validate it as `a`
 * pointing at `b link to d/e/c` and so bypass the hardlink rules of
 * `archiveLinkUnsafeReason` (hardlink to a symlink, link through an ancestor
 * symlink) that the kind-aware symlink anchoring relies on. Such lines fail
 * closed instead of guessing which separator is the real one.
 *
 * @param parts - The parsed listing line parts.
 * @param parts.kind - The member kind from {@link tarListingMemberKind}.
 * @param parts.line - The trimmed listing line, quoted in failure reasons.
 * @param parts.mode - The ten-character symbolic mode string.
 * @param parts.rest - The listing remainder after the date/time columns.
 * @returns The parsed link member, an ambiguous-line failure, or null when
 *   the remainder carries no link target.
 */
function parseTarLinkRemainder(parts: {
  kind: ArchiveMember["kind"]
  line: string
  mode: string
  rest: string
}): ArchiveMemberParseResult | null {
  const { kind, line, rest } = parts
  if (kind === "file") return null
  if (kind !== "hardlink") return parseTarLinkMember(parts, TAR_LINK_ARROW)
  if (rest.includes(TAR_LINK_ARROW) && rest.includes(TAR_HARDLINK_TARGET)) {
    return ambiguousTarLinkLine(
      line,
      `hardlink contains both ${JSON.stringify(TAR_LINK_ARROW)} and ${JSON.stringify(TAR_HARDLINK_TARGET)}`
    )
  }
  return parseTarLinkMember(parts, TAR_LINK_ARROW) ?? parseTarLinkMember(parts, TAR_HARDLINK_TARGET)
}

/**
 * Issue #219: refuse a listed name that cannot be decoded back to the name
 * stored in the archive.
 *
 * @param listed - The name or link target as listed.
 * @param detail - Why it cannot be decoded.
 * @returns The invalid-line result.
 */
function unmappableTarName(listed: string, detail: string): ArchiveMemberParseResult {
  return {
    failureReason: `member name ${JSON.stringify(listed)} in the tar listing cannot be mapped to the extracted name (${detail})`,
    status: "invalid",
  }
}

/**
 * Issue #219: decode the path and link target of a parsed member from the
 * escapes of GNU tar or bsdtar (see `decodeTarListingName`). The split at
 * `->` / `link to` happens before, on the listed text, because both
 * implementations print these separators and the spaces around them raw.
 *
 * @param parsed - The member parsed from the listed line.
 * @returns The member with decoded names, or why a name cannot be mapped.
 */
function decodeTarMemberNames(parsed: ArchiveMemberParseResult): ArchiveMemberParseResult {
  if (parsed.status !== "parsed") return parsed
  const { member } = parsed
  const path = decodeTarListingName(member.path)
  if ("failureReason" in path) return unmappableTarName(member.path, path.failureReason)
  if (member.linkTarget === null) {
    return { member: { ...member, path: path.name }, status: "parsed" }
  }
  const target = decodeTarListingName(member.linkTarget)
  if ("failureReason" in target) return unmappableTarName(member.linkTarget, target.failureReason)
  return { member: { ...member, linkTarget: target.name, path: path.name }, status: "parsed" }
}

/**
 * Issue #219: parse one tar listing line and, for GNU tar and bsdtar, decode
 * its names.
 *
 * @param line - A single line of the tar listing.
 * @param listingMode - The listing mode from the mode line.
 * @returns The parsed member, an ignored marker or an invalid-line reason.
 */
function parseTarVerboseLine(line: string, listingMode: TarListingMode): ArchiveMemberParseResult {
  const parsed = parseListedTarVerboseLine(line, listingMode)
  return tarListingDecodesNames(listingMode) ? decodeTarMemberNames(parsed) : parsed
}

/**
 * Parse one tar listing line with the names as listed.
 *
 * @param line - A single line of the tar listing.
 * @param listingMode - The listing mode; it selects the GNU or bsdtar layout.
 * @returns The parsed member, an ignored marker or an invalid-line reason.
 */
function parseListedTarVerboseLine(
  line: string,
  listingMode: TarListingMode
): ArchiveMemberParseResult {
  const trimmed = line.replace(/\r$/v, "")
  if (trimmed.length === 0) return { status: "ignored" }
  // mode owner/group size date time path[ -> link]
  // The trailing capture starts with a non-whitespace character so the
  // greedy `\s+` separators cannot exchange characters with the path
  // capture (avoids polynomial backtracking).
  const pattern =
    listingMode.flavor === "bsd" ? TAR_BSD_VERBOSE_LINE_PATTERN : TAR_VERBOSE_LINE_PATTERN
  const match = pattern.exec(trimmed) ?? null
  if (!match?.groups) {
    return {
      failureReason: `could not parse tar listing line: ${JSON.stringify(trimmed)}`,
      status: "invalid",
    }
  }
  const mode = match.groups.mode
  const rest = match.groups.rest
  const kind = tarListingMemberKind(mode, rest, listingMode.flavor)
  const linkMember = parseTarLinkRemainder({ kind, line: trimmed, mode, rest })
  if (linkMember !== null) return linkMember
  return {
    member: {
      format: "tar",
      kind,
      linkTarget: null,
      mode,
      path: rest,
    },
    status: "parsed",
  }
}

/**
 * Parse the full listing of a tar archive into {@link ArchiveMember}s.
 *
 * Issue #219: the listing starts with the mode line of `tarListingScript`;
 * it selects the line layout and whether names are decoded. Output without
 * it is refused.
 *
 * @param stdout - The stdout of the tar listing script.
 * @returns The parsed members, or a failure reason for unparsed member lines.
 */
export function parseTarListing(stdout: string): ArchiveListing {
  const split = splitTarListingModeLine(stdout)
  if ("failureReason" in split) return split
  const members: ArchiveMember[] = []
  for (const line of split.body.split("\n")) {
    const parsed = parseTarVerboseLine(line, split.mode)
    if (parsed.status === "invalid") return { failureReason: parsed.failureReason }
    if (parsed.status === "parsed") members.push(parsed.member)
  }
  return { members }
}
