import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER, InvalidUtf8OutputError } from "../sshHelpers.js"

/** Maximum captured bytes for archive listings and persisted member metadata. */
export const ARCHIVE_CAPTURE_LIMIT_BYTES = 16_777_216

/**
 * R-0000067: select the appropriate `tar` listing flag for an archive based
 * on the source extension. The `v` flag is intentionally included so the
 * output also encodes symlink/hardlink targets via the `name -> link`
 * syntax. The match mirrors `extractCommand` in archive.ts.
 *
 * @param lowerSource - The archive source path, lower-cased.
 * @returns The `tar` list flags or null when the format is not tar-based.
 */
function tarListFlags(lowerSource: string): null | string {
  if (lowerSource.endsWith(".tar.gz") || lowerSource.endsWith(".tgz")) return "-tvzf"
  if (lowerSource.endsWith(".tar.bz2")) return "-tvjf"
  if (lowerSource.endsWith(".tar.xz")) return "-tvJf"
  if (lowerSource.endsWith(".tar")) return "-tvf"
  return null
}

/**
 * Detect whether the source is a zip archive based on its file extension.
 *
 * @param lowerSource - The archive source path, lower-cased.
 * @returns True if the archive is a zip file.
 */
function isZipSource(lowerSource: string): boolean {
  return lowerSource.endsWith(".zip")
}

/**
 * Build the shell command that lists the archive members for validation.
 *
 * @param source - The original archive path used for format detection.
 * @param archivePath - The actual archive path on the remote host.
 * @returns The shell command to list members, or null when unsupported.
 */
export function listArchiveMembersCommand(source: string, archivePath: string): null | string {
  const lower = source.toLowerCase()
  const tarFlags = tarListFlags(lower)
  if (tarFlags !== null) {
    return `tar ${tarFlags} ${shellQuote(archivePath)}`
  }
  if (isZipSource(lower)) {
    // `unzip -Zs` includes Unix-style mode metadata, which lets us reject
    // symlinks before `unzip -o` can restore them on disk.
    return `unzip -Zs ${shellQuote(archivePath)}`
  }
  return null
}

/** A single archive member extracted from the listing output. */
export type ArchiveMember = {
  /** Original archive format used to derive this entry. */
  format: "tar" | "zip"
  /** Member kind inferred from listing metadata. */
  kind: "directory" | "file" | "hardlink" | "special" | "symlink"
  /** Resolved link target (relative or absolute) for symlinks/hardlinks, or null. */
  linkTarget: null | string
  /**
   * R-0000703: full ten-character symbolic mode string captured from the
   * archive listing (`tar -tv…f` or `unzip -Zs`). The mode is required to
   * detect setuid/setgid bits (`s`/`S` in the user- or group-execute slots)
   * so the archive validator can reject privileged members before `cp -aT`
   * propagates the elevated bits onto the destination.
   */
  mode: string
  /** Member path as recorded in the archive. */
  path: string
}

type ArchiveListing = { failureReason: string } | { members: ArchiveMember[] }
type ArchiveMemberParseResult =
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
 * Blank lines are ignored. Non-empty lines that do not match this shape are
 * rejected so the safety guard fails closed before extraction. Link lines
 * whose remainder contains the link separator (`->` for non-file members,
 * `link to` for hardlinks) more than once are rejected as ambiguous, because
 * the split between member name and link target cannot be recovered. For the
 * same reason a hardlink line whose remainder contains both `->` and
 * `link to` is rejected (Issue #219).
 *
 * @param line - A single line from `tar -tv…f` output.
 * @returns The parsed member, an ignored marker or an invalid-line reason.
 */
const TAR_LINK_ARROW = " -> "
const TAR_HARDLINK_TARGET = " link to "
const TAR_VERBOSE_LINE_PATTERN =
  /^(?<mode>[\-bcdhlps][\-rwxStTs]{9})\s+\S+\s+\S+\s+\S+\s+\S+\s+(?<rest>\S.*)$/v
const ZIP_INFO_LINE_PATTERN =
  // eslint-disable-next-line security/detect-unsafe-regex -- Anchored Info-ZIP listing parser with fixed-width mode and bounded column count.
  /^(?<mode>[\-bcdlps][\-rwxStTs]{9})\s+(?:\S+\s+){7}(?<path>\S.*)$/v
const ZIP_INFO_SIZE_LINE_PATTERN = /^Zip file size:\s+\d+\s+bytes,\s+number of entries:\s+\d+$/v
const ZIP_INFO_SUMMARY_LINE_PATTERN =
  /^\d+\s+files?,\s+\d+\s+bytes uncompressed,\s+\d+\s+bytes compressed:\s+[\d.]+%$/v

function archiveMemberKindFromMode(mode: string): ArchiveMember["kind"] {
  if (mode.startsWith("d")) return "directory"
  if (mode.startsWith("l")) return "symlink"
  if (mode.startsWith("h")) return "hardlink"
  if (!mode.startsWith("-")) return "special"
  return "file"
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
 * Issue #219: a hardlink remainder that contains both `->` and `link to` is
 * ambiguous. GNU tar prints the hardlink `a -> b` to `d/e/c` as
 * `a -> b link to d/e/c`; splitting at `->` first would validate it as `a`
 * pointing at `b link to d/e/c` and so bypass the hardlink rules of
 * `archiveLinkUnsafeReason` (hardlink to a symlink, link through an ancestor
 * symlink) that the kind-aware symlink anchoring relies on. Such lines fail
 * closed instead of guessing which separator is the real one.
 *
 * @param parts - The parsed listing line parts.
 * @param parts.kind - The member kind inferred from the mode.
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

function parseTarVerboseLine(line: string): ArchiveMemberParseResult {
  const trimmed = line.replace(/\r$/v, "")
  if (trimmed.length === 0) return { status: "ignored" }
  // mode owner/group size date time path[ -> link]
  // The trailing capture starts with a non-whitespace character so the
  // greedy `\s+` separators cannot exchange characters with the path
  // capture (avoids polynomial backtracking).
  const match = TAR_VERBOSE_LINE_PATTERN.exec(trimmed) ?? null
  if (!match?.groups) {
    return {
      failureReason: `could not parse tar listing line: ${JSON.stringify(trimmed)}`,
      status: "invalid",
    }
  }
  const mode = match.groups.mode
  const kind = archiveMemberKindFromMode(mode)
  const rest = match.groups.rest
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
 * @param stdout - The combined stdout of `tar -tv…f`.
 * @returns The parsed members, or a failure reason for unparsed member lines.
 */
function parseTarListing(stdout: string): ArchiveListing {
  const members: ArchiveMember[] = []
  for (const line of stdout.split("\n")) {
    const parsed = parseTarVerboseLine(line)
    if (parsed.status === "invalid") return { failureReason: parsed.failureReason }
    if (parsed.status === "parsed") members.push(parsed.member)
  }
  return { members }
}

/**
 * Parse one Info-ZIP `unzip -Zs` listing line into an {@link ArchiveMember}.
 *
 * @param line - A single line from `unzip -Zs`.
 * @returns The parsed member, an ignored marker or an invalid-line reason.
 */
function parseZipInfoLine(line: string): ArchiveMemberParseResult {
  const trimmed = line.replace(/\r$/v, "")
  if (trimmed.length === 0) return { status: "ignored" }
  if (isIgnoredZipInfoLine(trimmed)) return { status: "ignored" }
  const match = ZIP_INFO_LINE_PATTERN.exec(trimmed) ?? null
  if (!match?.groups) {
    return {
      failureReason: `could not parse zip listing line: ${JSON.stringify(trimmed)}`,
      status: "invalid",
    }
  }
  const mode = match.groups.mode
  return {
    member: {
      format: "zip",
      kind: archiveMemberKindFromMode(mode),
      linkTarget: null,
      mode,
      path: match.groups.path,
    },
    status: "parsed",
  }
}

function isIgnoredZipInfoLine(line: string): boolean {
  return (
    line.startsWith("Archive:") ||
    ZIP_INFO_SIZE_LINE_PATTERN.test(line) ||
    ZIP_INFO_SUMMARY_LINE_PATTERN.test(line)
  )
}

/**
 * Parse the listing of a zip archive into {@link ArchiveMember}s.
 *
 * @param stdout - The combined stdout of `unzip -Zs`.
 * @returns The parsed members, or a failure reason for unparsed member lines.
 */
function parseZipListing(stdout: string): ArchiveListing {
  const members: ArchiveMember[] = []
  for (const line of stdout.split("\n")) {
    const parsed = parseZipInfoLine(line)
    if (parsed.status === "invalid") return { failureReason: parsed.failureReason }
    if (parsed.status === "parsed") members.push(parsed.member)
  }
  return { members }
}

// R-0000636: control characters (\x00-\x1F) in archive member paths are
// rejected before any further validation. A literal `\n` in an entry name
// would otherwise split the guard-paths list that
// `moveExtractedContentsIntoDestination` feeds back into the symlink walk
// and let a crafted archive bypass the per-ancestor symlink check. NUL
// would terminate a path early when interpolated into a shell argument.
// Carriage returns and other control bytes serve no legitimate purpose in
// POSIX paths, so we reject them across the board.
/* eslint-disable-next-line regexp/no-control-character -- matching control characters is the explicit purpose of this guard */ /* oxlint-disable-next-line no-control-regex */
const ARCHIVE_MEMBER_CONTROL_CHARACTER_PATTERN = /[\x00-\x1F]/v

/**
 * Normalize a POSIX-style path for traversal validation.
 *
 * Resolves consecutive slashes, drops `.` segments and applies `..`
 * segments without ever escaping above the start. The returned string is
 * the canonical relative form used by {@link memberEscapesDestination}.
 * The destination root itself (`.`, `./`, the empty string) normalizes to
 * the empty string, and a trailing slash is dropped, so `./x`, `x` and `x/`
 * share one form.
 *
 * Issue #219: the normalization is purely lexical and knows nothing about
 * where a path is anchored. Member paths and hardlink targets are relative to
 * the archive root and can be passed in directly. A relative symlink target is
 * relative to the directory that contains the link, so callers join it to
 * {@link archiveMemberParentPath} of the normalized member path first; the
 * lexical result says nothing about symlinks the path passes through, which
 * `archiveLinkValidation.ts` resolves separately.
 *
 * Returns null when the path tries to escape the root via `..` segments at
 * the top level, or when the input contains control characters
 * (`\x00`–`\x1F`) that would let a crafted archive smuggle newlines or NUL
 * bytes through the downstream guard-paths processing.
 *
 * @param input - The raw path string from the archive listing.
 * @returns The normalized relative path, or null on traversal escape.
 */
export function normalizeArchiveMemberPath(input: string): null | string {
  // R-0000636: refuse paths containing control characters before splitting on
  // `/`. Performing the check up front means every downstream user of
  // `normalizeArchiveMemberPath` (path validation, link-target validation)
  // inherits the guard without each call having to remember it.
  if (ARCHIVE_MEMBER_CONTROL_CHARACTER_PATTERN.test(input)) return null
  const segments = input.split("/")
  const stack: string[] = []
  for (const segment of segments) {
    if (segment === "" || segment === ".") continue
    if (segment === "..") {
      if (stack.length === 0) return null
      stack.pop()
      continue
    }
    stack.push(segment)
  }
  return stack.join("/")
}

/**
 * Issue #219: return the parent of a normalized archive path — its POSIX
 * dirname, with the empty string standing for the destination root. A
 * root-level member such as `x` therefore has the parent `""`.
 *
 * @param normalizedPath - A path already normalized by {@link normalizeArchiveMemberPath}.
 * @returns The normalized parent path, `""` for a root-level path.
 */
export function archiveMemberParentPath(normalizedPath: string): string {
  const separator = normalizedPath.lastIndexOf("/")
  return separator === -1 ? "" : normalizedPath.slice(0, separator)
}

/**
 * Decide whether a single archive member would write outside the
 * destination directory. Treats absolute paths and any traversal escape as
 * unsafe and returns true.
 *
 * For symlinks/hardlinks, the link target itself is also validated: an
 * absolute target or a target that escapes the destination via `..` is
 * rejected to mirror typical zip-slip / tar-slip patterns.
 *
 * Issue #219: the target is anchored by member kind. A hardlink target is a
 * member name relative to the archive root, so it is normalized as is. A
 * relative symlink target is read by the kernel from the directory that
 * contains the link, so it is normalized after joining it to the link's
 * parent: `a/bin/x -> ../lib/y` stays inside, `a/x -> ../../y` escapes. This
 * check is lexical and per member; symlink chains through other archive
 * members are resolved by `archiveLinkUnsafeReason` afterwards.
 *
 * @param member - A single parsed archive member.
 * @returns True if the member is unsafe and must be rejected.
 */
export function memberEscapesDestination(member: ArchiveMember): boolean {
  if (member.path.startsWith("/")) return true
  const memberPath = normalizeArchiveMemberPath(member.path)
  if (memberPath === null) return true
  if (member.linkTarget === null) return false
  if (member.linkTarget.startsWith("/")) return true
  const anchor = member.kind === "symlink" ? archiveMemberParentPath(memberPath) : ""
  const anchoredTarget = anchor === "" ? member.linkTarget : `${anchor}/${member.linkTarget}`
  return normalizeArchiveMemberPath(anchoredTarget) === null
}

/**
 * R-0000703: detect whether the symbolic mode string carries the setuid or
 * setgid bit. Position 3 of the ten-character mode string encodes the
 * setuid bit (lowercase `s` when also executable, uppercase `S` when not).
 * Position 6 encodes the setgid bit using the same convention. Both must
 * be rejected before `cp -aT --no-dereference` propagates them onto the
 * destination filesystem; `tar`/`unzip` alone are happy to restore them.
 *
 * @param mode - The ten-character symbolic mode captured from the archive.
 * @returns True when setuid or setgid is set.
 */
function modeHasSetuidOrSetgid(mode: string): boolean {
  return mode[3] === "s" || mode[3] === "S" || mode[6] === "s" || mode[6] === "S"
}

/**
 * Return why a member's path or link target contains control characters.
 *
 * @param member - A single parsed archive member.
 * @returns The refusal reason, or null.
 */
function controlCharacterReason(member: ArchiveMember): null | string {
  // R-0000636: report control-character members with a dedicated reason so
  // the failure surface clearly identifies the cause instead of conflating
  // it with traversal escapes. The check runs before
  // `memberEscapesDestination` so even paths that would otherwise look
  // benign (no leading `/`, no `..`) are still rejected.
  if (ARCHIVE_MEMBER_CONTROL_CHARACTER_PATTERN.test(member.path)) {
    return `member ${JSON.stringify(member.path)} contains control characters`
  }
  if (
    member.linkTarget !== null &&
    ARCHIVE_MEMBER_CONTROL_CHARACTER_PATTERN.test(member.linkTarget)
  ) {
    return `member ${JSON.stringify(member.path)} -> ${JSON.stringify(member.linkTarget)} link target contains control characters`
  }
  return null
}

/**
 * Issue #219: refuse a member whose listed name cannot be mapped reliably to
 * the name that will be extracted.
 *
 * GNU tar prints non-printable bytes — and, outside a UTF-8 locale, every
 * non-ASCII byte — as a `\NNN` escape and a backslash as `\\`, while other tar
 * implementations print names raw. A listed name with a backslash can
 * therefore stand for different bytes on disk, and the paths the containment
 * checks compare could diverge from the names on the host. A U+FFFD
 * replacement character marks the same problem after decoding. Refusing both
 * in the path and in the link target keeps archive names and host names one
 * to one.
 *
 * @param member - A single parsed archive member.
 * @returns The refusal reason, or null.
 */
function ambiguousNameReason(member: ArchiveMember): null | string {
  const hint =
    "the listed name cannot be mapped reliably to the extracted name (a UTF-8 locale on the host avoids escaped non-ASCII names)"
  if (/[\\\uFFFD]/v.test(member.path)) {
    return `member ${JSON.stringify(member.path)} contains a backslash or a U+FFFD replacement character; ${hint}`
  }
  if (member.linkTarget !== null && /[\\\uFFFD]/v.test(member.linkTarget)) {
    return `member ${JSON.stringify(member.path)} -> ${JSON.stringify(member.linkTarget)} link target contains a backslash or a U+FFFD replacement character; ${hint}`
  }
  return null
}

/**
 * Return why an archive member is unsafe, or null when it may be extracted.
 *
 * @param member - A single parsed archive member.
 * @returns A human-readable unsafe reason, or null.
 */
export function archiveMemberUnsafeReason(member: ArchiveMember): null | string {
  if (member.format === "zip" && member.kind === "symlink") {
    return `member ${JSON.stringify(member.path)} is a symlink`
  }
  if (member.kind === "special") {
    return `member ${JSON.stringify(member.path)} is a special file`
  }
  // R-0000703: refuse archives carrying setuid/setgid members. Letting
  // `cp -aT --no-dereference` propagate these bits onto the destination
  // would yield a privileged binary owned by whoever the archive author
  // chose, which is a textbook local privilege-escalation primitive when
  // the archive originates from an untrusted source. Operators who need
  // an explicit setuid binary should chmod it in a follow-up module so
  // the change is visible in the playbook.
  if (modeHasSetuidOrSetgid(member.mode)) {
    return `member ${JSON.stringify(member.path)} has setuid or setgid bit set (mode ${member.mode})`
  }
  const nameProblem = controlCharacterReason(member) ?? ambiguousNameReason(member)
  if (nameProblem !== null) return nameProblem
  if (!memberEscapesDestination(member)) return null
  const detail =
    member.linkTarget === null
      ? `member ${JSON.stringify(member.path)}`
      : `member ${JSON.stringify(member.path)} -> ${JSON.stringify(member.linkTarget)}`
  return `${detail} would escape destination`
}

/**
 * Run the archive listing on the remote host and parse it into
 * {@link ArchiveMember}s for validation.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Listing inputs.
 * @param parameters.archivePath - The remote path to the archive.
 * @param parameters.source - The original source path (for format detection).
 * @returns Either the list of members or a failure reason.
 */
export async function listArchiveMembers(
  conn: SshConnection,
  parameters: { archivePath: string; source: string }
): Promise<ArchiveListing> {
  const command = listArchiveMembersCommand(parameters.source, parameters.archivePath)
  if (command === null) {
    return { failureReason: `unsupported archive format for ${parameters.source}` }
  }
  // Issue #219: the listing is decoded as strict UTF-8, so every member name
  // maps back to exactly the bytes the listing printed; a lossy decode could
  // turn two different names into the same string. A listing that is not
  // valid UTF-8 is refused.
  let result: ExecResult
  try {
    result = await conn.exec(command, {
      ignoreExitCode: true,
      maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
      silent: true,
      strictUtf8Stdout: true,
    })
  } catch (error) {
    if (!(error instanceof InvalidUtf8OutputError)) throw error
    return {
      failureReason: `archive listing for ${parameters.source} is not valid UTF-8; refusing to validate member names that cannot be mapped to the extracted names reliably (a UTF-8 locale on the host avoids this for non-ASCII names)`,
    }
  }
  if (
    result.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    result.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return {
      failureReason: `archive listing for ${parameters.source} was truncated at the captured-output limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes; refusing to validate incomplete member data`,
    }
  }
  if (result.code !== 0) {
    return {
      failureReason: `failed to list members of ${parameters.source}: ${result.stderr.trim()}`,
    }
  }
  const lower = parameters.source.toLowerCase()
  if (isZipSource(lower)) return parseZipListing(result.stdout)
  return parseTarListing(result.stdout)
}
