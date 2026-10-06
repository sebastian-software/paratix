import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER, InvalidUtf8OutputError } from "../sshHelpers.js"
import { tarListingScript } from "./archiveTarListing.js"
import {
  type ArchiveListing,
  archiveMemberKindFromMode,
  type ArchiveMemberParseResult,
  parseTarListing,
} from "./archiveTarListingParser.js"

/** Maximum captured bytes for archive listings and persisted member metadata. */
export const ARCHIVE_CAPTURE_LIMIT_BYTES = 16_777_216

/**
 * R-0000067: select the appropriate `tar` listing flag for an archive based
 * on the source extension. The `v` flag is intentionally included so the
 * output also encodes symlink/hardlink targets via the `name -> link`
 * syntax. The match mirrors `extractCommand` in archiveStagingMergeScript.ts.
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
 * Issue #219: a tar archive is listed by {@link tarListingScript}, which runs
 * `tar` under a UTF-8 C locale when the host has one (`LC_ALL=C` otherwise,
 * and always for bsdtar) and prints a listing mode line first, so the listed names do not depend on
 * the locale of the exec session.
 *
 * @param source - The original archive path used for format detection.
 * @param archivePath - The actual archive path on the remote host.
 * @returns The shell command to list members, or null when unsupported.
 */
export function listArchiveMembersCommand(source: string, archivePath: string): null | string {
  const lower = source.toLowerCase()
  const tarFlags = tarListFlags(lower)
  if (tarFlags !== null) {
    return tarListingScript(tarFlags, archivePath)
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

const ZIP_INFO_LINE_PATTERN =
  // eslint-disable-next-line security/detect-unsafe-regex -- Anchored Info-ZIP listing parser with fixed-width mode and bounded column count.
  /^(?<mode>[\-bcdlps][\-rwxStTs]{9})\s+(?:\S+\s+){7}(?<path>\S.*)$/v
const ZIP_INFO_SIZE_LINE_PATTERN = /^Zip file size:\s+\d+\s+bytes,\s+number of entries:\s+\d+$/v
const ZIP_INFO_SUMMARY_LINE_PATTERN =
  /^\d+\s+files?,\s+\d+\s+bytes uncompressed,\s+\d+\s+bytes compressed:\s+[\d.]+%$/v

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
// Issue #219: the guard paths now travel NUL-terminated on stdin
// (`buildStagingMergeExec`), so a newline no longer splits that list. The
// refusal stays: a NUL would now split it the same way, and would still cut a
// path short in a shell argument.
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
 * Issue #219: for GNU tar and bsdtar the tar listing is decoded before this
 * check (`decodeTarListingName`), so an escaped non-ASCII name arrives here
 * as its real characters in any host locale. A `\\` decodes to a real
 * backslash, which is still refused: a listing that is not decoded (another
 * tar, `unzip -Zs`) cannot tell a real backslash from an escape, and one rule
 * for every listing keeps the verdict for an archive independent of the
 * `tar` on the host.
 *
 * @param member - A single parsed archive member.
 * @returns The refusal reason, or null.
 */
function ambiguousNameReason(member: ArchiveMember): null | string {
  const hint =
    "member names with a backslash are refused in every listing, because a listing that Paratix does not decode (a tar other than GNU tar or bsdtar, or unzip) cannot tell a real backslash from an escape sequence, and a U+FFFD may stand for bytes a listing tool replaced"
  if (/[\\\uFFFD]/v.test(member.path)) {
    return `member ${JSON.stringify(member.path)} contains a backslash or a U+FFFD replacement character; ${hint}`
  }
  if (member.linkTarget !== null && /[\\\uFFFD]/v.test(member.linkTarget)) {
    return `member ${JSON.stringify(member.path)} -> ${JSON.stringify(member.linkTarget)} link target contains a backslash or a U+FFFD replacement character; ${hint}`
  }
  return null
}

/**
 * Return why a member path, or a hardlink's target, has a `..` segment.
 *
 * The containment rules compare normalized member paths, but the extracting
 * tool receives the raw names, and how it treats a `..` segment — in
 * particular one after a symlink the same archive creates — depends on the
 * implementation. Refusing such names for tar and zip alike keeps the names
 * the rules judge and the names that are extracted the same. Hardlink targets
 * are relative to the archive root like member paths, so they follow the same
 * rule. Symlink targets keep `..`: it is legitimate there, and the link
 * resolver judges where they lead. `.` segments and a leading `./` stay
 * allowed, as does a segment that merely contains dots, such as `a..b`.
 *
 * @param member - A single parsed archive member.
 * @returns The refusal reason, or null.
 */
function parentSegmentReason(member: ArchiveMember): null | string {
  if (hasParentSegment(member.path)) {
    return `member ${JSON.stringify(member.path)} contains a ".." path segment`
  }
  if (
    member.kind === "hardlink" &&
    member.linkTarget !== null &&
    hasParentSegment(member.linkTarget)
  ) {
    return `member ${JSON.stringify(member.path)} -> ${JSON.stringify(member.linkTarget)} hardlink target contains a ".." path segment`
  }
  return null
}

/**
 * Whether a slash-separated path has a segment that is exactly `..`.
 *
 * @param path - The path as the archive listing spells it.
 * @returns True when any segment is `..`.
 */
function hasParentSegment(path: string): boolean {
  return path.split("/").includes("..")
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
  const nameProblem =
    controlCharacterReason(member) ?? ambiguousNameReason(member) ?? parentSegmentReason(member)
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
  // valid UTF-8 is refused. GNU tar and bsdtar escape every byte of a name
  // that is not valid UTF-8 in the locale the listing script picks for them;
  // another tar may print such bytes raw, which lands here.
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
      failureReason: `archive listing for ${parameters.source} is not valid UTF-8; refusing to validate member names that cannot be mapped to the extracted names reliably (a member name whose bytes are not valid UTF-8 cannot be mapped)`,
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
