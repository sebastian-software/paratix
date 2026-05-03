import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

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
  kind: "file" | "hardlink" | "symlink"
  /** Resolved link target (relative or absolute) for symlinks/hardlinks, or null. */
  linkTarget: null | string
  /** Member path as recorded in the archive. */
  path: string
}

/**
 * Parse a `tar -tv…f` listing line into an {@link ArchiveMember}.
 *
 * The expected line shape is:
 *
 *     mode   user/group   size   date   time   name [-> linktarget]
 *
 * Lines that do not match this shape are skipped (e.g. blank lines,
 * locale-specific headers from non-coreutils tar implementations).
 *
 * @param line - A single line from `tar -tv…f` output.
 * @returns The parsed member, or null when the line cannot be parsed.
 */
const TAR_LINK_ARROW = " -> "
const ZIP_INFO_LINE_PATTERN =
  // eslint-disable-next-line security/detect-unsafe-regex -- Anchored Info-ZIP listing parser with fixed-width mode and bounded column count.
  /^(?<mode>[\-bcdlps][\-rwxStTs]{9})\s+(?:\S+\s+){7}(?<path>\S.*)$/v

function archiveMemberKindFromMode(mode: string): ArchiveMember["kind"] {
  if (mode.startsWith("l")) return "symlink"
  if (mode.startsWith("h")) return "hardlink"
  return "file"
}

function parseTarVerboseLine(line: string): ArchiveMember | null {
  const trimmed = line.replace(/\r$/v, "")
  if (trimmed.length === 0) return null
  // mode owner/group size date time path[ -> link]
  // The trailing capture starts with a non-whitespace character so the
  // greedy `\s+` separators cannot exchange characters with the path
  // capture (avoids polynomial backtracking).
  const match = /^(?<mode>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(?<rest>\S.*)$/v.exec(trimmed) ?? null
  if (!match?.groups) return null
  const kind = archiveMemberKindFromMode(match.groups.mode)
  const rest = match.groups.rest
  const arrowIndex = rest.indexOf(TAR_LINK_ARROW)
  if (arrowIndex !== -1 && kind !== "file") {
    return {
      format: "tar",
      kind,
      linkTarget: rest.slice(arrowIndex + TAR_LINK_ARROW.length),
      path: rest.slice(0, arrowIndex),
    }
  }
  return {
    format: "tar",
    kind,
    linkTarget: null,
    path: rest,
  }
}

/**
 * Parse the full listing of a tar archive into {@link ArchiveMember}s.
 *
 * @param stdout - The combined stdout of `tar -tv…f`.
 * @returns The parsed members.
 */
function parseTarListing(stdout: string): ArchiveMember[] {
  const members: ArchiveMember[] = []
  for (const line of stdout.split("\n")) {
    const parsed = parseTarVerboseLine(line)
    if (parsed !== null) members.push(parsed)
  }
  return members
}

/**
 * Parse one Info-ZIP `unzip -Zs` listing line into an {@link ArchiveMember}.
 *
 * @param line - A single line from `unzip -Zs`.
 * @returns The parsed member, or null for headers/unsupported lines.
 */
function parseZipInfoLine(line: string): ArchiveMember | null {
  const trimmed = line.replace(/\r$/v, "")
  if (trimmed.length === 0) return null
  const match = ZIP_INFO_LINE_PATTERN.exec(trimmed) ?? null
  if (!match?.groups) return null
  return {
    format: "zip",
    kind: match.groups.mode.startsWith("l") ? "symlink" : "file",
    linkTarget: null,
    path: match.groups.path,
  }
}

/**
 * Parse the listing of a zip archive into {@link ArchiveMember}s.
 *
 * @param stdout - The combined stdout of `unzip -Zs`.
 * @returns The parsed members.
 */
function parseZipListing(stdout: string): ArchiveMember[] {
  const members: ArchiveMember[] = []
  for (const line of stdout.split("\n")) {
    const parsed = parseZipInfoLine(line)
    if (parsed !== null) members.push(parsed)
  }
  return members
}

/**
 * Normalize a POSIX-style path for traversal validation.
 *
 * Resolves consecutive slashes, drops `.` segments and applies `..`
 * segments without ever escaping above the start. The returned string is
 * the canonical relative form used by {@link memberEscapesDestination}.
 *
 * Returns null when the path tries to escape the root via `..` segments at
 * the top level, in which case the caller must reject the member.
 *
 * @param input - The raw path string from the archive listing.
 * @returns The normalized relative path, or null on traversal escape.
 */
function normalizeRelativePath(input: string): null | string {
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
 * Decide whether a single archive member would write outside the
 * destination directory. Treats absolute paths and any traversal escape as
 * unsafe and returns true.
 *
 * For symlinks/hardlinks, the link target itself is also validated: an
 * absolute target or a target that escapes the destination via `..` is
 * rejected to mirror typical zip-slip / tar-slip patterns.
 *
 * @param member - A single parsed archive member.
 * @returns True if the member is unsafe and must be rejected.
 */
export function memberEscapesDestination(member: ArchiveMember): boolean {
  if (member.path.startsWith("/")) return true
  if (normalizeRelativePath(member.path) === null) return true
  if (member.linkTarget !== null) {
    if (member.linkTarget.startsWith("/")) return true
    if (normalizeRelativePath(member.linkTarget) === null) return true
  }
  return false
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
): Promise<{ failureReason: string } | { members: ArchiveMember[] }> {
  const command = listArchiveMembersCommand(parameters.source, parameters.archivePath)
  if (command === null) {
    return { failureReason: `unsupported archive format for ${parameters.source}` }
  }
  const result = await conn.exec(command, { ignoreExitCode: true, silent: true })
  if (result.code !== 0) {
    return {
      failureReason: `failed to list members of ${parameters.source}: ${result.stderr.trim()}`,
    }
  }
  const lower = parameters.source.toLowerCase()
  if (isZipSource(lower)) return { members: parseZipListing(result.stdout) }
  return { members: parseTarListing(result.stdout) }
}
