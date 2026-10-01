/**
 * The idempotency markers of `archive.extract`: their paths, the containment paths of a
 * destination, the parameter type built from both, and the write and read side of the content,
 * members and owner-paths markers.
 */

import type { ModuleResult, SshConnection } from "../types.js"
import type { ContainmentPaths } from "./archiveContainmentFlag.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import { archiveMemberDestinationPaths } from "./archiveDestinationValidation.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  type ArchiveMember,
  normalizeArchiveMemberPath,
} from "./archiveMemberValidation.js"
import { sha256String } from "./fileHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const ARCHIVE_CAPTURE_EXEC_OPTS = {
  ...EXEC_OPTS,
  maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
} as const
const FLAGS_DIR = "/var/lib/paratix/flags"
const ARCHIVE_MARKER_MODE = "0644"
const MISSING_OWNER_PATHS_MARKER_PATTERN = /no such file or directory/iv

/**
 * Derive the marker file path from the source and destination paths.
 *
 * @param source - The source archive path used as part of the stable key.
 * @param destination - The extraction target path used as part of the stable key.
 * @returns The absolute path to the marker file.
 */
export function markerPath(source: string, destination: string): string {
  const hash = sha256String(`${source}\n${destination}`)
  return `${FLAGS_DIR}/archive-${hash}.sha256`
}

/**
 * Issue #219: derive where the containment state of a destination lives.
 *
 * It is keyed by destination only, unlike the marker: an escaping link is a
 * property of the destination tree, so it must force `check` to report
 * needs-apply for every source that extracts there, including an earlier
 * source whose marker still matches after a rollback. Every apply owns one
 * entry in the entry directory `archive-containment-<sha256>.d`, whose body
 * records the offending links (see `archiveContainmentFlag.ts`); `check` only
 * tests whether any entry, or the single `.failed` flag file of older paratix
 * versions, exists.
 *
 * @param destination - The normalized extraction target path.
 * @returns The flags directory, the entry directory and the old flag file.
 */
export function containmentPathsFor(destination: string): ContainmentPaths {
  const base = `${FLAGS_DIR}/archive-containment-${sha256String(destination)}`
  return { directory: FLAGS_DIR, entryDirectory: `${base}.d`, legacyFlag: `${base}.failed` }
}

function ownerPathsMarkerPath(marker: string): string {
  return `${marker}.owner-paths`
}

function membersMarkerPath(marker: string): string {
  return `${marker}.members`
}

export type ExtractedArchiveMember = {
  kind: "directory" | "file" | "hardlink" | "symlink"
  path: string
}

type MembersMarkerReadResult = "invalid" | ExtractedArchiveMember[] | null

export type ArchiveMarkerPayloads = {
  members: string
  ownerPaths: null | string
}

type OwnerPathsMarkerReadResult =
  { kind: "invalid" } | { kind: "missing" } | { kind: "valid"; paths: string[] }

/**
 * Write the marker file using the SHA256 of the (possibly uploaded) remote archive.
 *
 * The cleanup of an uploaded temp file is intentionally **not** part of this
 * helper — the caller owns the lifecycle of the temp upload via try/finally so
 * the temp file is removed on every code path, including failures.
 *
 * @param conn - The SSH connection.
 * @param remoteSource - The remote archive path.
 * @param options - Marker path.
 * @param options.marker - The marker file path.
 * @returns Null when the marker was written, otherwise a structured failure.
 */
export async function writeMarker(
  conn: SshConnection,
  remoteSource: string,
  options: { marker: string }
): Promise<ModuleResult | null> {
  const sha = await conn.sha256(remoteSource)
  if (sha === null) return failed(`[archive.extract] failed to calculate marker hash`)
  const flagsDirectory = await conn.exec(`mkdir -p ${shellQuote(FLAGS_DIR)}`, EXEC_OPTS)
  if (flagsDirectory.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to create archive marker directory`,
      flagsDirectory
    )
  }
  try {
    await conn.writeFile(options.marker, sha, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive marker ${options.marker}: ${reason}`)
  }
  return null
}

/** Parameters of archive.extract, shared by apply and check. */
export type ArchiveExtractParameters = {
  /** Issue #219: where the destination's containment entries live. */
  containment: ContainmentPaths
  /** The destination directory on the remote host. */
  destination: string
  /** The marker file path. */
  marker: string
  /** Optional owner for extracted archive members. */
  owner: string | undefined
  /** The source archive path. */
  source: string
  /** Whether to upload a local file first. */
  upload: boolean
}

export async function writeOwnerPathsMarker(
  conn: SshConnection,
  parameters: {
    content: null | string
    marker: string
  }
): Promise<ModuleResult | null> {
  if (parameters.content === null) return null
  // R-0000166: persist the member list in *both* upload and non-upload mode.
  // The previous implementation only stored the list when `upload === true`
  // and re-derived it from the live archive (`tar -tvzf <source>`) in the
  // non-upload check. If the source archive was modified or removed between
  // apply and the next check, the re-derived list no longer matched what
  // was extracted, which produced false drift reports — or, worse, hid real
  // owner drift on disk because the per-path stat operated on the wrong
  // file list. Writing the marker on every successful apply ties the owner
  // re-check to the same paths the extract actually touched.
  const marker = ownerPathsMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, parameters.content, {
      mode: ARCHIVE_MARKER_MODE,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive owner marker ${marker}: ${reason}`)
  }
  return null
}

function extractedArchiveMembers(
  destination: string,
  members: ArchiveMember[]
): ExtractedArchiveMember[] {
  const extractedMembers = new Map<string, ExtractedArchiveMember>()
  for (const member of members) {
    const memberPath = normalizeArchiveMemberPath(member.path)
    if (memberPath === null) continue
    const path = memberPath === "" ? destination : `${destination}/${memberPath}`
    if (member.kind === "special") continue
    extractedMembers.set(path, { kind: member.kind, path })
  }
  return [...extractedMembers.values()]
}

export function serializeArchiveMarkerPayloads(parameters: {
  destination: string
  members: ArchiveMember[]
  owner?: string
  source: string
}): ArchiveMarkerPayloads | ModuleResult {
  const members = JSON.stringify(
    extractedArchiveMembers(parameters.destination, parameters.members)
  )
  const membersBytes = Buffer.byteLength(members, "utf8")
  if (membersBytes > ARCHIVE_CAPTURE_LIMIT_BYTES) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: archive members marker payload is ${String(membersBytes)} bytes and exceeds the limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`
    )
  }

  if (parameters.owner == null || parameters.owner === "") {
    return { members, ownerPaths: null }
  }
  const ownerPaths = JSON.stringify(
    archiveMemberDestinationPaths(parameters.destination, parameters.members)
  )
  const ownerPathsBytes = Buffer.byteLength(ownerPaths, "utf8")
  if (ownerPathsBytes > ARCHIVE_CAPTURE_LIMIT_BYTES) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: archive owner-paths marker payload is ${String(ownerPathsBytes)} bytes and exceeds the limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`
    )
  }
  return { members, ownerPaths }
}

export async function writeMembersMarker(
  conn: SshConnection,
  parameters: { content: string; marker: string }
): Promise<ModuleResult | null> {
  const marker = membersMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, parameters.content, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive members marker ${marker}: ${reason}`)
  }
  return null
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
}

function isExtractedArchiveMember(value: unknown): value is ExtractedArchiveMember {
  if (typeof value !== "object" || value === null) return false
  const member = value as { kind?: unknown; path?: unknown }
  return (
    typeof member.path === "string" &&
    (member.kind === "directory" ||
      member.kind === "file" ||
      member.kind === "hardlink" ||
      member.kind === "symlink")
  )
}

export async function readMembersMarker(
  conn: SshConnection,
  marker: string
): Promise<MembersMarkerReadResult> {
  const markerResult = await conn.exec(
    `cat ${shellQuote(membersMarkerPath(marker))}`,
    ARCHIVE_CAPTURE_EXEC_OPTS
  )
  if (markerResult.code !== 0) return null
  if (
    markerResult.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    markerResult.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return "invalid"
  }
  try {
    const members: unknown = JSON.parse(markerResult.stdout)
    return Array.isArray(members) && members.every((member) => isExtractedArchiveMember(member))
      ? members
      : "invalid"
  } catch {
    return "invalid"
  }
}

export async function readOwnerPathsMarker(
  conn: SshConnection,
  marker: string
): Promise<OwnerPathsMarkerReadResult> {
  const markerResult = await conn.exec(`cat ${shellQuote(ownerPathsMarkerPath(marker))}`, {
    ...ARCHIVE_CAPTURE_EXEC_OPTS,
    env: { LC_ALL: "C" },
  })
  if (markerResult.code !== 0) {
    // R-0000276: previously a non-"no such file" stderr (e.g. permission
    // denied after a flag-dir mode drift, or a transient truncate race) raised
    // an exception that propagated past archiveOwnerMatches and aborted the
    // whole run. Such failures remain recoverable drift, but only a genuine
    // missing-file diagnostic may use the legacy live-archive fallback.
    return MISSING_OWNER_PATHS_MARKER_PATTERN.test(markerResult.stderr)
      ? { kind: "missing" }
      : { kind: "invalid" }
  }
  if (
    markerResult.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    markerResult.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return { kind: "invalid" }
  }
  try {
    const paths: unknown = JSON.parse(markerResult.stdout)
    return isStringArray(paths) ? { kind: "valid", paths } : { kind: "invalid" }
  } catch {
    return { kind: "invalid" }
  }
}
