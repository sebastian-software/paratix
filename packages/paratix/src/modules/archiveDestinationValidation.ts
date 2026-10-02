import { posix as pathPosix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { archiveSymlinkTargetPrefixes } from "./archiveLinkValidation.js"
import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"
import {
  buildPreStagingProbeScript,
  buildSymlinkProbeScript,
  encodePreStagingEntry,
  type PreStagingCheck,
  runBatchedProbe,
} from "./archiveProbe.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000672: control characters (\x00-\x1F) in extract destinations are
// rejected before any further validation. `moveExtractedContentsIntoDestination`
// transported the guard-paths list as a newline-separated string, so a literal
// `\n` in the destination would have split that list and let a crafted invocation
// bypass the symlink probes that protect ancestor paths. NUL would terminate
// the path early when interpolated into a shell argument. Reject the full
// control-character range up front, mirroring `archiveMemberValidation.ts`.
// Issue #219: the guard paths now travel NUL-terminated on stdin into a host
// temp file (`buildStagingMergeExec`), so a newline no longer splits that
// list. The refusal stays: a NUL would now split it the same way, and the
// destination is still interpolated into shell arguments, where a NUL would
// cut it short.
/* eslint-disable-next-line regexp/no-control-character -- matching control characters is the explicit purpose of this guard */ /* oxlint-disable-next-line no-control-regex */
const EXTRACT_DESTINATION_CONTROL_CHARACTER_PATTERN = /[\x00-\x1F]/v

export function validateExtractDestination(
  destination: string
): { destination: string } | ModuleResult {
  if (EXTRACT_DESTINATION_CONTROL_CHARACTER_PATTERN.test(destination)) {
    return failed(
      `[archive.extract] destination must not contain control characters: ${JSON.stringify(destination)}`
    )
  }
  if (!destination.startsWith("/")) {
    return failed(`[archive.extract] destination must be an absolute path: ${destination}`)
  }
  const normalized = pathPosix.normalize(destination)
  if (normalized === "/") {
    return failed(`[archive.extract] refusing to extract to destructive destination /`)
  }
  return { destination: normalized }
}

function pathWithAncestors(path: string): string[] {
  const paths: string[] = []
  let current = pathPosix.normalize(path)
  while (current !== "/") {
    paths.push(current)
    current = pathPosix.dirname(current)
  }
  return paths.reverse()
}

// Issue #180: `pathIsSymlink` used to be one exec per path. The probe is now
// batched through `archiveProbe.ts`; see `validateNoSymlinkPaths`.

export function destinationPathWithAncestors(destination: string): string[] {
  return pathWithAncestors(destination)
}

function renderGuardedCreateDirectoryCommand(destination: string): string {
  const quotedDestination = shellQuote(destination)
  return [
    `if [ -L ${quotedDestination} ]; then`,
    `  printf '%s\\n' 'destination path is a symlink' >&2`,
    `  exit 1`,
    `fi`,
    `if [ -e ${quotedDestination} ] && [ ! -d ${quotedDestination} ]; then`,
    `  printf '%s\\n' 'destination path exists and is not a directory' >&2`,
    `  exit 1`,
    `fi`,
    `if [ ! -d ${quotedDestination} ]; then`,
    `  mkdir -- ${quotedDestination}`,
    `fi`,
  ].join("\n")
}

export async function createExtractDestinationDirectory(
  conn: SshConnection,
  destination: string
): Promise<ModuleResult | null> {
  for (const directory of destinationPathWithAncestors(destination)) {
    // eslint-disable-next-line no-await-in-loop -- parent directories must be created before children
    const result = await conn.exec(renderGuardedCreateDirectoryCommand(directory), EXEC_OPTS)
    if (result.code !== 0) {
      return failedCommand(
        `[archive.extract] failed to create destination directory ${destination}`,
        result
      )
    }
  }
  return null
}

function memberDestinationPath(destination: string, member: ArchiveMember): null | string {
  const memberPath = normalizeArchiveMemberPath(member.path)
  if (memberPath === null) return null
  if (memberPath === "") return destination
  return `${destination}/${memberPath}`
}

export function archiveMemberDestinationPaths(
  destination: string,
  members: ArchiveMember[]
): string[] {
  const paths = new Set<string>()
  for (const member of members) {
    const destinationPath = memberDestinationPath(destination, member)
    if (destinationPath !== null) paths.add(destinationPath)
  }
  return [...paths]
}

/**
 * Issue #219: list the destination paths that must not be symlinks while an
 * archive is extracted — every member path with all of its ancestors, except
 * the leaf path of an archive symlink member.
 *
 * The leaf used to be included, so an archive that ships symlinks tripped its
 * own guard: during the merge as soon as an earlier top-level entry had copied
 * the link, and on every later run because the link from the previous run was
 * still there. The merge replaces such a leaf with `cp --remove-destination`
 * and never writes through it. Ancestors of symlink members stay guarded, and
 * `archiveLinkUnsafeReason` rejects any member below an archive symlink, so no
 * guarded path can be reached through an omitted leaf.
 *
 * @param destination - The validated destination directory.
 * @param members - The validated archive members.
 * @returns The guarded absolute paths, including the destination and its ancestors.
 */
export function archiveMemberGuardPaths(destination: string, members: ArchiveMember[]): string[] {
  const paths = new Set<string>()
  for (const member of members) {
    const destinationPath = memberDestinationPath(destination, member)
    if (destinationPath === null) continue
    const chain = pathWithAncestors(destinationPath)
    const guarded = member.kind === "symlink" ? chain.slice(0, -1) : chain
    for (const path of guarded) paths.add(path)
  }
  return [...paths]
}

/**
 * Issue #219: map the non-member paths visited while resolving the archive's
 * symlink targets to absolute destination paths, each with the raw path of the
 * symlink member that visited it, for {@link preStagingProbeEntries}.
 *
 * @param destination - The validated destination directory.
 * @param members - The validated archive members.
 * @returns Absolute host path to the raw path of the symlink member.
 */
export function archiveSymlinkTargetProbePaths(
  destination: string,
  members: ArchiveMember[]
): Map<string, string> {
  const paths = new Map<string, string>()
  for (const prefix of archiveSymlinkTargetPrefixes(members)) {
    paths.set(`${destination}/${prefix.path}`, prefix.symlink)
  }
  return paths
}

function symlinkProbeViolation(
  unsafe: string,
  parameters: { linkTargets?: ReadonlyMap<string, string>; paths: string[] }
): string {
  const symlinkMember = parameters.paths.includes(unsafe)
    ? undefined
    : parameters.linkTargets?.get(unsafe)
  if (symlinkMember === undefined) return `destination path ${JSON.stringify(unsafe)} is a symlink`
  return `link target of member ${JSON.stringify(symlinkMember)} passes through existing host symlink ${JSON.stringify(unsafe)}`
}

/**
 * Refuse the extraction when any of the given host paths is a symlink, with
 * one batched probe.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.paths - Absolute destination paths that must not be symlinks.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when a probed path is a symlink or the probe failed, otherwise null.
 */
export async function validateNoSymlinkPaths(
  conn: SshConnection,
  parameters: { paths: string[]; source: string }
): Promise<ModuleResult | null> {
  const paths = [...new Set(parameters.paths)]
  const outcome = await runBatchedProbe(conn, {
    entries: paths,
    script: buildSymlinkProbeScript(),
  })
  // A probe that could not run is not a clean result. Reporting it as a failure
  // keeps the guard fail-closed; treating the empty output of a crashed script
  // as "no symlinks" would silently disable it.
  if (outcome.kind === "failed") {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: symlink probe failed: ${outcome.detail}`
    )
  }
  if (outcome.fields.length === 0) return null
  const [unsafe] = outcome.fields
  return failed(
    `[archive.extract] refusing to extract ${parameters.source}: ${symlinkProbeViolation(unsafe, { paths })}`
  )
}

/** Issue #219: how a member kind reads in a refusal message. */
export const ARCHIVE_MEMBER_KIND_LABELS: Readonly<Record<ArchiveMember["kind"], string>> = {
  directory: "directory",
  file: "regular file",
  hardlink: "hardlink",
  special: "special file",
  symlink: "symlink",
}

/**
 * Issue #219: the destination paths of the archive's non-directory members
 * below the destination, each with its normalized destination-relative key.
 *
 * @param destination - The validated, canonical destination directory.
 * @param members - The validated archive members.
 * @returns Absolute host path mapped to the member key, in listing order.
 */
export function nonDirectoryMemberPaths(
  destination: string,
  members: readonly ArchiveMember[]
): Map<string, string> {
  const paths = new Map<string, string>()
  for (const member of members) {
    if (member.kind === "directory" || member.kind === "special") continue
    const key = normalizeArchiveMemberPath(member.path)
    if (key !== null && key !== "") paths.set(`${destination}/${key}`, key)
  }
  return paths
}

/**
 * Issue #219: the `n` and `d` entries of the pre-staging probe for one member.
 *
 * @param destination - The validated destination directory.
 * @param member - One validated archive member.
 * @returns `[check, path, reason]` triples, the member's own path first.
 */
function memberTypeConflictChecks(
  destination: string,
  member: ArchiveMember
): Array<[PreStagingCheck, string, string]> {
  const path = memberDestinationPath(destination, member)
  if (path === null || member.kind === "special") return []
  const name = JSON.stringify(member.path)
  const checks: Array<[PreStagingCheck, string, string]> = []
  if (member.kind !== "directory") {
    checks.push([
      "n",
      path,
      `archive member ${name} is a ${ARCHIVE_MEMBER_KIND_LABELS[member.kind]} but destination path ${JSON.stringify(path)} is an existing directory`,
    ])
  } else if (path !== destination) {
    checks.push([
      "d",
      path,
      `archive member ${name} is a directory but destination path ${JSON.stringify(path)} exists and is not a directory`,
    ])
  }
  // Every proper ancestor below the destination has to become a directory,
  // whether or not the archive lists it; `cp -aT` cannot merge a directory
  // over a file there either.
  let ancestor = pathPosix.dirname(path)
  while (ancestor.startsWith(`${destination}/`)) {
    checks.push([
      "d",
      ancestor,
      `archive member ${name} needs destination path ${JSON.stringify(ancestor)} as a directory, but it exists and is not a directory`,
    ])
    ancestor = pathPosix.dirname(ancestor)
  }
  return checks
}

/**
 * Issue #219: build the entries of the pre-staging probe (see
 * {@link buildPreStagingProbeScript}) together with the refusal reason each
 * entry stands for.
 *
 * The `l` entries are the guard paths ({@link archiveMemberGuardPaths}) and the
 * paths the archive's link targets pass through
 * ({@link archiveSymlinkTargetProbePaths}), in that order, with the messages
 * of {@link symlinkProbeViolation}. The `n` entries are the paths of
 * non-directory members, the `d` entries the paths of directory members and
 * of every implicit ancestor directory below the destination. Symlink entries
 * come first, so a path that is a symlink keeps its symlink refusal.
 *
 * @param destination - The validated destination directory.
 * @param members - The validated archive members, in listing order.
 * @returns Encoded probe entry (see {@link encodePreStagingEntry}) mapped to
 *   the refusal reason, in probe order.
 */
export function preStagingProbeEntries(
  destination: string,
  members: ArchiveMember[]
): Map<string, string> {
  const paths = archiveMemberGuardPaths(destination, members)
  const linkTargets = archiveSymlinkTargetProbePaths(destination, members)
  const entries = new Map<string, string>()
  for (const path of new Set([...paths, ...linkTargets.keys()])) {
    entries.set(
      encodePreStagingEntry("l", path),
      symlinkProbeViolation(path, { linkTargets, paths })
    )
  }
  for (const member of members) {
    for (const [check, path, reason] of memberTypeConflictChecks(destination, member)) {
      const entry = encodePreStagingEntry(check, path)
      if (!entries.has(entry)) entries.set(entry, reason)
    }
  }
  return entries
}

/**
 * Issue #219: refuse the extraction before anything is staged when a guarded
 * path is a symlink or a member path has a host type the staging merge cannot
 * merge over, with one batched probe.
 *
 * This is the pre-staging probe of `archive.extract`: the symlink checks of
 * {@link validateNoSymlinkPaths} on the guard paths, the link-target paths with
 * their own message (see {@link symlinkProbeViolation}), plus the
 * type checks of {@link preStagingProbeEntries}, so a non-directory member
 * over an existing directory, or a directory over an existing file, is
 * refused before `cp -aT` would fail half-way through the merge. The probe
 * costs one `exec` regardless of member count. A probe failure, output that
 * is not made of `(check, path)` pairs and a record that matches no sent entry
 * all fail closed.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.destination - The validated destination directory.
 * @param parameters.members - The validated archive members.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure naming the first violation or the probe failure, otherwise null.
 */
export async function validatePreStagingPaths(
  conn: SshConnection,
  parameters: { destination: string; members: ArchiveMember[]; source: string }
): Promise<ModuleResult | null> {
  const entries = preStagingProbeEntries(parameters.destination, parameters.members)
  const outcome = await runBatchedProbe(conn, {
    entries: [...entries.keys()],
    script: buildPreStagingProbeScript(),
  })
  const prefix = `[archive.extract] refusing to extract ${parameters.source}`
  if (outcome.kind === "failed") {
    return failed(`${prefix}: destination path probe failed: ${outcome.detail}`)
  }
  const { fields } = outcome
  if (fields.length === 0) return null
  if (fields.length % 2 !== 0) {
    return failed(
      `${prefix}: destination path probe failed: probe returned ${String(fields.length)} fields, expected (check, path) pairs`
    )
  }
  const [check, path] = fields
  // The reported check code is untrusted text, so it is matched against the
  // sent entries by their encoded form instead of being narrowed to a type.
  const reason =
    entries.get(`${check}:${path}`) ??
    `destination path probe failed: unexpected record ${JSON.stringify(check)} for ${JSON.stringify(path)}`
  return failed(`${prefix}: ${reason}`)
}

export async function validateResolvedDestinationPath(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const resolved = await conn.exec(
    `readlink -f -- ${shellQuote(parameters.destination)}`,
    EXEC_OPTS
  )
  if (resolved.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to resolve destination path ${parameters.destination}`,
      resolved
    )
  }
  const resolvedPath = resolved.stdout.trim()
  if (resolvedPath === parameters.destination) return null
  return failed(
    `[archive.extract] refusing to extract ${parameters.source}: destination path ${JSON.stringify(parameters.destination)} resolves to ${JSON.stringify(resolvedPath)}`
  )
}

export async function validateExistingExtractDestination(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const validatedDestination = validateExtractDestination(parameters.destination)
  if ("status" in validatedDestination) return validatedDestination

  const destinationExists = await conn.exec(
    `[ -d ${shellQuote(validatedDestination.destination)} ] && [ ! -L ${shellQuote(validatedDestination.destination)} ]`,
    EXEC_OPTS
  )
  if (destinationExists.code !== 0) {
    return failed(
      `[archive.extract] destination path ${JSON.stringify(validatedDestination.destination)} is not an existing non-symlink directory`
    )
  }

  const unsafeDestinationAncestor = await validateNoSymlinkPaths(conn, {
    paths: destinationPathWithAncestors(validatedDestination.destination),
    source: parameters.source,
  })
  if (unsafeDestinationAncestor !== null) return unsafeDestinationAncestor

  return validateResolvedDestinationPath(conn, {
    destination: validatedDestination.destination,
    source: parameters.source,
  })
}
