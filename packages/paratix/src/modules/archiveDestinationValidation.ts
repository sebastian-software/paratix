import { posix as pathPosix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { archiveSymlinkTargetPrefixes } from "./archiveLinkValidation.js"
import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"
import { buildSymlinkProbeScript, runBatchedProbe } from "./archiveProbe.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000672: control characters (\x00-\x1F) in extract destinations are
// rejected before any further validation. `moveExtractedContentsIntoDestination`
// transports the guard-paths list as a newline-separated string, so a literal
// `\n` in the destination would split that list and let a crafted invocation
// bypass the symlink probes that protect ancestor paths. NUL would terminate
// the path early when interpolated into a shell argument. Reject the full
// control-character range up front, mirroring `archiveMemberValidation.ts`.
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
 * symlink member that visited it, for {@link validateNoSymlinkPaths}.
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
 * Issue #219: `linkTargets` adds the paths that archive symlink targets pass
 * through (see {@link archiveSymlinkTargetProbePaths}) to the same probe. A
 * hit there is reported against the symlink member it belongs to; a path in
 * `paths` keeps the plain destination-path message.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.linkTargets - Optional link-target paths mapped to their symlink member.
 * @param parameters.paths - Absolute destination paths that must not be symlinks.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when a probed path is a symlink or the probe failed, otherwise null.
 */
export async function validateNoSymlinkPaths(
  conn: SshConnection,
  parameters: { linkTargets?: ReadonlyMap<string, string>; paths: string[]; source: string }
): Promise<ModuleResult | null> {
  const paths = [...new Set([...parameters.paths, ...(parameters.linkTargets?.keys() ?? [])])]
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
    `[archive.extract] refusing to extract ${parameters.source}: ${symlinkProbeViolation(unsafe, parameters)}`
  )
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
