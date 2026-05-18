import { posix as pathPosix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SYMLINK_CHECK_CONCURRENCY = 8

async function mapWithConcurrencyLimit<TItem, TResult>(
  items: TItem[],
  limit: number,
  mapper: (item: TItem, index: number) => Promise<TResult>
): Promise<TResult[]> {
  if (items.length === 0) return []

  const results: TResult[] = []
  let nextIndex = 0

  async function worker(): Promise<void> {
    for (;;) {
      const index = nextIndex
      nextIndex += 1
      if (index >= items.length) return
      // eslint-disable-next-line no-await-in-loop -- each worker intentionally runs one bounded queue slot at a time
      results[index] = await mapper(items[index], index)
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      await worker()
    })
  )
  return results
}

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

async function pathIsSymlink(conn: SshConnection, path: string): Promise<boolean> {
  const result = await conn.exec(`test ! -L ${shellQuote(path)}`, EXEC_OPTS)
  return result.code !== 0
}

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

export function archiveMemberPathsWithAncestors(
  destination: string,
  members: ArchiveMember[]
): string[] {
  const paths = new Set<string>()
  for (const destinationPath of archiveMemberDestinationPaths(destination, members)) {
    for (const ancestor of pathWithAncestors(destinationPath)) {
      paths.add(ancestor)
    }
  }
  return [...paths]
}

export async function validateNoSymlinkPaths(
  conn: SshConnection,
  parameters: { paths: string[]; source: string }
): Promise<ModuleResult | null> {
  const paths = [...new Set(parameters.paths)]
  const symlinkChecks = await mapWithConcurrencyLimit(
    paths,
    SYMLINK_CHECK_CONCURRENCY,
    async (path) => ({ path, symlink: await pathIsSymlink(conn, path) })
  )
  const unsafe = symlinkChecks.find((check) => check.symlink)
  if (unsafe === undefined) return null
  return failed(
    `[archive.extract] refusing to extract ${parameters.source}: destination path ${JSON.stringify(unsafe.path)} is a symlink`
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
