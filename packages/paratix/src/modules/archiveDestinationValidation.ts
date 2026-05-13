import { posix as pathPosix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type ArchiveMember, normalizeArchiveMemberPath } from "./archiveMemberValidation.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

export function validateExtractDestination(
  destination: string
): { destination: string } | ModuleResult {
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
  const symlinkChecks = await Promise.all(
    paths.map(async (path) => ({ path, symlink: await pathIsSymlink(conn, path) }))
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
