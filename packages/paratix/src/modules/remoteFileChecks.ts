import { posix } from "node:path"

import type { ExecOptions, SshConnection } from "../types.js"

import { shellQuote, validateMktempPath } from "../ssh.js"

export async function isRegularFileWithoutSymlink(
  ssh: SshConnection,
  remotePath: string
): Promise<boolean> {
  const quotedPath = shellQuote(remotePath)
  return ssh.test(`[ -f ${quotedPath} ] && [ ! -L ${quotedPath} ]`)
}

/**
 * Detect whether `remotePath` is a symbolic link, including dangling links
 * whose target no longer exists. `[ -L path ]` reports the link itself rather
 * than dereferencing it, so this returns `true` even when `[ -e path ]` would
 * report the path as nonexistent.
 *
 * Use this guard before any operation that follows symlinks (chmod, chown,
 * chgrp, cat >>, sftp writes) when the operation must not silently mutate the
 * link target.
 *
 * @param ssh - The SSH connection.
 * @param remotePath - Path to probe on the remote host.
 * @returns `true` when the path itself is a symbolic link, dangling or not.
 */
export async function isSymlink(ssh: SshConnection, remotePath: string): Promise<boolean> {
  return ssh.test(`[ -L ${shellQuote(remotePath)} ]`)
}

/**
 * Outcome of a symlink ancestor walk: either a clean walk (`null` symlink) or
 * the offending path that turned out to be a symlink.
 */
export type AncestorSymlinkProbe =
  { kind: "ancestor"; path: string } | { kind: "leaf"; path: string } | null

/**
 * R-0000637: walk every existing ancestor of `remotePath` looking for a
 * symbolic link. Returns the offending ancestor when found, otherwise `null`.
 *
 * The walk iterates in TypeScript so the resulting `[ -L … ]` calls re-use
 * `isSymlink`, keeping mock-stub matching predictable for tests. The leaf
 * itself is probed first so callers can distinguish a symlinked target from
 * a symlinked intermediate directory without an extra round-trip.
 *
 * **TOCTOU warning (R-0000815):** this probe is fundamentally a
 * time-of-check / time-of-use snapshot. Between the `[ -L … ]` round-trips
 * here and any subsequent mutation a privileged or co-located attacker can:
 *
 *   - replace a clean ancestor directory with a symlink that points into an
 *     attacker-controlled tree;
 *   - swap the leaf path itself for a symlink between this probe and the
 *     follow-up `mkdir -p` / `mv -T` / `cp -aT` / `writeFile`;
 *   - mount a transient filesystem over an ancestor inside the gap.
 *
 * In other words, a clean result here does **not** prove that the actual
 * mutation will operate on a symlink-free path. Treat this helper as a
 * defence-in-depth advisory check only. Callers that perform the follow-up
 * mutation **must** use a TOCTOU-resistant pattern at the syscall layer:
 *
 *   - open the leaf with `O_NOFOLLOW | O_NOCTTY` (or pass `--no-dereference`
 *     to the underlying coreutils helper) so the kernel refuses to traverse
 *     a symlinked component that appears after this probe;
 *   - resolve and operate on a parent directory file descriptor (`openat`
 *     family) instead of repeatedly resolving the same path string;
 *   - or run the mutation under a privilege boundary that cannot be hijacked
 *     by the user owning the candidate ancestor.
 *
 * Use this guard before any `mkdir -p`, `mv -T`, `cp -aT`, or similar
 * helper whose path traversal would otherwise follow symlinks into an
 * attacker-controlled directory, but understand that it only narrows the
 * race window — it does not close it.
 *
 * @param ssh - The active SSH connection.
 * @param remotePath - Absolute path whose leaf and ancestors are probed.
 * @returns `null` when no symlink is found, otherwise `{ kind, path }` for
 *   the first symlink encountered (`"leaf"` for `remotePath` itself,
 *   `"ancestor"` for any intermediate directory).
 */
export async function findSymlinkInAncestorWalk(
  ssh: SshConnection,
  remotePath: string
): Promise<AncestorSymlinkProbe> {
  if (await isSymlink(ssh, remotePath)) {
    return { kind: "leaf", path: remotePath }
  }
  let ancestor = posix.dirname(remotePath)
  const seen = new Set<string>()
  while (ancestor !== "/" && ancestor !== "." && !seen.has(ancestor)) {
    seen.add(ancestor)
    // eslint-disable-next-line no-await-in-loop -- ancestor walk is sequential by nature
    if (await isSymlink(ssh, ancestor)) {
      return { kind: "ancestor", path: ancestor }
    }
    ancestor = posix.dirname(ancestor)
  }
  return null
}

export async function findSymlinkInAncestors(
  ssh: SshConnection,
  remotePath: string
): Promise<null | string> {
  let ancestor = posix.dirname(remotePath)
  const seen = new Set<string>()
  while (ancestor !== "/" && ancestor !== "." && !seen.has(ancestor)) {
    seen.add(ancestor)
    // eslint-disable-next-line no-await-in-loop -- ancestor walk is sequential by nature
    if (await isSymlink(ssh, ancestor)) return ancestor
    ancestor = posix.dirname(ancestor)
  }
  return null
}

export function verifiedPhysicalDirectoryCommand(directory: string, command: string): string {
  const quotedDirectory = shellQuote(directory)
  return `[ ! -L ${quotedDirectory} ] && [ -d ${quotedDirectory} ] && cd -P -- ${quotedDirectory} && [ "$(pwd -P)" = ${quotedDirectory} ] && ${command}`
}

export async function allocateRemoteStagingDirectory(
  ssh: SshConnection,
  parameters: { execOptions: ExecOptions; parent: string; prefix: string }
): Promise<null | string> {
  const { execOptions, parent, prefix } = parameters
  const quotedParent = shellQuote(parent)
  const result = await ssh.exec(
    verifiedPhysicalDirectoryCommand(parent, `mktemp -d -p ${quotedParent} -- ${prefix}.XXXXXX`),
    execOptions
  )
  if (result.code !== 0) return null
  try {
    return validateMktempPath(parent, result.stdout.trim(), prefix)
  } catch {
    return null
  }
}

export async function cleanupRemoteStagingPath(
  ssh: SshConnection,
  stagingPath: string,
  execOptions: ExecOptions
): Promise<void> {
  await ssh.exec(`rm -rf -- ${shellQuote(stagingPath)}`, execOptions)
}

export async function publishRemoteStagedDirectory(
  ssh: SshConnection,
  parameters: {
    destination: string
    execOptions: ExecOptions
    parent: string
    postPublishDirectory: string
    stagingDestination: string
  }
): Promise<boolean> {
  const { destination, execOptions, parent, postPublishDirectory, stagingDestination } = parameters
  const result = await ssh.exec(
    verifiedPhysicalDirectoryCommand(
      parent,
      [
        `[ ! -e ${shellQuote(destination)} ]`,
        `[ ! -L ${shellQuote(destination)} ]`,
        `mv -T -n -- ${shellQuote(stagingDestination)} ${shellQuote(destination)}`,
        `[ ! -e ${shellQuote(stagingDestination)} ]`,
        `[ -d ${shellQuote(postPublishDirectory)} ]`,
      ].join(" && ")
    ),
    execOptions
  )
  if (result.code === 0) return true
  await cleanupRemoteStagingPath(ssh, stagingDestination, execOptions)
  return false
}
