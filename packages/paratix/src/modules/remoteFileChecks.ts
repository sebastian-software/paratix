import { posix } from "node:path"

import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

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
  | { kind: "ancestor"; path: string }
  | { kind: "leaf"; path: string }
  | null

/**
 * R-0000637: walk every existing ancestor of `remotePath` looking for a
 * symbolic link. Returns the offending ancestor when found, otherwise `null`.
 *
 * The walk iterates in TypeScript so the resulting `[ -L … ]` calls re-use
 * `isSymlink`, keeping mock-stub matching predictable for tests. The leaf
 * itself is probed first so callers can distinguish a symlinked target from
 * a symlinked intermediate directory without an extra round-trip.
 *
 * Use this guard before any `mkdir -p`, `mv -T`, `cp -aT`, or similar
 * helper whose path traversal would otherwise follow symlinks into an
 * attacker-controlled directory.
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
