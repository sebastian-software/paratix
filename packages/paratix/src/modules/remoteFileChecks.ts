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
