import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

export async function isRegularFileWithoutSymlink(
  ssh: SshConnection,
  remotePath: string
): Promise<boolean> {
  const quotedPath = shellQuote(remotePath)
  return ssh.test(`[ -f ${quotedPath} ] && [ ! -L ${quotedPath} ]`)
}
