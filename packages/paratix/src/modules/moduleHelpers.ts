import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

export const FLAGS_DIRECTORY = "/var/lib/paratix/flags"

export async function ensureFlagsDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, { silent: true })
}

export async function hasFlag(ssh: SshConnection, flagName: string): Promise<boolean> {
  return ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`)
}

export async function setVersionedFlag(
  ssh: SshConnection,
  flagName: string,
  flagPrefix: string
): Promise<void> {
  await ensureFlagsDirectory(ssh)
  await ssh.exec(
    `rm -f ${FLAGS_DIRECTORY}/${shellQuote(flagPrefix)}* && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
    { silent: true }
  )
}

export async function setFlag(ssh: SshConnection, flagName: string): Promise<void> {
  await ensureFlagsDirectory(ssh)
  await ssh.exec(`touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`, { silent: true })
}
