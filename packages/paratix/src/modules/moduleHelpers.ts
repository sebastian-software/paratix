import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"

export const FLAGS_DIRECTORY = "/var/lib/paratix/flags"

// Flag names land directly in shell commands like `[ -f /var/lib/paratix/flags/<name> ]`
// and `find ... -name '<prefix>*' -delete`. We therefore reject any name that could
// resolve to a directory traversal segment (`..`, leading dot, trailing dot) or
// contain a path separator. The pattern requires an alphanumeric leading
// character; afterwards each character must either be a word character / dash, or
// a dot that is immediately followed by an alphanumeric character. That single
// alternation forbids `..`, leading or trailing dots, and slashes without
// nesting quantifiers (which would trigger the unsafe-regex heuristic).
const FLAG_NAME_PATTERN = /^[A-Za-z0-9](?:[\w\-]|\.[A-Za-z0-9])*$/v

function validateFlagName(value: string, label: string): void {
  if (!FLAG_NAME_PATTERN.test(value)) {
    throw new Error(
      `${label} must match ${String(FLAG_NAME_PATTERN)}, got: ${JSON.stringify(value)}`
    )
  }
}

export async function ensureFlagsDirectory(ssh: SshConnection): Promise<void> {
  await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, { silent: true })
}

export async function hasFlag(ssh: SshConnection, flagName: string): Promise<boolean> {
  validateFlagName(flagName, "flagName")
  return ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`)
}

export async function setVersionedFlag(
  ssh: SshConnection,
  flagName: string,
  flagPrefix: string
): Promise<void> {
  validateFlagName(flagName, "flagName")
  validateFlagName(flagPrefix, "flagPrefix")
  await ensureFlagsDirectory(ssh)
  const glob = shellQuote(`${flagPrefix}*`)
  await ssh.exec(
    `find ${FLAGS_DIRECTORY} -maxdepth 1 -name ${glob} -delete && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
    { silent: true }
  )
}

export async function setFlag(ssh: SshConnection, flagName: string): Promise<void> {
  await ensureFlagsDirectory(ssh)
  await ssh.exec(`touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`, { silent: true })
}
