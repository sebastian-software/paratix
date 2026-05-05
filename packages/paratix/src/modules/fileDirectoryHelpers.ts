import type { ModuleResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import {
  type FileOwnership,
  ownershipMatches,
  readOwnership,
  renderChownCommand,
} from "./fileMetadataHelpers.js"

/**
 * Issue `chmod` only when the current mode differs from the requested mode.
 *
 * Comparison strips leading zeros from the requested mode so callers can pass
 * canonical values like `"0755"` while `stat -c '%a'` reports `"755"`.
 *
 * @param input - Mode application context.
 * @param input.ownership - Current ownership state, or `undefined` when the
 *   directory does not yet exist (in which case `chmod` is always issued).
 * @param input.remotePath - Path of the directory on the remote host.
 * @param input.requestedMode - Desired chmod mode string (e.g. `"0755"`).
 * @param input.ssh - Connected SSH session.
 * @returns `true` when a chmod was issued, `false` when the mode already matches.
 */
export async function applyDirectoryMode(input: {
  ownership: FileOwnership | undefined
  remotePath: string
  requestedMode: string
  ssh: SshConnection
}): Promise<boolean> {
  const modeAlreadyMatches = input.ownership?.mode === input.requestedMode.replace(/^0+/v, "")
  if (modeAlreadyMatches) return false
  await input.ssh.exec(`chmod ${shellQuote(input.requestedMode)} ${shellQuote(input.remotePath)}`, {
    silent: true,
  })
  return true
}

/**
 * Issue `chown` only when the current owner (and optionally group) differs
 * from the requested value. The match logic mirrors {@link ownershipMatches}.
 *
 * @param input - Owner application context.
 * @param input.ownership - Current ownership state, or `undefined` when the
 *   directory does not yet exist (in which case `chown` is always issued).
 * @param input.remotePath - Path of the directory on the remote host.
 * @param input.requestedOwner - Desired chown spec (e.g. `"www-data:www-data"`).
 * @param input.ssh - Connected SSH session.
 * @returns `true` when a chown was issued, `false` when the owner already matches.
 */
export async function applyDirectoryOwner(input: {
  ownership: FileOwnership | undefined
  remotePath: string
  requestedOwner: string
  ssh: SshConnection
}): Promise<boolean> {
  const ownerAlreadyMatches =
    input.ownership != null && ownershipMatches(input.ownership, { owner: input.requestedOwner })
  if (ownerAlreadyMatches) return false
  await input.ssh.exec(renderChownCommand(input.requestedOwner, input.remotePath), {
    silent: true,
  })
  return true
}

/**
 * R-0000109: idempotent implementation of `file.directory.apply`. Probes
 * existence plus current metadata before mutating so apply only reports
 * `"changed"` when something actually changed. Mirrors the file.properties
 * no-op return pattern (R-0000028) and R-0000075/77/81/88.
 *
 * @param input - Apply context.
 * @param input.options - Optional desired metadata.
 * @param input.options.mode - Optional chmod mode string.
 * @param input.options.owner - Optional chown owner string.
 * @param input.remotePath - Path of the directory on the remote host.
 * @param input.ssh - Connected SSH session.
 * @returns A {@link ModuleResult} with status `"ok"` when nothing changed
 *   or `"changed"` when at least one mutation was issued.
 */
export async function applyDirectoryState(input: {
  options?: { mode?: string; owner?: string }
  remotePath: string
  ssh: SshConnection
}): Promise<ModuleResult> {
  const exists = await input.ssh.test(`[ -d ${shellQuote(input.remotePath)} ]`)
  let changed = false

  if (!exists) {
    await input.ssh.exec(`mkdir -p ${shellQuote(input.remotePath)}`, { silent: true })
    changed = true
  }

  const ownership = exists ? await readOwnership(input.ssh, input.remotePath) : undefined

  if (input.options?.mode != null) {
    const modeChanged = await applyDirectoryMode({
      ownership,
      remotePath: input.remotePath,
      requestedMode: input.options.mode,
      ssh: input.ssh,
    })
    changed ||= modeChanged
  }

  if (input.options?.owner != null) {
    const ownerChanged = await applyDirectoryOwner({
      ownership,
      remotePath: input.remotePath,
      requestedOwner: input.options.owner,
      ssh: input.ssh,
    })
    changed ||= ownerChanged
  }

  return { status: changed ? "changed" : "ok" }
}
