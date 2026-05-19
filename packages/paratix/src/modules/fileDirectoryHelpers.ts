import { posix as path } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type FileOwnership,
  ownershipMatches,
  readOwnership,
  renderGuardedChmodCommand,
  renderGuardedChownCommand,
} from "./fileMetadataHelpers.js"
import { findSymlinkInAncestorWalk } from "./remoteFileChecks.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/** Result of a directory mutation step: a failure result, "changed", or "unchanged". */
type DirectoryStepResult = boolean | ModuleResult

function isDirectoryFailure(result: DirectoryStepResult): result is ModuleResult {
  return typeof result !== "boolean"
}

/**
 * Issue `chmod` only when the current mode differs from the requested mode.
 *
 * Comparison strips leading zeros from the requested mode so callers can pass
 * canonical values like `"0755"` while `stat -c '%a'` reports `"755"`.
 *
 * R-0000270: failures (read-only fs, EPERM, missing path) are surfaced as a
 * failedCommand result instead of an unguarded CommandError so the caller can
 * forward the maskable failure through the runner pipeline.
 *
 * @param input - Mode application context.
 * @param input.ownership - Current ownership state, or `undefined` when the
 *   directory does not yet exist (in which case `chmod` is always issued).
 * @param input.remotePath - Path of the directory on the remote host.
 * @param input.requestedMode - Desired chmod mode string (e.g. `"0755"`).
 * @param input.ssh - Connected SSH session.
 * @returns `true` when a chmod was issued, `false` when the mode already
 *   matches, or a failed {@link ModuleResult} when chmod exited non-zero.
 */
export async function applyDirectoryMode(input: {
  ownership: FileOwnership | undefined
  remotePath: string
  requestedMode: string
  ssh: SshConnection
}): Promise<DirectoryStepResult> {
  const modeAlreadyMatches = input.ownership?.mode === input.requestedMode.replace(/^0+/v, "")
  if (modeAlreadyMatches) return false
  const result = await input.ssh.exec(
    renderGuardedChmodCommand(input.requestedMode, input.remotePath),
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(`[file.directory: ${input.remotePath}] chmod failed`, result)
  }
  return true
}

/**
 * Issue `chown` only when the current owner (and optionally group) differs
 * from the requested value. The match logic mirrors {@link ownershipMatches}.
 *
 * R-0000270: failures (NSS lookup error, EPERM) are surfaced as a
 * failedCommand result so apply does not mask the underlying cause.
 *
 * @param input - Owner application context.
 * @param input.ownership - Current ownership state, or `undefined` when the
 *   directory does not yet exist (in which case `chown` is always issued).
 * @param input.remotePath - Path of the directory on the remote host.
 * @param input.requestedOwner - Desired chown spec (e.g. `"www-data:www-data"`).
 * @param input.ssh - Connected SSH session.
 * @returns `true` when a chown was issued, `false` when the owner already
 *   matches, or a failed {@link ModuleResult} when chown exited non-zero.
 */
export async function applyDirectoryOwner(input: {
  ownership: FileOwnership | undefined
  remotePath: string
  requestedOwner: string
  ssh: SshConnection
}): Promise<DirectoryStepResult> {
  const ownerAlreadyMatches =
    input.ownership != null && ownershipMatches(input.ownership, { owner: input.requestedOwner })
  if (ownerAlreadyMatches) return false
  const result = await input.ssh.exec(
    renderGuardedChownCommand(input.requestedOwner, input.remotePath),
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(`[file.directory: ${input.remotePath}] chown failed`, result)
  }
  return true
}

async function ensureDirectoryExists(input: {
  exists: boolean
  remotePath: string
  ssh: SshConnection
}): Promise<DirectoryStepResult> {
  if (input.exists) return false
  // R-0000270: mkdir on a read-only fs or in a directory the current user
  // cannot write to must propagate as a failedCommand result, not as an
  // unguarded CommandError that bypasses the runner failure pipeline.
  for (const directory of directoryPathWithAncestors(input.remotePath)) {
    // eslint-disable-next-line no-await-in-loop -- parent directories must be created before children
    const result = await input.ssh.exec(renderGuardedMkdirCommand(directory), EXEC_OPTS)
    if (result.code !== 0) {
      return failedCommand(`[file.directory: ${input.remotePath}] mkdir failed`, result)
    }
  }
  return true
}

function directoryPathWithAncestors(remotePath: string): string[] {
  const normalized = path.normalize(remotePath)
  const parts = normalized.split("/").filter(Boolean)
  const directories: string[] = []
  let current = ""
  for (const part of parts) {
    current = `${current}/${part}`
    directories.push(current)
  }
  return directories
}

function renderFinalDirectoryValidationLines(quotedDirectory: string): string[] {
  return [
    `if [ ! -L ${quotedDirectory} ] && [ -d ${quotedDirectory} ]; then`,
    `  :`,
    `else`,
    `  printf '%s\\n' 'directory path failed final validation' >&2`,
    `  exit 1`,
    `fi`,
  ]
}

function renderFinalDirectoryValidationCommand(directory: string): string {
  return renderFinalDirectoryValidationLines(shellQuote(directory)).join("\n")
}

async function assertFinalDirectoryTarget(input: {
  remotePath: string
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const result = await input.ssh.exec(
    renderFinalDirectoryValidationCommand(input.remotePath),
    EXEC_OPTS
  )
  if (result.code === 0) return null
  return failedCommand(`[file.directory: ${input.remotePath}] final validation failed`, result)
}

function renderGuardedMkdirCommand(directory: string): string {
  const quotedDirectory = shellQuote(directory)
  return [
    `if [ -L ${quotedDirectory} ]; then`,
    `  printf '%s\\n' 'directory path is a symlink' >&2`,
    `  exit 1`,
    `fi`,
    `if [ -e ${quotedDirectory} ] && [ ! -d ${quotedDirectory} ]; then`,
    `  printf '%s\\n' 'directory path exists and is not a directory' >&2`,
    `  exit 1`,
    `fi`,
    `if [ ! -d ${quotedDirectory} ]; then`,
    `  mkdir -- ${quotedDirectory}`,
    `fi`,
    ...renderFinalDirectoryValidationLines(quotedDirectory),
  ].join("\n")
}
async function ensureDirectoryPathNotSymlinked(input: {
  remotePath: string
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const symlinkProbe = await findSymlinkInAncestorWalk(input.ssh, input.remotePath)
  if (symlinkProbe?.kind === "leaf") {
    return failed(`[file.directory: ${input.remotePath}] path must not be a symlink`)
  }
  if (symlinkProbe?.kind === "ancestor") {
    return failed(
      `[file.directory: ${input.remotePath}] ancestor must not be a symlink: ${symlinkProbe.path}`
    )
  }
  return null
}

async function applyDirectoryMetadataDrift(input: {
  options?: { mode?: string; owner?: string }
  ownership: FileOwnership | undefined
  remotePath: string
  ssh: SshConnection
}): Promise<DirectoryStepResult> {
  let changed = false
  if (input.options?.mode != null) {
    const modeResult = await applyDirectoryMode({
      ownership: input.ownership,
      remotePath: input.remotePath,
      requestedMode: input.options.mode,
      ssh: input.ssh,
    })
    if (isDirectoryFailure(modeResult)) return modeResult
    changed ||= modeResult
  }
  if (input.options?.owner != null) {
    const ownerResult = await applyDirectoryOwner({
      ownership: input.ownership,
      remotePath: input.remotePath,
      requestedOwner: input.options.owner,
      ssh: input.ssh,
    })
    if (isDirectoryFailure(ownerResult)) return ownerResult
    changed ||= ownerResult
  }
  return changed
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
  // R-0000637: walk every existing ancestor of remotePath in addition to the
  // leaf itself. Without this walk, a symlinked intermediate directory (e.g.
  // /opt -> /tmp/attacker) would let the subsequent `mkdir -p` create the
  // target underneath an attacker-controlled tree. Mirrors the ancestor walks
  // performed by `ensureComposeProjectDirectoryNotSymlinked` (compose.ts) and
  // `ensureDownloadDestinationNotSymlinked` (download.ts).
  const symlinkFailure = await ensureDirectoryPathNotSymlinked({
    remotePath: input.remotePath,
    ssh: input.ssh,
  })
  if (symlinkFailure != null) return symlinkFailure

  const exists = await input.ssh.test(`[ -d ${shellQuote(input.remotePath)} ]`)
  const mkdirResult = await ensureDirectoryExists({
    exists,
    remotePath: input.remotePath,
    ssh: input.ssh,
  })
  if (isDirectoryFailure(mkdirResult)) return mkdirResult

  const finalValidation = await assertFinalDirectoryTarget({
    remotePath: input.remotePath,
    ssh: input.ssh,
  })
  if (finalValidation != null) return finalValidation

  const ownership = exists ? await readOwnership(input.ssh, input.remotePath) : undefined
  const metadataResult = await applyDirectoryMetadataDrift({
    options: input.options,
    ownership,
    remotePath: input.remotePath,
    ssh: input.ssh,
  })
  if (isDirectoryFailure(metadataResult)) return metadataResult

  const changed = mkdirResult || metadataResult
  return { status: changed ? "changed" : "ok" }
}
