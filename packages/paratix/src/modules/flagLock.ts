import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

export const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
export const FLAG_LOCK_WAIT_SECONDS = 300
const SECONDS_PER_MINUTE = 60
const MINUTES_PER_HOUR = 60
const FLAG_LOCK_STALE_HOURS = 4
// Locks older than this are considered stale: a holder process likely crashed
// (SIGKILL, OOM, power loss) without releasing the lock. We use the holder
// marker mtime instead of the lock directory mtime because the latter can be
// updated by tools traversing the parent directory.
export const FLAG_LOCK_STALE_SECONDS = FLAG_LOCK_STALE_HOURS * MINUTES_PER_HOUR * SECONDS_PER_MINUTE
const HOLDER_MARKER_NAME = "holder"

// Flag names land directly in shell commands like `[ -f /var/lib/paratix/flags/<name> ]`
// and `find ... -name '<prefix>*' -delete`. We therefore reject any name that could
// resolve to a directory traversal segment (`..`, leading dot, trailing dot) or
// contain a path separator. The pattern requires an alphanumeric leading
// character; afterwards each character must either be a word character / dash, or
// a dot that is immediately followed by an alphanumeric character. That single
// alternation forbids `..`, leading or trailing dots, and slashes without
// nesting quantifiers (which would trigger the unsafe-regex heuristic).
const FLAG_NAME_PATTERN = /^[A-Za-z0-9](?:[\w\-]|\.[A-Za-z0-9])*$/v

export function validateFlagName(value: string, label: string): void {
  if (!FLAG_NAME_PATTERN.test(value)) {
    throw new Error(
      `${label} must match ${String(FLAG_NAME_PATTERN)}, got: ${JSON.stringify(value)}`
    )
  }
}

/**
 * Ensure the paratix flags directory exists on the remote host.
 *
 * R-0000273: `mkdir -p` runs after a converged apply step, so failures
 * (EROFS, EPERM, ENOSPC, ...) must not throw and undo a successful change.
 * The helper captures the exit code via `ignoreExitCode` and returns a
 * failed {@link ModuleResult} when the command did not succeed; on success
 * it returns `null` so callers can keep their happy path concise.
 *
 * @param ssh - The active SSH connection.
 * @returns A failed `ModuleResult` when `mkdir -p` failed, otherwise `null`.
 */
export async function ensureFlagsDirectory(ssh: SshConnection): Promise<ModuleResult | null> {
  const result = await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
  return failedCommand(`[moduleHelpers] failed to create ${FLAGS_DIRECTORY}`, result)
}

export function flagPath(flagName: string): string {
  return `${FLAGS_DIRECTORY}/${shellQuote(flagName)}`
}

/**
 * Return the unquoted on-disk path of a flag lock directory for use in
 * operator-facing diagnostics.
 *
 * R-0000619: When a remote-mutex section cannot release its lock (typically
 * because the SSH connection died during a sshd restart and the fallback
 * reconnect failed too), the lock directory stays in place until the stale
 * threshold expires. Callers surface this path in their failure message so
 * the operator can clean up manually instead of waiting four hours.
 *
 * @param lockName - The validated lock identifier used by `withMutexLock`.
 * @returns The plain `/var/lib/paratix/flags/<lockName>` path (no shell quoting).
 */
export function flagLockDisplayPath(lockName: string): string {
  return `${FLAGS_DIRECTORY}/${lockName}`
}

export function flagLockName(flagName: string): string {
  return `${flagName}.lock`
}

async function writeFlagLockHolderMarker(ssh: SshConnection, lockName: string): Promise<void> {
  // R-0000494: capture hostname via ssh.output (not inline `$(hostname)`).
  const hostname = await ssh
    .output("hostname")
    .then((rawHostname) => rawHostname.trim())
    .catch(() => "")
  const markerPath = `${flagPath(lockName)}/${HOLDER_MARKER_NAME}`
  await ssh.exec(
    `printf '%s@%s %s\\n' "$$" ${shellQuote(hostname)} "$(date +%s)" > ${markerPath}`,
    { ignoreExitCode: true, silent: true }
  )
}

export type FlagLockAcquireResult =
  | { failure: ModuleResult; kind: "failed" }
  | { kind: "acquired" }
  | { kind: "contended" }

export async function acquireFlagLock(
  ssh: SshConnection,
  lockName: string
): Promise<FlagLockAcquireResult> {
  validateFlagName(lockName, "lockName")
  const ensureFailure = await ensureFlagsDirectory(ssh)
  if (ensureFailure) return { failure: ensureFailure, kind: "failed" }
  const result = await ssh.exec(`mkdir ${flagPath(lockName)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) {
    await writeFlagLockHolderMarker(ssh, lockName)
    return { kind: "acquired" }
  }
  return { kind: "contended" }
}

export async function releaseFlagLock(ssh: SshConnection, lockName: string): Promise<void> {
  validateFlagName(lockName, "lockName")
  // Remove the holder marker first (if present) so `rmdir` succeeds. The
  // ignoreExitCode keeps the cleanup tolerant when the marker was already
  // removed (e.g. by a stale-lock recovery path).
  const markerPath = `${flagPath(lockName)}/${HOLDER_MARKER_NAME}`
  await ssh.exec(`rm -f ${markerPath}`, { ignoreExitCode: true, silent: true })
  await ssh.exec(`rmdir ${flagPath(lockName)}`, { ignoreExitCode: true, silent: true })
}

/**
 * Detect a stale lock and remove it so the next acquire attempt can proceed.
 *
 * Stale-detection compares the holder marker's mtime against the configured
 * timeout. A missing marker is also treated as stale because a healthy holder
 * always writes the marker right after `mkdir`. Removal is best-effort: if the
 * race-test fails (another process just claimed the lock), the helper returns
 * `false` without raising. Returning `true` does NOT mean the caller now holds
 * the lock — only that the previous holder was determined stale and removed.
 *
 * @param ssh - The active SSH connection.
 * @param lockName - The lock directory name under {@link FLAGS_DIRECTORY}.
 * @param staleSeconds - Maximum holder marker age before the lock is reclaimed.
 * @returns `true` when a stale lock was reclaimed, otherwise `false`.
 */
export async function tryReclaimStaleFlagLock(
  ssh: SshConnection,
  lockName: string,
  staleSeconds: number
): Promise<boolean> {
  const lock = flagPath(lockName)
  const markerPath = `${lock}/${HOLDER_MARKER_NAME}`
  // Use `find -mmin` to detect a marker older than the threshold, falling
  // back to the lock directory mtime when the marker is missing entirely.
  const staleMinutes = Math.max(1, Math.ceil(staleSeconds / SECONDS_PER_MINUTE))
  const mminThreshold = String(staleMinutes - 1)
  const command =
    `if [ -d ${lock} ]; then ` +
    `if [ -f ${markerPath} ]; then ` +
    `if find ${markerPath} -maxdepth 0 -mmin +${mminThreshold} -print -quit | grep -q .; then ` +
    `rm -f ${markerPath} && rmdir ${lock}; ` +
    `else exit 1; fi; ` +
    `else ` +
    // Missing marker is treated as stale only if the lock directory itself
    // is older than the threshold to avoid racing with a holder that has
    // not yet written its marker.
    `if find ${lock} -maxdepth 0 -mmin +${mminThreshold} -print -quit | grep -q .; then ` +
    `rm -f ${markerPath} && rmdir ${lock}; ` +
    `else exit 1; fi; ` +
    `fi; ` +
    `else exit 1; fi`
  const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  return result.code === 0
}

export async function waitForFlagLockResolution(
  ssh: SshConnection,
  parameters: {
    flagName: string
    lockName: string
    staleSeconds: number
    waitSeconds: number
  }
): Promise<"resolved" | ModuleResult> {
  const flag = flagPath(parameters.flagName)
  const lock = flagPath(parameters.lockName)
  const waitSeconds = String(parameters.waitSeconds)
  const command =
    `i=0; while [ -d ${lock} ] && [ ! -f ${flag} ] && [ "$i" -lt ${waitSeconds} ]; do ` +
    "sleep 1; i=$((i+1)); done; " +
    `[ ! -d ${lock} ] || [ -f ${flag} ]`
  const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  if (result.code === 0) return "resolved"
  // Wait window expired — try to reclaim a stale lock so the next attempt
  // can proceed instead of failing forever after a crashed holder.
  if (await tryReclaimStaleFlagLock(ssh, parameters.lockName, parameters.staleSeconds)) {
    return "resolved"
  }
  return failedCommand(
    `[moduleHelpers] timed out waiting for flag lock ${parameters.lockName}`,
    result
  )
}
