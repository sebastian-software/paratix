import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

export const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
const FLAG_LOCK_WAIT_SECONDS = 300
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
    `find ${FLAGS_DIRECTORY} -maxdepth 1 -name ${glob} ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
    { silent: true }
  )
}

export async function setFlag(ssh: SshConnection, flagName: string): Promise<void> {
  validateFlagName(flagName, "flagName")
  await ensureFlagsDirectory(ssh)
  await ssh.exec(`touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`, { silent: true })
}

function flagPath(flagName: string): string {
  return `${FLAGS_DIRECTORY}/${shellQuote(flagName)}`
}

function flagLockName(flagName: string): string {
  return `${flagName}.lock`
}

async function writeFlagLockHolderMarker(ssh: SshConnection, lockName: string): Promise<void> {
  const markerPath = `${flagPath(lockName)}/${HOLDER_MARKER_NAME}`
  // The marker captures pid, hostname and unix timestamp so an operator can
  // identify a stale lock holder. The exact contents are informational only —
  // staleness is decided via the marker's mtime.
  await ssh.exec(`printf '%s@%s %s\\n' "$$" "$(hostname)" "$(date +%s)" > ${markerPath}`, {
    ignoreExitCode: true,
    silent: true,
  })
}

async function acquireFlagLock(ssh: SshConnection, lockName: string): Promise<boolean> {
  validateFlagName(lockName, "lockName")
  await ensureFlagsDirectory(ssh)
  const result = await ssh.exec(`mkdir ${flagPath(lockName)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) {
    await writeFlagLockHolderMarker(ssh, lockName)
    return true
  }
  return false
}

async function releaseFlagLock(ssh: SshConnection, lockName: string): Promise<void> {
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
async function tryReclaimStaleFlagLock(
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

async function waitForFlagLockResolution(
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

export async function applyWithFlagLock(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    shouldApply?: () => Promise<boolean>
    /** Override the default stale-lock threshold (seconds) for tests. */
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<ModuleResult> {
  validateFlagName(parameters.flagName, "flagName")
  const lockName = flagLockName(parameters.flagName)
  validateFlagName(lockName, "lockName")

  return tryApplyWithFlagLock(ssh, { ...parameters, lockName })
}

async function runLockedFlagApply(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    lockName: string
    shouldApply?: () => Promise<boolean>
  }
): Promise<ModuleResult> {
  try {
    if (!(await shouldRunFlagApply(ssh, parameters))) return { status: "ok" }
    return await parameters.apply()
  } finally {
    await releaseFlagLock(ssh, parameters.lockName)
  }
}

async function shouldRunFlagApply(
  ssh: SshConnection,
  parameters: {
    flagName: string
    shouldApply?: () => Promise<boolean>
  }
): Promise<boolean> {
  if (!(await hasFlag(ssh, parameters.flagName))) return true
  return parameters.shouldApply == null ? false : parameters.shouldApply()
}

async function tryApplyWithFlagLock(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    lockName: string
    shouldApply?: () => Promise<boolean>
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<ModuleResult> {
  if (!(await shouldRunFlagApply(ssh, parameters))) return { status: "ok" }

  if (await acquireFlagLock(ssh, parameters.lockName)) {
    return runLockedFlagApply(ssh, parameters)
  }

  const staleSeconds = parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS
  const waitResult = await waitForFlagLockResolution(ssh, {
    flagName: parameters.flagName,
    lockName: parameters.lockName,
    staleSeconds,
    waitSeconds: parameters.waitSeconds ?? FLAG_LOCK_WAIT_SECONDS,
  })
  if (waitResult !== "resolved") return waitResult
  return tryApplyWithFlagLock(ssh, parameters)
}
