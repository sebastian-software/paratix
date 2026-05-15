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

export async function hasFlag(ssh: SshConnection, flagName: string): Promise<boolean> {
  validateFlagName(flagName, "flagName")
  return ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`)
}

/**
 * Persist a versioned flag, deleting any older flag files that share the
 * given prefix.
 *
 * R-0000273: Apply-paths call this helper *after* the underlying convergence
 * already happened. A roh-throw on EROFS/EPERM/ENOSPC would mask the
 * successful state change behind an uncaught exception, so this helper now
 * returns a typed failure instead. Callers must propagate the returned
 * failure (or `null` on success) through their normal failure path.
 *
 * @param ssh - The active SSH connection.
 * @param flagName - The new flag file name (validated).
 * @param flagPrefix - Prefix shared by older flag files that should be deleted.
 * @returns A failed `ModuleResult` when the flag could not be persisted, otherwise `null`.
 */
export async function setVersionedFlag(
  ssh: SshConnection,
  flagName: string,
  flagPrefix: string
): Promise<ModuleResult | null> {
  validateFlagName(flagName, "flagName")
  validateFlagName(flagPrefix, "flagPrefix")
  const ensureFailure = await ensureFlagsDirectory(ssh)
  if (ensureFailure) return ensureFailure
  const glob = shellQuote(`${flagPrefix}*`)
  const result = await ssh.exec(
    `find ${FLAGS_DIRECTORY} -maxdepth 1 -name ${glob} ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
    { ignoreExitCode: true, silent: true }
  )
  if (result.code === 0) return null
  return failedCommand(`[moduleHelpers] failed to persist versioned flag ${flagName}`, result)
}

/**
 * Persist a flag file marker for idempotent re-runs.
 *
 * R-0000273: see {@link setVersionedFlag} — convergence already happened, so
 * a `touch` failure must surface as a typed `ModuleResult` rather than a roh
 * throw. Callers handle the returned failure on the standard failure path.
 *
 * @param ssh - The active SSH connection.
 * @param flagName - The flag file name to create.
 * @returns A failed `ModuleResult` when `touch` failed, otherwise `null`.
 */
export async function setFlag(ssh: SshConnection, flagName: string): Promise<ModuleResult | null> {
  validateFlagName(flagName, "flagName")
  const ensureFailure = await ensureFlagsDirectory(ssh)
  if (ensureFailure) return ensureFailure
  const result = await ssh.exec(`touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
  return failedCommand(`[moduleHelpers] failed to persist flag ${flagName}`, result)
}

function flagPath(flagName: string): string {
  return `${FLAGS_DIRECTORY}/${shellQuote(flagName)}`
}

function flagLockName(flagName: string): string {
  return `${flagName}.lock`
}

async function writeFlagLockHolderMarker(ssh: SshConnection, lockName: string): Promise<void> {
  const markerPath = `${flagPath(lockName)}/${HOLDER_MARKER_NAME}`
  // R-0000494: capture hostname via a dedicated `ssh.output` call instead of
  // an inline `$(hostname)` substitution so unusual remote hostnames (quotes,
  // shell metacharacters) cannot break the marker write. The marker is
  // informational only — if the hostname lookup fails or returns empty, fall
  // back to an empty string. Staleness is decided via the marker's mtime.
  let hostname = ""
  try {
    hostname = (await ssh.output("hostname")).trim()
  } catch {
    hostname = ""
  }
  // The marker captures pid, hostname and unix timestamp so an operator can
  // identify a stale lock holder. The exact contents are informational only —
  // staleness is decided via the marker's mtime.
  await ssh.exec(
    `printf '%s@%s %s\\n' "$$" ${shellQuote(hostname)} "$(date +%s)" > ${markerPath}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
}

type FlagLockAcquireResult =
  | { failure: ModuleResult; kind: "failed" }
  | { kind: "acquired" }
  | { kind: "contended" }

async function acquireFlagLock(
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

/**
 * Run a critical section while holding a named mutex lock on the remote host.
 *
 * Unlike {@link applyWithFlagLock}, this helper does NOT consult or update a
 * flag file — it serializes read-modify-write sequences on shared resources
 * such as `/etc/hosts` or `/etc/fstab` so concurrent Paratix invocations or
 * other processes cannot lose updates between the read and the write step.
 *
 * The lock uses the same atomic `mkdir` primitive as {@link applyWithFlagLock}
 * and reuses the stale-reclaim and wait-with-backoff machinery so a crashed
 * holder cannot deadlock future runs.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Lock and section parameters.
 * @param parameters.lockName - Lock identifier; reused processes targeting the
 *   same resource must use the same name.
 * @param parameters.section - Async function executed while holding the lock.
 * @param parameters.staleSeconds - Optional stale-lock reclaim threshold.
 * @param parameters.waitSeconds - Optional wait window when contended.
 * @returns The value returned by `section`.
 */
export async function withMutexLock<TValue>(
  ssh: SshConnection,
  parameters: {
    lockName: string
    section: () => Promise<TValue>
    /** Override the default stale-lock threshold (seconds) for tests. */
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<TValue> {
  validateFlagName(parameters.lockName, "lockName")
  const result = await acquireMutexAndRun(ssh, parameters)
  if (result.kind === "ok") return result.value
  throw new Error(result.error)
}

type MutexRunResult<TValue> = { error: string; kind: "error" } | { kind: "ok"; value: TValue }

async function acquireMutexAndRun<TValue>(
  ssh: SshConnection,
  parameters: {
    lockName: string
    section: () => Promise<TValue>
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<MutexRunResult<TValue>> {
  const acquireResult = await acquireFlagLock(ssh, parameters.lockName)
  if (acquireResult.kind === "failed") return moduleFailureToMutexError(acquireResult.failure)
  if (acquireResult.kind === "acquired") {
    return runMutexSection(ssh, parameters)
  }
  const waitResult = await waitForMutexLockRelease(ssh, parameters)
  if (waitResult.kind !== "resolved") return waitResult
  return acquireMutexAndRun(ssh, parameters)
}

function moduleFailureToMutexError(result: ModuleResult): MutexRunResult<never> {
  if (result.status !== "failed") {
    return { error: "[moduleHelpers] failed to acquire mutex lock", kind: "error" }
  }
  return {
    error: result.error?.message ?? "[moduleHelpers] failed to acquire mutex lock",
    kind: "error",
  }
}

async function runMutexSection<TValue>(
  ssh: SshConnection,
  parameters: { lockName: string; section: () => Promise<TValue> }
): Promise<MutexRunResult<TValue>> {
  try {
    const value = await parameters.section()
    return { kind: "ok", value }
  } finally {
    await releaseFlagLock(ssh, parameters.lockName)
  }
}

async function waitForMutexLockRelease(
  ssh: SshConnection,
  parameters: {
    lockName: string
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<{ error: string; kind: "error" } | { kind: "resolved" }> {
  const lock = flagPath(parameters.lockName)
  const waitSeconds = String(parameters.waitSeconds ?? FLAG_LOCK_WAIT_SECONDS)
  const command =
    `i=0; while [ -d ${lock} ] && [ "$i" -lt ${waitSeconds} ]; do ` +
    "sleep 1; i=$((i+1)); done; " +
    `[ ! -d ${lock} ]`
  const probe = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  if (probe.code === 0) return { kind: "resolved" }
  const staleSeconds = parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS
  if (await tryReclaimStaleFlagLock(ssh, parameters.lockName, staleSeconds)) {
    return { kind: "resolved" }
  }
  return {
    error: `[moduleHelpers] timed out waiting for mutex lock ${parameters.lockName}`,
    kind: "error",
  }
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

  const acquireResult = await acquireFlagLock(ssh, parameters.lockName)
  if (acquireResult.kind === "failed") return acquireResult.failure
  if (acquireResult.kind === "acquired") {
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
