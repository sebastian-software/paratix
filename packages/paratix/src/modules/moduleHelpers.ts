import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  acquireFlagLock,
  ensureFlagsDirectory,
  FLAG_LOCK_STALE_SECONDS,
  FLAG_LOCK_WAIT_SECONDS,
  flagLockName,
  flagPath,
  FLAGS_DIRECTORY,
  releaseFlagLock,
  tryReclaimStaleFlagLock,
  validateFlagName,
  waitForFlagLockResolution,
} from "./flagLock.js"

// R-0000619: re-export the lock display helper so existing import paths keep
// working after the moduleHelpers/flagLock split.
export { flagLockDisplayPath } from "./flagLock.js"
// Re-export the directory constant and stale threshold for tests that depend
// on the historic moduleHelpers exports.
export { FLAG_LOCK_STALE_SECONDS, FLAGS_DIRECTORY } from "./flagLock.js"
// Re-export `ensureFlagsDirectory` so callers (e.g. `setFlag`, `setVersionedFlag`,
// and external module helpers) keep their existing import path.
export { ensureFlagsDirectory } from "./flagLock.js"

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
    return runMutexSection(ssh, { ...parameters, holderToken: acquireResult.holderToken })
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
  parameters: { holderToken: string; lockName: string; section: () => Promise<TValue> }
): Promise<MutexRunResult<TValue>> {
  try {
    const value = await parameters.section()
    return { kind: "ok", value }
  } finally {
    // R-0000619: a `releaseFlagLock` failure (typically because the SSH
    // connection died during a sshd restart and was not recovered before the
    // release ran) must not replace the section's own result. The release
    // already uses `ignoreExitCode: true`, but the underlying `ssh.exec`
    // implementation may still reject when the transport is gone. Swallow
    // those failures here — the lock directory will be reclaimed by the
    // stale-lock detection on the next run, and callers that need to surface
    // the stale-lock path do so via `flagLockDisplayPath` from their own
    // error-handling path.
    // R-0000634: pass the acquire-time holder token so release only removes
    // the lock when the marker still belongs to us.
    try {
      await releaseFlagLock(ssh, parameters.lockName, parameters.holderToken)
    } catch {
      // Best-effort cleanup; never override the section result.
    }
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
    holderToken: string
    lockName: string
    shouldApply?: () => Promise<boolean>
  }
): Promise<ModuleResult> {
  try {
    if (!(await shouldRunFlagApply(ssh, parameters))) return { status: "ok" }
    return await parameters.apply()
  } finally {
    // R-0000619: mirror `runMutexSection` — a release failure (e.g. broken
    // SSH transport after a restart) must not replace the apply result.
    // R-0000634: pass the acquire-time holder token so release only removes
    // the lock when the marker still belongs to us.
    try {
      await releaseFlagLock(ssh, parameters.lockName, parameters.holderToken)
    } catch {
      // Best-effort cleanup; stale-lock detection reclaims the directory on
      // the next run.
    }
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
    return runLockedFlagApply(ssh, { ...parameters, holderToken: acquireResult.holderToken })
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
