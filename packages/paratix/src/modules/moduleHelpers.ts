import type { ModuleResult, SshConnection } from "../types.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  acquireFlagLock,
  ensureFlagsDirectory,
  FLAG_LOCK_STALE_SECONDS,
  FLAG_LOCK_WAIT_SECONDS,
  flagLockName,
  FLAGS_DIRECTORY,
  releaseFlagLock,
  validateFlagName,
} from "./flagLock.js"
import {
  createFlagLockWaitBudget,
  type FlagLockWaitBudget,
  waitForFlagLockResolution,
} from "./flagLockWait.js"

// R-0000619: re-export the lock display helper so existing import paths keep
// working after the moduleHelpers/flagLock split.
export { flagLockDisplayPath } from "./flagLock.js"
// Re-export the directory constant and stale threshold for tests that depend
// on the historic moduleHelpers exports.
export { FLAG_LOCK_STALE_SECONDS, FLAGS_DIRECTORY } from "./flagLock.js"
// Re-export `ensureFlagsDirectory` so callers (e.g. `setFlag`, `setVersionedFlag`,
// and external module helpers) keep their existing import path.
export { ensureFlagsDirectory } from "./flagLock.js"
// Issue #224: the mutex lock moved to `mutexLock.ts`; re-export it so
// existing callers keep importing `withMutexLock` from here.
export {
  type MutexLockHandle,
  type MutexLockHeartbeat,
  type MutexLockLostReason,
  type MutexLockParameters,
  type MutexLockResult,
  type MutexLockWaitFailureContext,
  withMutexLock,
} from "./mutexLock.js"

export async function hasFlag(ssh: SshConnection, flagName: string): Promise<boolean> {
  validateFlagName(flagName, "flagName")
  return ssh.test(`[ -f ${FLAGS_DIRECTORY}/${shellQuote(flagName)} ]`)
}

/**
 * Persist a versioned flag, deleting any older flag files that share the
 * given prefix.
 *
 * Only call this with a prefix that carries the call site's identity, such as
 * a hash of the unit name, package name or destination path. The deletion
 * glob spans the whole flags directory, so a prefix without an identity
 * component is host-global: two calls of the same module would share one
 * namespace and evict each other's marker on every run, and neither could
 * converge. Modules whose flag name is only a caller-supplied date have no
 * such identity and use {@link setFlag} instead.
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
    `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name ${glob} ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/${shellQuote(flagName)}`,
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

/**
 * Acquire the flag lock and run `apply` unless the flag already exists.
 *
 * Issue #224: a contended acquisition waits in bounded rounds against one
 * budget that is created at the first contention and carried through every
 * retry, so a lost re-acquire race never starts a fresh full wait.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Flag, lock and apply parameters.
 * @param parameters.apply - The apply step run while holding the lock.
 * @param parameters.flagName - The validated flag identifier.
 * @param parameters.lockName - The validated lock identifier.
 * @param parameters.shouldApply - Optional re-check when the flag exists.
 * @param parameters.staleSeconds - Optional stale-lock reclaim threshold.
 * @param parameters.waitBudget - The wait budget of an earlier round, if any.
 * @param parameters.waitSeconds - Optional overall wait window when contended.
 * @returns The apply result, `ok` when the flag exists, or a failure.
 */
async function tryApplyWithFlagLock(
  ssh: SshConnection,
  parameters: {
    apply: () => Promise<ModuleResult>
    flagName: string
    lockName: string
    shouldApply?: () => Promise<boolean>
    staleSeconds?: number
    waitBudget?: FlagLockWaitBudget
    waitSeconds?: number
  }
): Promise<ModuleResult> {
  if (!(await shouldRunFlagApply(ssh, parameters))) return { status: "ok" }

  const acquireResult = await acquireFlagLock(ssh, parameters.lockName)
  if (acquireResult.kind === "failed") return acquireResult.failure
  if (acquireResult.kind === "acquired") {
    return runLockedFlagApply(ssh, { ...parameters, holderToken: acquireResult.holderToken })
  }

  const waitBudget =
    parameters.waitBudget ??
    createFlagLockWaitBudget(parameters.waitSeconds ?? FLAG_LOCK_WAIT_SECONDS)
  const waitResult = await waitForFlagLockResolution(
    ssh,
    {
      flagName: parameters.flagName,
      lockName: parameters.lockName,
      staleSeconds: parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS,
    },
    waitBudget
  )
  if (waitResult !== "resolved") return waitResult
  return tryApplyWithFlagLock(ssh, { ...parameters, waitBudget })
}
