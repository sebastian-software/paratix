import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
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

/**
 * Structured outcome of {@link withMutexLock}.
 *
 * R-0000757: lock acquisition failures, wait-timeouts, and unexpected throws
 * from the critical section are surfaced as a structured `failed` ModuleResult
 * via the `failed` variant. Successful sections expose their return value via
 * the `ok` variant. Callers match on `kind` instead of catching thrown errors
 * so the failure path stays symmetric with every other module helper.
 */
export type MutexLockResult<TValue> =
  { failure: ModuleResult; kind: "failed" } | { kind: "ok"; value: TValue }

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
 * R-0000757: returns a structured {@link MutexLockResult} so callers can
 * branch on `kind` instead of wrapping the call in `try/catch`. Lock-acquire
 * failures, wait timeouts, and unexpected throws from `section` are surfaced
 * as a `failed` ModuleResult whose message is prefixed with
 * `parameters.failureMessage`. Validation errors on the lock name remain
 * synchronous throws because they indicate a programmer mistake.
 *
 * Callers that want section throws to propagate verbatim (typically when the
 * underlying transport failure should bubble up to a higher recovery layer)
 * can pass `propagateSectionThrows: true`; only lock-acquire and wait-timeout
 * failures are then converted into a structured `{ kind: "failed" }` result.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Lock and section parameters.
 * @param parameters.failureMessage - Operator-facing prefix used when the lock
 *   could not be acquired or when a section throw is converted (see
 *   `propagateSectionThrows`). The underlying reason is appended after `: `.
 * @param parameters.lockName - Lock identifier; reused processes targeting the
 *   same resource must use the same name.
 * @param parameters.propagateSectionThrows - When `true`, section throws are
 *   rethrown instead of being converted into a `failed` ModuleResult. Defaults
 *   to `false`.
 * @param parameters.section - Async function executed while holding the lock.
 * @param parameters.staleSeconds - Optional stale-lock reclaim threshold.
 * @param parameters.waitSeconds - Optional wait window when contended.
 * @returns Either `{ kind: "ok", value }` with the section's return value, or
 *   `{ kind: "failed", failure }` carrying a failed `ModuleResult`.
 */
export async function withMutexLock<TValue>(
  ssh: SshConnection,
  parameters: {
    failureMessage: string
    lockName: string
    propagateSectionThrows?: boolean
    section: () => Promise<TValue>
    /** Override the default stale-lock threshold (seconds) for tests. */
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<MutexLockResult<TValue>> {
  validateFlagName(parameters.lockName, "lockName")
  return acquireMutexAndRun(ssh, parameters)
}

async function acquireMutexAndRun<TValue>(
  ssh: SshConnection,
  parameters: {
    failureMessage: string
    lockName: string
    propagateSectionThrows?: boolean
    section: () => Promise<TValue>
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<MutexLockResult<TValue>> {
  const acquireResult = await acquireFlagLock(ssh, parameters.lockName)
  if (acquireResult.kind === "failed") {
    return {
      failure: prefixModuleFailure(parameters.failureMessage, acquireResult.failure),
      kind: "failed",
    }
  }
  if (acquireResult.kind === "acquired") {
    return runMutexSection(ssh, { ...parameters, holderToken: acquireResult.holderToken })
  }
  const waitResult = await waitForMutexLockRelease(ssh, parameters)
  if (waitResult.kind === "failed") return waitResult
  return acquireMutexAndRun(ssh, parameters)
}

/**
 * Compose the operator-facing failure prefix with the underlying error message
 * coming from {@link acquireFlagLock} or {@link waitForMutexLockRelease}.
 *
 * R-0000757: keeps the upstream `error` (typically a `CommandError` carrying
 * stdout/stderr) attached to the wrapped failure so the runner can render the
 * full diagnostic — only the leading message line is rewritten with the
 * operator-facing context provided by the caller.
 *
 * @param prefix - The operator-facing message that contextualizes the failure.
 * @param failure - The structured failure returned by `acquireFlagLock` or
 *   `waitForMutexLockRelease`.
 * @returns A `failed` ModuleResult whose error message starts with `prefix`
 *   followed by `: ` and the underlying reason.
 */
function prefixModuleFailure(prefix: string, failure: ModuleResult): ModuleResult {
  const reason = failure.error?.message ?? "unknown reason"
  return failed(`${prefix}: ${reason}`)
}

async function runMutexSection<TValue>(
  ssh: SshConnection,
  parameters: {
    failureMessage: string
    holderToken: string
    lockName: string
    propagateSectionThrows?: boolean
    section: () => Promise<TValue>
  }
): Promise<MutexLockResult<TValue>> {
  const sectionOutcome = await runSectionCapturingErrors(parameters)
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
  // R-0000757: when the caller opted to propagate section throws, rethrow the
  // captured error AFTER the release ran so the lock is always cleaned up.
  if (sectionOutcome.kind === "threw") throw sectionOutcome.error
  return sectionOutcome.result
}

type SectionCaptureOutcome<TValue> =
  { error: unknown; kind: "threw" } | { kind: "captured"; result: MutexLockResult<TValue> }

async function runSectionCapturingErrors<TValue>(parameters: {
  failureMessage: string
  propagateSectionThrows?: boolean
  section: () => Promise<TValue>
}): Promise<SectionCaptureOutcome<TValue>> {
  try {
    const value = await parameters.section()
    return { kind: "captured", result: { kind: "ok", value } }
  } catch (error) {
    // R-0000757: convert section throws into a typed `failed` ModuleResult so
    // callers no longer need a surrounding try/catch. Callers that explicitly
    // opt out via `propagateSectionThrows` get the original throw back (see
    // `releaseUpgrade.upgrade`, where the upstream layer owns recovery).
    if (parameters.propagateSectionThrows === true) {
      return { error, kind: "threw" }
    }
    const reason = error instanceof Error ? error.message : String(error)
    return {
      kind: "captured",
      result: {
        failure: failed(`${parameters.failureMessage}: ${reason}`),
        kind: "failed",
      },
    }
  }
}

async function waitForMutexLockRelease(
  ssh: SshConnection,
  parameters: {
    failureMessage: string
    lockName: string
    staleSeconds?: number
    waitSeconds?: number
  }
): Promise<{ failure: ModuleResult; kind: "failed" } | { kind: "resolved" }> {
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
    failure: failed(
      `${parameters.failureMessage}: timed out waiting for mutex lock ${parameters.lockName}`
    ),
    kind: "failed",
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
