/**
 * Remote mutex lock built on the flag-lock `mkdir` primitive.
 *
 * Split out of `moduleHelpers.ts` for issue #224, which re-exports
 * {@link withMutexLock} so existing import paths keep working.
 */
import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import {
  acquireFlagLock,
  FLAG_LOCK_STALE_SECONDS,
  FLAG_LOCK_WAIT_SECONDS,
  flagLockDisplayPath,
  releaseFlagLock,
  validateFlagName,
} from "./flagLock.js"
import {
  type FlagLockHolderDiagnostics,
  readFlagLockHolderDiagnostics,
  refreshFlagLock,
} from "./flagLockRefresh.js"
import {
  type FlagLockAgeThreshold,
  flagLockAgeThreshold,
  type FlagLockHolder,
  validateFlagLockHolder,
} from "./flagLockScripts.js"
import {
  createFlagLockWaitBudget,
  type FlagLockWaitBudget,
  waitForMutexLockRound,
} from "./flagLockWait.js"

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
 * Issue #224: why a lock handle was latched as lost.
 *
 * - `refused`: the refresh guard ran and refused: the marker is gone,
 *   carries another token, or was not refreshed within the guard age.
 * - `error`: the refresh exec threw (typically a transport failure), so it
 *   is unknown whether the lock is still held; `message` is the error's.
 */
export type MutexLockLostReason = { kind: "error"; message: string } | { kind: "refused" }

/**
 * Issue #224: the held lock as seen by the critical section.
 *
 * `token` is marker line 1 (the caller-supplied holder token, or the
 * historic `<pid>@<hostname>` value). `refresh()` runs the refresh guard in
 * its own exec; a refusal or a throwing exec latches the handle as lost,
 * after which `refresh()` returns `false` without contacting the host.
 * `lostReason()` says which of the two latched it.
 * `lockPath`, `token` and `guardSeconds` are what a section needs to embed
 * the same guard into its own scripts (see `buildFlagLockRefreshGuard`).
 */
export type MutexLockHandle = {
  /** Guard age in seconds used by `refresh()`. */
  readonly guardSeconds: number
  /** Whether a refresh failed; latched once `true`. */
  isLost: () => boolean
  readonly lockName: string
  /** Unquoted `/var/lib/paratix/flags/<lockName>` path. */
  readonly lockPath: string
  /** Why the handle was latched as lost; `undefined` while it is not lost. */
  lostReason: () => MutexLockLostReason | undefined
  /** Refresh the marker; resolves `false` (and latches lost) on failure. */
  refresh: () => Promise<boolean>
  readonly token: string
}

/** Issue #224: default interval of the opt-in heartbeat. */
export const MUTEX_LOCK_HEARTBEAT_INTERVAL_MILLISECONDS = 60_000

/** Issue #224: opt-in periodic refresh while the section runs. */
export type MutexLockHeartbeat = {
  /** Refresh interval; defaults to {@link MUTEX_LOCK_HEARTBEAT_INTERVAL_MILLISECONDS}. */
  intervalMilliseconds?: number
}

/** Issue #224: input of a custom wait-failure message. */
export type MutexLockWaitFailureContext = {
  diagnostics: FlagLockHolderDiagnostics
  lockName: string
  /** Unquoted `/var/lib/paratix/flags/<lockName>` path. */
  lockPath: string
  /** The reclaim threshold the wait used. */
  staleThreshold: FlagLockAgeThreshold
  waitSeconds: number
}

/** Parameters of {@link withMutexLock}. */
export type MutexLockParameters<TValue> = {
  /**
   * Issue #224: build the reason of a wait failure (appended after
   * `failureMessage: `). When set, the holder diagnostics are read in one
   * extra exec. Defaults to `timed out waiting for mutex lock <lockName>`.
   */
  describeWaitFailure?: (context: MutexLockWaitFailureContext) => string
  /**
   * Operator-facing prefix used when the lock could not be acquired or when
   * a section throw is converted. The underlying reason is appended after `: `.
   */
  failureMessage: string
  /** Issue #224: opt into a periodic refresh while the section runs. */
  heartbeat?: MutexLockHeartbeat
  /** Issue #224: caller-supplied marker token and owner lines. */
  holder?: FlagLockHolder
  /** Lock identifier; processes targeting the same resource use the same name. */
  lockName: string
  /** When `true`, section throws are rethrown after the release. */
  propagateSectionThrows?: boolean
  /**
   * Issue #224: guard age in seconds for `handle.refresh()` and the
   * heartbeat; defaults to `staleSeconds`, so a reclaimable marker is
   * never refreshed.
   */
  refreshGuardSeconds?: number
  /** Critical section; receives the lock handle. */
  section: (handle: MutexLockHandle) => Promise<TValue>
  /** Override the default stale-lock threshold (seconds). */
  staleSeconds?: number
  /** Overall wait window in seconds when contended. */
  waitSeconds?: number
}

/**
 * Run a critical section while holding a named mutex lock on the remote host.
 *
 * Unlike `applyWithFlagLock`, this helper does NOT consult or update a
 * flag file — it serializes read-modify-write sequences on shared resources
 * such as `/etc/hosts` or `/etc/fstab` so concurrent Paratix invocations or
 * other processes cannot lose updates between the read and the write step.
 *
 * The lock uses the same atomic `mkdir` primitive as `applyWithFlagLock`
 * and reuses the stale-reclaim machinery so a crashed holder cannot
 * deadlock future runs.
 *
 * Issue #224: a contended acquisition tries a stale reclaim right away,
 * then waits in short polls of at most 60 s against one overall deadline
 * (`waitSeconds`), tries a stale reclaim again in every still-held round,
 * retries a lost re-acquire race within the same deadline, and returns a
 * structured failure when the deadline passes. The section
 * receives a {@link MutexLockHandle}; with `heartbeat` set the handle is
 * refreshed periodically and the timer is stopped before the release.
 *
 * R-0000757: returns a structured {@link MutexLockResult} so callers can
 * branch on `kind` instead of wrapping the call in `try/catch`. Lock-acquire
 * failures, wait timeouts, and unexpected throws from `section` are surfaced
 * as a `failed` ModuleResult whose message is prefixed with
 * `parameters.failureMessage`. Validation errors on the lock name, the
 * holder, the heartbeat or the threshold combination remain synchronous
 * throws because they indicate a programmer mistake.
 *
 * Callers that want section throws to propagate verbatim (typically when the
 * underlying transport failure should bubble up to a higher recovery layer)
 * can pass `propagateSectionThrows: true`; only lock-acquire and wait-timeout
 * failures are then converted into a structured `{ kind: "failed" }` result.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Lock and section parameters, see {@link MutexLockParameters}.
 * @returns Either `{ kind: "ok", value }` with the section's return value, or
 *   `{ kind: "failed", failure }` carrying a failed `ModuleResult`.
 */
export async function withMutexLock<TValue>(
  ssh: SshConnection,
  parameters: MutexLockParameters<TValue>
): Promise<MutexLockResult<TValue>> {
  validateMutexLockParameters(parameters)
  const budget = createFlagLockWaitBudget(parameters.waitSeconds ?? FLAG_LOCK_WAIT_SECONDS)
  const acquired = await acquireMutex(ssh, parameters, budget)
  if (acquired.kind === "failed") return acquired
  return runMutexSection(ssh, parameters, acquired.token)
}

const MILLISECONDS_PER_SECOND = 1000

/**
 * Validate the lock parameters before any remote command.
 *
 * Issue #224: the timing must be consistent, compared on the effective
 * `find -mmin` ages (see {@link flagLockAgeThreshold}), not on the inputs:
 *
 * - The refresh guard must not accept a marker the stale reclaim already
 *   treats as reclaimable, so its effective age must not exceed the reclaim
 *   age; otherwise a holder could refresh a lock another acquirer is
 *   allowed to take.
 * - A heartbeat must refresh before the guard would refuse the marker, so
 *   its interval must stay below the guard's effective age; otherwise a
 *   healthy holder loses its lock between two refreshes.
 *
 * @param parameters - The parameters of {@link withMutexLock}.
 * @throws {Error} On an invalid lock name, holder, heartbeat interval or
 *   threshold combination.
 */
function validateMutexLockParameters<TValue>(parameters: MutexLockParameters<TValue>): void {
  validateFlagName(parameters.lockName, "lockName")
  if (parameters.holder !== undefined) validateFlagLockHolder(parameters.holder)
  const interval = parameters.heartbeat?.intervalMilliseconds
  if (interval !== undefined && (!Number.isFinite(interval) || interval <= 0)) {
    throw new Error(
      `heartbeat.intervalMilliseconds must be a positive number, got: ${String(interval)}`
    )
  }
  validateMutexLockTiming(parameters)
}

/**
 * Issue #224: the threshold part of {@link validateMutexLockParameters}.
 *
 * @param parameters - The parameters of {@link withMutexLock}; a heartbeat
 *   interval, when given, is already known to be positive.
 * @throws {Error} When the guard accepts a reclaimable marker or the
 *   heartbeat is not faster than the guard.
 */
function validateMutexLockTiming<TValue>(parameters: MutexLockParameters<TValue>): void {
  const staleSeconds = parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS
  const reclaimAge = flagLockAgeThreshold(staleSeconds).effectiveAgeSeconds
  const guardAge = flagLockAgeThreshold(
    parameters.refreshGuardSeconds ?? staleSeconds
  ).effectiveAgeSeconds
  if (guardAge > reclaimAge) {
    throw new Error(
      `refreshGuardSeconds must not accept a marker older than the stale threshold: effective guard age ${String(guardAge)} s exceeds effective reclaim age ${String(reclaimAge)} s`
    )
  }
  if (parameters.heartbeat === undefined) return
  const intervalSeconds =
    (parameters.heartbeat.intervalMilliseconds ?? MUTEX_LOCK_HEARTBEAT_INTERVAL_MILLISECONDS) /
    MILLISECONDS_PER_SECOND
  if (intervalSeconds >= guardAge) {
    throw new Error(
      `heartbeat.intervalMilliseconds must stay below the effective refresh guard age: ${String(intervalSeconds)} s is not below ${String(guardAge)} s`
    )
  }
}

type MutexAcquireOutcome =
  { failure: ModuleResult; kind: "failed" } | { kind: "acquired"; token: string }

async function acquireMutex<TValue>(
  ssh: SshConnection,
  parameters: MutexLockParameters<TValue>,
  budget: FlagLockWaitBudget
): Promise<MutexAcquireOutcome> {
  const acquireResult = await acquireFlagLock(ssh, parameters.lockName, parameters.holder)
  if (acquireResult.kind === "failed") {
    return {
      failure: prefixModuleFailure(parameters.failureMessage, acquireResult.failure),
      kind: "failed",
    }
  }
  if (acquireResult.kind === "acquired") {
    return { kind: "acquired", token: acquireResult.holderToken }
  }
  const staleSeconds = parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS
  const round = await waitForMutexLockRound(
    ssh,
    { lockName: parameters.lockName, staleSeconds },
    budget
  )
  // Issue #224: a lost re-acquire race retries within the same budget.
  if (round === "released") return acquireMutex(ssh, parameters, budget)
  return { failure: await buildWaitFailure(ssh, parameters, budget), kind: "failed" }
}

async function buildWaitFailure<TValue>(
  ssh: SshConnection,
  parameters: MutexLockParameters<TValue>,
  budget: FlagLockWaitBudget
): Promise<ModuleResult> {
  const { describeWaitFailure, failureMessage, lockName } = parameters
  if (describeWaitFailure === undefined) {
    return failed(`${failureMessage}: timed out waiting for mutex lock ${lockName}`)
  }
  const diagnostics = await readFlagLockHolderDiagnostics(ssh, lockName)
  const reason = describeWaitFailure({
    diagnostics,
    lockName,
    lockPath: flagLockDisplayPath(lockName),
    staleThreshold: flagLockAgeThreshold(parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS),
    waitSeconds: budget.totalSeconds,
  })
  return failed(`${failureMessage}: ${reason}`)
}

/**
 * Compose the operator-facing failure prefix with the underlying error message
 * coming from `acquireFlagLock`.
 *
 * R-0000757: only the leading message line is rewritten with the
 * operator-facing context provided by the caller.
 *
 * @param prefix - The operator-facing message that contextualizes the failure.
 * @param failure - The structured failure returned by `acquireFlagLock`.
 * @returns A `failed` ModuleResult whose error message starts with `prefix`
 *   followed by `: ` and the underlying reason.
 */
function prefixModuleFailure(prefix: string, failure: ModuleResult): ModuleResult {
  const reason = failure.error?.message ?? "unknown reason"
  return failed(`${prefix}: ${reason}`)
}

function createMutexLockHandle(
  ssh: SshConnection,
  identity: { guardSeconds: number; lockName: string; token: string }
): MutexLockHandle {
  let lostReason: MutexLockLostReason | undefined
  // Latch only: a later success never clears an earlier loss, and the first
  // reason is kept.
  const markLost = (reason: MutexLockLostReason): void => {
    lostReason ??= reason
  }
  const isLost = (): boolean => lostReason !== undefined
  return {
    guardSeconds: identity.guardSeconds,
    isLost,
    lockName: identity.lockName,
    lockPath: flagLockDisplayPath(identity.lockName),
    lostReason: () => lostReason,
    async refresh() {
      if (isLost()) return false
      try {
        if (!(await refreshFlagLock(ssh, identity))) markLost({ kind: "refused" })
      } catch (error) {
        markLost({
          kind: "error",
          message: error instanceof Error ? error.message : String(error),
        })
      }
      return !isLost()
    },
    token: identity.token,
  }
}

/**
 * Issue #224: refresh the handle every `intervalMilliseconds` until stopped
 * or lost. Refreshes never overlap: the next one is scheduled after the
 * previous one settled. `stop()` clears the pending timer and waits for an
 * in-flight refresh, so no refresh can run after the release.
 *
 * @param handle - The lock handle to refresh.
 * @param intervalMilliseconds - Refresh interval.
 * @returns A stopper.
 */
function startMutexLockHeartbeat(
  handle: MutexLockHandle,
  intervalMilliseconds: number
): { stop: () => Promise<void> } {
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let inFlight: Promise<void> | undefined
  const schedule = (): void => {
    if (stopped || handle.isLost()) return
    timer = setTimeout(() => {
      timer = undefined
      inFlight = handle.refresh().then(() => {
        inFlight = undefined
        schedule()
      })
    }, intervalMilliseconds)
    // Never keep the process alive just for a heartbeat.
    timer.unref()
  }
  schedule()
  return {
    async stop() {
      stopped = true
      clearTimeout(timer)
      await inFlight
    },
  }
}

async function runMutexSection<TValue>(
  ssh: SshConnection,
  parameters: MutexLockParameters<TValue>,
  token: string
): Promise<MutexLockResult<TValue>> {
  const staleSeconds = parameters.staleSeconds ?? FLAG_LOCK_STALE_SECONDS
  const handle = createMutexLockHandle(ssh, {
    guardSeconds: parameters.refreshGuardSeconds ?? staleSeconds,
    lockName: parameters.lockName,
    token,
  })
  const heartbeat =
    parameters.heartbeat === undefined
      ? undefined
      : startMutexLockHeartbeat(
          handle,
          parameters.heartbeat.intervalMilliseconds ?? MUTEX_LOCK_HEARTBEAT_INTERVAL_MILLISECONDS
        )
  let sectionOutcome: SectionCaptureOutcome<TValue>
  try {
    sectionOutcome = await runSectionCapturingErrors(parameters, handle)
  } finally {
    // Issue #224: stop the heartbeat BEFORE the token-compared release so
    // no refresh can touch a marker after it was released.
    await heartbeat?.stop()
    await releaseQuietly(ssh, parameters.lockName, token)
  }
  // R-0000757: when the caller opted to propagate section throws, rethrow the
  // captured error AFTER the release ran so the lock is always cleaned up.
  if (sectionOutcome.kind === "threw") throw sectionOutcome.error
  return sectionOutcome.result
}

/**
 * R-0000619: a `releaseFlagLock` failure (typically because the SSH
 * connection died during a sshd restart and was not recovered before the
 * release ran) must not replace the section's own result. The release
 * already uses `ignoreExitCode: true`, but the underlying `ssh.exec`
 * implementation may still reject when the transport is gone. Swallow
 * those failures here — the lock directory will be reclaimed by the
 * stale-lock detection on the next run, and callers that need to surface
 * the stale-lock path do so via `flagLockDisplayPath` from their own
 * error-handling path.
 * R-0000634: pass the acquire-time holder token so release only removes
 * the lock when the marker still belongs to us.
 *
 * @param ssh - The active SSH connection.
 * @param lockName - The validated lock identifier.
 * @param token - The acquire-time holder token.
 */
async function releaseQuietly(ssh: SshConnection, lockName: string, token: string): Promise<void> {
  try {
    await releaseFlagLock(ssh, lockName, token)
  } catch {
    // Best-effort cleanup; never override the section result.
  }
}

type SectionCaptureOutcome<TValue> =
  { error: unknown; kind: "threw" } | { kind: "captured"; result: MutexLockResult<TValue> }

async function runSectionCapturingErrors<TValue>(
  parameters: MutexLockParameters<TValue>,
  handle: MutexLockHandle
): Promise<SectionCaptureOutcome<TValue>> {
  try {
    const value = await parameters.section(handle)
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
