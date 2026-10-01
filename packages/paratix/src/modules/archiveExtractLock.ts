/**
 * The per-destination extract lock of `archive.extract`.
 *
 * Issue #224: concurrent applies to one destination used to share the
 * containment entries without any coordination, so a successful apply could
 * remove the `in-progress` entry of a live concurrent apply (race 1 in
 * `archiveContainmentFlag.ts`). Applies to one destination are now
 * serialized by a `mkdir` lock in the flags directory, built on
 * `withMutexLock`. It is taken right before the own containment entry is
 * created and released after the containment entries were cleared, so an
 * `in-progress` entry an apply reads under the lock belongs to an apply that
 * stopped without finishing.
 *
 * A live holder keeps its lock fresh with a periodic heartbeat. A killed
 * holder's lock is reclaimed only once its holder marker is older than the
 * stale threshold, which lies well above the host-side merge limit; the
 * refresh guard refuses a marker older than the guard threshold, so a marker
 * that is reclaimable can no longer be refreshed. The guard also runs inside
 * the merge exec and the clear exec, which stop the apply visibly when the
 * lock was lost anyway.
 */
import { randomBytes } from "node:crypto"
import { hostname } from "node:os"

import type { SshConnection } from "../types.js"

import { sha256String } from "./fileHelpers.js"
import { flagLockDisplayPath } from "./flagLock.js"
import { describeFlagLockHolder } from "./flagLockRefresh.js"
import { flagLockAgeThreshold, type FlagLockHolder } from "./flagLockScripts.js"
import {
  type MutexLockHandle,
  type MutexLockResult,
  type MutexLockWaitFailureContext,
  withMutexLock,
} from "./mutexLock.js"

/**
 * Issue #224: the timing of the extract lock.
 *
 * - `staleSeconds`: a holder marker older than this is reclaimable
 *   (`find -mmin +9` for 600 s, i.e. above 540 s, see `flagLockAgeThreshold`).
 * - `refreshGuardSeconds`: the refresh guard, the merge guard and the clear
 *   guard refuse a marker older than this (`-mmin +5` for 360 s, i.e. above
 *   300 s).
 * - `heartbeatIntervalMilliseconds`: how often the holder refreshes its
 *   marker while it holds the lock.
 * - `waitSeconds`: how long a contended apply waits for the lock overall.
 */
export type ArchiveExtractLockSettings = {
  heartbeatIntervalMilliseconds: number
  refreshGuardSeconds: number
  staleSeconds: number
  waitSeconds: number
}

/**
 * Issue #224: the one archive constant both age thresholds derive from.
 *
 * Invariant (asserted by a test): the effective guard age plus the host-side
 * merge bound (`STAGING_MERGE_TIME_LIMITS.timeoutSeconds + killAfterSeconds`)
 * plus {@link ARCHIVE_EXTRACT_LOCK_MERGE_SLACK_SECONDS} stays below the
 * effective reclaim age. A merge the guard let start has therefore ended on
 * the host before anybody can reclaim the lock, even when no heartbeat got
 * through while it ran. The heartbeat interval stays well below the
 * effective guard age, so a healthy holder always passes its guards.
 */
export const ARCHIVE_EXTRACT_LOCK_SETTINGS: Readonly<ArchiveExtractLockSettings> = Object.freeze({
  heartbeatIntervalMilliseconds: 60_000,
  refreshGuardSeconds: 360,
  staleSeconds: 600,
  waitSeconds: 300,
})

/**
 * Issue #224: the margin the threshold invariant keeps between the latest end
 * of a guarded merge on the host and the effective reclaim age: the exit
 * status traveling back, the minute granularity of `find -mmin` and clock
 * skew between the steps.
 */
export const ARCHIVE_EXTRACT_LOCK_MERGE_SLACK_SECONDS = 60

/**
 * Issue #224: the exit status of the merge exec and of the clear exec when
 * their embedded refresh guard refused: the lock is no longer this apply's,
 * and the guarded step did not start. It lies outside every status the
 * guarded steps report themselves: 1, 64, 124, 127, 129, 130, 137 and 143 of
 * the merge, and 3, 4, 5, 6 and 64 of the clear.
 */
export const ARCHIVE_EXTRACT_LOCK_LOST_EXIT = 75

/** Issue #224: the lock as the guarded steps of an apply need it. */
export type ArchiveExtractLock = Pick<
  MutexLockHandle,
  "guardSeconds" | "isLost" | "lockName" | "lockPath" | "lostReason" | "token"
>

/** Issue #224: test hooks, see {@link setArchiveExtractLockOverridesForTests}. */
export type ArchiveExtractLockOverrides = {
  /** Replaces the random holder token, e.g. with the mock's readback token. */
  newToken?: () => string
} & Partial<ArchiveExtractLockSettings>

let overrides: ArchiveExtractLockOverrides = {}

/**
 * Issue #224: override the lock timing or the token generator, for unit and
 * integration tests that cannot wait for the production thresholds. Not part
 * of the public API; every call replaces the previous overrides.
 *
 * @param next - The overrides; omitted fields keep the production values.
 */
export function setArchiveExtractLockOverridesForTests(next: ArchiveExtractLockOverrides): void {
  overrides = { ...next }
}

/** Issue #224: drop every override set by {@link setArchiveExtractLockOverridesForTests}. */
export function resetArchiveExtractLockOverridesForTests(): void {
  overrides = {}
}

/**
 * Issue #224: the settings in effect: the production constant with any test
 * overrides applied.
 *
 * @returns The lock timing.
 */
export function archiveExtractLockSettings(): ArchiveExtractLockSettings {
  const { newToken: _newToken, ...timing } = overrides
  return { ...ARCHIVE_EXTRACT_LOCK_SETTINGS, ...timing }
}

/**
 * Issue #224: the lock name of a destination. It is keyed by the destination
 * exactly like the containment entries (`containmentPathsFor` in
 * `archive.ts`): the sha256 of the normalized destination.
 *
 * @param destination - The normalized extraction target path.
 * @returns `archive-extract-lock-<sha256>`, a valid flag name.
 */
export function archiveExtractLockName(destination: string): string {
  return `archive-extract-lock-${sha256String(destination)}`
}

/** Issue #224: the random bytes of a holder token. */
const TOKEN_BYTES = 16

function newToken(): string {
  return overrides.newToken?.() ?? `paratix-${randomBytes(TOKEN_BYTES).toString("hex")}`
}

/** Issue #224: characters an owner line must not carry, see `validateFlagLockHolder`. */
const OWNER_LINE_UNSAFE_PATTERN = /[^[\x20-\x7E]--[\x22\x24\x27\x5C\x60]]/gv
const OWNER_HOSTNAME_LIMIT = 120

function ownerHostname(): string {
  let name: string
  try {
    name = hostname()
  } catch {
    name = ""
  }
  const safe = name.replaceAll(OWNER_LINE_UNSAFE_PATTERN, "?").slice(0, OWNER_HOSTNAME_LIMIT)
  return safe === "" ? "unknown" : safe
}

/**
 * Issue #224: the holder an apply writes into the lock's marker: a random
 * token on line 1, which is the only value ever compared, then owner lines
 * for an operator who inspects a contended or leftover lock.
 *
 * @param entryName - The own containment entry name of the apply.
 * @returns The holder identity.
 */
function archiveExtractLockHolder(entryName: string): FlagLockHolder {
  return {
    ownerLines: [
      `controller ${ownerHostname()} pid ${String(process.pid)}`,
      `started ${new Date().toISOString()}`,
      `entry ${entryName}`,
    ],
    token: newToken(),
  }
}

/**
 * Issue #224: how to release the lock by hand, and when that is safe.
 *
 * @param lockPath - The unquoted lock directory path.
 * @returns The sentence fragment.
 */
export function archiveExtractLockManualReleaseHint(lockPath: string): string {
  return `remove the lock by hand (rm -f -- '${lockPath}/holder' && rmdir -- '${lockPath}') only when no archive.extract apply for this destination runs anywhere`
}

/**
 * Issue #224: the reason of a wait that ran out: the destination, the lock
 * path, the holder's owner lines, the marker age and when the lock becomes
 * reclaimable. When the lock is already gone by the time the holder details
 * are read, it was released only after the wait ran out, so the reason says
 * that and asks for a retry instead of naming a holder.
 *
 * @param destination - The extraction target.
 * @param context - What `withMutexLock` hands to `describeWaitFailure`.
 * @returns The reason, appended after the failure prefix.
 */
function describeArchiveExtractWaitFailure(
  destination: string,
  context: MutexLockWaitFailureContext
): string {
  if (context.diagnostics.kind === "absent") {
    return `the extract lock ${context.lockPath} of ${destination} was released only after waiting ${String(context.waitSeconds)} s ran out; retry the apply`
  }
  const holder = describeFlagLockHolder({
    diagnostics: context.diagnostics,
    lockName: context.lockName,
    staleThreshold: context.staleThreshold,
  })
  return `another archive.extract apply to ${destination} still holds its extract lock after waiting ${String(context.waitSeconds)} s: ${holder}; retry once that apply has finished, or ${archiveExtractLockManualReleaseHint(context.lockPath)}`
}

/**
 * Issue #224: why a guarded step refused: the lock is no longer this apply's.
 *
 * A guard that refused (in its own refresh exec, or embedded in the merge or
 * clear exec) proves that the marker is gone, carries another token, or is
 * too old. A refresh exec that threw proves nothing about the marker: the
 * handle was latched as lost because the apply can no longer confirm that it
 * holds the lock, so the reason names the error instead of a marker state.
 *
 * @param lock - The lock the apply took; without `lostReason`, or while it
 *   reports none, a guard refusal is assumed.
 * @returns The reason, without a prefix.
 */
export function archiveExtractLockLostReason(
  lock: Partial<Pick<ArchiveExtractLock, "lostReason">> &
    Pick<ArchiveExtractLock, "guardSeconds" | "lockPath">
): string {
  const lost = lock.lostReason?.()
  if (lost?.kind === "error") {
    return `this apply can no longer confirm that it holds the extract lock ${lock.lockPath} of this destination (refreshing its holder marker failed: ${lost.message})`
  }
  const guardAge = flagLockAgeThreshold(lock.guardSeconds).effectiveAgeSeconds
  return `the extract lock ${lock.lockPath} of this destination is no longer held by this apply (its holder marker is gone, carries another token, or was not refreshed for more than ${String(guardAge)} s)`
}

/** Issue #224: inputs of {@link withArchiveExtractLock}. */
export type ArchiveExtractLockParameters = {
  /** The normalized extraction target. */
  destination: string
  /** The own containment entry name, generated before the lock is taken. */
  entryName: string
  /** The archive source, for failure messages. */
  source: string
}

/**
 * Issue #224: run `section` while holding the destination's extract lock.
 *
 * A contended apply waits up to `waitSeconds` in bounded polls and reclaims a
 * stale lock in any round; a wait that runs out fails with the holder's
 * details. The section receives the lock handle and must check `isLost()`
 * and embed the guard into the steps that need the lock; a lost lock does not
 * change this function's result. Section throws are rethrown after a
 * best-effort, token-compared release.
 *
 * @param conn - The SSH connection.
 * @param parameters - The destination, the own entry name and the source.
 * @param section - The locked part of the apply.
 * @returns The section's value, or the failure to take the lock.
 */
export async function withArchiveExtractLock<TValue>(
  conn: SshConnection,
  parameters: ArchiveExtractLockParameters,
  section: (lock: MutexLockHandle) => Promise<TValue>
): Promise<MutexLockResult<TValue>> {
  const { destination, entryName, source } = parameters
  const settings = archiveExtractLockSettings()
  const lockName = archiveExtractLockName(destination)
  return withMutexLock(conn, {
    describeWaitFailure: (context) => describeArchiveExtractWaitFailure(destination, context),
    failureMessage: `[archive.extract] refusing to extract ${source}: failed to take the extract lock ${flagLockDisplayPath(lockName)} of ${destination}`,
    heartbeat: { intervalMilliseconds: settings.heartbeatIntervalMilliseconds },
    holder: archiveExtractLockHolder(entryName),
    lockName,
    propagateSectionThrows: true,
    refreshGuardSeconds: settings.refreshGuardSeconds,
    section,
    staleSeconds: settings.staleSeconds,
    waitSeconds: settings.waitSeconds,
  })
}
