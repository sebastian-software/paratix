/**
 * Issue #224: bounded waiting for a contended flag lock.
 *
 * Before #224 a contended acquirer slept up to the whole wait window
 * (300 s by default) inside one remote exec, although every exec is
 * limited to 120 s by the SSH layer, so the wait threw a timeout instead
 * of returning a structured failure. It also tried a stale reclaim only
 * once at the very end, and after a "resolved" wait that then lost the
 * `mkdir` race it started a fresh full wait.
 *
 * Waiting now runs in rounds against one overall budget. The first
 * contended result tries a stale reclaim right away, before any poll, so a
 * lock that is already stale does not cost a full poll round. Every round
 * then is a short poll exec of at most {@link FLAG_LOCK_WAIT_POLL_SECONDS}
 * followed, while the lock is still held, by another stale-reclaim attempt.
 * Lost re-acquire races retry within the same budget, and an exhausted
 * budget is reported to the caller instead of throwing.
 */
import type { ExecResult, ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { flagPath, tryReclaimStaleFlagLock } from "./flagLock.js"

/**
 * Longest single poll exec while waiting for a lock, in seconds. Well
 * below the 120 s SSH exec timeout so a poll can never time out.
 */
export const FLAG_LOCK_WAIT_POLL_SECONDS = 60

const MILLISECONDS_PER_SECOND = 1000

/**
 * Issue #224: one overall wait deadline shared by every poll round and
 * every re-acquire attempt of one lock acquisition.
 *
 * The budget is charged twice over: by wall-clock time against a fixed
 * deadline, and by the poll seconds a round consumed on the target (a
 * still-held poll used its full duration, a released poll at least one
 * second). The smaller remainder wins, so rounds terminate both against a
 * real remote clock and against instant test doubles.
 */
export type FlagLockWaitBudget = {
  /**
   * `true` exactly once per budget: for the stale reclaim tried right after
   * the first contended result, before the first poll.
   */
  claimInitialReclaim: () => boolean
  /** Whether the budget is spent. The first round always runs. */
  isExhausted: () => boolean
  /** Duration of the next poll exec in seconds, `0..FLAG_LOCK_WAIT_POLL_SECONDS`. */
  nextPollSeconds: () => number
  /** Record a finished round. */
  recordRound: (round: { held: boolean; pollSeconds: number; startedAt: number }) => void
  /** Number of rounds recorded so far. */
  rounds: () => number
  readonly totalSeconds: number
}

/**
 * Issue #224: create the wait budget for one lock acquisition.
 *
 * @param totalSeconds - Overall wait window in seconds.
 * @param now - Clock in milliseconds; injectable for tests.
 * @returns A fresh budget.
 */
export function createFlagLockWaitBudget(
  totalSeconds: number,
  now: () => number = Date.now
): FlagLockWaitBudget {
  const deadline = now() + totalSeconds * MILLISECONDS_PER_SECOND
  let consumedSeconds = 0
  let rounds = 0
  let initialReclaimClaimed = false
  const remainingSeconds = (): number => {
    const wallClock = Math.ceil((deadline - now()) / MILLISECONDS_PER_SECOND)
    return Math.max(0, Math.min(totalSeconds - consumedSeconds, wallClock))
  }
  return {
    claimInitialReclaim() {
      if (initialReclaimClaimed) return false
      initialReclaimClaimed = true
      return true
    },
    isExhausted: () => rounds > 0 && remainingSeconds() <= 0,
    nextPollSeconds: () => Math.min(FLAG_LOCK_WAIT_POLL_SECONDS, remainingSeconds()),
    recordRound(round) {
      rounds += 1
      const elapsed = Math.ceil((now() - round.startedAt) / MILLISECONDS_PER_SECOND)
      consumedSeconds += Math.max(1, round.held ? round.pollSeconds : 0, elapsed)
    },
    rounds: () => rounds,
    totalSeconds,
  }
}

/**
 * Issue #224: the mutex poll exec. The shape (`i=0; while [ -d <lock> ] …`)
 * is unchanged from before #224; only the bound is now one poll round.
 *
 * @param lockName - The validated lock identifier.
 * @param pollSeconds - The poll duration in seconds.
 * @returns The poll command; exit `0` means the lock directory is gone.
 */
function mutexPollCommand(lockName: string, pollSeconds: number): string {
  const lock = flagPath(lockName)
  return (
    `i=0; while [ -d ${lock} ] && [ "$i" -lt ${String(pollSeconds)} ]; do ` +
    "sleep 1; i=$((i+1)); done; " +
    `[ ! -d ${lock} ]`
  )
}

/**
 * Issue #224: try the one stale reclaim a budget allows before its first
 * poll. It costs one extra exec, and only on the contended path; a lock
 * that is already stale is then reclaimed at once instead of after a full
 * poll round.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Reclaim inputs.
 * @param parameters.lockName - The validated lock identifier.
 * @param parameters.staleSeconds - Stale-reclaim threshold in seconds.
 * @param budget - The acquisition's shared wait budget.
 * @returns `true` when the stale lock was reclaimed.
 */
async function tryInitialReclaim(
  ssh: SshConnection,
  parameters: { lockName: string; staleSeconds: number },
  budget: FlagLockWaitBudget
): Promise<boolean> {
  if (!budget.claimInitialReclaim()) return false
  return tryReclaimStaleFlagLock(ssh, parameters.lockName, parameters.staleSeconds)
}

/**
 * Issue #224: wait for a contended mutex lock in bounded rounds. The first
 * contended result tries a stale reclaim before polling; each round then
 * polls for at most {@link FLAG_LOCK_WAIT_POLL_SECONDS} and, while the lock
 * is still held, tries a stale reclaim again.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Wait inputs.
 * @param parameters.lockName - The validated lock identifier.
 * @param parameters.staleSeconds - Stale-reclaim threshold in seconds.
 * @param budget - The acquisition's shared wait budget.
 * @returns `released` when the lock went away or was reclaimed (the caller
 *   re-acquires), `exhausted` when the budget ran out while it was held.
 */
export async function waitForMutexLockRound(
  ssh: SshConnection,
  parameters: { lockName: string; staleSeconds: number },
  budget: FlagLockWaitBudget
): Promise<"exhausted" | "released"> {
  if (budget.isExhausted()) return "exhausted"
  if (await tryInitialReclaim(ssh, parameters, budget)) return "released"
  const pollSeconds = budget.nextPollSeconds()
  const startedAt = Date.now()
  const probe = await ssh.exec(mutexPollCommand(parameters.lockName, pollSeconds), {
    ignoreExitCode: true,
    silent: true,
  })
  const held = probe.code !== 0
  budget.recordRound({ held, pollSeconds, startedAt })
  if (!held) return "released"
  if (await tryReclaimStaleFlagLock(ssh, parameters.lockName, parameters.staleSeconds)) {
    return "released"
  }
  return waitForMutexLockRound(ssh, parameters, budget)
}

/**
 * Wait until a flag lock is released or its flag file appears, in bounded
 * rounds (issue #224): a stale reclaim right after the first contended
 * result, before any poll, and another one in every still-held round.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Wait inputs.
 * @param parameters.flagName - The validated flag identifier.
 * @param parameters.lockName - The validated lock identifier.
 * @param parameters.staleSeconds - Stale-reclaim threshold in seconds.
 * @param budget - The acquisition's shared wait budget.
 * @returns `"resolved"` when the caller should retry, otherwise the failed
 *   `ModuleResult` of the last poll once the budget is exhausted.
 */
export async function waitForFlagLockResolution(
  ssh: SshConnection,
  parameters: { flagName: string; lockName: string; staleSeconds: number },
  budget: FlagLockWaitBudget
): Promise<"resolved" | ModuleResult> {
  // A lost re-acquire race after the budget ran out ends the wait here
  // instead of polling again; no poll result exists for this attempt.
  if (budget.isExhausted()) return flagWaitTimeout(parameters.lockName, undefined)
  if (await tryInitialReclaim(ssh, parameters, budget)) return "resolved"
  const pollSeconds = budget.nextPollSeconds()
  const startedAt = Date.now()
  const result = await ssh.exec(flagPollCommand(parameters, pollSeconds), {
    ignoreExitCode: true,
    silent: true,
  })
  budget.recordRound({ held: result.code !== 0, pollSeconds, startedAt })
  if (result.code === 0) return "resolved"
  // Still held — try to reclaim a stale lock so the next attempt can
  // proceed instead of failing forever after a crashed holder.
  if (await tryReclaimStaleFlagLock(ssh, parameters.lockName, parameters.staleSeconds)) {
    return "resolved"
  }
  if (budget.isExhausted()) return flagWaitTimeout(parameters.lockName, result)
  return waitForFlagLockResolution(ssh, parameters, budget)
}

function flagPollCommand(
  parameters: { flagName: string; lockName: string },
  pollSeconds: number
): string {
  const flag = flagPath(parameters.flagName)
  const lock = flagPath(parameters.lockName)
  return (
    `i=0; while [ -d ${lock} ] && [ ! -f ${flag} ] && [ "$i" -lt ${String(pollSeconds)} ]; do ` +
    "sleep 1; i=$((i+1)); done; " +
    `[ ! -d ${lock} ] || [ -f ${flag} ]`
  )
}

function flagWaitTimeout(lockName: string, result: ExecResult | undefined): ModuleResult {
  const message = `[moduleHelpers] timed out waiting for flag lock ${lockName}`
  return result === undefined ? failed(message) : failedCommand(message, result)
}
