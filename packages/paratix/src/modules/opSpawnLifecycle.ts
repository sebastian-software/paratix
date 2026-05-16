import type { ChildProcess } from "node:child_process"

import { getRunnerAbortSignal } from "../runnerAbortSignal.js"

/** Grace window between SIGTERM and SIGKILL when killing a hung `op` child. */
const OP_KILL_GRACE_MILLISECONDS = 1000

/**
 * Whether `child` has already produced an `exit` event. Checks both
 * `exitCode` (process exited normally) and `signalCode` (process was
 * terminated by a signal) so a child that has been killed via SIGTERM is
 * not re-killed by a subsequent escalation pass.
 *
 * @param child - The spawned child process to probe.
 * @returns `true` when the process has exited or been signal-terminated.
 */
function childHasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null
}

/**
 * Force-kill a hung child by escalating SIGTERM → SIGKILL after a short
 * grace period. Used when the runner is shutting down or when the per-call
 * timeout fires (R-0000220).
 *
 * @param child - The spawned child process to terminate.
 */
function killChildEscalating(child: ChildProcess): void {
  if (childHasExited(child)) return
  try {
    child.kill("SIGTERM")
  } catch {
    // ignored — child may have exited between the guard and kill
  }
  setTimeout(() => {
    if (childHasExited(child)) return
    try {
      child.kill("SIGKILL")
    } catch {
      // ignored — best-effort SIGKILL
    }
  }, OP_KILL_GRACE_MILLISECONDS).unref()
}

/**
 * Wire the per-call abort signal and timeout onto a spawned child so a stuck
 * `op` invocation cannot hang the runner.
 *
 * @param parameters - Wiring inputs.
 * @param parameters.child - The spawned child process.
 * @param parameters.command - The executable name used in error messages.
 * @param parameters.rejectOnce - Reject closure invoked when the timeout or
 *   abort signal fires.
 * @param parameters.timeoutMs - Timeout in milliseconds; <= 0 disables the timer.
 * @returns A `cleanup` function that detaches both the timer and the abort
 *   listener; safe to call multiple times.
 */
export function attachSpawnLifecycle(parameters: {
  child: ChildProcess
  command: string
  rejectOnce: (error: Error) => void
  timeoutMs: number
}): () => void {
  const { child, command, rejectOnce, timeoutMs } = parameters
  let timeoutHandle: NodeJS.Timeout | undefined
  if (timeoutMs > 0) {
    timeoutHandle = setTimeout(() => {
      killChildEscalating(child)
      rejectOnce(new Error(`${command} timed out after ${String(timeoutMs)}ms`))
    }, timeoutMs)
    timeoutHandle.unref()
  }
  const abortSignal = getRunnerAbortSignal()
  let abortListener: (() => void) | undefined
  if (abortSignal !== undefined) {
    abortListener = (): void => {
      killChildEscalating(child)
      rejectOnce(new Error(`${command} aborted — runner shutdown in progress`))
    }
    // R-0000601: an `aborted` signal that fires between `spawn(...)` and the
    // `addEventListener` call below would otherwise be missed — the listener
    // is registered with `{ once: true }` and only future events trigger it,
    // so the spawned `op` child would keep running until the 60 s timeout.
    // Mirroring the synchronous probe in rsyncProcess.ts:119-124 (R-0000570),
    // check `abortSignal.aborted` first and invoke the listener inline. The
    // returned cleanup only needs to clear the timer because no event
    // listener was ever registered.
    if (abortSignal.aborted) {
      abortListener()
      return (): void => {
        if (timeoutHandle !== undefined) {
          clearTimeout(timeoutHandle)
          timeoutHandle = undefined
        }
      }
    }
    abortSignal.addEventListener("abort", abortListener, { once: true })
  }
  return (): void => {
    if (timeoutHandle !== undefined) {
      clearTimeout(timeoutHandle)
      timeoutHandle = undefined
    }
    if (abortListener !== undefined && abortSignal !== undefined) {
      abortSignal.removeEventListener("abort", abortListener)
      abortListener = undefined
    }
  }
}
