const SIGNAL_EXIT_BASE = 128
const SIGTERM_NUMBER = 15
const SIGINT_NUMBER = 2

/**
 * Returns the conventional exit code for a termination signal.
 * Follows the POSIX convention of 128 + signal number.
 *
 * @param signal - The received signal (`SIGTERM` or `SIGINT`).
 * @returns The exit code to use when the process is terminated by `signal`.
 */
export function signalExitCode(signal: NodeJS.Signals): number {
  return SIGNAL_EXIT_BASE + (signal === "SIGTERM" ? SIGTERM_NUMBER : SIGINT_NUMBER)
}

/**
 * Sets `process.exitCode` based on the run outcome.
 * A received shutdown signal takes precedence over module failures.
 *
 * @param shutdownSignal - The signal that interrupted the run, or `null` if the
 *   run completed normally.
 * @param stats - Accumulated run statistics used to detect module failures.
 * @param stats.failed - Number of modules that failed.
 */
export function resolveExitCode(
  shutdownSignal: NodeJS.Signals | null,
  stats: { failed: number }
): void {
  if (shutdownSignal != null) {
    process.exitCode = signalExitCode(shutdownSignal)
  } else if (stats.failed > 0) {
    process.exitCode = 1
  }
}
