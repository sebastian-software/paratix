/**
 * Helpers describing flag-lock implementation details so that the generic
 * mock SSH stays decoupled from the production behaviour.
 */
const FLAG_LOCK_INTERNAL_SUCCESS_PATTERNS: RegExp[] = [
  /^printf '%s@%s %s\\n' "\$\$" "\$\(hostname\)" "\$\(date \+%s\)" > \S+\/holder$/v,
  /^rm -f \S+\/holder$/v,
]

/**
 * Pattern matched by the stale-lock reclaim probe. Tests that simulate a
 * fresh, held lock should default this command to non-zero so the lock is
 * not silently reclaimed.
 */
const FLAG_LOCK_RECLAIM_PATTERN =
  /^if \[ -d \S+ \]; then if \[ -f \S+\/holder \]; then if find \S+\/holder -maxdepth 0 -mmin /v

/**
 * @param command - The command intercepted by the mock.
 * @returns `true` if the command is an internal holder-marker write or
 *   marker cleanup that should default to success.
 */
export function isFlagLockInternalSuccessCommand(command: string): boolean {
  return FLAG_LOCK_INTERNAL_SUCCESS_PATTERNS.some((pattern) => pattern.test(command))
}

/**
 * @param command - The command intercepted by the mock.
 * @returns `true` if the command is the stale-lock reclaim probe.
 */
export function isFlagLockReclaimProbe(command: string): boolean {
  return FLAG_LOCK_RECLAIM_PATTERN.test(command)
}
