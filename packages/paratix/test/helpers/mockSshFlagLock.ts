/**
 * Helpers describing flag-lock implementation details so that the generic
 * mock SSH can expose a narrow, explicit opt-in for production lock internals
 * without making strict mocks globally permissive.
 */
const FLAG_LOCK_INTERNAL_SUCCESS_PATTERNS: RegExp[] = [
  /^printf '%s@%s %s\\n' "\$\$" "\$\(hostname\)" "\$\(date \+%s\)" > \S+\/holder$/v,
  /^rm -f \S+\/holder$/v,
  // Mutex-lock acquire and release commands target lock directories whose
  // last path segment ends in the `-mutex` suffix.
  /^mkdir \/var\/lib\/paratix\/flags\/'[\w.\-]*-mutex'$/v,
  /^rmdir \/var\/lib\/paratix\/flags\/'[\w.\-]*-mutex'$/v,
  /^mkdir -p \/var\/lib\/paratix\/flags$/v,
]

/**
 * Pattern matched by the mutex-lock release wait loop.
 */
const MUTEX_LOCK_WAIT_PATTERN =
  /^i=0; while \[ -d \S+ \] && \[ "\$i" -lt \d+ \]; do sleep 1; i=\$\(\(i\+1\)\); done; \[ ! -d \S+ \]$/v

/**
 * Pattern matched by the stale-lock reclaim probe.
 */
const FLAG_LOCK_RECLAIM_PATTERN =
  /^if \[ -d \S+ \]; then if \[ -f \S+\/holder \]; then if find \S+\/holder -maxdepth 0 -mmin /v

/**
 * @param command - The command intercepted by the mock.
 * @returns `true` if the command is a known internal lock command that can
 *   default to success when a test explicitly opts into lock defaults.
 */
export function isFlagLockInternalSuccessCommand(command: string): boolean {
  if (FLAG_LOCK_INTERNAL_SUCCESS_PATTERNS.some((pattern) => pattern.test(command))) return true
  return MUTEX_LOCK_WAIT_PATTERN.test(command)
}

/**
 * @param command - The command intercepted by the mock.
 * @returns `true` if the command is the stale-lock reclaim probe.
 */
export function isFlagLockReclaimProbe(command: string): boolean {
  return FLAG_LOCK_RECLAIM_PATTERN.test(command)
}
