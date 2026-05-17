/**
 * Helpers describing flag-lock implementation details so that the generic
 * mock SSH can expose a narrow, explicit opt-in for production lock internals
 * without making strict mocks globally permissive.
 */
/**
 * R-0000634: deterministic stand-in token returned by the
 * `awk 'NR==1{print $1}' .../holder` readback so the verified release
 * command can match against a known value in tests that opt into
 * flag-lock internal defaults.
 */
export const MOCK_FLAG_LOCK_HOLDER_TOKEN = "12345@mockhost"

const FLAG_LOCK_INTERNAL_SUCCESS_PATTERNS: RegExp[] = [
  // R-0000494: hostname is now captured via `ssh.output("hostname")` before the
  // marker write, so the literal hostname is shell-quoted into the printf. The
  // captured value may be empty (catch fallback) or any non-double-quote string.
  /^printf '%s@%s %s\\n' "\$\$" [^"]+ "\$\(date \+%s\)" > \S+\/holder$/v,
  /^rm -f \S+\/holder$/v,
  // R-0000634: verified release combines the ownership check, marker
  // removal and `rmdir` into a single shell statement to keep the steps
  // atomic against a concurrent stale-lock reclaim.
  /^\[ "\$\(awk 'NR==1\{print \$1\}' \S+\/holder 2>\/dev\/null\)" = '[^']*' \] && rm -f \S+\/holder && rmdir \S+$/v,
  // Mutex-lock acquire and release commands target lock directories whose
  // last path segment ends in the `-mutex` suffix.
  /^mkdir \/var\/lib\/paratix\/flags\/'[\w.\-]*-mutex'$/v,
  /^rmdir \/var\/lib\/paratix\/flags\/'[\w.\-]*-mutex'$/v,
  /^mkdir -p \/var\/lib\/paratix\/flags$/v,
]

/**
 * Pattern matched by the holder-marker readback `ssh.output` invocation
 * (R-0000634). The readback is issued for every successful acquire so
 * `releaseFlagLock` can verify ownership.
 */
const FLAG_LOCK_HOLDER_READBACK_PATTERN = /^awk 'NR==1\{print \$1\}' \S+\/holder$/v

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

/**
 * @param command - The command intercepted by the mock.
 * @returns `true` if the command is the holder-marker readback used by
 *   `writeFlagLockHolderMarker` after a successful acquire (R-0000634).
 */
export function isFlagLockHolderReadback(command: string): boolean {
  return FLAG_LOCK_HOLDER_READBACK_PATTERN.test(command)
}

const REGEX_METACHARACTERS = new Set([
  "?",
  ".",
  "(",
  ")",
  "[",
  "]",
  "{",
  "}",
  "*",
  "\\",
  "^",
  "+",
  "|",
  "$",
])

function escapeRegex(value: string): string {
  let escaped = ""
  for (const char of value) {
    escaped += REGEX_METACHARACTERS.has(char) ? `\\${char}` : char
  }
  return escaped
}

/**
 * R-0000634: build a predicate that matches the verified-release shell
 * statement for a given lock name. Centralised so individual tests do not
 * trip on `eslint-plugin-vitest(no-conditional-in-test)` by composing the
 * prefix/suffix check inline.
 *
 * @param lockName - The validated lock identifier (without quotes).
 * @returns Predicate that returns `true` when `call` is the verified
 *   release command for `lockName`.
 */
export function makeIsVerifiedReleaseCall(lockName: string): (call: string) => boolean {
  const markerPath = `/var/lib/paratix/flags/'${lockName}'/holder`
  const lockPath = `/var/lib/paratix/flags/'${lockName}'`
  // eslint-disable-next-line security/detect-non-literal-regexp -- markerPath and lockPath are derived from a validated lockName and shell-escaped above
  const pattern = new RegExp(
    `^\\[ "\\$\\(awk 'NR==1\\{print \\$1\\}' ${escapeRegex(markerPath)} 2>/dev/null\\)" = '[^']*' \\] && rm -f ${escapeRegex(markerPath)} && rmdir ${escapeRegex(lockPath)}$`,
    "v"
  )
  return (call) => pattern.test(call)
}
