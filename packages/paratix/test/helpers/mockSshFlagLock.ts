/**
 * Helpers describing flag-lock implementation details so that the generic
 * mock SSH can expose a narrow, explicit opt-in for production lock internals
 * without making strict mocks globally permissive.
 */
/* eslint-disable security/detect-non-literal-regexp -- Patterns are composed from fixed regex fragments, not runtime input. */
/**
 * R-0000634: deterministic stand-in token returned by the
 * `awk 'NR==1{print $1}' .../holder` readback so the verified release
 * command can match against a known value in tests that opt into
 * flag-lock internal defaults.
 */
export const MOCK_FLAG_LOCK_HOLDER_TOKEN = "12345@mockhost"

const VALID_FLAG_NAME_PATTERN_SOURCE = String.raw`[A-Za-z0-9](?:[A-Za-z0-9_\-]|\.[A-Za-z0-9])*`
const VALID_MUTEX_LOCK_NAME_PATTERN_SOURCE = String.raw`[A-Za-z0-9](?:[A-Za-z0-9_\-]|\.[A-Za-z0-9])*-mutex`
const FLAGS_DIRECTORY_PATTERN_SOURCE = String.raw`\/var\/lib\/paratix\/flags`

function flagPathPattern(
  lockGroupName: string,
  namePatternSource = VALID_FLAG_NAME_PATTERN_SOURCE
): string {
  return `${FLAGS_DIRECTORY_PATTERN_SOURCE}\\/'(?<${lockGroupName}>${namePatternSource})'`
}

function sameFlagPathPattern(lockGroupName: string): string {
  return `${FLAGS_DIRECTORY_PATTERN_SOURCE}\\/'\\k<${lockGroupName}>'`
}

function quotedMarkerPathPattern(lockGroupName: string): string {
  return `'${FLAGS_DIRECTORY_PATTERN_SOURCE}\\/(?<${lockGroupName}>${VALID_FLAG_NAME_PATTERN_SOURCE})\\/holder'`
}

function sameQuotedMarkerPathPattern(lockGroupName: string): string {
  return `'${FLAGS_DIRECTORY_PATTERN_SOURCE}\\/\\k<${lockGroupName}>\\/holder'`
}

function markerPathPattern(lockGroupName: string): string {
  return `${flagPathPattern(lockGroupName)}\\/holder`
}

function sameMarkerPathPattern(lockGroupName: string): string {
  return `${sameFlagPathPattern(lockGroupName)}\\/holder`
}

const FLAG_LOCK_INTERNAL_SUCCESS_PATTERNS: RegExp[] = [
  // R-0000494: hostname is now captured via `ssh.output("hostname")` before the
  // marker write, so the literal hostname is shell-quoted into the printf. The
  // captured value may be empty (catch fallback) or any non-double-quote string.
  new RegExp(
    `^printf '%s@%s %s\\\\n' "\\$\\$" [^"]+ "\\$\\(date \\+%s\\)" > ${markerPathPattern("holderWriteLock")}$`,
    "v"
  ),
  // R-0000749: production code now emits the `--` separator before path
  // arguments in rm/rmdir/awk invocations.
  new RegExp(`^rm -f -- ${markerPathPattern("holderRemovalLock")}$`, "v"),
  // R-0000634: verified release combines the ownership check, marker
  // removal and `rmdir` into a single shell statement to keep the steps
  // atomic against a concurrent stale-lock reclaim.
  // R-0000758: release captures the awk readback into `$awk_token` so the
  // awk exit code can be inspected; the comparison uses the POSIX
  // `x`-prefix idiom on both sides of `=`.
  // R-0000803: the awk path is quoted as a single token (`'…/holder'`),
  // while rm/rmdir use the partially quoted `${markerPath}`/`${lock}` form.
  new RegExp(
    `^awk_token=\\$\\(awk 'NR==1\\{print \\$1\\}' ${quotedMarkerPathPattern("releaseLock")} 2>\\/dev\\/null\\); awk_status=\\$\\?; \\[ "\\$awk_status" = 0 \\] && \\[ "x\\$awk_token" = 'x[^']*' \\] && rm -f -- ${sameMarkerPathPattern("releaseLock")} && rmdir -- ${sameFlagPathPattern("releaseLock")}$`,
    "v"
  ),
  // Mutex-lock acquire and release commands target lock directories whose
  // last path segment ends in the `-mutex` suffix.
  new RegExp(
    `^mkdir ${flagPathPattern("mutexAcquireLock", VALID_MUTEX_LOCK_NAME_PATTERN_SOURCE)}$`,
    "v"
  ),
  new RegExp(
    `^rmdir -- ${flagPathPattern("mutexReleaseLock", VALID_MUTEX_LOCK_NAME_PATTERN_SOURCE)}$`,
    "v"
  ),
  /^mkdir -p \/var\/lib\/paratix\/flags$/v,
]

/**
 * Pattern matched by the holder-marker readback `ssh.output` invocation
 * (R-0000634). The readback is issued for every successful acquire so
 * `releaseFlagLock` can verify ownership.
 */
// R-0000749: awk now receives the path after a `--` separator.
// R-0000803: the awk path is shell-quoted as a single token.
const FLAG_LOCK_HOLDER_READBACK_PATTERN = new RegExp(
  `^awk 'NR==1\\{print \\$1\\}' ${quotedMarkerPathPattern("holderReadbackLock")}$`,
  "v"
)

/**
 * Pattern matched by the mutex-lock release wait loop.
 */
const MUTEX_LOCK_WAIT_PATTERN = new RegExp(
  `^i=0; while \\[ -d ${flagPathPattern("waitLock")} \\] && \\[ "\\$i" -lt \\d+ \\]; do sleep 1; i=\\$\\(\\(i\\+1\\)\\); done; \\[ ! -d ${sameFlagPathPattern("waitLock")} \\]$`,
  "v"
)

/**
 * Pattern matched by the stale-lock reclaim probe.
 *
 * R-0000671: the reclaim path now captures the stale holder token via an
 * intermediate `STALE_TOKEN="$(...)";` shell statement before the
 * `find ... -mmin` check, so the matcher must tolerate that prefix.
 */
// R-0000749: awk now emits the `--` separator before its path argument.
const FLAG_LOCK_RECLAIM_PATTERN = new RegExp(
  `^if \\[ -d ${flagPathPattern("reclaimLock")} \\]; then if \\[ -f ${sameMarkerPathPattern("reclaimLock")} \\]; then STALE_TOKEN="\\$\\(awk 'NR==1\\{print \\$1\\}' ${sameQuotedMarkerPathPattern("reclaimLock")} 2>\\/dev\\/null\\)"; if find ${sameMarkerPathPattern("reclaimLock")} -maxdepth 0 -mmin \\+\\d+ -print -quit \\| grep -q \\.; then \\[ "\\$\\(awk 'NR==1\\{print \\$1\\}' ${sameQuotedMarkerPathPattern("reclaimLock")} 2>\\/dev\\/null\\)" = "\\$STALE_TOKEN" \\] && rm -f -- ${sameMarkerPathPattern("reclaimLock")} && rmdir -- ${sameFlagPathPattern("reclaimLock")}; else exit 1; fi; else if find ${sameFlagPathPattern("reclaimLock")} -maxdepth 0 -mmin \\+\\d+ -print -quit \\| grep -q \\.; then find ${sameFlagPathPattern("reclaimLock")} -maxdepth 0 -mmin \\+\\d+ -print -quit \\| grep -q \\. && rm -f -- ${sameMarkerPathPattern("reclaimLock")} && rmdir -- ${sameFlagPathPattern("reclaimLock")}; else exit 1; fi; fi; else exit 1; fi$`,
  "v"
)

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
  // R-0000803: awk now receives the marker as a single shell-quoted token.
  const quotedMarkerPath = `'/var/lib/paratix/flags/${lockName}/holder'`
  // R-0000749: production code now emits the `--` separator before path
  // arguments in awk / rm / rmdir invocations.
  // R-0000758: release captures the awk readback in `$awk_token` and uses
  // the POSIX `x`-prefix comparison so unusual awk output cannot collide
  // with `[` operator syntax.
  const pattern = new RegExp(
    `^awk_token=\\$\\(awk 'NR==1\\{print \\$1\\}' ${escapeRegex(quotedMarkerPath)} 2>/dev/null\\); awk_status=\\$\\?; \\[ "\\$awk_status" = 0 \\] && \\[ "x\\$awk_token" = 'x[^']*' \\] && rm -f -- ${escapeRegex(markerPath)} && rmdir -- ${escapeRegex(lockPath)}$`,
    "v"
  )
  return (call) => pattern.test(call)
}
