/**
 * Pure POSIX shell builders and validators for the flag-lock layer.
 *
 * Issue #224: the refresh guard, the stale-reclaim statement, the holder
 * marker write and the holder diagnostics read are rendered here from
 * already-quoted shell words, so the production command strings can be run
 * verbatim against a temporary directory by the shell smoke tests. The
 * SSH-facing helpers in `flagLock.ts` and `flagLockRefresh.ts` render the
 * same builders against `/var/lib/paratix/flags/<lockName>`.
 */
import { shellQuote } from "../ssh.js"

/** File name of the holder marker inside a lock directory. */
export const FLAG_LOCK_HOLDER_MARKER_NAME = "holder"

const SECONDS_PER_MINUTE = 60

/**
 * Issue #224: an age threshold expressed with the `find -mmin +N` primitive.
 *
 * `find -mmin +N` matches files whose age is strictly above `N × 60`
 * seconds, on GNU and BSD `find` alike. `effectiveAgeSeconds` is that
 * bound: a marker matches (is "older than the threshold") exactly when its
 * age exceeds `effectiveAgeSeconds`.
 */
export type FlagLockAgeThreshold = {
  /** Strict lower age bound in seconds, `mminMinutes × 60`. */
  effectiveAgeSeconds: number
  /** The `N` passed to `find -mmin +N`. */
  mminMinutes: number
}

/**
 * Issue #224: derive the `find -mmin +N` threshold for an age given in
 * seconds, using the same rounding as the stale-lock reclaim has always
 * used: `N = max(1, ceil(seconds / 60)) - 1`. For example `600` yields
 * `-mmin +9`, which matches ages above 540 seconds, and `360` yields
 * `-mmin +5` (above 300 seconds). Callers stating invariants between two
 * thresholds must compare the `effectiveAgeSeconds` values, not the inputs.
 *
 * @param seconds - The configured age in seconds; a finite number ≥ 0.
 * @returns The `-mmin` argument and the effective age bound in seconds.
 * @throws {Error} When `seconds` is negative or not finite.
 */
export function flagLockAgeThreshold(seconds: number): FlagLockAgeThreshold {
  if (!Number.isFinite(seconds) || seconds < 0) {
    throw new Error(`flag lock age threshold must be a finite number ≥ 0, got: ${String(seconds)}`)
  }
  const mminMinutes = Math.max(1, Math.ceil(seconds / SECONDS_PER_MINUTE)) - 1
  return { effectiveAgeSeconds: mminMinutes * SECONDS_PER_MINUTE, mminMinutes }
}

/**
 * Issue #224: a shell operand of a guard fragment. A `literal` is
 * single-quoted into the script; a `parameter` expands a shell parameter
 * such as the positional `"${1}"` of a script that receives the lock path
 * and token as arguments.
 */
export type FlagLockShellOperand =
  { kind: "literal"; value: string } | { kind: "parameter"; name: string }

const SHELL_PARAMETER_NAME_PATTERN = /^(?:[1-9]\d*|[A-Z_a-z]\w*)$/v

function renderOperand(operand: FlagLockShellOperand): string {
  if (operand.kind === "literal") return shellQuote(operand.value)
  if (!SHELL_PARAMETER_NAME_PATTERN.test(operand.name)) {
    throw new Error(`invalid shell parameter name for a flag lock operand: ${operand.name}`)
  }
  return `"\${${operand.name}}"`
}

function renderMarkerOperand(lockDirectory: FlagLockShellOperand): string {
  if (lockDirectory.kind === "literal") {
    return shellQuote(`${lockDirectory.value}/${FLAG_LOCK_HOLDER_MARKER_NAME}`)
  }
  return `${renderOperand(lockDirectory)}/${FLAG_LOCK_HOLDER_MARKER_NAME}`
}

/**
 * Issue #224: build the refresh guard as a prefixable POSIX shell fragment.
 *
 * The fragment is one brace group, `{ …; }`, whose exit status is `0` only
 * when all of the following hold, in this order:
 * 1. the lock directory exists,
 * 2. its holder marker is a regular file,
 * 3. the first whitespace-separated field of marker line 1 equals the token,
 * 4. the marker is NOT older than the guard threshold
 *    (`find -mmin +N` with `N` from {@link flagLockAgeThreshold}), and
 * 5. `touch -c` refreshed the marker's mtime.
 *
 * Any failed step yields a non-zero status (normally `1`) and leaves the
 * marker untouched, because `touch` is the last step of the `&&` chain. The
 * fragment never calls `exit`, reads no stdin (every command that could
 * read it is redirected from `/dev/null`), and writes nothing to stdout, so
 * it can be prepended to an exec that streams its own input:
 * `<guard> || exit <G>; <command>`.
 *
 * Once a marker is older than the stale-reclaim threshold it is also older
 * than any guard threshold that is not larger, so a reclaimable marker can
 * never be refreshed; and a marker the guard may refresh is younger than
 * the reclaim threshold, so it is never reclaimed.
 *
 * @param parameters - Guard inputs.
 * @param parameters.guardSeconds - Guard age in seconds; converted with
 *   {@link flagLockAgeThreshold}.
 * @param parameters.lockDirectory - The lock directory path operand.
 * @param parameters.token - The holder token operand (marker line 1).
 * @returns The shell fragment.
 */
export function buildFlagLockRefreshGuard(parameters: {
  guardSeconds: number
  lockDirectory: FlagLockShellOperand
  token: FlagLockShellOperand
}): string {
  const { mminMinutes } = flagLockAgeThreshold(parameters.guardSeconds)
  const lock = renderOperand(parameters.lockDirectory)
  const marker = renderMarkerOperand(parameters.lockDirectory)
  const token = renderOperand(parameters.token)
  return (
    `{ [ -d ${lock} ] && [ -f ${marker} ] && ` +
    `[ "x$(awk 'NR==1{print $1}' ${marker} 2>/dev/null </dev/null)" = x${token} ] && ` +
    `[ -n "$(find ${marker} -maxdepth 0 ! -mmin +${String(mminMinutes)} -print 2>/dev/null </dev/null)" ] && ` +
    `touch -c ${marker} </dev/null 2>/dev/null; }`
  )
}

/**
 * Issue #224: build the token-verified stale-lock reclaim statement used by
 * `tryReclaimStaleFlagLock`. The words are inserted verbatim and must
 * already be shell-quoted. See `tryReclaimStaleFlagLock` for the R-0000671 /
 * R-0000698 reasoning behind the shape.
 *
 * Exported for the shell smoke tests.
 *
 * @internal
 * @param parameters - Pre-quoted shell words and the stale threshold.
 * @param parameters.awkMarkerWord - The marker path as one quoted word for awk.
 * @param parameters.lockWord - The lock directory path word.
 * @param parameters.markerWord - The marker path word for `find`/`rm`/`[`.
 * @param parameters.staleSeconds - Stale age in seconds; converted with
 *   {@link flagLockAgeThreshold}.
 * @returns The reclaim statement; exit `0` means the lock was removed.
 */
export function buildStaleFlagLockReclaimCommand(parameters: {
  awkMarkerWord: string
  lockWord: string
  markerWord: string
  staleSeconds: number
}): string {
  const { awkMarkerWord, lockWord, markerWord } = parameters
  const mmin = String(flagLockAgeThreshold(parameters.staleSeconds).mminMinutes)
  return (
    `if [ -d ${lockWord} ]; then ` +
    `if [ -f ${markerWord} ]; then ` +
    `STALE_TOKEN="$(awk 'NR==1{print $1}' ${awkMarkerWord} 2>/dev/null)"; ` +
    `if find ${markerWord} -maxdepth 0 -mmin +${mmin} -print -quit | grep -q .; then ` +
    `[ "$(awk 'NR==1{print $1}' ${awkMarkerWord} 2>/dev/null)" = "$STALE_TOKEN" ] && ` +
    `rm -f -- ${markerWord} && rmdir -- ${lockWord}; ` +
    `else exit 1; fi; ` +
    `else ` +
    `if find ${lockWord} -maxdepth 0 -mmin +${mmin} -print -quit | grep -q .; then ` +
    `find ${lockWord} -maxdepth 0 -mmin +${mmin} -print -quit | grep -q . && ` +
    `rm -f -- ${markerWord} && rmdir -- ${lockWord}; ` +
    `else exit 1; fi; ` +
    `fi; ` +
    `else exit 1; fi`
  )
}

/**
 * Issue #224: a caller-supplied holder identity for a flag lock. `token`
 * becomes marker line 1 and is the only value compared on release and by
 * the refresh guard; `ownerLines` follow it for operators (for example the
 * controller hostname and PID, the start time, an entry name).
 */
export type FlagLockHolder = {
  ownerLines?: readonly string[]
  token: string
}

// A token is one awk field: no whitespace, no quotes, no shell expansion
// characters. It starts with an alphanumeric character so it can never be
// mistaken for an option.
const FLAG_LOCK_TOKEN_PATTERN = /^[A-Za-z0-9][\w.:@+=\-]{7,127}$/v
// Owner lines are printable ASCII without quotes, backslash, backtick or
// `$`; they are single-quoted into the marker write anyway, the narrower set
// is defence in depth for operator-facing diagnostics.
const FLAG_LOCK_OWNER_LINE_PATTERN = /^[[\x20-\x7E]--[\x22\x24\x27\x5C\x60]]{1,200}$/v
const MAX_FLAG_LOCK_OWNER_LINES = 8

/**
 * Issue #224: validate a caller-supplied holder before it reaches a remote
 * shell. Throws because an invalid holder is a programmer mistake.
 *
 * @param holder - The holder identity to validate.
 * @throws {Error} When the token or an owner line is outside the allowed
 *   character set or length, or when there are too many owner lines.
 */
export function validateFlagLockHolder(holder: FlagLockHolder): void {
  if (!FLAG_LOCK_TOKEN_PATTERN.test(holder.token)) {
    throw new Error(
      `flag lock holder token must match ${String(FLAG_LOCK_TOKEN_PATTERN)}, got: ${JSON.stringify(holder.token)}`
    )
  }
  const ownerLines = holder.ownerLines ?? []
  if (ownerLines.length > MAX_FLAG_LOCK_OWNER_LINES) {
    throw new Error(
      `flag lock holder allows at most ${String(MAX_FLAG_LOCK_OWNER_LINES)} owner lines, got ${String(ownerLines.length)}`
    )
  }
  for (const line of ownerLines) {
    if (!FLAG_LOCK_OWNER_LINE_PATTERN.test(line)) {
      throw new Error(
        `flag lock owner line must be 1-200 printable ASCII characters without quotes, backslash, backtick or $, got: ${JSON.stringify(line)}`
      )
    }
  }
}

/**
 * Issue #224: build the marker write for a caller-supplied holder: the
 * token on line 1, then one owner line per line. `printf` reuses its
 * format for every argument, so each word becomes its own line.
 *
 * Exported for the shell smoke tests.
 *
 * @internal
 * @param markerWord - The marker path as a shell word (already quoted).
 * @param holder - A holder that passed {@link validateFlagLockHolder}.
 * @returns The marker write command.
 */
export function buildFlagLockHolderMarkerWrite(markerWord: string, holder: FlagLockHolder): string {
  const words = [holder.token, ...(holder.ownerLines ?? [])].map((word) => shellQuote(word))
  return `printf '%s\\n' ${words.join(" ")} > ${markerWord}`
}
