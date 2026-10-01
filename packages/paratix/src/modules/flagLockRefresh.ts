/**
 * Issue #224: SSH-facing refresh guard and holder diagnostics for flag
 * locks. The shell text comes from `flagLockScripts.ts`.
 */
import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { flagLockDisplayPath, validateFlagName } from "./flagLock.js"
import {
  buildFlagLockRefreshGuard,
  FLAG_LOCK_HOLDER_MARKER_NAME,
  type FlagLockAgeThreshold,
} from "./flagLockScripts.js"

/**
 * Issue #224: build the refresh guard fragment for a lock under the flags
 * directory, with the lock path and token as single-quoted literals. See
 * {@link buildFlagLockRefreshGuard} for the fragment contract.
 *
 * @param parameters - Guard inputs.
 * @param parameters.guardSeconds - Guard age in seconds.
 * @param parameters.lockName - The validated lock identifier.
 * @param parameters.token - The holder token (marker line 1).
 * @returns The prefixable shell fragment.
 */
export function flagLockRefreshGuard(parameters: {
  guardSeconds: number
  lockName: string
  token: string
}): string {
  validateFlagName(parameters.lockName, "lockName")
  return buildFlagLockRefreshGuard({
    guardSeconds: parameters.guardSeconds,
    lockDirectory: { kind: "literal", value: flagLockDisplayPath(parameters.lockName) },
    token: { kind: "literal", value: parameters.token },
  })
}

/**
 * Issue #224: run the refresh guard in its own short exec. Succeeds only if
 * the lock still belongs to `token` and its marker is not older than the
 * guard threshold; the marker mtime is then refreshed. An exec that throws
 * (transport failure) propagates; callers that latch a lost lock treat a
 * throw like a refusal.
 *
 * @param ssh - The active SSH connection.
 * @param parameters - Guard inputs, see {@link flagLockRefreshGuard}.
 * @param parameters.guardSeconds - Guard age in seconds.
 * @param parameters.lockName - The validated lock identifier.
 * @param parameters.token - The holder token (marker line 1).
 * @returns `true` when the marker was refreshed, `false` when the guard refused.
 */
export async function refreshFlagLock(
  ssh: SshConnection,
  parameters: { guardSeconds: number; lockName: string; token: string }
): Promise<boolean> {
  const result = await ssh.exec(flagLockRefreshGuard(parameters), {
    ignoreExitCode: true,
    silent: true,
  })
  return result.code === 0
}

/**
 * Issue #224: what an operator needs to know about the current holder of a
 * contended lock. The token (marker line 1) is deliberately not exposed.
 */
export type FlagLockHolderDiagnostics =
  | {
      /** Approximate age of the marker (or of the directory without a marker). */
      ageSeconds: number | undefined
      kind: "held"
      markerPresent: boolean
      /** Marker lines after line 1, sanitized and truncated. */
      ownerLines: string[]
    }
  | { kind: "absent" }
  | { kind: "unknown"; reason: string }

const DIAGNOSTIC_OWNER_LINE_LIMIT = 8
const DIAGNOSTIC_LINE_LENGTH_LIMIT = 200
const DIAGNOSTICS_HEADER_TAG = "paratix-lock"
const DIAGNOSTICS_STATES = new Set(["absent", "marker", "no-marker"])
const DIGITS_PATTERN = /^\d+$/v
const NON_PRINTABLE_PATTERN = /[^\x20-\x7E]/gv

/**
 * Issue #224: build the read-only diagnostics command. Ages use
 * `stat -c %Y` with a BSD `stat -f %m` fallback; they only feed operator
 * messages, never a threshold decision (thresholds use `find -mmin`).
 *
 * Exported for the shell smoke tests.
 *
 * @internal
 * @param parameters - Pre-quoted shell words.
 * @param parameters.lockWord - The lock directory path word.
 * @param parameters.markerWord - The marker path word.
 * @returns The diagnostics command; its output is parsed by
 *   {@link parseFlagLockHolderDiagnostics}.
 */
export function buildFlagLockDiagnosticsCommand(parameters: {
  lockWord: string
  markerWord: string
}): string {
  const { lockWord, markerWord } = parameters
  return (
    `if [ ! -d ${lockWord} ]; then echo 'paratix-lock absent'; ` +
    `elif [ -f ${markerWord} ]; then ` +
    `echo "paratix-lock marker $(date +%s) ${mtimeOf(markerWord)}"; ` +
    `sed -n '2,${String(DIAGNOSTIC_OWNER_LINE_LIMIT + 1)}p' ${markerWord} </dev/null 2>/dev/null; ` +
    `else echo "paratix-lock no-marker $(date +%s) ${mtimeOf(lockWord)}"; fi`
  )
}

function mtimeOf(word: string): string {
  return `$(stat -c %Y ${word} 2>/dev/null || stat -f %m ${word} 2>/dev/null)`
}

function sanitizeDiagnosticLine(line: string): string {
  return line.replaceAll(NON_PRINTABLE_PATTERN, "?").slice(0, DIAGNOSTIC_LINE_LENGTH_LIMIT)
}

function ageFrom(now: string | undefined, mtime: string | undefined): number | undefined {
  if (now === undefined || mtime === undefined) return undefined
  if (!DIGITS_PATTERN.test(now) || !DIGITS_PATTERN.test(mtime)) return undefined
  return Math.max(0, Number(now) - Number(mtime))
}

/**
 * Issue #224: parse the output of {@link buildFlagLockDiagnosticsCommand}.
 *
 * Exported for the shell smoke tests.
 *
 * @internal
 * @param stdout - The command's stdout.
 * @returns The parsed diagnostics; `unknown` for unexpected output.
 */
export function parseFlagLockHolderDiagnostics(stdout: string): FlagLockHolderDiagnostics {
  const [header = "", ...rest] = stdout.split("\n")
  // The header is split on single spaces untrimmed: an empty mtime (both
  // `stat` forms failed) leaves an empty last field instead of shifting.
  const [tag, state = "", now, mtime] = header.split(" ")
  if (tag !== DIAGNOSTICS_HEADER_TAG || !DIAGNOSTICS_STATES.has(state)) {
    return { kind: "unknown", reason: "unexpected diagnostics output" }
  }
  if (state === "absent") return { kind: "absent" }
  const ownerLines = rest
    .filter((line) => line.trim().length > 0)
    .slice(0, DIAGNOSTIC_OWNER_LINE_LIMIT)
    .map((line) => sanitizeDiagnosticLine(line))
  return {
    ageSeconds: ageFrom(now, mtime),
    kind: "held",
    markerPresent: state === "marker",
    ownerLines,
  }
}

/**
 * Issue #224: read the holder's owner lines and the approximate marker age
 * of a lock, for an operator-facing wait-failure message. Best effort: it
 * never throws and reports `unknown` when the read failed.
 *
 * @param ssh - The active SSH connection.
 * @param lockName - The validated lock identifier.
 * @returns Owner lines and marker age of a held lock, `absent` when the lock
 *   is gone, or `unknown` when the read failed.
 */
export async function readFlagLockHolderDiagnostics(
  ssh: SshConnection,
  lockName: string
): Promise<FlagLockHolderDiagnostics> {
  validateFlagName(lockName, "lockName")
  const lockPath = flagLockDisplayPath(lockName)
  const command = buildFlagLockDiagnosticsCommand({
    lockWord: shellQuote(lockPath),
    markerWord: shellQuote(`${lockPath}/${FLAG_LOCK_HOLDER_MARKER_NAME}`),
  })
  try {
    const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
    if (result.code !== 0) {
      return { kind: "unknown", reason: `diagnostics read exited ${String(result.code)}` }
    }
    return parseFlagLockHolderDiagnostics(result.stdout)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return { kind: "unknown", reason: `diagnostics read failed: ${reason}` }
  }
}

/**
 * Issue #224: render diagnostics as one operator-facing sentence fragment:
 * lock path, owner lines, marker age and when the lock becomes reclaimable.
 *
 * @param parameters - Rendering inputs.
 * @param parameters.diagnostics - What {@link readFlagLockHolderDiagnostics} reported.
 * @param parameters.lockName - The lock identifier.
 * @param parameters.staleThreshold - The reclaim threshold of the lock.
 * @returns For example `lock /var/lib/paratix/flags/x is held (owner: a; b),
 *   marker age 120 s, reclaimable once older than 540 s (in about 420 s)`,
 *   or `lock /var/lib/paratix/flags/x was released only after the wait ran
 *   out` when the lock is gone by the time the diagnostics are read.
 */
export function describeFlagLockHolder(parameters: {
  diagnostics: FlagLockHolderDiagnostics
  lockName: string
  staleThreshold: FlagLockAgeThreshold
}): string {
  const { diagnostics, staleThreshold } = parameters
  const path = flagLockDisplayPath(parameters.lockName)
  // The diagnostics are read after the wait gave up, so an absent lock was
  // released between the last poll and that read.
  if (diagnostics.kind === "absent") return `lock ${path} was released only after the wait ran out`
  if (diagnostics.kind === "unknown") {
    return `lock ${path} is held (holder details unavailable: ${diagnostics.reason})`
  }
  const owner = diagnostics.ownerLines.length > 0 ? diagnostics.ownerLines.join("; ") : "unknown"
  const marker = diagnostics.markerPresent ? "marker" : "lock directory (no marker)"
  const reclaim = `reclaimable once older than ${String(staleThreshold.effectiveAgeSeconds)} s`
  if (diagnostics.ageSeconds === undefined) {
    return `lock ${path} is held (owner: ${owner}), ${marker} age unknown, ${reclaim}`
  }
  const remaining = Math.max(0, staleThreshold.effectiveAgeSeconds + 1 - diagnostics.ageSeconds)
  return (
    `lock ${path} is held (owner: ${owner}), ${marker} age ${String(diagnostics.ageSeconds)} s, ` +
    `${reclaim} (in about ${String(remaining)} s)`
  )
}
