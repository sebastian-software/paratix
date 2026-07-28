import type { ExecResult, ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"

export const FLAGS_DIRECTORY = "/var/lib/paratix/flags"
export const FLAG_LOCK_WAIT_SECONDS = 300
const SECONDS_PER_MINUTE = 60
const MINUTES_PER_HOUR = 60
const FLAG_LOCK_STALE_HOURS = 4
// Locks older than this are considered stale: a holder process likely crashed
// (SIGKILL, OOM, power loss) without releasing the lock. We use the holder
// marker mtime instead of the lock directory mtime because the latter can be
// updated by tools traversing the parent directory.
export const FLAG_LOCK_STALE_SECONDS = FLAG_LOCK_STALE_HOURS * MINUTES_PER_HOUR * SECONDS_PER_MINUTE
const HOLDER_MARKER_NAME = "holder"

// Flag names land directly in shell commands like `[ -f /var/lib/paratix/flags/<name> ]`
// and `find ... -name '<prefix>*' -delete`. We therefore reject any name that could
// resolve to a directory traversal segment (`..`, leading dot, trailing dot) or
// contain a path separator. The pattern requires an alphanumeric leading
// character; afterwards each character must either be a word character / dash, or
// a dot that is immediately followed by an alphanumeric character. That single
// alternation forbids `..`, leading or trailing dots, and slashes without
// nesting quantifiers (which would trigger the unsafe-regex heuristic).
const FLAG_NAME_PATTERN = /^[A-Za-z0-9](?:[\w\-]|\.[A-Za-z0-9])*$/v

export function validateFlagName(value: string, label: string): void {
  if (!FLAG_NAME_PATTERN.test(value)) {
    throw new Error(
      `${label} must match ${String(FLAG_NAME_PATTERN)}, got: ${JSON.stringify(value)}`
    )
  }
}

/**
 * Ensure the paratix flags directory exists on the remote host.
 *
 * R-0000273: `mkdir -p` runs after a converged apply step, so failures
 * (EROFS, EPERM, ENOSPC, ...) must not throw and undo a successful change.
 * The helper captures the exit code via `ignoreExitCode` and returns a
 * failed {@link ModuleResult} when the command did not succeed; on success
 * it returns `null` so callers can keep their happy path concise.
 *
 * @param ssh - The active SSH connection.
 * @returns A failed `ModuleResult` when `mkdir -p` failed, otherwise `null`.
 */
export async function ensureFlagsDirectory(ssh: SshConnection): Promise<ModuleResult | null> {
  const result = await ssh.exec(`mkdir -p ${FLAGS_DIRECTORY}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) return null
  return failedCommand(`[moduleHelpers] failed to create ${FLAGS_DIRECTORY}`, result)
}

export function flagPath(flagName: string): string {
  return `${FLAGS_DIRECTORY}/${shellQuote(flagName)}`
}

/**
 * Return the unquoted on-disk path of a flag lock directory for use in
 * operator-facing diagnostics.
 *
 * R-0000619: When a remote-mutex section cannot release its lock (typically
 * because the SSH connection died during a sshd restart and the fallback
 * reconnect failed too), the lock directory stays in place until the stale
 * threshold expires. Callers surface this path in their failure message so
 * the operator can clean up manually instead of waiting four hours.
 *
 * @param lockName - The validated lock identifier used by `withMutexLock`.
 * @returns The plain `/var/lib/paratix/flags/<lockName>` path (no shell quoting).
 */
export function flagLockDisplayPath(lockName: string): string {
  return `${FLAGS_DIRECTORY}/${lockName}`
}

export function flagLockName(flagName: string): string {
  return `${flagName}.lock`
}

/**
 * Typed result of {@link writeFlagLockHolderMarker}: the success arm carries
 * the readback token; the failure arm carries the raw `ExecResult` so callers
 * can surface a `failedCommand(...)` ModuleResult with masked stdout/stderr.
 */
type WriteHolderMarkerResult =
  { failure: ModuleResult; kind: "failed" } | { holderToken: string; kind: "ok" }

/**
 * Write the holder marker into the freshly acquired lock directory and read
 * the `pid@hostname` token back so {@link releaseFlagLock} can verify
 * ownership later.
 *
 * R-0000670: when the marker write fails (e.g. ENOSPC, EROFS, transient EIO)
 * the previous `ignoreExitCode` swallow let an empty readback short-circuit
 * the release path, leaving the lock directory behind for the full
 * stale-lock threshold. Detect a missing marker explicitly (non-zero printf
 * exit code, or an empty readback that indicates the marker is unreadable),
 * remove the lock directory immediately, and surface a structured failure so
 * the caller can react instead of silently entering the critical section
 * without a verifiable holder token.
 *
 * @param ssh - The active SSH connection.
 * @param lockName - The validated lock identifier.
 * @returns The verified holder token, or a structured failure when the
 *   marker could not be persisted or read back.
 */
async function writeFlagLockHolderMarker(
  ssh: SshConnection,
  lockName: string
): Promise<WriteHolderMarkerResult> {
  // R-0000494: capture hostname via ssh.output (not inline `$(hostname)`).
  const hostname = await ssh
    .output("hostname")
    .then((rawHostname) => rawHostname.trim())
    .catch(() => "")
  const lock = flagPath(lockName)
  const markerPath = `${lock}/${HOLDER_MARKER_NAME}`
  // R-0000803: `flagLockDisplayPath(lockName)` returns the un-shellQuoted
  // version of the same `${FLAGS_DIRECTORY}/${lockName}/${HOLDER_MARKER_NAME}`
  // path that `markerPath` represents. Use it as the input to `shellQuote`
  // so the awk argument is a single quoted token, defending against future
  // relaxations of `validateFlagName` that could allow shell metacharacters.
  const quotedMarker = shellQuote(`${flagLockDisplayPath(lockName)}/${HOLDER_MARKER_NAME}`)
  const printfResult = await ssh.exec(
    `printf '%s@%s %s\\n' "$$" ${shellQuote(hostname)} "$(date +%s)" > ${markerPath}`,
    { ignoreExitCode: true, silent: true }
  )
  if (printfResult.code !== 0) {
    // R-0000670: the marker write failed (ENOSPC, EROFS, transient EIO, ...).
    // Without a marker the verified-release fast path cannot work, so the
    // lock directory would sit until the four-hour stale-lock threshold
    // expires. Drop the directory now so the next acquirer is not blocked.
    // R-0000749: `rmdir --` so a future `flagPath`-style value that begins
    // with `-` cannot be mis-parsed as an option, matching the convention in
    // archive.ts / compose.ts / aptKeyStaging.ts.
    await ssh.exec(`rmdir -- ${lock}`, { ignoreExitCode: true, silent: true })
    return {
      failure: failedCommand(
        `[moduleHelpers] failed to write flag lock holder marker for ${lockName}`,
        printfResult
      ),
      kind: "failed",
    }
  }
  // R-0000634: read back the `pid@hostname` token from the marker so
  // releaseFlagLock can verify ownership before removing the lock.
  // R-0000840: use `ssh.exec` instead of `ssh.output` so the readback's
  // exit code and stderr survive into the failure diagnostic. The previous
  // `ssh.output(...).catch(() => "")` form silently mapped every readback
  // failure (awk EUSAGE in issue #35, permission denied, transient IO
  // errors, …) onto an empty token, which then surfaced as the
  // mis-leading "marker is empty after write" message. Capturing the raw
  // ExecResult lets the empty-stdout vs. non-zero-exit branches split
  // cleanly into "readback failed" and "readable but empty".
  // Note: unlike rm/rmdir/find, GNU awk and mawk do NOT recognise `--` as
  // an end-of-options sentinel — they treat it as a literal filename and
  // exit with "cannot open file `--'" (see issue #35). `quotedMarker` is
  // built from the absolute `/var/lib/paratix/flags/` prefix, so a path
  // that begins with `-` is not reachable; the bare invocation below is
  // the portable form across awk implementations.
  const readbackResult = await ssh
    .exec(`awk 'NR==1{print $1}' ${quotedMarker}`, { ignoreExitCode: true, silent: true })
    .catch(() => null)
  const holderToken = readbackResult?.stdout.trim() ?? ""
  if (readbackResult?.code !== 0 || holderToken.length === 0) {
    // R-0000670: a failed readback or an empty marker leaves the holder
    // unverifiable — without a token releaseFlagLock can never remove the
    // directory, so we drop it eagerly here and surface a structured
    // failure instead of silently entering the critical section with an
    // unrecoverable lock.
    // R-0000749: `rm -f --` and `rmdir --` so path arguments are never
    // mis-parsed as options.
    await ssh.exec(`rm -f -- ${markerPath}`, { ignoreExitCode: true, silent: true })
    await ssh.exec(`rmdir -- ${lock}`, { ignoreExitCode: true, silent: true })
    return {
      failure: buildReadbackFailure(lockName, readbackResult),
      kind: "failed",
    }
  }
  return { holderToken, kind: "ok" }
}

/**
 * R-0000840: render the structured failure for a missing or unreadable
 * holder marker.
 *
 * Three input shapes feed into the same one-failure-result API:
 * 1. `readbackResult == null` — `ssh.exec` threw before producing a
 *    result. We have no ExecResult to forward through `failedCommand`,
 *    so we surface the thrown shape inline.
 * 2. `readbackResult.code !== 0` — the readback itself failed. Route
 *    through `failedCommand` so the operator sees awk's exit code and
 *    stderr (already masked by `failedCommand`'s secret-sink path).
 * 3. `readbackResult.code === 0 && stdout.trim().length === 0` — the
 *    marker file was readable but contained no token, almost always a
 *    race against an external truncate. Use `failed` because there is
 *    no underlying ExecResult to display.
 *
 * @param lockName - The validated lock identifier.
 * @param readbackResult - The captured exec result, or `null` when
 *   `ssh.exec` itself threw.
 * @returns A `ModuleResult` describing the failure.
 */
function buildReadbackFailure(lockName: string, readbackResult: ExecResult | null): ModuleResult {
  if (readbackResult == null) {
    return failed(
      `[moduleHelpers] flag lock holder marker for ${lockName} readback failed: ssh.exec threw before returning a result`
    )
  }
  if (readbackResult.code !== 0) {
    return failedCommand(
      `[moduleHelpers] flag lock holder marker for ${lockName} readback failed`,
      readbackResult
    )
  }
  return failed(`[moduleHelpers] flag lock holder marker for ${lockName} is readable but empty`)
}

export type FlagLockAcquireResult =
  | { failure: ModuleResult; kind: "failed" }
  | { holderToken: string; kind: "acquired" }
  | { kind: "contended" }

export async function acquireFlagLock(
  ssh: SshConnection,
  lockName: string
): Promise<FlagLockAcquireResult> {
  validateFlagName(lockName, "lockName")
  const ensureFailure = await ensureFlagsDirectory(ssh)
  if (ensureFailure) return { failure: ensureFailure, kind: "failed" }
  const result = await ssh.exec(`mkdir ${flagPath(lockName)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code === 0) {
    // R-0000670: surface a failed marker-write as a structured ModuleResult
    // failure. `writeFlagLockHolderMarker` already removed the lock
    // directory in that case so the caller does not need to clean up.
    const markerResult = await writeFlagLockHolderMarker(ssh, lockName)
    if (markerResult.kind === "failed") return { failure: markerResult.failure, kind: "failed" }
    return { holderToken: markerResult.holderToken, kind: "acquired" }
  }
  return { kind: "contended" }
}

/**
 * Release a previously acquired flag lock.
 *
 * R-0000634: the release is gated on the holder marker's `pid@hostname`
 * token matching the value captured at acquire time. Without that check, a
 * delayed release whose holder was already declared stale and replaced by
 * another acquirer would silently break mutual exclusion. The compare,
 * marker removal and `rmdir` run in a single shell statement so the check
 * cannot race against a concurrent reclaim.
 *
 * An empty `holderToken` short-circuits the release: with R-0000670 the
 * acquire path now fails fast and removes the lock directory when the
 * marker write or read-back did not yield a verifiable token, so callers
 * normally never see an empty token here. The defensive check stays in
 * place so that a manually-constructed empty token cannot evict a foreign
 * holder that may have already reclaimed the lock.
 *
 * @param ssh - The active SSH connection.
 * @param lockName - The validated lock identifier used for the directory name.
 * @param holderToken - The `pid@hostname` value returned by
 *   {@link acquireFlagLock}'s `acquired` result.
 */
export async function releaseFlagLock(
  ssh: SshConnection,
  lockName: string,
  holderToken: string
): Promise<void> {
  validateFlagName(lockName, "lockName")
  if (holderToken.length === 0) {
    // No verifiable ownership — refuse to touch the lock so a concurrent
    // holder that successfully reclaimed it is not silently evicted.
    return
  }
  const lock = flagPath(lockName)
  const markerPath = `${lock}/${HOLDER_MARKER_NAME}`
  // R-0000803: re-shellQuote the marker path as a single token for awk
  // rather than relying on `flagPath`'s embedded quotes propagating cleanly
  // through interpolation.
  const quotedMarker = shellQuote(`${flagLockDisplayPath(lockName)}/${HOLDER_MARKER_NAME}`)
  // Single atomic shell statement so the ownership check, marker removal
  // and `rmdir` cannot interleave with a stale-lock reclaim that already
  // handed the lock to another acquirer.
  // R-0000749: `rm -f --` and `rmdir --` so path arguments are never
  // mis-parsed as options. `awk` does NOT support `--` as an end-of-options
  // sentinel (it treats it as a literal filename and exits with "cannot
  // open file `--'", see issue #35), so the readback below uses the bare
  // form — the marker path is always rooted at `/var/lib/paratix/flags/`,
  // so a path beginning with `-` is structurally impossible.
  // R-0000758: prefix both sides of the `=` with a literal `x` so an
  // unusual awk output that begins with `-` (or expands to a `[`/`]`
  // operator on a strict POSIX `[`) cannot turn the comparison itself
  // into an option lookup. The `x`-prefix is the canonical POSIX idiom
  // for "compare these two strings as opaque values" and is preserved
  // by `shellQuote`'s single-quote wrapping.
  // R-0000758: the holder readback is now captured in a shell variable
  // so we can also check awk's exit code: `awk` may exit non-zero when
  // the marker file disappeared between the `[ -d $lock ]` outer check
  // and the readback, and a silently empty stdout would otherwise look
  // like "no match" and skip the rm/rmdir branch — leaving the lock
  // dangling. Capturing `awk_status=$?` lets the comparison short-circuit
  // when awk failed, so the release attempt fails closed.
  const expectedToken = `x${holderToken}`
  const command =
    `awk_token=$(awk 'NR==1{print $1}' ${quotedMarker} 2>/dev/null); awk_status=$?; ` +
    `[ "$awk_status" = 0 ] && ` +
    `[ "x$awk_token" = ${shellQuote(expectedToken)} ] && ` +
    `rm -f -- ${markerPath} && ` +
    `rmdir -- ${lock}`
  await ssh.exec(command, { ignoreExitCode: true, silent: true })
}

/**
 * Detect a stale lock and remove it so the next acquire attempt can proceed.
 *
 * Stale-detection compares the holder marker's mtime against the configured
 * timeout. A missing marker is also treated as stale because a healthy holder
 * always writes the marker right after `mkdir`. Removal is best-effort: if the
 * race-test fails (another process just claimed the lock), the helper returns
 * `false` without raising. Returning `true` does NOT mean the caller now holds
 * the lock — only that the previous holder was determined stale and removed.
 *
 * R-0000698: the token verification (R-0000671) only protects the
 * marker-present branch — by re-reading the marker token immediately before
 * the `rm -f` it rejects the reclaim when a fresh acquirer raced into the
 * window between the stale probe and the removal. The missing-marker branch
 * has no token to re-verify, so it relies on a second `find -mmin` age probe
 * just before `rmdir` as the equivalent TOCTOU guard: if a fresh acquirer
 * touched the lock directory after the first probe, the second probe fails
 * and the reclaim is aborted.
 *
 * @param ssh - The active SSH connection.
 * @param lockName - The lock directory name under {@link FLAGS_DIRECTORY}.
 * @param staleSeconds - Maximum holder marker age before the lock is reclaimed.
 * @returns `true` when a stale lock was reclaimed, otherwise `false`.
 */
export async function tryReclaimStaleFlagLock(
  ssh: SshConnection,
  lockName: string,
  staleSeconds: number
): Promise<boolean> {
  const lock = flagPath(lockName)
  const markerPath = `${lock}/${HOLDER_MARKER_NAME}`
  // R-0000803: defensively re-shellQuote the marker path for awk so any
  // future change to `validateFlagName` cannot leak shell metacharacters
  // through the partially-quoted `${markerPath}` interpolation.
  const quotedMarker = shellQuote(`${flagLockDisplayPath(lockName)}/${HOLDER_MARKER_NAME}`)
  // Use `find -mmin` to detect a marker older than the threshold, falling
  // back to the lock directory mtime when the marker is missing entirely.
  const staleMinutes = Math.max(1, Math.ceil(staleSeconds / SECONDS_PER_MINUTE))
  const mminThreshold = String(staleMinutes - 1)
  // R-0000671: the reclaim is gated on the holder marker's token still
  // matching the token observed when the marker was declared stale.
  // Without this check, a holder that became active again between the
  // stale probe and the rm — or a fresh acquirer racing into the same
  // window — would have its marker destroyed. The token capture, stale
  // probe, second-read comparison, marker removal and `rmdir` all run in
  // a single shell statement so the entire sequence is atomic against
  // concurrent acquirers, releasers and reclaimers. Mirrors the
  // verified-release shell statement built by R-0000634.
  //
  // R-0000698: the token verification scope is limited to the
  // marker-present branch — the second `awk` read just before `rm -f`
  // catches a fresh acquirer that planted a new marker between the stale
  // probe and the removal. The missing-marker branch cannot apply a token
  // check (there is no marker to read), so it relies on a second
  // `find -mmin` age probe immediately before `rmdir` as the equivalent
  // TOCTOU guard: if a fresh acquirer touched the lock directory between
  // the first age probe and the rmdir, the second probe fails and the
  // reclaim is aborted instead of destroying the new holder's lock.
  // R-0000749: `rm -f --` and `rmdir --` so path arguments are never
  // mis-parsed as options, mirroring the convention used in archive.ts /
  // compose.ts / aptKeyStaging.ts. `awk` does NOT support `--` (see issue
  // #35) and `find` is not affected here because its path argument is
  // followed by additional flags (`-maxdepth`), so `--` cannot be placed
  // without breaking the operand/expression split.
  const command =
    `if [ -d ${lock} ]; then ` +
    `if [ -f ${markerPath} ]; then ` +
    `STALE_TOKEN="$(awk 'NR==1{print $1}' ${quotedMarker} 2>/dev/null)"; ` +
    `if find ${markerPath} -maxdepth 0 -mmin +${mminThreshold} -print -quit | grep -q .; then ` +
    `[ "$(awk 'NR==1{print $1}' ${quotedMarker} 2>/dev/null)" = "$STALE_TOKEN" ] && ` +
    `rm -f -- ${markerPath} && rmdir -- ${lock}; ` +
    `else exit 1; fi; ` +
    `else ` +
    // Missing marker is treated as stale only if the lock directory itself
    // is older than the threshold to avoid racing with a holder that has
    // not yet written its marker. R-0000698: re-probe the directory mtime
    // immediately before `rmdir` so a fresh acquirer that touched the
    // directory between the two probes aborts the reclaim.
    `if find ${lock} -maxdepth 0 -mmin +${mminThreshold} -print -quit | grep -q .; then ` +
    `find ${lock} -maxdepth 0 -mmin +${mminThreshold} -print -quit | grep -q . && ` +
    `rm -f -- ${markerPath} && rmdir -- ${lock}; ` +
    `else exit 1; fi; ` +
    `fi; ` +
    `else exit 1; fi`
  const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  return result.code === 0
}

export async function waitForFlagLockResolution(
  ssh: SshConnection,
  parameters: {
    flagName: string
    lockName: string
    staleSeconds: number
    waitSeconds: number
  }
): Promise<"resolved" | ModuleResult> {
  const flag = flagPath(parameters.flagName)
  const lock = flagPath(parameters.lockName)
  const waitSeconds = String(parameters.waitSeconds)
  const command =
    `i=0; while [ -d ${lock} ] && [ ! -f ${flag} ] && [ "$i" -lt ${waitSeconds} ]; do ` +
    "sleep 1; i=$((i+1)); done; " +
    `[ ! -d ${lock} ] || [ -f ${flag} ]`
  const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  if (result.code === 0) return "resolved"
  // Wait window expired — try to reclaim a stale lock so the next attempt
  // can proceed instead of failing forever after a crashed holder.
  if (await tryReclaimStaleFlagLock(ssh, parameters.lockName, parameters.staleSeconds)) {
    return "resolved"
  }
  return failedCommand(
    `[moduleHelpers] timed out waiting for flag lock ${parameters.lockName}`,
    result
  )
}
