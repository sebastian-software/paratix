/* eslint-disable max-lines -- releaseUpgrade keeps distro-specific upgrade flow in one module. */
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  type ExecOptions,
  type ExecResult,
  type Module,
  type ModuleMetaEntry,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { withMutexLock } from "./moduleHelpers.js"
import { type Distro, parseOsReleaseDistro } from "./releaseUpgradeDistro.js"
import {
  isAcceptableSourcesPath,
  isAllowedDebianStableTargetCodename,
  isSupportedDebianUpgradePath,
  isVanishedSourcesFileError,
  readSourcesFileMode,
  RELEASE_UPGRADE_DEFAULT_TIMEOUT_MS,
  rewriteAptSourcesContent,
  wrapMissingSourcesFileError,
} from "./releaseUpgradeSources.js"
import {
  buildRebootMetaEntriesWithTimeout,
  type ResolveHostCallback,
} from "./resolveHostTimeout.js"

const NONINTERACTIVE = "DEBIAN_FRONTEND=noninteractive"
const CODENAME_RE = /^[a-z]{3,20}$/v
const NO_UBUNTU_RELEASE_PATTERN = /no new release (?:found|available)/iv
const DEBIAN_RELEASE_UPGRADE_MUTEX = "release-upgrade-mutex"
function isNoUbuntuReleaseAvailable(result: ExecResult): boolean {
  if (result.code === 0) return false
  return NO_UBUNTU_RELEASE_PATTERN.test(`${result.stdout}\n${result.stderr}`)
}

/**
 * Options for the {@link releaseUpgrade.upgrade} module.
 */
type ReleaseUpgradeOptions = {
  /**
   * When `true`, only check whether an upgrade is available without applying
   * any changes. The module returns `"ok"` regardless of what is found.
   */
  dryRun?: boolean
  /**
   * Optional async function to resolve the new host address after the
   * post-upgrade reboot. Useful when the server's IP address may change
   * (e.g. DHCP or cloud environments). The resolved value is emitted as
   * `system.host` meta so the runner can reconnect to the correct address.
   *
   * R-0000575: the callback receives an `AbortSignal` that fires when the
   * configured timeout elapses. Honoring the signal lets DNS/cloud lookups
   * abort their in-flight work promptly.
   */
  resolveHost?: ResolveHostCallback
  /**
   * Wall-clock timeout (ms) applied to {@link ReleaseUpgradeOptions.resolveHost}.
   * Defaults to 30 seconds (R-0000243) so a hanging DNS/cloud lookup cannot
   * stall the playbook indefinitely.
   */
  resolveHostTimeoutMs?: number
  /** Override the per-step command timeout (ms). Default: 30 minutes. */
  timeout?: number
}

/**
 * Detect the Linux distribution of the remote host by reading
 * `/etc/os-release`. See {@link parseOsReleaseDistro} for the comparison
 * rules (case-insensitive explicit `ID=` only).
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns `"debian"`, `"ubuntu"`, or `null` when the distribution cannot be
 *   identified.
 */
async function detectDistro(ssh: SshConnection): Promise<Distro | null> {
  const osRelease = await ssh.readFile("/etc/os-release")
  return parseOsReleaseDistro(osRelease)
}

/**
 * Return the current Debian/Ubuntu release codename via `lsb_release -cs`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @returns The codename string (e.g. `"bookworm"` or `"noble"`).
 */
async function getDebianCurrentCodename(ssh: SshConnection): Promise<string> {
  const codename = await ssh.output("lsb_release -cs")
  if (!CODENAME_RE.test(codename)) {
    throw new Error(`Invalid codename from lsb_release: ${JSON.stringify(codename)}`)
  }
  return codename
}

/**
 * R-0000716: pinned filesystem path of the Debian archive keyring shipped by
 * the `debian-archive-keyring` package. `gpgv` verifies the inline signature
 * of the `InRelease` file against the keys in this keyring; using the
 * package-managed keyring ensures we trust the same set of release-signing
 * keys that apt itself would trust on the same host.
 */
const DEBIAN_ARCHIVE_KEYRING_PATH = "/usr/share/keyrings/debian-archive-keyring.gpg"

/**
 * R-0000716: URL of the signed `InRelease` file from `dists/stable`. Unlike
 * the unsigned `Release` file the previous flow fetched, `InRelease` is a
 * clearsigned OpenPGP message: a TLS-MITM or CDN-hijack that swaps the body
 * will invalidate the inline signature and `gpgv` will reject it before any
 * codename is extracted. R-0000632/R-0000715 still apply as defense in depth
 * even after the signature verification succeeds.
 */
const DEBIAN_INRELEASE_URL = "https://deb.debian.org/debian/dists/stable/InRelease"

const DEBIAN_INRELEASE_FETCH_FAILURE_PREFIX = "Failed to fetch signed Debian InRelease"
const DEBIAN_INRELEASE_VERIFY_FAILURE_PREFIX = "Failed to verify signed Debian InRelease"

// R-0000716: exit codes emitted by the InRelease fetch/verify shell pipeline.
// Naming each code keeps {@link formatDebianInReleaseFailure} readable and
// keeps the literal that lands in the shell command body in sync with the
// JavaScript matcher.
const DEBIAN_INRELEASE_FETCH_EXIT_CODE = 10
const DEBIAN_INRELEASE_KEYRING_MISSING_EXIT_CODE = 11
const DEBIAN_INRELEASE_SIGNATURE_REJECTED_EXIT_CODE = 12

/**
 * R-0000716: build the shell pipeline that fetches `InRelease`, verifies it
 * with `gpgv` against the Debian archive keyring, and prints the cleartext
 * body to stdout on success. The full pipeline runs in a single ssh round so
 * that the body never lands on disk in an unverified state. `mktemp -d`
 * provides an isolated workspace that `trap … EXIT` cleans up irrespective
 * of where the pipeline fails, and `set -eu` makes any non-zero step abort
 * the pipeline with a recognisable exit code.
 *
 * Output contract:
 *   - exit 0 with stdout = cleartext body when verification succeeded
 *   - exit 10 when the InRelease fetch failed (curl error / non-HTTP-200)
 *   - exit 11 when the keyring is missing
 *   - exit 12 when `gpgv` rejected the signature
 *   - any other non-zero exit indicates an unexpected shell failure
 *
 * @returns The shell command string suitable for `ssh.exec`.
 */
function buildDebianInReleaseFetchAndVerifyCommand(): string {
  const url = shellQuote(DEBIAN_INRELEASE_URL)
  const keyring = shellQuote(DEBIAN_ARCHIVE_KEYRING_PATH)
  return [
    "set -eu",
    "tmpdir=$(mktemp -d -t paratix-inrelease.XXXXXX)",
    "trap 'rm -rf -- \"$tmpdir\"' EXIT",
    `[ -r ${keyring} ] || exit ${String(DEBIAN_INRELEASE_KEYRING_MISSING_EXIT_CODE)}`,
    `curl --max-time 30 -fsSL ${url} -o "$tmpdir/InRelease" || exit ${String(DEBIAN_INRELEASE_FETCH_EXIT_CODE)}`,
    `gpgv --keyring ${keyring} "$tmpdir/InRelease" >/dev/null 2>&1 || exit ${String(DEBIAN_INRELEASE_SIGNATURE_REJECTED_EXIT_CODE)}`,
    'cat -- "$tmpdir/InRelease"',
  ].join("; ")
}

function formatDebianInReleaseFailure(result: ExecResult): string {
  if (result.code === DEBIAN_INRELEASE_FETCH_EXIT_CODE) {
    return `${DEBIAN_INRELEASE_FETCH_FAILURE_PREFIX} from ${DEBIAN_INRELEASE_URL}`
  }
  if (result.code === DEBIAN_INRELEASE_KEYRING_MISSING_EXIT_CODE) {
    return `${DEBIAN_INRELEASE_VERIFY_FAILURE_PREFIX}: Debian archive keyring not found at ${DEBIAN_ARCHIVE_KEYRING_PATH}`
  }
  if (result.code === DEBIAN_INRELEASE_SIGNATURE_REJECTED_EXIT_CODE) {
    return `${DEBIAN_INRELEASE_VERIFY_FAILURE_PREFIX}: gpgv rejected the InRelease signature against ${DEBIAN_ARCHIVE_KEYRING_PATH}`
  }
  const stderr = result.stderr.trim()
  const detail = stderr.length > 0 ? `: ${stderr}` : ""
  return `${DEBIAN_INRELEASE_VERIFY_FAILURE_PREFIX} (exit code ${String(result.code)})${detail}`
}

/**
 * R-0000764: extract the signed body lines of a cleartext PGP message.
 * The cleartext PGP header ends at the first blank line; the signed body
 * ends at the `-----BEGIN PGP SIGNATURE-----` marker. Lines outside that
 * range must never feed back into downstream parsing, otherwise a quirky
 * or hostile signer could plant an arbitrary `Codename:` line in the
 * header and override the real signed value.
 *
 * @param body - The full cleartext `InRelease` body as returned by gpgv.
 * @returns An array of lines that belong to the signed metadata body
 *   (i.e. between the cleartext header's blank-line separator and the
 *   signature marker), in their original order.
 */
function extractCleartextPgpBodyLines(body: string): string[] {
  const lines = body.split("\n")
  const headerEndIndex = lines.indexOf("")
  if (headerEndIndex === -1) return []
  const candidateBodyLines = lines.slice(headerEndIndex + 1)
  const signatureIndex = candidateBodyLines.findIndex((line) =>
    line.startsWith("-----BEGIN PGP SIGNATURE-----")
  )
  return signatureIndex === -1 ? candidateBodyLines : candidateBodyLines.slice(0, signatureIndex)
}

/**
 * R-0000716: parse the cleartext body of a verified `InRelease` file and
 * return the `Codename:` field. The body looks like:
 *
 * ```
 * -----BEGIN PGP SIGNED MESSAGE-----
 * Hash: SHA256
 *
 * Origin: Debian
 * Codename: trixie
 * Suite: stable
 * ...
 * -----BEGIN PGP SIGNATURE-----
 * ...
 * -----END PGP SIGNATURE-----
 * ```
 *
 * R-0000764: only scan the signed body (the lines between the cleartext
 * header's blank-line separator and the signature marker) so that the
 * PGP cleartext header — which may legitimately carry arbitrary
 * `Hash:`/`Comment:`/`Charset:` fields — cannot smuggle a planted
 * `Codename:` line past the verification. The body extraction is shared
 * with future cleartext-PGP parsing helpers via
 * {@link extractCleartextPgpBodyLines}.
 *
 * @param body - The full cleartext `InRelease` body as returned by gpgv.
 * @returns The codename extracted from the body.
 * @throws {Error} When the `Codename:` field is absent or invalid.
 */
function parseDebianStableCodenameFromInRelease(body: string): string {
  for (const line of extractCleartextPgpBodyLines(body)) {
    const match = /^Codename:\s+(?<name>\S+)$/v.exec(line)
    if (!match?.groups) continue
    const codename = match.groups.name
    if (!CODENAME_RE.test(codename)) {
      throw new Error(`Invalid stable codename from Debian mirrors: ${JSON.stringify(codename)}`)
    }
    return codename
  }
  throw new Error("Could not determine Debian stable codename")
}

/**
 * Fetch the codename of the current Debian stable release from the official
 * mirrors and verify the response against the Debian archive keyring.
 *
 * R-0000716: replaces the previous unsigned `Release` fetch with a signed
 * `InRelease` fetch verified by `gpgv` against
 * `/usr/share/keyrings/debian-archive-keyring.gpg` on the target host. This
 * closes the gap that R-0000632/R-0000715 only mitigated through the
 * codename allowlist: a TLS-MITM or CDN-hijack now fails at signature
 * verification before any codename is ever inspected.
 *
 * R-0000715: the allowlist enforced by
 * {@link isAllowedDebianStableTargetCodename} still runs on the parsed
 * codename as defense in depth, before the value is returned to any caller.
 *
 * @param ssh - Active SSH connection.
 * @returns The stable codename (e.g. `"bookworm"`).
 * @throws {Error} When the `InRelease` fetch or gpgv verification fails,
 *   when the `Codename:` field is absent, when the codename does not match
 *   the basic shape expected for a Debian suite, or when the shape-valid
 *   codename is not on the allowlist of legitimate stable upgrade targets
 *   (R-0000632).
 */
/**
 * R-0000852/R-0000869: per-process cache for verified Debian stable
 * codenames keyed first by SSH connection and then by keyring path. `check`
 * and `applyDebian` both call
 * {@link getDebianStableCodename}, and a playbook that bundles several
 * Debian-targeting modules can resolve the same codename multiple times in
 * quick succession. Each resolution issues a remote `gpgv` round-trip, which
 * is wasteful when the same host keyring (and therefore the trust root) has
 * not changed.
 *
 * The outer `WeakMap` prevents one host's verified codename from being reused
 * for another host that happens to expose the same keyring path. The inner
 * cache key is the resolved keyring filesystem path so a future call site that
 * overrides the path (e.g. a test harness pinning a different keyring) is
 * automatically isolated from previously cached results. The TTL is kept
 * intentionally short so operator-driven changes to the keyring or the
 * upstream `InRelease` body are picked up on the next run without requiring a
 * process restart.
 */
const DEBIAN_STABLE_CODENAME_CACHE_TTL_MS = 300_000

type DebianStableCodenameCacheEntry = {
  codename: string
  expiresAt: number
}

let debianStableCodenameCache = new WeakMap<
  SshConnection,
  Map<string, DebianStableCodenameCacheEntry>
>()

/**
 * R-0000852: test-only hook to clear the per-process codename cache between
 * test cases. Tests that exercise different mirror responses against the same
 * keyring (e.g. a benign run followed by a hijacked-codename run) must start
 * from a clean cache so the second run actually issues the verify pipeline
 * instead of returning the previously cached value. Production code never
 * calls this — the cache is invalidated naturally by the TTL.
 *
 * @internal
 */
export function clearDebianStableCodenameCacheForTests(): void {
  debianStableCodenameCache = new WeakMap<
    SshConnection,
    Map<string, DebianStableCodenameCacheEntry>
  >()
}

function getDebianStableCodenameCacheForConnection(
  ssh: SshConnection
): Map<string, DebianStableCodenameCacheEntry> {
  const cache = debianStableCodenameCache.get(ssh)
  if (cache !== undefined) return cache
  const next = new Map<string, DebianStableCodenameCacheEntry>()
  debianStableCodenameCache.set(ssh, next)
  return next
}

async function getDebianStableCodename(ssh: SshConnection): Promise<string> {
  const keyringPath = DEBIAN_ARCHIVE_KEYRING_PATH
  const cache = getDebianStableCodenameCacheForConnection(ssh)
  const cached = cache.get(keyringPath)
  const now = Date.now()
  if (cached !== undefined && cached.expiresAt > now) {
    return cached.codename
  }
  const result = await ssh.exec(buildDebianInReleaseFetchAndVerifyCommand(), {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) {
    throw new Error(formatDebianInReleaseFailure(result))
  }
  const codename = parseDebianStableCodenameFromInRelease(result.stdout)
  // R-0000715: enforce the allowlist at the extraction point so check,
  // dry-run and apply all reject untrusted codenames consistently — even
  // when the gpgv signature verification accepted them. R-0000716 makes a
  // forged codename much harder to deliver, but the allowlist remains as a
  // last line of defense against a compromised release-signing key or a
  // legitimate but unexpected upgrade target.
  if (!isAllowedDebianStableTargetCodename(codename)) {
    throw new Error(`unexpected Debian stable codename from mirrors: ${JSON.stringify(codename)}`)
  }
  // R-0000852: only cache after every validation step has accepted the value
  // so an invalid response cannot poison the cache for the remainder of the
  // TTL window.
  cache.set(keyringPath, {
    codename,
    expiresAt: now + DEBIAN_STABLE_CODENAME_CACHE_TTL_MS,
  })
  return codename
}

const APT_SOURCES_LIST = "/etc/apt/sources.list"

/**
 * Snapshot of an apt sources file as it was before
 * {@link replaceCodenameInSourcesList} rewrote it. Used by
 * {@link restoreSourcesSnapshots} to roll back when a subsequent apt step
 * fails so the host never ends up with sources pointing at the new suite
 * while the upgrade itself failed. Mirrors the snapshot format used in
 * `quadlet.ts` and `timerFileSnapshots.ts` (R-0000241/R-0000217) where the
 * captured mode preserves operator-specific permissions across the
 * rollback.
 */
type SourcesSnapshot = {
  mode: string
  originalContent: string
  remotePath: string
}

type RestoreSourcesFailure = {
  error: unknown
  remotePath: string
}

type RewriteSourcesParameters = {
  currentCodename: string
  originalContent: string
  remotePath: string
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
  targetCodename: string
}

async function writeSourcesFileWithRegisteredSnapshot(parameters: {
  content: string
  mode: string
  remotePath: string
  snapshot: SourcesSnapshot
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
}): Promise<void> {
  const { content, mode, remotePath, snapshot, snapshots, ssh } = parameters
  const snapshotIndex = snapshots.length
  snapshots.push(snapshot)
  try {
    await writeSourcesFileNoFollow({ content, mode, remotePath, ssh })
  } catch (error) {
    if (!(error instanceof SourcesWriteCommandError) || !error.mayHaveMutated) {
      snapshots.splice(snapshotIndex, 1)
    }
    throw error
  }
}

async function rewriteSourcesFile(
  parameters: RewriteSourcesParameters
): Promise<null | SourcesSnapshot> {
  const { currentCodename, originalContent, remotePath, snapshots, ssh, targetCodename } =
    parameters
  // Rewrite only apt suite fields. URLs, comments and unrelated deb822 fields
  // may contain release codenames as substrings and must remain untouched.
  const updatedContent = rewriteAptSourcesContent({
    currentCodename,
    originalContent,
    remotePath,
    targetCodename,
  })
  if (updatedContent === originalContent) return null

  // R-0000241: capture the original mode before overwriting so the rollback
  // can restore the operator's exact permissions instead of forcing 0644.
  const mode = await readSourcesFileMode(ssh, remotePath, shellQuote)
  // R-0000629: re-read through the fused `[ -L ] + dd iflag=nofollow`
  // statement before writing, mirroring `guardedWriteFile`'s
  // concurrent-modification check but keeping the no-follow guarantee on
  // the re-read open(2). A plain `ssh.readFile` would briefly drop the
  // O_NOFOLLOW guarantee that `readSourcesFileNoFollow` provides on the
  // original snapshot read, reintroducing the very TOCTOU window we are
  // closing here.
  const currentContent = await readSourcesFileNoFollow(ssh, remotePath)
  if (currentContent === null) {
    // The file vanished or turned into a symlink between the snapshot read
    // and the rewrite. Abort this file's rewrite so we never overwrite a
    // symlink target or recreate a vanished file with stale content.
    return null
  }
  if (currentContent !== originalContent) {
    throw new Error(
      `Concurrent modification detected on ${remotePath}: ` +
        "file content changed between read and write. Aborting to prevent data loss."
    )
  }
  const snapshot = { mode, originalContent, remotePath }
  // R-0000718: route the write through the NOFOLLOW pipeline so a
  // symlink swap between the snapshot read above and this write step
  // cannot redirect the rewrite to an attacker-controlled target.
  await writeSourcesFileWithRegisteredSnapshot({
    content: updatedContent,
    mode,
    remotePath,
    snapshot,
    snapshots,
    ssh,
  })
  return snapshot
}

type SnapshotSourcesParameters = Omit<RewriteSourcesParameters, "originalContent">

type ReplaceSourcesListParameters = {
  currentCodename: string
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
  targetCodename: string
}

// R-0000629: marker exit code used by the combined symlink-guard + nofollow
// read to signal "the path is (or became) a symbolic link between
// enumeration and read". Picked outside the normal dd/test exit-code range
// (1, 2, 124, 126/127) so the symlink branch is distinguishable from a
// genuine dd error or a shell command-not-found.
const SOURCES_FILE_SYMLINK_EXIT_CODE = 200

// R-0000718: marker exit codes used by the NOFOLLOW write pipeline. The
// values mirror the no-follow read pattern in `readSourcesFileNoFollow`
// (R-0000629) and are picked outside dd's normal exit-code range so the
// symlink/chmod branches stay distinguishable from genuine dd or shell
// failures.
const SOURCES_FILE_WRITE_SYMLINK_EXIT_CODE = 201
const SOURCES_FILE_WRITE_CHMOD_EXIT_CODE = 202

class SourcesWriteCommandError extends Error {
  public readonly mayHaveMutated: boolean

  public constructor(message: string, mayHaveMutated: boolean) {
    super(message)
    this.name = "SourcesWriteCommandError"
    this.mayHaveMutated = mayHaveMutated
  }
}

const SOURCES_FILE_NOFOLLOW_WRITER_SCRIPT = [
  "import errno",
  "import os",
  "import sys",
  "path = sys.argv[1]",
  "mode = int(sys.argv[2], 8)",
  "data = sys.stdin.buffer.read()",
  "fd = None",
  "try:",
  "    try:",
  "        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)",
  "    except OSError as error:",
  "        if error.errno == errno.ELOOP:",
  `            sys.exit(${String(SOURCES_FILE_WRITE_SYMLINK_EXIT_CODE)})`,
  "        raise",
  "    offset = 0",
  "    while offset < len(data):",
  "        offset += os.write(fd, data[offset:])",
  "    os.ftruncate(fd, len(data))",
  "    try:",
  "        os.fchmod(fd, mode)",
  "    except OSError as error:",
  "        print(str(error), file=sys.stderr)",
  `        sys.exit(${String(SOURCES_FILE_WRITE_CHMOD_EXIT_CODE)})`,
  "finally:",
  "    if fd is not None:",
  "        os.close(fd)",
].join("\n")

// R-0000718/R-0000905: write an apt sources file with O_NOFOLLOW semantics
// so a symlink swap between the snapshot read and the rewrite (or between
// the pipeline failure and the rollback) cannot trick the writer into
// overwriting an attacker-controlled target. The fused shell statement:
//
//   - probes `[ -L <path> ]` to reject the path early if it already is a
//     symlink at the time of the probe, with exit code 201 so the caller
//     can distinguish it from generic dd failures
//   - opens the destination in Python with `os.O_WRONLY | os.O_NOFOLLOW`
//     so a TOCTOU symlink swap between the probe and the open fails with
//     ELOOP at open(2) — the load-bearing guarantee that the `[ -L ]`
//     check alone cannot provide
//   - writes stdin, truncates to the new content length, and restores the
//     snapshot mode through the same fd using `os.write`, `os.ftruncate`,
//     and `os.fchmod`, so a symlink swap after the open cannot redirect
//     truncate or chmod to a different target
//
// `set -eu` aborts the pipeline on the first non-zero step. `input` is
// supplied by `ssh.exec` so the content is streamed to Python's stdin instead
// of embedded in the argv (which would leak via `ps`).
function buildWriteSourcesFileNoFollowCommand(remotePath: string, mode: string): string {
  const quotedPath = shellQuote(remotePath)
  const quotedMode = shellQuote(mode)
  const quotedWriterScript = shellQuote(SOURCES_FILE_NOFOLLOW_WRITER_SCRIPT)
  return [
    "set -eu",
    `[ ! -L ${quotedPath} ] || exit ${String(SOURCES_FILE_WRITE_SYMLINK_EXIT_CODE)}`,
    `python3 -c ${quotedWriterScript} ${quotedPath} ${quotedMode}`,
  ].join("; ")
}

/**
 * R-0000718: write `content` to `remotePath` with O_NOFOLLOW semantics so
 * a symlink swap cannot redirect the write to an attacker-controlled
 * target. Used by the apt sources rewrite and the rollback path: both
 * touch files under `/etc/apt/sources.list.d/`, a directory that a
 * compromised process with limited write rights might briefly populate
 * with symlinks pointing at sensitive files (e.g. `/etc/shadow`,
 * `/root/.ssh/authorized_keys`) between the time Paratix reads the
 * original content and the time it writes back. The fused
 * `[ -L ] + Python O_NOFOLLOW fd-writer` statement collapses that TOCTOU
 * window and keeps write, truncate and chmod on the same opened file.
 *
 * @param parameters - Bundle of inputs for the NOFOLLOW write.
 * @param parameters.ssh - Active SSH connection to the remote host.
 * @param parameters.remotePath - Absolute path of the apt sources file to write.
 * @param parameters.content - The new content to write.
 * @param parameters.mode - The desired filesystem mode (string with octal digits).
 * @throws {Error} When the path is a symlink, when the NOFOLLOW open
 *   fails (ELOOP), when dd reports a write failure, or when chmod fails
 *   to restore the captured mode.
 */
async function writeSourcesFileNoFollow(parameters: {
  content: string
  mode: string
  remotePath: string
  ssh: SshConnection
}): Promise<void> {
  const { content, mode, remotePath, ssh } = parameters
  const command = buildWriteSourcesFileNoFollowCommand(remotePath, mode)
  const result = await ssh.exec(command, {
    ignoreExitCode: true,
    input: content,
    silent: true,
  })
  if (result.code === 0) return
  if (result.code === SOURCES_FILE_WRITE_SYMLINK_EXIT_CODE) {
    throw new SourcesWriteCommandError(
      `writing ${remotePath} refused: path is a symbolic link (NOFOLLOW guard)`,
      false
    )
  }
  if (result.code === SOURCES_FILE_WRITE_CHMOD_EXIT_CODE) {
    throw new SourcesWriteCommandError(
      `writing ${remotePath} succeeded but chmod to ${mode} failed: ${result.stderr.trim() || "no stderr"}`,
      true
    )
  }
  throw new SourcesWriteCommandError(
    `writing ${remotePath} failed (exit code ${String(result.code)}): ${result.stderr.trim() || "no stderr"}`,
    true
  )
}

// R-0000629: read an apt sources file with the symlink probe and the read
// fused into a single shell statement. The previous flow ran `[ -L ]` and
// `readFile` (which expands to `cat`) in separate ssh rounds, leaving a
// TOCTOU window where an attacker with write access to
// `/etc/apt/sources.list.d/` could swap the regular file for a symlink
// between the probe and the read. Combining the `[ -L ]` guard with
// `dd if=<path> iflag=nofollow status=none` collapses the race window:
// even if the path becomes a symlink between the `[ -L ]` check and the dd
// open(2), `iflag=nofollow` makes dd fail with ELOOP at open(2) time so we
// never follow the link.
//
// The shell statement returns:
//   - exit 0 with stdout = file content when the path is a regular file
//   - exit 200 when the path is a symlink at the time of the `[ -L ]`
//     probe (skip)
//   - dd's natural non-zero exit (typically 1) with an ENOENT-shaped
//     stderr when the file vanished between enumeration and read (skip)
//   - any other non-zero exit re-throws so genuine read failures
//     (permission denied, ELOOP from a planted symlink, …) stay visible
async function readSourcesFileNoFollow(
  ssh: SshConnection,
  remotePath: string
): Promise<null | string> {
  const quotedPath = shellQuote(remotePath)
  // The `{ … }` group runs the symlink probe and dd in the same shell so
  // the exit code reported back to ssh.exec is the exit code of whichever
  // branch was taken. `iflag=nofollow` is the load-bearing flag — it makes
  // dd fail with ELOOP when the file is a symlink at open(2) time, closing
  // the residual race that the `[ -L ]` guard alone cannot.
  const command = `{ if [ -L ${quotedPath} ]; then exit ${String(SOURCES_FILE_SYMLINK_EXIT_CODE)}; fi; dd if=${quotedPath} iflag=nofollow status=none; }`
  const result = await ssh.exec(command, { ignoreExitCode: true, silent: true })
  if (result.code === 0) return result.stdout
  if (result.code === SOURCES_FILE_SYMLINK_EXIT_CODE) return null
  // dd's stderr looks like `dd: failed to open '<path>': No such file or
  // directory`. Funnel the message through `wrapMissingSourcesFileError`
  // so the ENOENT detection — including localized variants — stays
  // centralized in releaseUpgradeSources.ts. Anything else (permission
  // denied, ELOOP from a planted symlink, …) re-throws so the runner sees
  // it.
  const decorated = wrapMissingSourcesFileError(
    new Error(`reading ${remotePath} failed (exit code ${String(result.code)}): ${result.stderr}`)
  )
  if (isVanishedSourcesFileError(decorated)) return null
  throw decorated
}

// R-0000240: a sources file enumerated by `find -print0` may vanish between
// enumeration and the subsequent read. Skip ENOENT-style errors so a single
// transient absence does not abort the entire release upgrade.
//
// R-0000286: decorate the raw error with `code: "ENOENT"` so downstream
// detection can rely on the structured field rather than scanning the
// (possibly localized) message text.
//
// R-0000629: the read itself now goes through `readSourcesFileNoFollow`
// so the `[ -L ]` symlink probe and the `dd … iflag=nofollow` read share a
// single shell statement. A symlink at the path surfaces here as a `null`
// return from `readSourcesFileNoFollow`, replacing the previous separate
// `isSymlink` probe.
async function snapshotSourcesFileSafely(
  parameters: SnapshotSourcesParameters
): Promise<null | SourcesSnapshot> {
  try {
    const originalContent = await readSourcesFileNoFollow(parameters.ssh, parameters.remotePath)
    if (originalContent === null) return null
    return await rewriteSourcesFile({ ...parameters, originalContent })
  } catch (error) {
    const decorated = wrapMissingSourcesFileError(error)
    if (isVanishedSourcesFileError(decorated)) return null
    throw decorated
  }
}

// R-0000571 / R-0000629: defend against a TOCTOU window between `find
// -type f` and the subsequent read by performing the symlink probe and
// the read in the same shell statement (see `readSourcesFileNoFollow`).
// The path allowlist still runs first so an enumerated path that escapes
// the apt sources directory or carries ASCII control characters is
// rejected before any shell command is issued.
async function snapshotEnumeratedSourcesFile(parameters: {
  currentCodename: string
  filePath: string
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
  targetCodename: string
}): Promise<null | SourcesSnapshot> {
  if (parameters.filePath.length === 0 || !isAcceptableSourcesPath(parameters.filePath)) return null
  return snapshotSourcesFileSafely({
    currentCodename: parameters.currentCodename,
    remotePath: parameters.filePath,
    snapshots: parameters.snapshots,
    ssh: parameters.ssh,
    targetCodename: parameters.targetCodename,
  })
}

/**
 * Replace all occurrences of `currentCodename` with `targetCodename` in
 * `/etc/apt/sources.list` and every `.list` and `.sources` file under
 * `/etc/apt/sources.list.d/`.
 *
 * This is the core step for upgrading Debian: pointing apt at the new release
 * suite before running `apt-get full-upgrade`.
 *
 * @param parameters - Active SSH connection, source and target codenames,
 *   and externally owned snapshots for transactional rollback.
 * @returns Snapshots of every sources file that was modified, in the order
 *   they were rewritten. The caller can hand these to
 *   {@link restoreSourcesSnapshots} to roll back on a downstream apt failure.
 */
async function replaceCodenameInSourcesList(
  parameters: ReplaceSourcesListParameters
): Promise<SourcesSnapshot[]> {
  const { currentCodename, snapshots, ssh, targetCodename } = parameters
  if (await ssh.exists(APT_SOURCES_LIST)) {
    await snapshotSourcesFileSafely({
      currentCodename,
      remotePath: APT_SOURCES_LIST,
      snapshots,
      ssh,
      targetCodename,
    })
  }

  // R-0000053: use `find ... -print0` and split on the NUL byte so the
  // pipeline stays safe against pathological filenames containing
  // newlines, leading dashes (which `find` could otherwise treat as
  // flags), or embedded whitespace. The previous newline-split approach
  // could miss files or corrupt their paths in those edge cases.
  const listFilesResult = await ssh.exec(
    "find /etc/apt/sources.list.d/ \\( -name '*.list' -o -name '*.sources' \\) -type f -print0",
    { ignoreExitCode: true, silent: true }
  )
  if (listFilesResult.code !== 0 || listFilesResult.stdout.length === 0) {
    return snapshots
  }

  // R-0000172: defense-in-depth — paths that escape the sources directory or
  // carry ASCII control characters are skipped before readFile / writeFile.
  for (const filePath of listFilesResult.stdout.split("\0")) {
    // eslint-disable-next-line no-await-in-loop
    await snapshotEnumeratedSourcesFile({
      currentCodename,
      filePath,
      snapshots,
      ssh,
      targetCodename,
    })
  }

  return snapshots
}

async function failAfterSourcesRewriteError(parameters: {
  error: unknown
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { error, snapshots, ssh } = parameters
  const reason = error instanceof Error ? error.message : String(error)
  const rewriteFailure = failed(`[releaseUpgrade.upgrade] sources rewrite failed: ${reason}`)
  if (snapshots.length === 0) return rewriteFailure
  const restoreFailures = await restoreSourcesSnapshots(ssh, snapshots)
  return appendRestoreSourcesFailures(rewriteFailure, restoreFailures)
}

/**
 * Restore every snapshot returned by {@link replaceCodenameInSourcesList} so
 * the host's apt sources point at the original suite again. Failures during
 * the rollback are swallowed per file: a single missing or now-protected file
 * must not prevent the remaining snapshots from being restored.
 *
 * Mirrors the rollback strategy used by `sshd.config` (see
 * `validateSshdConfig` in `packages/paratix/src/modules/sshd.ts`), where a
 * failed `sshd -t` validation also writes the original content back via
 * `ssh.writeFile`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param snapshots - The snapshots to restore, in any order.
 * @returns Restore failures collected while attempting all snapshots.
 */
async function restoreSourcesSnapshots(
  ssh: SshConnection,
  snapshots: SourcesSnapshot[]
): Promise<RestoreSourcesFailure[]> {
  const failures: RestoreSourcesFailure[] = []
  for (const snapshot of snapshots) {
    try {
      // Intentional: unguarded write — restoring the original sources is
      // more important than concurrency safety during a failed-upgrade
      // rollback. An additional guarded write would refuse to roll back if
      // the file content changed mid-flight. R-0000241: the mode captured
      // in the snapshot is restored so operator-specific permissions
      // (e.g. `chmod 0640` for a sources file with secrets) survive the
      // rollback unchanged.
      // R-0000718: route the rollback write through the NOFOLLOW pipeline
      // so a symlink that appears between the failed upgrade and the
      // rollback cannot trick the writer into restoring the original
      // content into an attacker-controlled symlink target.
      // eslint-disable-next-line no-await-in-loop
      await writeSourcesFileNoFollow({
        content: snapshot.originalContent,
        mode: snapshot.mode,
        remotePath: snapshot.remotePath,
        ssh,
      })
    } catch (error) {
      // Best-effort: if a single file cannot be restored, keep going so the
      // remaining snapshots still revert. The caller appends these failures
      // to the original apt error so incomplete rollbacks remain visible.
      failures.push({ error, remotePath: snapshot.remotePath })
    }
  }
  return failures
}

function formatRestoreSourcesFailure(failure: RestoreSourcesFailure): string {
  const reason = failure.error instanceof Error ? failure.error.message : String(failure.error)
  return `${failure.remotePath}: ${reason}`
}

function appendRestoreSourcesFailures(
  pipelineFailure: ModuleResult,
  restoreFailures: RestoreSourcesFailure[]
): ModuleResult {
  if (restoreFailures.length === 0) return pipelineFailure
  const pipelineMessage = pipelineFailure.error?.message ?? "[releaseUpgrade.upgrade] failed"
  const restoreMessage = restoreFailures
    .map((failure) => formatRestoreSourcesFailure(failure))
    .join("; ")
  return failed(
    `${pipelineMessage}\nsources rollback failed for ${String(restoreFailures.length)} file(s): ${restoreMessage}`
  )
}

async function refreshAptCacheAfterSourcesRollback(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult | null> {
  const result = await ssh.exec(
    `${NONINTERACTIVE} apt-get update`,
    releaseUpgradeExecOptions(options)
  )
  if (result.code === 0) return null
  return failedCommand("[releaseUpgrade.upgrade] apt-get update on restored sources failed", result)
}

function appendRollbackRefreshFailure(
  pipelineFailure: ModuleResult,
  refreshFailure: ModuleResult | null
): ModuleResult {
  if (refreshFailure == null) return pipelineFailure
  const pipelineMessage = pipelineFailure.error?.message ?? "[releaseUpgrade.upgrade] failed"
  const refreshMessage =
    refreshFailure.error?.message ?? "apt-get update on restored sources failed"
  return failed(`${pipelineMessage}\nrollback succeeded but ${refreshMessage}`)
}

async function handleDebianPipelineFailure(parameters: {
  options: ReleaseUpgradeOptions
  pipelineFailure: ModuleResult
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, pipelineFailure, snapshots, ssh } = parameters
  const restoreFailures = await restoreSourcesSnapshots(ssh, snapshots)
  if (restoreFailures.length > 0) {
    return appendRestoreSourcesFailures(pipelineFailure, restoreFailures)
  }
  const refreshFailure = await refreshAptCacheAfterSourcesRollback(ssh, options)
  return appendRollbackRefreshFailure(pipelineFailure, refreshFailure)
}

/**
 * Build the meta signal map that triggers a runner reboot and optional host
 * re-resolution after the upgrade completes.
 *
 * Always sets `system.reboot` to `"true"`. If `options.resolveHost` is
 * provided, `system.host` is set to the returned address. Failures from
 * `resolveHost` are returned as module failures so reconnect drift is visible.
 *
 * @param options - Upgrade options containing an optional `resolveHost` callback.
 * @returns A meta map suitable for inclusion in a `ModuleResult`, or a failure result.
 */
async function buildRebootMeta(
  options: ReleaseUpgradeOptions
): Promise<ModuleMetaEntry[] | ModuleResult> {
  // R-0000243: bound the resolver with a wall-clock timeout so a hanging
  // DNS/cloud lookup surfaces as a `failed` result instead of stalling the
  // playbook forever.
  return buildRebootMetaEntriesWithTimeout({
    failurePrefix: "[releaseUpgrade.upgrade]",
    resolveHost: options.resolveHost,
    timeoutMs: options.resolveHostTimeoutMs,
  })
}

function releaseUpgradeExecOptions(options: ReleaseUpgradeOptions): ExecOptions {
  // prettier-ignore
  return { ignoreExitCode: true, silent: true, timeout: options.timeout ?? RELEASE_UPGRADE_DEFAULT_TIMEOUT_MS }
}

async function runReleaseUpgradeCommand(parameters: {
  command: string
  failureMessage: string
  options: ReleaseUpgradeOptions
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const result = await parameters.ssh.exec(
    parameters.command,
    releaseUpgradeExecOptions(parameters.options)
  )
  return result.code === 0 ? null : failedCommand(parameters.failureMessage, result)
}

/**
 * Run the Ubuntu release upgrade via `do-release-upgrade`.
 *
 * Executes `apt-get update` first, then invokes `do-release-upgrade` in
 * non-interactive mode. When `dryRun` is set, only the check flag (`-c`) is
 * passed and no changes are made.
 *
 * On success, returns `status: "changed"` with reboot meta so the runner
 * can reconnect after the post-upgrade restart.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options (see {@link ReleaseUpgradeOptions}).
 * @returns A `ModuleResult` — `"changed"` with reboot meta on success,
 *   `"ok"` on dry-run, or `"failed"` when any command returns a non-zero
 *   exit code.
 */
async function applyUbuntu(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult> {
  if (options.dryRun === true) {
    const result = await ssh.exec("do-release-upgrade -c", releaseUpgradeExecOptions(options))
    if (result.code !== 0 && !isNoUbuntuReleaseAvailable(result)) {
      return failedCommand("[releaseUpgrade.upgrade] do-release-upgrade -c failed", result)
    }
    return { status: "ok" }
  }

  const updateFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get update`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get update failed",
    options,
    ssh,
  })
  if (updateFailure != null) return updateFailure

  const upgradeFailure = await runReleaseUpgradeCommand({
    command: "do-release-upgrade -f DistUpgradeViewNonInteractive",
    failureMessage: "[releaseUpgrade.upgrade] do-release-upgrade failed",
    options,
    ssh,
  })
  if (upgradeFailure != null) return upgradeFailure

  const entries = await buildRebootMeta(options)
  if (!Array.isArray(entries)) return entries
  return { meta: entries, status: "changed" }
}

/**
 * Run the four-step Debian apt upgrade pipeline (`apt-get update`,
 * `dpkg --configure -a`, `apt-get full-upgrade -y`, `apt-get autoremove -y`)
 * and return the first failure encountered, or `null` when all four steps
 * succeeded.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options used to derive per-command exec options.
 * @returns The first non-zero apt-step failure, or `null`.
 */
async function runDebianUpgradePipeline(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult | null> {
  const updateFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get update`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get update failed",
    options,
    ssh,
  })
  if (updateFailure != null) return updateFailure

  const configureFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} dpkg --configure -a`,
    failureMessage: "[releaseUpgrade.upgrade] dpkg --configure -a failed",
    options,
    ssh,
  })
  if (configureFailure != null) return configureFailure

  const upgradeFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get full-upgrade -y`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get full-upgrade failed",
    options,
    ssh,
  })
  if (upgradeFailure != null) return upgradeFailure

  const autoremoveFailure = await runReleaseUpgradeCommand({
    command: `${NONINTERACTIVE} apt-get autoremove -y`,
    failureMessage: "[releaseUpgrade.upgrade] apt-get autoremove failed",
    options,
    ssh,
  })
  if (autoremoveFailure != null) return autoremoveFailure

  return null
}

/**
 * Drive the apt pipeline for a Debian release upgrade once snapshots are in
 * place. Translates pipeline failures into a rollback-aware ModuleResult and
 * decorates the success case with reboot meta when applicable.
 *
 * @param parameters - Pipeline context.
 * @param parameters.options - User-supplied release upgrade options.
 * @param parameters.snapshots - Sources snapshots captured before the apt run.
 * @param parameters.ssh - Active SSH connection to the remote host.
 * @returns The terminal ModuleResult for the apt pipeline branch.
 */
async function runDebianAptPipelineAfterSourcesRewrite(parameters: {
  options: ReleaseUpgradeOptions
  snapshots: SourcesSnapshot[]
  ssh: SshConnection
}): Promise<ModuleResult> {
  const { options, snapshots, ssh } = parameters
  let pipelineFailure: ModuleResult | null
  try {
    pipelineFailure = await runDebianUpgradePipeline(ssh, options)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    pipelineFailure = failed(`[releaseUpgrade.upgrade] apt pipeline failed: ${reason}`)
  }
  if (pipelineFailure != null) {
    return handleDebianPipelineFailure({ options, pipelineFailure, snapshots, ssh })
  }

  const entries = await buildRebootMeta(options)
  if (!Array.isArray(entries)) return entries
  return { meta: entries, status: "changed" }
}

async function runDebianUpgradeCriticalSection(parameters: {
  options: ReleaseUpgradeOptions
  ssh: SshConnection
  targetCodename: string
}): Promise<ModuleResult> {
  const { options, ssh, targetCodename } = parameters
  const currentCodename = await getDebianCurrentCodename(ssh)
  if (currentCodename === targetCodename) return { status: "ok" }

  if (!isSupportedDebianUpgradePath(currentCodename, targetCodename)) {
    return failed(
      `[releaseUpgrade.upgrade] unsupported Debian release upgrade path: ${currentCodename} -> ${targetCodename}`
    )
  }

  // R-0000046: snapshot every sources file before rewriting it so a
  // downstream apt failure can roll the sources back to the original suite.
  // Without rollback, a partial failure would leave the host pointing at the
  // new suite while no upgrade has actually completed — the next apt run
  // would then operate on a half-migrated system.
  //
  // R-0000718: the NOFOLLOW write pipeline throws on symlink/dd/chmod
  // failures (so the error message is preserved for the operator). Convert
  // those throws into a structured `failed(...)` ModuleResult so the
  // playbook runner reports them alongside the other apt failure modes
  // instead of letting them escape as uncaught exceptions.
  const snapshots: SourcesSnapshot[] = []
  try {
    await replaceCodenameInSourcesList({ currentCodename, snapshots, ssh, targetCodename })
  } catch (error) {
    return failAfterSourcesRewriteError({ error, snapshots, ssh })
  }

  return runDebianAptPipelineAfterSourcesRewrite({ options, snapshots, ssh })
}

async function runDebianUpgradeWithMutex(parameters: {
  options: ReleaseUpgradeOptions
  ssh: SshConnection
  targetCodename: string
}): Promise<ModuleResult> {
  // R-0000757: `withMutexLock` now returns a structured `MutexLockResult`,
  // so lock-acquire failures surface as typed `failed` ModuleResults via the
  // `failed` variant. Section throws from `runDebianUpgradeCriticalSection`
  // (e.g. a transport failure inside an apt pipeline step) intentionally
  // propagate to the surrounding apply path via `propagateSectionThrows`,
  // preserving the pre-R-0000757 separation between mutex failures and
  // application-level errors that the previous `isMutexLockFailure` heuristic
  // tried to distinguish.
  const lockResult = await withMutexLock(parameters.ssh, {
    failureMessage: "[releaseUpgrade.upgrade] failed to acquire release upgrade mutex",
    lockName: DEBIAN_RELEASE_UPGRADE_MUTEX,
    propagateSectionThrows: true,
    section: async () => runDebianUpgradeCriticalSection(parameters),
  })
  return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
}

/**
 * Run the Debian release upgrade by rewriting sources and running
 * `apt-get full-upgrade`.
 *
 * Determines the current and target (stable) codenames, rewrites all
 * apt sources to point at the new suite, then executes the four-step
 * upgrade sequence: `apt-get update`, `dpkg --configure -a` (to resolve
 * any previously interrupted package configurations), `apt-get full-upgrade`,
 * and `apt-get autoremove`. When `dryRun` is set or the host already runs
 * the target codename, the upgrade is skipped entirely and `"ok"` is returned.
 *
 * On success, returns `status: "changed"` with reboot meta so the runner
 * can reconnect after the post-upgrade restart. On failure of any apt
 * step, the rewritten sources files are restored from the snapshots taken
 * before the rewrite (R-0000046).
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param options - Upgrade options (see {@link ReleaseUpgradeOptions}).
 * @returns A `ModuleResult` — `"changed"` with reboot meta on success,
 *   `"ok"` on dry-run, or `"failed"` when any command returns a non-zero
 *   exit code.
 */
async function applyDebian(
  ssh: SshConnection,
  options: ReleaseUpgradeOptions
): Promise<ModuleResult> {
  const currentCodename = await getDebianCurrentCodename(ssh)
  // R-0000715: `getDebianStableCodename` now enforces the allowlist directly
  // (see `isAllowedDebianStableTargetCodename` inside that helper). A
  // rejected codename surfaces here as a thrown error, which we convert into
  // a structured `failed(...)` ModuleResult so the runner reports the issue
  // alongside the normal failure output instead of an unhandled exception.
  let targetCodename: string
  try {
    targetCodename = await getDebianStableCodename(ssh)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[releaseUpgrade.upgrade] ${reason}`)
  }

  if (options.dryRun === true || currentCodename === targetCodename) return { status: "ok" }

  // R-0000632 / R-0000715: the pair-level `isSupportedDebianUpgradePath`
  // check remains as defense-in-depth on top of the allowlist guard now
  // enforced inside `getDebianStableCodename` itself.
  if (!isSupportedDebianUpgradePath(currentCodename, targetCodename)) {
    return failed(
      `[releaseUpgrade.upgrade] unsupported Debian release upgrade path: ${currentCodename} -> ${targetCodename}`
    )
  }

  return runDebianUpgradeWithMutex({ options, ssh, targetCodename })
}

/**
 * Modules for upgrading the operating system to the next major release.
 *
 * Supports Ubuntu (via `do-release-upgrade`) and Debian (via sources.list
 * rewrite + `apt-get full-upgrade`). After a successful upgrade the module
 * signals the runner to reboot and optionally reconnect to a new host address
 * via the `system.reboot` / `system.host` meta keys.
 */
export const releaseUpgrade = {
  /**
   * Upgrade the remote host to the next major OS release.
   *
   * The distribution is auto-detected from `/etc/os-release`. Ubuntu hosts
   * are upgraded with `do-release-upgrade`; Debian hosts are upgraded by
   * rewriting apt sources to the current stable suite and running
   * `apt-get full-upgrade`.
   *
   * The `check` phase returns `"needs-apply"` when an upgrade is available
   * (Ubuntu: `do-release-upgrade -c` exits 0; Debian: current codename differs
   * from stable codename) and `"ok"` when the host is already up to date.
   *
   * @param options - Optional settings.
   * @param options.dryRun - When `true`, only inspect whether an upgrade is
   *   available without modifying the system.
   * @param options.resolveHost - Async callback invoked after the upgrade to
   *   determine the new host address before the runner reconnects.
   * @returns A Module that performs the OS release upgrade.
   *
   * @example
   * // Simple upgrade — auto-detect distro and apply
   * releaseUpgrade.upgrade()
   *
   * @example
   * // Dry-run: check availability without making changes
   * releaseUpgrade.upgrade({ dryRun: true })
   *
   * @example
   * // Resolve the new host address after reboot (e.g. dynamic DNS or DHCP)
   * releaseUpgrade.upgrade({
   *   resolveHost: async () => {
   *     const ip = await myDns.resolve("my-server.example.com")
   *     return ip
   *   },
   * })
   */
  upgrade(options: ReleaseUpgradeOptions = {}): Module {
    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed("[releaseUpgrade.upgrade] SSH connection is required")

        const distro = await detectDistro(ssh)
        if (distro == null) return failed("[releaseUpgrade.upgrade] Unsupported distribution")

        if (distro === "ubuntu") return applyUbuntu(ssh, options)
        return applyDebian(ssh, options)
      },

      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const distro = await detectDistro(ssh)
        if (distro == null) return NEEDS_APPLY

        if (distro === "ubuntu") {
          const result = await ssh.exec("do-release-upgrade -c", releaseUpgradeExecOptions(options))
          if (isNoUbuntuReleaseAvailable(result)) return "ok"
          return NEEDS_APPLY
        }

        // Debian: compare current codename to stable
        try {
          const currentCodename = await getDebianCurrentCodename(ssh)
          const targetCodename = await getDebianStableCodename(ssh)
          return currentCodename === targetCodename ? "ok" : NEEDS_APPLY
        } catch {
          return NEEDS_APPLY
        }
      },

      name: "releaseUpgrade.upgrade",
    }
  },
}
