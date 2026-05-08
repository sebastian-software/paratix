/* eslint-disable max-lines -- ssh module keeps known_hosts/authorized_keys helpers together */
import { computeFingerprint } from "../knownHosts.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { assertValidUserName } from "./posixNames.js"
import { applyAuthorizedKeys, checkAuthorizedKeys } from "./sshAuthorizedKeysHelpers.js"
import { assertAuthorizedKeyValue } from "./sshPublicKeyValidation.js"

type KnownHostsOptions = {
  expectedFingerprint?: string
  port?: number
  publicKey?: string
  state?: "absent" | "present"
}

const SSH_KEYSCAN_MIN_FIELDS = 3
const DEFAULT_SSH_PORT = 22
const ASCII_SPACE_CODE_POINT = 0x20
const ASCII_DELETE_CODE_POINT = 0x7f

function normalizePublicKey(publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/v)
  if (parts.length < 2) {
    throw new Error(
      "ssh.knownHosts requires a full public key in the format '<algorithm> <base64>'"
    )
  }
  const [algorithm, key] = parts
  return `${algorithm} ${key}`
}

function parseHostKeyLines(output: string): string[] {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
}

function scannedLinePublicKey(line: string): string {
  const parts = line.split(/\s+/v)
  if (parts.length < SSH_KEYSCAN_MIN_FIELDS) {
    throw new Error(`ssh.knownHosts received invalid ssh-keyscan output: ${line}`)
  }
  const [, algorithm, key] = parts
  return `${algorithm} ${key}`
}

function scannedLineFingerprint(line: string): string {
  const publicKey = scannedLinePublicKey(line)
  const [, key] = publicKey.split(" ")
  return computeFingerprint(Buffer.from(key, "base64"))
}

function lineMatchesTrustAnchor(line: string, options: KnownHostsOptions): boolean {
  const normalizedExpectedKey =
    options.publicKey == null ? null : normalizePublicKey(options.publicKey)
  const expectedFingerprint = options.expectedFingerprint

  // R-0000252: a malformed line in ~/.ssh/known_hosts (truncated entry,
  // garbage after a partial write, missing algorithm/key fields) makes
  // `scannedLinePublicKey` throw. Callers expect a boolean result so they
  // can treat the line as drift; an uncaught exception escaping past
  // `check`/`apply` would mean a single corrupted entry breaks the entire
  // module. Treat malformed lines as "does not match" so the drift path
  // takes over (ssh-keygen -R replaces them with verified entries).
  try {
    const publicKeyMatches =
      normalizedExpectedKey != null && scannedLinePublicKey(line) === normalizedExpectedKey
    const fingerprintMatches =
      expectedFingerprint != null && scannedLineFingerprint(line) === expectedFingerprint
    return publicKeyMatches || fingerprintMatches
  } catch {
    return false
  }
}

function getVerifiedScannedHostKeyLines(
  host: string,
  scannedLines: string[],
  options: KnownHostsOptions
): string[] {
  const normalizedExpectedKey =
    options.publicKey == null ? null : normalizePublicKey(options.publicKey)
  const expectedFingerprint = options.expectedFingerprint

  if (normalizedExpectedKey == null && expectedFingerprint == null) {
    throw new Error(
      `ssh.knownHosts(${host}) requires expectedFingerprint or publicKey before accepting ssh-keyscan output`
    )
  }

  const verifiedLines = scannedLines.filter((line) => lineMatchesTrustAnchor(line, options))

  if (verifiedLines.length === 0) {
    throw new Error(
      `ssh.knownHosts(${host}) could not verify the scanned host key against the provided trust anchor`
    )
  }

  return verifiedLines
}

function hasKnownHostsTrustAnchor(options?: KnownHostsOptions): boolean {
  return options?.expectedFingerprint != null || options?.publicKey != null
}

function assertKnownHostsPort(host: string, options?: KnownHostsOptions): void {
  if (options?.port === undefined) return
  if (!isValidTcpPort(options.port)) {
    throw new Error(`ssh.knownHosts(${host}) port must be an integer between 1 and 65535`)
  }
}

function hasUnsafeKnownHostsHostCharacter(host: string): boolean {
  for (const character of host) {
    const codePoint = character.codePointAt(0)
    if (codePoint == null) return true
    if (
      codePoint <= ASCII_SPACE_CODE_POINT ||
      codePoint === ASCII_DELETE_CODE_POINT ||
      character.trim().length === 0
    ) {
      return true
    }
  }
  return false
}

function assertKnownHostsHost(host: string): void {
  if (host.length === 0 || host.startsWith("-") || hasUnsafeKnownHostsHostCharacter(host)) {
    throw new Error(
      `ssh.knownHosts host must not be empty, start with '-', or contain whitespace/control characters: ${JSON.stringify(host)}`
    )
  }
}

function knownHostsLookupTarget(host: string, options?: KnownHostsOptions): string {
  const port = options?.port
  if (port == null || port === DEFAULT_SSH_PORT) return host
  return `[${host}]:${port}`
}

function sshKeyscanCommand(host: string, options?: KnownHostsOptions): string {
  const port = options?.port
  if (port == null || port === DEFAULT_SSH_PORT) {
    return `ssh-keyscan -H ${shellQuote(host)} 2>/dev/null`
  }
  return `ssh-keyscan -p ${port} -H ${shellQuote(host)} 2>/dev/null`
}

/**
 * R-0000173: ssh-keygen -F documents only exit codes 0 (host found) and 1
 * (host not found). Anything else (e.g. 2 for argument errors, 255 for
 * known_hosts file corruption) is an unexpected condition that must surface
 * as a failure instead of being silently coerced into "not found".
 *
 * @param exitCode - The exit code returned by `ssh-keygen -F`.
 * @returns `true` when the exit code is one of the documented values.
 */
function isExpectedSshKeygenLookupExitCode(exitCode: number): boolean {
  return exitCode === 0 || exitCode === 1
}

class SshKeygenLookupError extends Error {
  public readonly exitCode: number
  public readonly stderr: string

  public constructor(host: string, exitCode: number, stderr: string) {
    super(
      `ssh.knownHosts(${host}) ssh-keygen -F exited with unexpected code ${String(exitCode)}: ${stderr.trim() || "no stderr"}`
    )
    this.name = "SshKeygenLookupError"
    this.exitCode = exitCode
    this.stderr = stderr
  }
}

async function hasMatchingKnownHostTrustAnchor(
  conn: SshConnection,
  host: string,
  options: KnownHostsOptions
): Promise<boolean> {
  const result = await conn.exec(
    `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  if (result.code === 1) return false
  // R-0000173: code 0 means a match was found; any other value is a real
  // error that must propagate so the caller can return a failed result.
  if (!isExpectedSshKeygenLookupExitCode(result.code)) {
    throw new SshKeygenLookupError(host, result.code, result.stderr)
  }

  const knownHostLines = parseHostKeyLines(result.stdout)

  if (knownHostLines.length === 0) return false

  return knownHostLines.every((line) => lineMatchesTrustAnchor(line, options))
}

async function getKnownHostLines(
  conn: SshConnection,
  host: string,
  options?: KnownHostsOptions
): Promise<string[]> {
  const result = await conn.exec(
    `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  if (result.code === 1) return []
  // R-0000173: same guard as hasMatchingKnownHostTrustAnchor — refuse to
  // silently treat unexpected codes (corrupted known_hosts, bad argv) as
  // an empty result set.
  if (!isExpectedSshKeygenLookupExitCode(result.code)) {
    throw new SshKeygenLookupError(host, result.code, result.stderr)
  }
  return parseHostKeyLines(result.stdout)
}

function isSshKeygenLookupError(error: unknown): error is SshKeygenLookupError {
  return error instanceof SshKeygenLookupError
}

/**
 * Filter `verifiedLines` down to those that are not yet present in
 * `~/.ssh/known_hosts`. Each verified line is compared against the file with
 * `grep -qxF` (whole-line literal match) so the apply path appends only
 * missing entries. R-0000038: prevents duplicate entries when a re-run lands
 * in `needs-apply` (e.g. trust-anchor mismatch on a single algorithm) but
 * the bulk of the lines are already on disk.
 *
 * @param conn - The SSH connection.
 * @param verifiedLines - Lines that passed trust-anchor verification.
 * @returns The subset of `verifiedLines` that still need to be appended.
 */
async function filterMissingKnownHostLines(
  conn: SshConnection,
  verifiedLines: string[]
): Promise<string[]> {
  const checks = await Promise.all(
    verifiedLines.map(async (line) => conn.test(`grep -qxF ${shellQuote(line)} ~/.ssh/known_hosts`))
  )
  return verifiedLines.filter((_line, index) => !checks[index])
}

/**
 * R-0000170: resolve the verified scanned host key lines or convert a
 * verification throw into a failed ModuleResult. Keeps the verification
 * boundary in a single helper so applyKnownHostsPresent stays under the
 * project's max-statements lint cap.
 *
 * @param host - The hostname or IP address being scanned.
 * @param scannedLines - The raw lines returned by ssh-keyscan.
 * @param options - The knownHosts options containing the trust anchor.
 * @returns A tuple of (verifiedLines, failureResult). Exactly one is set.
 */
function resolveVerifiedLines(
  host: string,
  scannedLines: string[],
  options: KnownHostsOptions
): { failure: ModuleResult; verifiedLines: null } | { failure: null; verifiedLines: string[] } {
  try {
    const verifiedLines = getVerifiedScannedHostKeyLines(host, scannedLines, options)
    return { failure: null, verifiedLines }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return {
      failure: failed(`[ssh.knownHosts: ${host} (present)] ${detail}`),
      verifiedLines: null,
    }
  }
}

/**
 * R-0000173: resolve the existing known_hosts lines or convert an
 * unexpected ssh-keygen exit code (corrupt file, bad argv) into a failed
 * ModuleResult instead of letting it escape as an uncaught exception.
 *
 * @param conn - The SSH connection.
 * @param host - The hostname being looked up.
 * @param options - The knownHosts options carrying the optional port.
 * @returns A tuple of (existingLines, failureResult). Exactly one is set.
 */
async function resolveExistingKnownHostLines(
  conn: SshConnection,
  host: string,
  options?: KnownHostsOptions
): Promise<
  { existingLines: null; failure: ModuleResult } | { existingLines: string[]; failure: null }
> {
  try {
    const existingLines = await getKnownHostLines(conn, host, options)
    return { existingLines, failure: null }
  } catch (error) {
    if (isSshKeygenLookupError(error)) {
      return {
        existingLines: null,
        failure: failed(`[ssh.knownHosts: ${host} (present)] ${error.message}`),
      }
    }
    throw error
  }
}

/**
 * Compute the lines that still need to be appended to `~/.ssh/known_hosts`,
 * removing any drifted entries first when the existing lines do not match
 * the configured trust anchor.
 *
 * @param conn - The SSH connection.
 * @param parameters - Reconciliation context.
 * @param parameters.host - The hostname being scanned.
 * @param parameters.options - The knownHosts options carrying the trust anchor.
 * @param parameters.existingLines - Lines currently present in known_hosts.
 * @param parameters.verifiedLines - Lines that passed trust-anchor verification.
 * @returns The set of lines that still need to be written.
 */
async function reconcileKnownHostsState(
  conn: SshConnection,
  parameters: {
    existingLines: string[]
    host: string
    options?: KnownHostsOptions
    verifiedLines: string[]
  }
): Promise<
  { failure: ModuleResult; missingLines: null } | { failure: null; missingLines: string[] }
> {
  const { existingLines, host, options, verifiedLines } = parameters
  const hasMismatchedExistingLines = existingLines.some(
    (line) => !lineMatchesTrustAnchor(line, options ?? {})
  )
  if (hasMismatchedExistingLines) {
    // R-0000213: ssh-keygen -R can fail (corrupt known_hosts, permission
    // denied). Run with ignoreExitCode and surface a failedCommand result
    // instead of letting the exec throw and propagate as an uncaught
    // exception. Mirrors the absent-state guard from R-0000212.
    const removeResult = await conn.exec(
      `ssh-keygen -R ${shellQuote(knownHostsLookupTarget(host, options))}`,
      { ignoreExitCode: true, silent: true }
    )
    if (removeResult.code !== 0) {
      return {
        failure: failedCommand(
          `[ssh.knownHosts: ${host} (present)] ssh-keygen -R failed during drift cleanup`,
          removeResult
        ),
        missingLines: null,
      }
    }
    return { failure: null, missingLines: verifiedLines }
  }
  return { failure: null, missingLines: await filterMissingKnownHostLines(conn, verifiedLines) }
}

async function runSshKeyscanForKnownHosts(
  conn: SshConnection,
  host: string,
  options?: KnownHostsOptions
): Promise<{ failure: ModuleResult; lines: null } | { failure: null; lines: string[] }> {
  // R-0000214: ssh-keyscan exits non-zero when the host is unreachable, the
  // port is closed, or DNS fails. The previous `conn.output` call propagated
  // that as an uncaught exception even though `2>/dev/null` suppressed the
  // diagnostic. Run with ignoreExitCode and surface a failedCommand result.
  const result = await conn.exec(sshKeyscanCommand(host, options), {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) {
    return {
      failure: failedCommand(`[ssh.knownHosts: ${host} (present)] ssh-keyscan failed`, result),
      lines: null,
    }
  }
  return { failure: null, lines: parseHostKeyLines(result.stdout) }
}

/**
 * Apply the `state: "present"` path of `ssh.knownHosts`: scan the host,
 * verify each line against the trust anchor, and append only the lines that
 * are not yet in `~/.ssh/known_hosts` (R-0000038 idempotency).
 *
 * @param conn - The SSH connection.
 * @param parameters - Apply context for the present-state branch.
 * @param parameters.host - The hostname or IP address to scan.
 * @param parameters.options - Configuration including the trust anchor.
 * @returns A {@link ModuleResult} describing the outcome.
 */
async function applyKnownHostsPresent(
  conn: SshConnection,
  parameters: { host: string; options?: KnownHostsOptions }
): Promise<ModuleResult> {
  const { host, options } = parameters
  const scan = await runSshKeyscanForKnownHosts(conn, host, options)
  if (scan.failure) return scan.failure
  const verification = resolveVerifiedLines(host, scan.lines, options ?? {})
  if (verification.failure) return verification.failure

  // Mirror R-0000212/213/214/215: `mkdir -p ~/.ssh && chmod 700 ~/.ssh` can
  // fail when ~/.ssh is a symlink, has wrong permissions, or the parent
  // directory denies writes. Run with `ignoreExitCode` and surface a
  // failedCommand result instead of letting the exec throw past
  // applyKnownHostsPresent.
  const sshDirectoryResult = await conn.exec("mkdir -p ~/.ssh && chmod 700 ~/.ssh", {
    ignoreExitCode: true,
    silent: true,
  })
  if (sshDirectoryResult.code !== 0) {
    return failedCommand(
      `[ssh.knownHosts: ${host} (present)] failed to prepare ~/.ssh directory`,
      sshDirectoryResult
    )
  }

  const existing = await resolveExistingKnownHostLines(conn, host, options)
  if (existing.failure) return existing.failure

  const reconciled = await reconcileKnownHostsState(conn, {
    existingLines: existing.existingLines,
    host,
    options,
    verifiedLines: verification.verifiedLines,
  })
  if (reconciled.failure) return reconciled.failure
  if (reconciled.missingLines.length === 0) {
    return { status: "ok" }
  }

  return appendVerifiedKnownHostLines(conn, host, reconciled.missingLines)
}

async function appendVerifiedKnownHostLines(
  conn: SshConnection,
  host: string,
  missingLines: string[]
): Promise<ModuleResult> {
  // R-0000215: the final append to ~/.ssh/known_hosts can fail (permission
  // denied, ENOSPC). Run with ignoreExitCode and report failedCommand on
  // non-zero exit instead of letting the exec throw and leaving the trust
  // anchor half-written.
  const appendResult = await conn.exec(
    `printf '%s\\n' ${missingLines.map((line) => shellQuote(line)).join(" ")} >> ~/.ssh/known_hosts`,
    { ignoreExitCode: true, silent: true }
  )
  if (appendResult.code !== 0) {
    return failedCommand(
      `[ssh.knownHosts: ${host} (present)] failed to append to ~/.ssh/known_hosts`,
      appendResult
    )
  }
  return { status: "changed" }
}

/**
 * Modules for managing SSH client-side resources such as known hosts
 * and authorized keys.
 */
export const ssh = {
  /**
   * Ensure a public key is present in (or absent from) a user's `authorized_keys` file.
   *
   * When `state` is `"present"` (the default), the key is appended if missing and the
   * `.ssh` directory and `authorized_keys` file are created with correct ownership
   * and permissions. When `state` is `"absent"`, the matching line is removed.
   *
   * @param user - The target user whose `authorized_keys` file is managed.
   * @param key - The full public key string (e.g. `"ssh-ed25519 AAAA... comment"`).
   * @param options - Optional settings.
   * @param options.state - Whether the key should be `"present"` or `"absent"`. Defaults to `"present"`.
   * @returns A Module that manages the authorized key entry.
   */
  authorizedKeys(user: string, key: string, options?: { state?: "absent" | "present" }): Module {
    assertValidUserName(user)
    assertAuthorizedKeyValue(key)
    const state = options?.state ?? "present"

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        return applyAuthorizedKeys(conn, { key, state, user })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        return checkAuthorizedKeys(conn, { key, state, user })
      },
      name: `ssh.authorizedKeys: ${user} (${state})`,
    }
  },

  /**
   * Ensure a host is present in (or absent from) the connecting user's `~/.ssh/known_hosts`.
   *
   * When `state` is `"present"` (the default), the host's public keys are fetched
   * via `ssh-keyscan` and appended to `~/.ssh/known_hosts`. When `state` is
   * `"absent"`, the host entry is removed via `ssh-keygen -R`.
   *
   * @param host - The hostname or IP address to manage.
   * @param options - Optional settings.
   * @param options.state - Whether the host should be `"present"` or `"absent"`. Defaults to `"present"`.
   * @returns A Module that manages the known hosts entry.
   */
  knownHosts(host: string, options?: KnownHostsOptions): Module {
    assertKnownHostsHost(host)
    assertKnownHostsPort(host, options)
    const state = options?.state ?? "present"
    const lookupTarget = knownHostsLookupTarget(host, options)

    if (state === "present" && !hasKnownHostsTrustAnchor(options)) {
      // Mirror the failure message from getVerifiedScannedHostKeyLines so the
      // construction-time rejection matches the apply-time rejection. Without
      // a trust anchor `check` could otherwise return "ok" for any pre-existing
      // entry, including ones from a prior TOFU acceptance — see R-0000029.
      throw new Error(
        `ssh.knownHosts(${host}) requires expectedFingerprint or publicKey before accepting ssh-keyscan output`
      )
    }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[ssh.knownHosts: ${host} (${state})] SSH connection is required`)

        if (state === "present") {
          return applyKnownHostsPresent(conn, { host, options })
        }

        const hostKnownBefore = await conn.test(`ssh-keygen -F ${shellQuote(lookupTarget)}`)
        if (!hostKnownBefore) {
          return { status: "ok" }
        }

        // R-0000212: ssh-keygen -R can fail (permission denied, corrupted
        // known_hosts file, ENOSPC). Mirror the present-state guards: run
        // with ignoreExitCode and surface a failedCommand result instead of
        // letting the exec throw and propagate as an uncaught exception.
        const removeResult = await conn.exec(`ssh-keygen -R ${shellQuote(lookupTarget)}`, {
          ignoreExitCode: true,
          silent: true,
        })
        if (removeResult.code !== 0) {
          return failedCommand(
            `[ssh.knownHosts: ${host} (absent)] ssh-keygen -R failed`,
            removeResult
          )
        }
        return { status: "changed" }
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        if (state === "present" && hasKnownHostsTrustAnchor(options)) {
          return (await hasMatchingKnownHostTrustAnchor(conn, host, options ?? {}))
            ? "ok"
            : NEEDS_APPLY
        }

        const hostKnown = await conn.test(`ssh-keygen -F ${shellQuote(lookupTarget)}`)

        if (state === "present") {
          return hostKnown ? "ok" : NEEDS_APPLY
        }
        return hostKnown ? NEEDS_APPLY : "ok"
      },
      name: `ssh.knownHosts: ${host} (${state})`,
    }
  },
}
