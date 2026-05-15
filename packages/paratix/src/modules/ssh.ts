/* eslint-disable max-lines -- ssh module keeps known_hosts/authorized_keys helpers together */
import { computeFingerprint } from "../knownHosts.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { isValidTcpPort } from "../serverDefinitionValidation.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { assertValidUserName } from "./posixNames.js"
import { applyAuthorizedKeys, checkAuthorizedKeys } from "./sshAuthorizedKeysHelpers.js"
import { assertAuthorizedKeyValue } from "./sshPublicKeyValidation.js"

type KnownHostsOptions = {
  expectedFingerprint?: string
  port?: number
  publicKey?: string
  state?: KnownHostsState
}

type KnownHostsState = "absent" | "present"
type KnownHostsPaths = {
  knownHostsPath: string
  sshDirectoryPath: string
}
type KnownHostsLookupParameters = {
  host: string
  knownHostsPath?: string
  options?: KnownHostsOptions
}
type AuthorizedKeysState = "absent" | "present"

type AuthorizedKeysOptions = {
  state?: AuthorizedKeysState
}

const SSH_KEYSCAN_MIN_FIELDS = 3
const DEFAULT_SSH_PORT = 22
const ASCII_SPACE_CODE_POINT = 0x20
const ASCII_DELETE_CODE_POINT = 0x7f
const KNOWN_HOSTS_TEMPORARY_PREFIX = ".paratix-known-hosts"
const MUTATION_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

function assertAuthorizedKeysState(state: unknown): asserts state is AuthorizedKeysState {
  if (state === "absent" || state === "present") return
  throw new Error('ssh.authorizedKeys state must be "present" or "absent"')
}

function resolveAuthorizedKeysState(options?: AuthorizedKeysOptions): AuthorizedKeysState {
  const state = options?.state ?? "present"
  assertAuthorizedKeysState(state)
  return state
}

function assertKnownHostsState(state: unknown): asserts state is KnownHostsState {
  if (state === "absent" || state === "present") return
  throw new Error('ssh.knownHosts state must be "present" or "absent"')
}

function resolveKnownHostsState(options?: KnownHostsOptions): KnownHostsState {
  let state: unknown = "present"
  if (options?.state !== undefined) {
    state = options.state
  }
  assertKnownHostsState(state)
  return state
}

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

function sshKeygenKnownHostsFileArgument(knownHostsPath?: string): string {
  return knownHostsPath == null ? "" : ` -f ${shellQuote(knownHostsPath)}`
}

function validateKnownHostsHome(home: string): string {
  if (home.length === 0 || home === "/" || !home.startsWith("/")) {
    throw new Error("failed to resolve a safe home directory")
  }
  return home
}

async function resolveKnownHostsPaths(conn: SshConnection): Promise<{
  home: string
  knownHostsPath: string
  sshDirectoryPath: string
}> {
  const home = validateKnownHostsHome(await conn.output("printf '%s' \"$HOME\""))
  const sshDirectoryPath = `${home}/.ssh`
  return {
    home,
    knownHostsPath: `${sshDirectoryPath}/known_hosts`,
    sshDirectoryPath,
  }
}

async function resolveKnownHostsPathsForState(
  conn: SshConnection,
  parameters: { host: string; state: KnownHostsState }
): Promise<{ failure: ModuleResult; paths: null } | { failure: null; paths: KnownHostsPaths }> {
  const { host, state } = parameters
  try {
    const paths = await resolveKnownHostsPaths(conn)
    return { failure: null, paths }
  } catch (error) {
    if (isKnownHostsPathValidationError(error)) {
      return {
        failure: failed(`[ssh.knownHosts: ${host} (${state})] ${error.message}`),
        paths: null,
      }
    }
    throw error
  }
}

function isKnownHostsPathValidationError(error: unknown): error is Error {
  return (
    error instanceof Error &&
    (error.message.startsWith("Unexpected mktemp output:") ||
      error.message.startsWith("Unexpected mktemp directory:") ||
      error.message === "failed to resolve a safe home directory")
  )
}

async function createKnownHostsTemporaryPath(
  conn: SshConnection,
  sshDirectoryPath: string
): Promise<string> {
  const template = `${sshDirectoryPath}/${KNOWN_HOSTS_TEMPORARY_PREFIX}.XXXXXX`
  const temporaryPath = await conn.output(`mktemp ${shellQuote(template)}`)
  return validateMktempPath(sshDirectoryPath, temporaryPath, KNOWN_HOSTS_TEMPORARY_PREFIX)
}

async function ensureSshDirectoryForKnownHosts(
  conn: SshConnection,
  parameters: {
    host: string
    sshDirectoryPath: string
  }
): Promise<ModuleResult | null> {
  const { host, sshDirectoryPath } = parameters
  const directory = shellQuote(sshDirectoryPath)
  const result = await conn.exec(
    `[ ! -L ${directory} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; if [ -e ${directory} ]; then [ -d ${directory} ] || { echo '.ssh must be a directory' >&2; exit 1; }; else mkdir -p ${directory}; fi; [ -d ${directory} ] && [ ! -L ${directory} ] || { echo '.ssh must be a real directory' >&2; exit 1; }; chmod 700 ${directory}`,
    MUTATION_EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(
      `[ssh.knownHosts: ${host} (present)] failed to prepare .ssh directory`,
      result
    )
  }
  return null
}

async function ensureKnownHostsIsNotSymlink(
  conn: SshConnection,
  parameters: {
    host: string
    knownHostsPath: string
    state: KnownHostsState
  }
): Promise<ModuleResult | null> {
  const { host, knownHostsPath, state } = parameters
  const result = await conn.exec(
    `[ ! -L ${shellQuote(knownHostsPath)} ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }`,
    MUTATION_EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(
      `[ssh.knownHosts: ${host} (${state})] known_hosts symlink check failed`,
      result
    )
  }
  return null
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
  parameters: { options: KnownHostsOptions } & KnownHostsLookupParameters
): Promise<boolean> {
  const { host, knownHostsPath, options } = parameters
  const result = await conn.exec(
    `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))}${sshKeygenKnownHostsFileArgument(knownHostsPath)}`,
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
  parameters: KnownHostsLookupParameters
): Promise<string[]> {
  const { host, knownHostsPath, options } = parameters
  const result = await conn.exec(
    `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))}${sshKeygenKnownHostsFileArgument(knownHostsPath)}`,
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

async function hasKnownHostEntry(
  conn: SshConnection,
  parameters: KnownHostsLookupParameters
): Promise<boolean> {
  const { host, knownHostsPath, options } = parameters
  const result = await conn.exec(
    `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))}${sshKeygenKnownHostsFileArgument(knownHostsPath)}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  if (result.code === 1) return false
  if (!isExpectedSshKeygenLookupExitCode(result.code)) {
    throw new SshKeygenLookupError(host, result.code, result.stderr)
  }
  return true
}

async function resolveKnownHostsAbsentLookup(
  conn: SshConnection,
  parameters: KnownHostsLookupParameters
): Promise<{ failure: ModuleResult; known: null } | { failure: null; known: boolean }> {
  const { host } = parameters
  try {
    return { failure: null, known: await hasKnownHostEntry(conn, parameters) }
  } catch (error) {
    if (isSshKeygenLookupError(error)) {
      return {
        failure: failed(`[ssh.knownHosts: ${host} (absent)] ${error.message}`),
        known: null,
      }
    }
    throw error
  }
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
 * @param knownHostsPath - Absolute known_hosts path to inspect.
 * @param verifiedLines - Lines that passed trust-anchor verification.
 * @returns The subset of `verifiedLines` that still need to be appended.
 */
async function filterMissingKnownHostLines(
  conn: SshConnection,
  knownHostsPath: string,
  verifiedLines: string[]
): Promise<string[]> {
  const checks = await Promise.all(
    verifiedLines.map(async (line) =>
      conn.test(`grep -qxF ${shellQuote(line)} ${shellQuote(knownHostsPath)}`)
    )
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
 * @param parameters - Lookup context.
 * @param parameters.host - The hostname being looked up.
 * @param parameters.knownHostsPath - Optional explicit known_hosts path.
 * @param parameters.options - The knownHosts options carrying the optional port.
 * @returns A tuple of (existingLines, failureResult). Exactly one is set.
 */
async function resolveExistingKnownHostLines(
  conn: SshConnection,
  parameters: KnownHostsLookupParameters
): Promise<
  { existingLines: null; failure: ModuleResult } | { existingLines: string[]; failure: null }
> {
  const { host, knownHostsPath } = parameters
  try {
    const existingLines =
      knownHostsPath != null && !(await conn.exists(knownHostsPath))
        ? []
        : await getKnownHostLines(conn, parameters)
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
 * @param parameters.knownHostsPath - Absolute known_hosts path to reconcile.
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
    knownHostsPath: string
    options?: KnownHostsOptions
    verifiedLines: string[]
  }
): Promise<
  | { failure: ModuleResult; lines: null; mode: null }
  | { failure: null; lines: string[]; mode: "append" | "replace" }
> {
  const { existingLines, knownHostsPath, options, verifiedLines } = parameters
  const hasMismatchedExistingLines = existingLines.some(
    (line) => !lineMatchesTrustAnchor(line, options ?? {})
  )
  if (hasMismatchedExistingLines) {
    return { failure: null, lines: verifiedLines, mode: "replace" }
  }
  return {
    failure: null,
    lines: await filterMissingKnownHostLines(conn, knownHostsPath, verifiedLines),
    mode: "append",
  }
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

async function ensureKnownHostsPresentPath(
  conn: SshConnection,
  parameters: { host: string; paths: KnownHostsPaths }
): Promise<ModuleResult | null> {
  const { host, paths } = parameters
  const directoryFailure = await ensureSshDirectoryForKnownHosts(conn, {
    host,
    sshDirectoryPath: paths.sshDirectoryPath,
  })
  if (directoryFailure) return directoryFailure

  return ensureKnownHostsIsNotSymlink(conn, {
    host,
    knownHostsPath: paths.knownHostsPath,
    state: "present",
  })
}

async function rewriteReconciledKnownHosts(
  conn: SshConnection,
  parameters: {
    host: string
    paths: KnownHostsPaths
    reconciled: { lines: string[]; mode: "append" | "replace" }
  }
): Promise<ModuleResult> {
  const { host, paths, reconciled } = parameters
  if (reconciled.lines.length === 0) return { status: "ok" }
  return rewriteKnownHostsFile(conn, {
    host,
    knownHostsPath: paths.knownHostsPath,
    lines: reconciled.lines,
    mode: reconciled.mode,
    sshDirectoryPath: paths.sshDirectoryPath,
  })
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
  const pathResolution = await resolveKnownHostsPathsForState(conn, { host, state: "present" })
  if (pathResolution.failure) return pathResolution.failure

  const scan = await runSshKeyscanForKnownHosts(conn, host, options)
  if (scan.failure) return scan.failure
  const verification = resolveVerifiedLines(host, scan.lines, options ?? {})
  if (verification.failure) return verification.failure

  const pathFailure = await ensureKnownHostsPresentPath(conn, {
    host,
    paths: pathResolution.paths,
  })
  if (pathFailure) return pathFailure

  const existing = await resolveExistingKnownHostLines(conn, {
    host,
    knownHostsPath: pathResolution.paths.knownHostsPath,
    options,
  })
  if (existing.failure) return existing.failure

  const reconciled = await reconcileKnownHostsState(conn, {
    existingLines: existing.existingLines,
    host,
    knownHostsPath: pathResolution.paths.knownHostsPath,
    options,
    verifiedLines: verification.verifiedLines,
  })
  if (reconciled.failure) return reconciled.failure
  return rewriteReconciledKnownHosts(conn, { host, paths: pathResolution.paths, reconciled })
}

function knownHostsStageCommand(parameters: {
  knownHostsPath: string
  lines: string[]
  mode: "append" | "replace"
  temporaryPath: string
}): string {
  const { knownHostsPath, lines, mode, temporaryPath } = parameters
  const quotedKnownHostsPath = shellQuote(knownHostsPath)
  const quotedTemporaryPath = shellQuote(temporaryPath)
  const existingKnownHostsGuard = `[ ! -L ${quotedKnownHostsPath} ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }; [ -f ${quotedKnownHostsPath} ] || { echo 'known_hosts must be a regular file' >&2; exit 1; }`
  const writeLines = `printf '%s\\n' ${lines.map((line) => shellQuote(line)).join(" ")}`

  if (mode === "replace") return `${writeLines} > ${quotedTemporaryPath}`

  const appendMissingLines = lines
    .map(
      (line) =>
        `grep -qxF ${shellQuote(line)} ${quotedTemporaryPath}; grep_status=$?; if [ "$grep_status" -eq 0 ]; then :; elif [ "$grep_status" -eq 1 ]; then printf '%s\\n' ${shellQuote(line)} >> ${quotedTemporaryPath}; else exit "$grep_status"; fi`
    )
    .join("; ")
  return `{ if [ -e ${quotedKnownHostsPath} ]; then ${existingKnownHostsGuard}; awk '1' ${quotedKnownHostsPath} > ${quotedTemporaryPath} || exit $?; else : > ${quotedTemporaryPath}; fi; ${appendMissingLines}; }`
}

async function stageKnownHostsContent(
  conn: SshConnection,
  parameters: {
    host: string
    knownHostsPath: string
    lines: string[]
    mode: "append" | "replace"
    temporaryPath: string
  }
): Promise<ModuleResult | null> {
  const { host } = parameters
  const stageResult = await conn.exec(knownHostsStageCommand(parameters), MUTATION_EXEC_OPTS)
  if (stageResult.code !== 0) {
    return failedCommand(
      `[ssh.knownHosts: ${host} (present)] failed to stage known_hosts rewrite`,
      stageResult
    )
  }
  return null
}

async function replaceKnownHostsAtomically(
  conn: SshConnection,
  parameters: {
    host: string
    knownHostsPath: string
    sshDirectoryPath: string
    temporaryPath: string
  }
): Promise<ModuleResult | null> {
  const { host, knownHostsPath, sshDirectoryPath, temporaryPath } = parameters
  const quotedKnownHostsPath = shellQuote(knownHostsPath)
  const quotedSshDirectoryPath = shellQuote(sshDirectoryPath)
  const quotedTemporaryPath = shellQuote(temporaryPath)
  const expectedKnownHostsState = shellQuote("600 regular file")
  const replaceResult = await conn.exec(
    `chmod 600 ${quotedTemporaryPath} && { expected_known_hosts_hash=$(sha256sum ${quotedTemporaryPath} | cut -d' ' -f1) || exit $?; [ ! -L ${quotedSshDirectoryPath} ] || { echo '.ssh must not be a symlink' >&2; exit 1; }; [ -d ${quotedSshDirectoryPath} ] || { echo '.ssh must be a directory' >&2; exit 1; }; [ ! -L ${quotedKnownHostsPath} ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }; if [ -e ${quotedKnownHostsPath} ]; then [ -f ${quotedKnownHostsPath} ] || { echo 'known_hosts must be a regular file' >&2; exit 1; }; rm -f -- ${quotedKnownHostsPath}; fi; mv -T -n -- ${quotedTemporaryPath} ${quotedKnownHostsPath} || { echo 'known_hosts was recreated during replace; refusing to clobber' >&2; exit 1; }; [ ! -e ${quotedTemporaryPath} ] || { echo 'known_hosts replace did not consume temporary file' >&2; exit 1; }; [ ! -L ${quotedKnownHostsPath} ] || { echo 'known_hosts must not be a symlink' >&2; exit 1; }; [ -f ${quotedKnownHostsPath} ] || { echo 'known_hosts must be a regular file' >&2; exit 1; }; known_hosts_state=$(stat -c '%a %F' ${quotedKnownHostsPath}) || exit $?; [ "$known_hosts_state" = ${expectedKnownHostsState} ] || { echo 'known_hosts metadata changed during replace' >&2; exit 1; }; known_hosts_hash=$(sha256sum ${quotedKnownHostsPath} | cut -d' ' -f1) || exit $?; [ "$known_hosts_hash" = "$expected_known_hosts_hash" ] || { echo 'known_hosts content changed during replace' >&2; exit 1; }; }`,
    MUTATION_EXEC_OPTS
  )
  if (replaceResult.code !== 0) {
    return failedCommand(
      `[ssh.knownHosts: ${host} (present)] failed to replace known_hosts`,
      replaceResult
    )
  }
  return null
}

async function rewriteKnownHostsFile(
  conn: SshConnection,
  parameters: {
    host: string
    knownHostsPath: string
    lines: string[]
    mode: "append" | "replace"
    sshDirectoryPath: string
  }
): Promise<ModuleResult> {
  const { host, sshDirectoryPath } = parameters
  let temporaryPath: string
  try {
    temporaryPath = await createKnownHostsTemporaryPath(conn, sshDirectoryPath)
  } catch (error) {
    if (isKnownHostsPathValidationError(error)) {
      return failed(`[ssh.knownHosts: ${host} (present)] ${error.message}`)
    }
    throw error
  }

  try {
    const stageFailure = await stageKnownHostsContent(conn, {
      ...parameters,
      temporaryPath,
    })
    if (stageFailure) return stageFailure

    const replaceFailure = await replaceKnownHostsAtomically(conn, {
      ...parameters,
      temporaryPath,
    })
    if (replaceFailure) return replaceFailure

    return { status: "changed" }
  } finally {
    await conn.exec(`rm -f ${shellQuote(temporaryPath)}`, MUTATION_EXEC_OPTS)
  }
}

async function checkKnownHostsAbsentPath(
  conn: SshConnection,
  parameters: { host: string; paths: KnownHostsPaths }
): Promise<{ exists: boolean; failure: ModuleResult | null }> {
  const { host, paths } = parameters
  const directorySymlink = await conn.test(`[ -L ${shellQuote(paths.sshDirectoryPath)} ]`)
  if (directorySymlink) {
    return {
      exists: false,
      failure: failed(`[ssh.knownHosts: ${host} (absent)] .ssh must not be a symlink`),
    }
  }
  const knownHostsSymlink = await conn.test(`[ -L ${shellQuote(paths.knownHostsPath)} ]`)
  if (knownHostsSymlink) {
    return {
      exists: false,
      failure: failed(`[ssh.knownHosts: ${host} (absent)] known_hosts must not be a symlink`),
    }
  }
  return { exists: await conn.exists(paths.knownHostsPath), failure: null }
}

async function removeKnownHostEntry(
  conn: SshConnection,
  parameters: { host: string; knownHostsPath: string; options?: KnownHostsOptions }
): Promise<ModuleResult> {
  const { host, knownHostsPath, options } = parameters
  const removeResult = await conn.exec(
    `ssh-keygen -R ${shellQuote(knownHostsLookupTarget(host, options))} -f ${shellQuote(knownHostsPath)}`,
    MUTATION_EXEC_OPTS
  )
  if (removeResult.code !== 0) {
    return failedCommand(`[ssh.knownHosts: ${host} (absent)] ssh-keygen -R failed`, removeResult)
  }
  return { status: "changed" }
}

async function applyKnownHostsAbsent(
  conn: SshConnection,
  parameters: { host: string; options?: KnownHostsOptions }
): Promise<ModuleResult> {
  const { host, options } = parameters
  const pathResolution = await resolveKnownHostsPathsForState(conn, { host, state: "absent" })
  if (pathResolution.failure) return pathResolution.failure

  const pathCheck = await checkKnownHostsAbsentPath(conn, { host, paths: pathResolution.paths })
  if (pathCheck.failure) return pathCheck.failure
  if (!pathCheck.exists) return { status: "ok" }

  const lookup = await resolveKnownHostsAbsentLookup(conn, {
    host,
    knownHostsPath: pathResolution.paths.knownHostsPath,
    options,
  })
  if (lookup.failure != null) return lookup.failure
  if (!lookup.known) return { status: "ok" }

  return removeKnownHostEntry(conn, {
    host,
    knownHostsPath: pathResolution.paths.knownHostsPath,
    options,
  })
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
  authorizedKeys(user: string, key: string, options?: AuthorizedKeysOptions): Module {
    assertValidUserName(user)
    assertAuthorizedKeyValue(key)
    const state = resolveAuthorizedKeysState(options)

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
   * via `ssh-keyscan` and written to `~/.ssh/known_hosts`. When `state` is
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
    const state = resolveKnownHostsState(options)

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

        return applyKnownHostsAbsent(conn, { host, options })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        // R-0000550: route the check through the same known_hosts path that
        // apply uses. Without forwarding `knownHostsPath`, `ssh-keygen -F`
        // would default to `$HOME/.ssh/known_hosts`, which can diverge from
        // the path resolved in the apply path (e.g. when running with a
        // different effective HOME). The lookup must operate on the file
        // that apply would actually mutate.
        const knownHostsPaths = await resolveKnownHostsPaths(conn)
        const knownHostsPath = knownHostsPaths.knownHostsPath

        if (state === "present" && hasKnownHostsTrustAnchor(options)) {
          return (await hasMatchingKnownHostTrustAnchor(conn, {
            host,
            knownHostsPath,
            options: options ?? {},
          }))
            ? "ok"
            : NEEDS_APPLY
        }

        const hostKnown =
          state === "absent"
            ? await hasKnownHostEntry(conn, { host, knownHostsPath, options })
            : await conn.test(
                `ssh-keygen -F ${shellQuote(knownHostsLookupTarget(host, options))} -f ${shellQuote(knownHostsPath)}`
              )

        if (state === "present") {
          return hostKnown ? "ok" : NEEDS_APPLY
        }
        return hostKnown ? NEEDS_APPLY : "ok"
      },
      name: `ssh.knownHosts: ${host} (${state})`,
    }
  },
}
