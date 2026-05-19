/* eslint-disable max-lines -- R-0000673 adds an ancestor-walk helper; splitting the module is out of scope for this finding */
import { createHash, timingSafeEqual } from "node:crypto"
import { posix as path } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { maskRegisteredSecrets, withRegisteredSecrets } from "../secretSink.js"
import { shellQuote, validateMktempPath, validateMode } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  buildCurlArgvHeaderFlags,
  buildCurlConfigPayload as buildSharedCurlConfigPayload,
  hasSensitiveHeaders,
  hasSensitiveQueryParameters,
  validateHeaderPair,
} from "./curlHelpers.js"
import { renderGuardedChmodCommand, renderGuardedChownCommand } from "./fileMetadataHelpers.js"
import { applyWithFlagLock, hasFlag, setVersionedFlag } from "./moduleHelpers.js"
import { validateHttpUrl } from "./netHelpers.js"

/**
 * Options shared by all download methods.
 */
type BaseDownloadOptions = {
  /** Allow unencrypted `http://` downloads explicitly. */
  allowInsecureHttp?: boolean
  /** Explicitly opt out of integrity verification for trusted sources. */
  allowUnverifiedDownload?: boolean
  /** Maximum time to establish the curl connection, in milliseconds. */
  connectTimeout?: number
  /** Group owner to set on the downloaded file via `chown`. */
  group?: string
  /** File mode to set via `chmod` (e.g. `"0755"`). */
  mode?: string
  /** User owner to set on the downloaded file via `chown`. */
  owner?: string
  /** Expected SHA-256 hex digest for integrity verification. */
  sha256?: string
  /** Maximum time for the full curl transfer, in milliseconds. */
  timeout?: number
}

/**
 * Full set of parameters for the internal download helpers.
 * Combines {@link BaseDownloadOptions} with the required download coordinates.
 */
type DownloadParameters = {
  /** Allow sending sensitive headers over unencrypted `http://` explicitly. */
  allowInsecureHttpHeaders?: boolean
  /** Absolute path on the remote server where the file is written. */
  destination: string
  /** Force a fresh transfer even when the destination already matches sha256. */
  force?: boolean
  /** Additional HTTP headers sent with the curl request. */
  headers?: Record<string, string>
  /** Strings to mask in error messages (e.g. tokens). */
  secrets?: string[]
  /** The URL to download from. */
  url: string
} & BaseDownloadOptions

type DownloadOwnership = {
  group: string
  mode: string
  owner: string
}

const DEFAULT_CURL_CONNECT_TIMEOUT_MS = 10_000
const DEFAULT_CURL_TIMEOUT_MS = 300_000
const MS_PER_SECOND = 1000

function validateCurlTimeoutOption(label: string, value: number): void {
  if (Number.isFinite(value) && value > 0) return
  throw new Error(`[download] invalid ${label}: value must be a finite positive number`)
}

function resolveCurlTimeouts(options: { connectTimeout?: number; timeout?: number }): {
  connectTimeout: number
  timeout: number
} {
  const connectTimeout = options.connectTimeout ?? DEFAULT_CURL_CONNECT_TIMEOUT_MS
  const timeout = options.timeout ?? DEFAULT_CURL_TIMEOUT_MS
  validateCurlTimeoutOption("connectTimeout", connectTimeout)
  validateCurlTimeoutOption("timeout", timeout)
  return { connectTimeout, timeout }
}

function formatCurlTimeoutSeconds(milliseconds: number): string {
  return String(milliseconds / MS_PER_SECOND)
}

function buildCurlTimeoutFlags(options: { connectTimeout?: number; timeout?: number }): string {
  const { connectTimeout, timeout } = resolveCurlTimeouts(options)
  return `--connect-timeout ${shellQuote(formatCurlTimeoutSeconds(connectTimeout))} --max-time ${shellQuote(formatCurlTimeoutSeconds(timeout))}`
}

function extractUrlSecrets(url: string): string[] {
  const parsed = new URL(url)
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new Error(
      "Download URLs must not embed credentials. Pass credentials via headers instead."
    )
  }
  return hasSensitiveQueryParameters(parsed) ? [url] : []
}

function buildDownloadParameters(
  destination: string,
  options: { headers?: Record<string, string> } & BaseDownloadOptions,
  url: string
): DownloadParameters {
  const urlSecrets = extractUrlSecrets(url)
  return {
    ...options,
    destination,
    secrets: [
      ...Object.values(options.headers ?? {}).filter((value) => value.length > 0),
      ...urlSecrets,
    ],
    url,
  }
}

function canonicalizeHeaders(headers?: Record<string, string>): string {
  return JSON.stringify(
    Object.entries(headers ?? {}).sort(([leftName], [rightName]) =>
      leftName.localeCompare(rightName)
    )
  )
}

/**
 * R-0000274: derive both a destination-stable flag prefix and the
 * URL/headers-keyed flag name for `download.large`. The prefix encodes a
 * sha256 of the destination so {@link setVersionedFlag} can evict older flag
 * files when the URL or headers change for the same destination, instead of
 * accumulating an unbounded number of `/var/lib/paratix/flags/download-*`
 * entries on every URL/header rotation.
 *
 * @param parameters - Destination, URL and headers used to derive both keys.
 * @returns The versioned flag name and the destination-keyed flag prefix.
 */
function buildLargeDownloadFlagInfo(
  parameters: Pick<DownloadParameters, "destination" | "headers" | "url">
): {
  flagName: string
  flagPrefix: string
} {
  const destinationHash = createHash("sha256").update(parameters.destination).digest("hex")
  const flagPrefix = `download-large-${destinationHash}-`
  const flagKey = JSON.stringify({
    destination: parameters.destination,
    headers: canonicalizeHeaders(parameters.headers),
    url: parameters.url,
  })
  const flagHash = createHash("sha256").update(flagKey).digest("hex")
  return {
    flagName: `${flagPrefix}${flagHash}`,
    flagPrefix,
  }
}

/**
 * Validate the download destination path before any shell helper consumes it.
 *
 * Mirrors `validateAbsentPath` from `file.ts`: the destination must be a
 * non-empty, absolute, normalized POSIX path that does not start with `-`
 * (so a future refactor cannot turn it into a CLI flag for `rm`, `curl`, …)
 * and that is not padded with whitespace. Without this guard a relative or
 * whitespace-padded value would reach `path.dirname` and downstream
 * `shellQuote`/`mktemp` calls and land the download at an unexpected
 * location.
 *
 * @param moduleName - Module label used in the error message prefix.
 * @param destination - The destination path to validate.
 * @throws {Error} When the destination violates any of the rules above.
 */
function validateDownloadDestination(
  moduleName: "download.github" | "download.large" | "download.url",
  destination: string
): void {
  const trimmedDestination = destination.trim()
  if (trimmedDestination.length === 0) {
    throw new Error(`[${moduleName}] destination must not be empty`)
  }
  if (trimmedDestination !== destination) {
    throw new Error(
      `[${moduleName}] destination must not start or end with whitespace: ${destination}`
    )
  }
  if (trimmedDestination.startsWith("-")) {
    throw new Error(`[${moduleName}] destination must not start with "-": ${destination}`)
  }
  if (!path.isAbsolute(trimmedDestination)) {
    throw new Error(`[${moduleName}] destination must be an absolute path: ${destination}`)
  }
  const normalizedDestination = path.normalize(trimmedDestination)
  if (normalizedDestination === "/") {
    throw new Error(`[${moduleName}] refusing to use root path as destination: ${destination}`)
  }
  if (trimmedDestination !== normalizedDestination) {
    throw new Error(`[${moduleName}] destination must be normalized: ${destination}`)
  }
}

function validateIntegrityConfiguration(
  moduleName: "download.github" | "download.large" | "download.url",
  options: BaseDownloadOptions
): void {
  if (options.sha256 != null || options.allowUnverifiedDownload === true) return
  throw new Error(
    `${moduleName} requires options.sha256 for integrity verification. ` +
      "If you intentionally trust the remote artifact, set allowUnverifiedDownload: true explicitly."
  )
}

/**
 * R-0000701: validate every supplied header name/value at module construction
 * so newline-injection or otherwise malformed header pairs surface a clear
 * synchronous error during playbook build, long before any async apply/check
 * work runs. `validateHeaderPair` is also called later by `buildCurlConfigPayload`,
 * but the second pass cannot help operators who pre-build hundreds of modules:
 * a single bad header would otherwise only fail at runtime.
 *
 * @param headers - Optional header map, possibly undefined.
 */
function validateHeadersFailFast(headers: Record<string, string> | undefined): void {
  for (const [name, value] of Object.entries(headers ?? {})) {
    validateHeaderPair(name, value)
  }
}

function rejectSensitiveHeadersOverHttp(parameters: {
  allowInsecureHttpHeaders: boolean | undefined
  headers: Record<string, string> | undefined
  moduleName: "download.large" | "download.url"
  url: string
}): void {
  const { allowInsecureHttpHeaders, headers, moduleName, url } = parameters
  if (allowInsecureHttpHeaders === true) return
  if (headers === undefined || !hasSensitiveHeaders(headers)) return

  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return
  }
  if (parsed.protocol !== "http:") return

  throw new Error(
    `[${moduleName}] refusing to send sensitive headers (Authorization, Cookie, X-Api-Key, ...) over plaintext http; switch to https or pass allowInsecureHttpHeaders: true to opt in`
  )
}

async function readDownloadOwnership(
  conn: SshConnection,
  destination: string
): Promise<DownloadOwnership> {
  // R-0000558: route the stat call through ssh.exec with ignoreExitCode so a
  // transient stat failure (file removed between an earlier existence probe
  // and the metadata read, EACCES, EIO, …) does not propagate as a raw
  // CommandError out of check/apply. Empty fields make the subsequent
  // drift-comparison treat the file as needing re-apply, mirroring the
  // crontab/R-0000272 pattern.
  const result = await conn.exec(`stat -c '%a %U %G' ${shellQuote(destination)}`, {
    ignoreExitCode: true,
    silent: true,
  })
  if (result.code !== 0) return { group: "", mode: "", owner: "" }
  // R-0000253: split on any whitespace run (mirrors mount.ts/archive.ts)
  // because BusyBox/POSIX `stat` implementations may emit tabs or multiple
  // spaces between the columns, which broke the previous single-space
  // split and produced empty owner/group fields.
  const [mode = "", owner = "", group = ""] = result.stdout.trim().split(/\s+/v)
  return { group, mode, owner }
}

function downloadOwnershipMatches(
  current: DownloadOwnership,
  options: BaseDownloadOptions
): boolean {
  if (options.mode != null && current.mode !== options.mode.replace(/^0+/v, "")) return false
  if (options.owner != null && current.owner !== options.owner) return false
  if (options.group != null && current.group !== options.group) return false
  return true
}

async function metadataMatches(
  conn: SshConnection,
  destination: string,
  options: BaseDownloadOptions
): Promise<boolean> {
  if (options.mode == null && options.owner == null && options.group == null) return true
  const ownership = await readDownloadOwnership(conn, destination)
  return downloadOwnershipMatches(ownership, options)
}

async function destinationIsRegularFile(
  conn: SshConnection,
  destination: string
): Promise<boolean> {
  const quotedDestination = shellQuote(destination)
  if (!(await conn.test(`[ -f ${quotedDestination} ]`))) return false
  return !(await conn.test(`[ -L ${quotedDestination} ]`))
}

async function destinationIsDirectory(conn: SshConnection, destination: string): Promise<boolean> {
  return conn.test(`[ -d ${shellQuote(destination)} ]`)
}

/**
 * R-0000226: refuse to write through a symlink at the destination, at the
 * immediate `dirname(destination)`, or at any ancestor in between. Without
 * this guard a symlinked `dirname(destination)` would steer the temp file
 * into an attacker-controlled directory, and a symlinked `destination` itself
 * would let `mv -T` clobber the link target instead of replacing the link.
 *
 * @param conn - The SSH connection.
 * @param destination - The final download destination on the remote host.
 * @returns A failed ModuleResult on any symlink, or null when the path is safe.
 */
async function ensureDownloadDestinationNotSymlinked(
  conn: SshConnection,
  destination: string
): Promise<ModuleResult | null> {
  // `[ -L destination ]` only fires when destination itself is a symlink,
  // including dangling links. Guard explicitly so that `mv -T` cannot replace
  // the link and orphan the previously-pointed file.
  if (await conn.test(`[ -L ${shellQuote(destination)} ]`)) {
    return failed(`[download] destination is a symlink: ${destination}`)
  }
  // Walk every existing ancestor of dirname(destination) looking for a
  // symlink. We iterate in TypeScript so the resulting `[ -L ... ]` calls
  // re-use the same primitives as the destination test, keeping mock-stub
  // matching predictable.
  let ancestor = path.dirname(destination)
  const seen = new Set<string>()
  while (ancestor !== "/" && ancestor !== "." && !seen.has(ancestor)) {
    seen.add(ancestor)
    // eslint-disable-next-line no-await-in-loop -- ancestor walk is sequential by nature
    if (await conn.test(`[ -L ${shellQuote(ancestor)} ]`)) {
      return failed(`[download] ancestor of ${destination} is a symlink: ${ancestor}`)
    }
    ancestor = path.dirname(ancestor)
  }
  return null
}

async function finalizeDownloadedFile(
  conn: SshConnection,
  parameters: DownloadParameters,
  downloadParameters: DownloadParameters
): Promise<ModuleResult | undefined> {
  if (await destinationIsDirectory(conn, parameters.destination)) {
    return failed(`[download] destination is a directory: ${parameters.destination}`)
  }
  // R-0000226: re-check destination + ancestor symlinks immediately before the
  // atomic mv. Earlier check in runCurlDownload may race with operator action
  // during the curl download itself.
  const symlinkFailure = await ensureDownloadDestinationNotSymlinked(conn, parameters.destination)
  if (symlinkFailure != null) return symlinkFailure
  // R-0000696: combine the final `mv -T` with inline parent/destination
  // symlink and directory guards so the kernel resolves all probes plus the
  // rename in a single shell pipeline. The earlier
  // `ensureDownloadDestinationNotSymlinked` call still gives operators a
  // friendly, distinct error path for the common cases; the inline guards
  // below close the residual TOCTOU window between that probe and `mv -T`
  // where an attacker with write access on `dirname(destination)` could
  // otherwise plant a symlink between the check and the rename.
  // R-0000158: convert non-zero exit codes (e.g. cross-device link, EACCES,
  // EROFS) into a failedCommand result so callers see a maskable failure
  // instead of an uncaught CommandError exception.
  const parentDirectory = path.dirname(parameters.destination)
  const quotedParent = shellQuote(parentDirectory)
  const quotedDestination = shellQuote(parameters.destination)
  const quotedSource = shellQuote(downloadParameters.destination)
  const guardedMoveCommand =
    `[ ! -L ${quotedParent} ] && ` +
    `[ ! -L ${quotedDestination} ] && ` +
    `[ ! -d ${quotedDestination} ] && ` +
    `mv -T -- ${quotedSource} ${quotedDestination}`
  const result = await conn.exec(guardedMoveCommand, {
    ignoreExitCode: true,
    secrets: parameters.secrets,
    silent: true,
  })
  if (result.code !== 0) {
    return failedCommand(
      `[download] mv into place failed for ${parameters.destination}`,
      result,
      parameters.secrets
    )
  }
  return undefined
}

async function allocateTemporaryDownloadParameters(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<DownloadParameters> {
  const rawTemporaryDestination = await conn.output(
    buildTemporaryDownloadPathCommand(parameters.destination)
  )
  const temporaryDestination = validateTemporaryDownloadPath(
    parameters.destination,
    rawTemporaryDestination
  )
  return { ...parameters, destination: temporaryDestination }
}

// R-0000673: `mkdir -p` followed an attacker-planted symlink at any
// not-yet-existing ancestor and would happily create directories outside the
// operator-supplied tree. `ensureDownloadDestinationNotSymlinked` only probes
// ancestors that already existed at the time of the check, so it cannot close
// the race for missing levels. Walk the ancestor chain top-down in TypeScript
// and create each missing directory with plain `mkdir` (no `-p`, so a planted
// symlink at the leaf trips EEXIST instead of being silently followed). A
// trailing `[ ! -L "$current" ]` test catches any link that appeared between
// the existence check and the `mkdir` call. The shell snippet below keeps the
// existence probe, the create, and the symlink re-check in a single remote
// round-trip per level so the operator-visible call sequence stays compact.
function buildAncestorMkdirCommand(ancestor: string): string {
  const quoted = shellQuote(ancestor)
  return (
    `if [ -L ${quoted} ]; then ` +
    `printf 'ancestor is symlink: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi; ` +
    `if [ ! -e ${quoted} ]; then ` +
    `mkdir -- ${quoted} || exit 1; ` +
    `if [ -L ${quoted} ]; then ` +
    `printf 'ancestor became symlink after mkdir: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi; ` +
    `elif [ ! -d ${quoted} ]; then ` +
    `printf 'ancestor exists but is not a directory: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi`
  )
}

function ancestorsTopDown(directory: string): string[] {
  const ancestors: string[] = []
  let current = directory
  const seen = new Set<string>()
  while (current !== "/" && current !== "." && !seen.has(current)) {
    seen.add(current)
    ancestors.push(current)
    current = path.dirname(current)
  }
  return ancestors.reverse()
}

async function createDownloadTargetDirectory(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<ModuleResult | undefined> {
  const targetDirectory = path.dirname(parameters.destination)
  for (const ancestor of ancestorsTopDown(targetDirectory)) {
    // eslint-disable-next-line no-await-in-loop -- ancestor walk is sequential by nature
    const result = await conn.exec(buildAncestorMkdirCommand(ancestor), {
      ignoreExitCode: true,
      secrets: parameters.secrets,
      silent: true,
    })
    if (result.code !== 0) {
      return failedCommand(
        `[download] failed to create target directory for ${parameters.destination}`,
        result,
        parameters.secrets
      )
    }
  }
  return undefined
}

async function destinationHashMatches(
  conn: SshConnection,
  destination: string,
  options: BaseDownloadOptions
): Promise<boolean> {
  if (options.sha256 == null) return true
  const actualHash = await conn.sha256(destination)
  return hashMatches(actualHash, options.sha256)
}

async function checkLargeDownload(
  conn: SshConnection,
  parameters: {
    destination: string
    flagName: string
    options: BaseDownloadOptions
  }
): Promise<"needs-apply" | "ok"> {
  const { destination, flagName, options } = parameters
  const flagExists = await hasFlag(conn, flagName)
  const destinationExists = await destinationIsRegularFile(conn, destination)

  if (!flagExists) return NEEDS_APPLY
  if (!destinationExists) return NEEDS_APPLY
  if (!(await destinationHashMatches(conn, destination, options))) return NEEDS_APPLY
  if (!(await metadataMatches(conn, destination, options))) return NEEDS_APPLY

  return "ok"
}

// R-0000107: prefix used by `mktemp` for the in-flight download path. The
// leading dot keeps the temp file hidden from typical glob expansions; the
// validateMktempPath check rejects any output that does not start with
// "<destinationDir>/.paratix-download.".
const DOWNLOAD_TEMPORARY_PREFIX = ".paratix-download"

function buildTemporaryDownloadPathCommand(destination: string): string {
  return `mktemp "$(dirname -- ${shellQuote(destination)})/${DOWNLOAD_TEMPORARY_PREFIX}.XXXXXX"`
}

/**
 * Validate the path returned by `mktemp` against the expected destination
 * directory and prefix. Without this guard, a locale warning, multi-line
 * stdout or a tampered `mktemp` could smuggle an unexpected path into the
 * subsequent curl, mv, chmod/chown and rm -f calls.
 *
 * @param destination - The final download destination — its directory is
 *   the only path under which the temp file may live.
 * @param rawTemporaryPath - The raw stdout from `mktemp` (already trimmed
 *   by `conn.output`).
 * @returns The validated temp path.
 * @throws {Error} When the path does not match the expected pattern.
 */
function validateTemporaryDownloadPath(destination: string, rawTemporaryPath: string): string {
  const directory = path.dirname(destination)
  try {
    return validateMktempPath(directory, rawTemporaryPath, DOWNLOAD_TEMPORARY_PREFIX)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(`[download] mktemp produced an unexpected path for ${destination}: ${reason}`, {
      cause: error,
    })
  }
}

function buildCurlProtocolFlags(parameters: Pick<DownloadParameters, "allowInsecureHttp">): string {
  const allowedProtocols = parameters.allowInsecureHttp === true ? "http,https" : "https"
  return `--proto '=${allowedProtocols}' --proto-redir '=${allowedProtocols}'`
}

/**
 * Build the curl command string and the stdin payload that carries request
 * material (URL plus headers).
 *
 * The URL and all headers flow through `curl --config -` via stdin so
 * credentials in arbitrary custom headers never leak into `/var/log/auth.log`
 * (sudo logging) or `/proc/<pid>/cmdline` / `ps -ef` while the download runs.
 *
 * @param parameters - Download parameters containing destination, url, and optional headers.
 * @returns The assembled curl shell command and the stdin config payload.
 */
function buildCurlCommand(parameters: DownloadParameters): {
  command: string
  input: string
} {
  const { argvHeaders, configInput } = buildSharedCurlConfigPayload({
    headers: parameters.headers,
    routeUrlThroughConfig: true,
    url: parameters.url,
  })
  const headerPart = buildCurlArgvHeaderFlags(argvHeaders)
  const protocolFlags = buildCurlProtocolFlags(parameters)
  const timeoutFlags = buildCurlTimeoutFlags(parameters)
  return {
    command: `curl -fsSL -o ${shellQuote(parameters.destination)} ${timeoutFlags} ${protocolFlags} ${headerPart}--config -`,
    input: configInput,
  }
}

/**
 * Verify the SHA-256 digest of a downloaded file.
 *
 * @param conn - Active SSH connection.
 * @param parameters - Download parameters containing destination and expected sha256.
 * @returns `true` if verification passed or was skipped, `false` on mismatch.
 */
async function verifyChecksum(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<boolean> {
  if (parameters.sha256 == null) return true
  const actualHash = await conn.sha256(parameters.destination)
  if (hashMatches(actualHash, parameters.sha256)) return true
  return false
}

/**
 * Apply file ownership and permission settings after download.
 *
 * @param conn - Active SSH connection.
 * @param parameters - Download parameters containing destination, mode, owner, and group.
 * @returns A failed ModuleResult when chmod/chown exits non-zero, otherwise undefined.
 */
async function applyFileAttributes(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<ModuleResult | undefined> {
  if (parameters.mode != null) {
    validateMode(parameters.mode)
    // R-0000158: capture chmod failures as failedCommand so permission-denied
    // / invalid-target errors report a maskable failure instead of throwing.
    const chmodResult = await conn.exec(
      renderGuardedChmodCommand(parameters.mode, parameters.destination),
      {
        ignoreExitCode: true,
        secrets: parameters.secrets,
        silent: true,
      }
    )
    if (chmodResult.code !== 0) {
      return failedCommand(
        `[download] chmod failed for ${parameters.destination}`,
        chmodResult,
        parameters.secrets
      )
    }
  }
  if (parameters.owner != null || parameters.group != null) {
    const ownerSpec = `${parameters.owner ?? ""}:${parameters.group ?? ""}`
    const chownResult = await conn.exec(
      renderGuardedChownCommand(ownerSpec, parameters.destination),
      {
        ignoreExitCode: true,
        secrets: parameters.secrets,
        silent: true,
      }
    )
    if (chownResult.code !== 0) {
      return failedCommand(
        `[download] chown failed for ${parameters.destination}`,
        chownResult,
        parameters.secrets
      )
    }
  }
  return undefined
}

function downloadModeDrifted(current: DownloadOwnership, options: BaseDownloadOptions): boolean {
  return options.mode != null && current.mode !== options.mode.replace(/^0+/v, "")
}

function downloadOwnerDrifted(current: DownloadOwnership, options: BaseDownloadOptions): boolean {
  return (
    (options.owner != null && current.owner !== options.owner) ||
    (options.group != null && current.group !== options.group)
  )
}

type DriftHealOutcome = { changed: boolean; failure?: ModuleResult }

async function healModeDrift(
  conn: SshConnection,
  parameters: DownloadParameters,
  current: DownloadOwnership
): Promise<DriftHealOutcome> {
  if (parameters.mode == null || !downloadModeDrifted(current, parameters)) {
    return { changed: false }
  }
  validateMode(parameters.mode)
  const result = await conn.exec(
    renderGuardedChmodCommand(parameters.mode, parameters.destination),
    { ignoreExitCode: true, secrets: parameters.secrets, silent: true }
  )
  if (result.code !== 0) {
    return {
      changed: false,
      failure: failedCommand(
        `[download] chmod failed for ${parameters.destination}`,
        result,
        parameters.secrets
      ),
    }
  }
  return { changed: true }
}

async function healOwnerDrift(
  conn: SshConnection,
  parameters: DownloadParameters,
  current: DownloadOwnership
): Promise<DriftHealOutcome> {
  if (!downloadOwnerDrifted(current, parameters)) return { changed: false }
  const ownerSpec = `${parameters.owner ?? ""}:${parameters.group ?? ""}`
  const result = await conn.exec(renderGuardedChownCommand(ownerSpec, parameters.destination), {
    ignoreExitCode: true,
    secrets: parameters.secrets,
    silent: true,
  })
  if (result.code !== 0) {
    return {
      changed: false,
      failure: failedCommand(
        `[download] chown failed for ${parameters.destination}`,
        result,
        parameters.secrets
      ),
    }
  }
  return { changed: true }
}

async function applyDriftedFileAttributes(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<DriftHealOutcome> {
  if (parameters.mode == null && parameters.owner == null && parameters.group == null) {
    return { changed: false }
  }

  const current = await readDownloadOwnership(conn, parameters.destination)
  const modeOutcome = await healModeDrift(conn, parameters, current)
  if (modeOutcome.failure) return modeOutcome
  const ownerOutcome = await healOwnerDrift(conn, parameters, current)
  if (ownerOutcome.failure) return { changed: modeOutcome.changed, failure: ownerOutcome.failure }
  return { changed: modeOutcome.changed || ownerOutcome.changed }
}

async function cleanupTemporaryDownloadFile(
  conn: SshConnection,
  parameters: Pick<DownloadParameters, "destination" | "secrets">
): Promise<void> {
  try {
    // R-0000565: pass `--` so a future refactor that loosens the staging
    // prefix cannot turn the destination into an `rm` flag (e.g. an
    // attacker-controlled path starting with `-`).
    await conn.exec(`rm -f -- ${shellQuote(parameters.destination)}`, { silent: true })
  } catch (cleanupError) {
    // R-0000675: route the warning through the global secret sink instead of
    // building the mask list from the call site's local `parameters.secrets`.
    // `CommandError` messages can embed `--config` stdin fragments or other
    // material that the call site does not know about; relying on the
    // registered sink ensures every secret active for the current run is
    // masked, not just the headers/URL the caller happens to track.
    process.stderr.write(
      maskRegisteredSecrets(
        `Warning: failed to remove temp file ${parameters.destination}: ${String(cleanupError)}\n`
      )
    )
  }
}

/**
 * Run the curl download with the URL and headers passed via
 * `--config -` from stdin. Stdout/stderr remain masked through `secrets` so
 * verbose logs do not leak signed URLs or bearer tokens.
 *
 * @param conn - The active SSH connection.
 * @param downloadParameters - Download parameters with destination set to the
 *   temporary file used during the transfer.
 * @returns A failed ModuleResult when curl exits non-zero, otherwise undefined.
 */
async function executeCurlDownload(
  conn: SshConnection,
  downloadParameters: DownloadParameters
): Promise<ModuleResult | undefined> {
  const { command: curlCommand, input: curlConfig } = buildCurlCommand(downloadParameters)
  // R-0000158: capture curl failures (network error, 404, expired token,
  // proto-mismatch) as a failedCommand result so callers see a maskable
  // failure with stdout/stderr instead of an uncaught CommandError. The
  // existing secret list keeps the rendered failure free of leaked tokens.
  const result = await conn.exec(curlCommand, {
    ignoreExitCode: true,
    input: curlConfig,
    secrets: downloadParameters.secrets,
    silent: true,
    timeout: resolveCurlTimeouts(downloadParameters).timeout,
  })
  if (result.code !== 0) {
    return failedCommand(
      `[download] curl failed for ${downloadParameters.destination}`,
      result,
      downloadParameters.secrets
    )
  }
  return undefined
}

/**
 * R-0000062: skip the curl roundtrip when only metadata (mode/owner/group)
 * drifted on an otherwise-correct file. Returns `true` when the destination
 * exists and its sha256 matches the expected digest, so callers can heal
 * via chmod/chown without re-fetching the payload over the network.
 *
 * The check is gated on `parameters.sha256` — without an integrity digest
 * we cannot prove that the on-disk content is correct, so we keep the slow
 * path for unverified downloads.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Download parameters with the final destination.
 * @returns `true` when the existing file matches the expected sha256.
 */
async function destinationContentMatchesSha256(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<boolean> {
  if (parameters.sha256 == null) return false
  const exists = await destinationIsRegularFile(conn, parameters.destination)
  if (!exists) return false
  const actualHash = await conn.sha256(parameters.destination)
  return hashMatches(actualHash, parameters.sha256)
}

/**
 * R-0000167: derive the path of the unverified-download hash marker that
 * `download.url` keeps next to the destination when `allowUnverifiedDownload`
 * is set. The marker captures the sha256 of the payload as observed
 * immediately after a successful curl run, so subsequent checks can detect
 * post-write tampering even though the operator opted out of an a-priori
 * digest.
 *
 * @param destination - The download destination path.
 * @returns The marker path adjacent to the destination.
 */
function unverifiedHashMarkerPath(destination: string): string {
  return `${destination}.sha256`
}

/**
 * R-0000167: best-effort write of the hash marker `<destination>.sha256`
 * containing the sha256 hex digest of the downloaded payload. The marker is
 * read back in `check` to detect post-write tampering when no a-priori
 * digest was provided. We do not fail the download if the marker cannot be
 * written — the download itself succeeded, and the worst case is an extra
 * round-trip on the next run, when the absent marker forces `needs-apply`.
 *
 * @param conn - The active SSH connection.
 * @param destination - The download destination path.
 */
async function writeUnverifiedHashMarker(conn: SshConnection, destination: string): Promise<void> {
  const hash = await conn.sha256(destination)
  if (hash == null || hash.length === 0) return
  const markerPath = unverifiedHashMarkerPath(destination)
  // R-0000528: the `[ -L ]` probe and the subsequent `conn.writeFile` run in
  // separate SSH round-trips, so this test alone cannot close the TOCTOU
  // window where an attacker swaps the marker for a symlink in between.
  // We keep the probe purely as fail-fast diagnostic so the common case
  // ("marker is already a symlink from a prior compromise") short-circuits
  // before we stage a temp file. The final atomicity guarantee comes from
  // `conn.writeFile` itself: it streams to a temporary path via SFTP and
  // hands off to `finalizeRemoteTempFile`, which evaluates the symlink
  // guard (`[ ! -L target ] && [ ! -d target ]`) and the atomic
  // `mv -T -- temp target` inside a single remote shell invocation, so the
  // actual finalize step is symlink-safe regardless of the outcome here.
  if (await conn.test(`[ -L ${shellQuote(markerPath)} ]`)) return
  // Atomic single-line write — no shell expansion of the hash, no risk of
  // partial writes contaminating later checks. The marker only needs read
  // access for sha256sum -c to consume it.
  // R-0000805: write the marker as 0o444 (read-only for owner/group/world)
  // so an unprivileged process that already has write access to the
  // destination directory cannot rewrite the hash record in place to mask a
  // post-download tampering attempt. A future apply that needs to refresh
  // the marker stages a fresh temp file via `finalizeRemoteTempFile`'s
  // atomic `mv -T`, which replaces the read-only marker with a new
  // owner-controlled file.
  try {
    await conn.writeFile(markerPath, `${hash}\n`, { mode: "0444" })
  } catch {
    // Best-effort marker: a failed marker write only causes the next check to
    // re-apply, while the downloaded payload itself has already converged.
  }
}

/**
 * R-0000167: read back the hash marker `<destination>.sha256` if present and
 * compare it against the destination's current sha256 digest. Returns
 * `"missing"` when no marker exists (legacy state pre-R-0000167), `"match"`
 * when the marker matches the current file, and `"drift"` when they differ.
 *
 * @param conn - The active SSH connection.
 * @param destination - The download destination path.
 * @returns The comparison outcome.
 */
async function compareUnverifiedHashMarker(
  conn: SshConnection,
  destination: string
): Promise<"drift" | "match" | "missing"> {
  const markerPath = unverifiedHashMarkerPath(destination)
  const quotedMarkerPath = shellQuote(markerPath)
  // Pre-existence probe purely to distinguish the legacy "no marker yet"
  // state (→ "missing", triggers a clean re-record) from active drift
  // (→ "missing" would silently hide tampering). The probe is racy on its
  // own, but every TOCTOU outcome of this branch funnels into the atomic
  // symlink-guarded read below.
  if (!(await conn.test(`[ -f ${quotedMarkerPath} ]`))) return "missing"
  // R-0000529: fuse the symlink test and the marker read into a single
  // shell invocation (`[ ! -L p ] && [ -f p ] && cat -- p`). Splitting
  // them across two SSH round-trips opens a TOCTOU window where an
  // attacker can swap the marker for a symlink after the `[ -L ]` probe
  // but before `cat` runs, defeating the drift detection. Combining the
  // checks pins both decisions to the same remote shell process so the
  // symlink guard and the read observe the same inode without an
  // intermediate network gap. `cat --` defends against marker paths that
  // begin with `-` after destination-derived prefixes.
  const markerRead = await conn.exec(
    `[ ! -L ${quotedMarkerPath} ] && [ -f ${quotedMarkerPath} ] && cat -- ${quotedMarkerPath}`,
    {
      ignoreExitCode: true,
      silent: true,
    }
  )
  if (markerRead.code !== 0) return "drift"
  const markerContent = markerRead.stdout
  const recordedHash = markerContent.trim()
  if (recordedHash.length === 0) return "drift"
  const actualHash = await conn.sha256(destination)
  if (actualHash == null) return "drift"
  return hashMatches(actualHash, recordedHash) ? "match" : "drift"
}

/**
 * Execute the download, verify integrity, and set ownership/permissions.
 * Shared implementation behind both `download.url()` and `download.github()`.
 *
 * @param conn - SSH connection or `null` for dry-run mode.
 * @param parameters - Download parameters including destination, url, and options.
 * @returns A {@link ModuleResult} indicating the outcome.
 */
async function performDownload(
  conn: null | SshConnection,
  parameters: DownloadParameters
): Promise<ModuleResult> {
  if (!conn) return failed(`[download] SSH connection is required for ${parameters.destination}`)

  // R-0000041: register the URL and any token-bearing headers in the
  // process-scoped secret sink so generic Error/stack-trace output during
  // the download (e.g. an unrelated SSH disconnect mid-curl) is masked,
  // not just the CommandError stdout/stderr that ssh.exec already redacts.
  const registeredSecrets = parameters.secrets ?? []
  return withRegisteredSecrets(registeredSecrets, async () => {
    // R-0000062: metadata-only fast path — when sha256 is known and the
    // existing destination already matches the digest, we only need to
    // re-apply ownership/permissions instead of re-downloading the payload.
    // This honors download.large's "fetched once" contract even when the
    // operator drifted mode/owner/group out-of-band.
    if (parameters.force !== true && (await destinationContentMatchesSha256(conn, parameters))) {
      const symlinkFailure = await ensureDownloadDestinationNotSymlinked(
        conn,
        parameters.destination
      )
      if (symlinkFailure != null) return symlinkFailure
      const drift = await applyDriftedFileAttributes(conn, parameters)
      if (drift.failure) return drift.failure
      return { status: drift.changed ? "changed" : "ok" }
    }

    return runCurlDownload(conn, parameters)
  })
}

/**
 * Slow path of {@link performDownload}: download the payload via curl, verify
 * its sha256, apply ownership/permissions, and atomically move it into place.
 *
 * @param conn - The active SSH connection.
 * @param parameters - Download parameters including destination and url.
 * @returns A {@link ModuleResult} indicating the outcome.
 */
/**
 * Result tuple from {@link runCurlDownloadCore}.
 *
 * `failure` carries the ModuleResult to surface; `cleanedUp` indicates whether
 * the temp file was already moved into place (so the outer finally must not
 * remove it).
 */
type CurlDownloadOutcome = { cleanedUp: boolean; result: ModuleResult }

async function runCurlDownloadCore(
  conn: SshConnection,
  parameters: DownloadParameters,
  downloadParameters: DownloadParameters
): Promise<CurlDownloadOutcome> {
  const curlFailure = await executeCurlDownload(conn, downloadParameters)
  if (curlFailure) return { cleanedUp: false, result: curlFailure }
  if (!(await verifyChecksum(conn, downloadParameters))) {
    return {
      cleanedUp: false,
      result: failed(`[download] checksum verification failed for ${parameters.destination}`),
    }
  }
  const attributesFailure = await applyFileAttributes(conn, downloadParameters)
  if (attributesFailure) return { cleanedUp: false, result: attributesFailure }
  const finalizeFailure = await finalizeDownloadedFile(conn, parameters, downloadParameters)
  if (finalizeFailure) return { cleanedUp: false, result: finalizeFailure }
  return { cleanedUp: true, result: { status: "changed" } }
}

async function runCurlDownload(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<ModuleResult> {
  // R-0000226: refuse to download into a directory whose dirname or
  // destination itself traverses a symlink — otherwise the temp file would
  // land outside the operator-supplied tree and `mv -T` could be steered
  // toward an attacker-controlled target.
  const symlinkFailure = await ensureDownloadDestinationNotSymlinked(conn, parameters.destination)
  if (symlinkFailure != null) return symlinkFailure
  const targetDirectoryFailure = await createDownloadTargetDirectory(conn, parameters)
  if (targetDirectoryFailure != null) return targetDirectoryFailure
  // R-0000107: validate the mktemp output before any subcommand consumes
  // it. Reuses the shared validateMktempPath helper from ssh.ts (already
  // applied in aptKeyHelpers.ts and archive.ts/allocateRemoteUploadPath).
  const downloadParameters = await allocateTemporaryDownloadParameters(conn, parameters)
  try {
    const outcome = await runCurlDownloadCore(conn, parameters, downloadParameters)
    return outcome.result
  } finally {
    // Best-effort cleanup: if finalize moved the temp file into place
    // successfully, the rm below is a no-op (file already gone). The runner
    // does not surface temp-file rm errors per R-0000158.
    await cleanupTemporaryDownloadFile(conn, downloadParameters)
  }
}

/**
 * Check whether a download needs to be applied based on SHA-256, file
 * existence, and the `force` flag.
 *
 * @param conn - SSH connection or `null` for dry-run mode.
 * @param destination - Absolute path of the target file on the remote server.
 * @param options - Options containing sha256 and force settings.
 * @returns `"ok"` if the desired state is already present, `"needs-apply"` otherwise.
 */
async function checkDownload(
  conn: null | SshConnection,
  destination: string,
  options: { force?: boolean } & BaseDownloadOptions
): Promise<"needs-apply" | "ok"> {
  if (!conn) return NEEDS_APPLY
  if (options.force === true) return NEEDS_APPLY

  const fileExists = await destinationIsRegularFile(conn, destination)
  if (!fileExists) return NEEDS_APPLY

  if (options.sha256 != null) {
    const actualHash = await conn.sha256(destination)
    if (!hashMatches(actualHash, options.sha256)) return NEEDS_APPLY
    return (await metadataMatches(conn, destination, options)) ? "ok" : NEEDS_APPLY
  }

  return (await metadataMatches(conn, destination, options)) ? "ok" : NEEDS_APPLY
}

/**
 * Compare an actual remote SHA-256 hash against an expected digest using
 * timing-safe comparison.
 *
 * @param actualHash - The hex digest returned by the remote `sha256` command, or `undefined`.
 * @param expectedHash - The expected hex digest.
 * @returns `true` when hashes match, `false` otherwise.
 */
function hashMatches(actualHash: null | string | undefined, expectedHash: string): boolean {
  if (actualHash?.length !== expectedHash.length) return false
  const actual = Buffer.from(actualHash, "hex")
  const expected = Buffer.from(expectedHash, "hex")
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

/**
 * Validate that a string is a 64-character lowercase hex SHA-256 digest.
 *
 * @param value - The string to validate.
 * @throws {Error} If the value is not a valid SHA-256 hex digest.
 */
function validateSha256(value: string): void {
  if (!/^[\da-f]{64}$/v.test(value)) {
    throw new Error(
      `Invalid SHA-256 hex digest: expected 64 lowercase hex characters, got "${value}"`
    )
  }
}

/**
 * Validate GitHub download options and return the parsed `[owner, repo]` parts.
 *
 * @param options - The GitHub download options to validate.
 * @param options.asset - GitHub release asset filename.
 * @param options.repo - GitHub repository in `owner/repo` format.
 * @param options.tag - Release tag.
 * @returns A two-element array `[owner, repo]`.
 * @throws {Error} If repo, tag, or asset are invalid.
 */
function validateGithubOptions(options: {
  asset: string
  repo: string
  tag: string
}): [string, string] {
  const parts = options.repo.split("/")
  if (parts.length !== 2 || parts.some((p) => p.length === 0 || p.includes(".."))) {
    throw new Error(`Invalid GitHub repo format: ${options.repo} (expected "owner/repo")`)
  }
  if (options.tag.length === 0 || options.tag.includes("..")) {
    throw new Error(`Invalid GitHub release tag: ${options.tag}`)
  }
  if (options.asset.length === 0 || options.asset.includes("..")) {
    throw new Error(`Invalid GitHub release asset: ${options.asset}`)
  }
  return [parts[0], parts[1]]
}

/**
 * Modules for downloading files to remote servers via `curl`.
 */
export const download = {
  /**
   * Download a release asset from a GitHub repository.
   *
   * Builds the download URL from the repository, tag, and asset name. For
   * private repositories, provide a `token` which is sent as an
   * `Authorization` header.
   *
   * Idempotency follows the same rules as {@link download.url}: SHA-256
   * comparison when a digest is given, otherwise file-existence check.
   *
   * R-0000805: same caveat as `download.url` — `allowUnverifiedDownload`
   * stores the post-download sha256 in a read-only sibling marker
   * (`<destination>.sha256`, mode 0o444) to detect later tampering, but a
   * root-equivalent attacker can replace both the payload and the marker
   * together. Prefer providing an explicit `sha256` from the GitHub
   * release notes whenever it is available.
   *
   * @param destination - Absolute path on the remote server where the asset is saved.
   * @param options - Repository coordinates and optional download settings.
   * @param options.repo - GitHub repository in `owner/repo` format (e.g. `"hashicorp/terraform"`).
   * @param options.tag - Release tag (e.g. `"v1.5.0"`).
   * @param options.asset - GitHub release asset filename (e.g. `"terraform_1.5.0_linux_amd64.zip"`).
   * @param options.token - GitHub Personal Access Token for private repositories.
   * @param options.sha256 - Expected SHA-256 hex digest for integrity verification.
   * @param options.allowUnverifiedDownload - Explicitly opt out of integrity verification.
   * @param options.mode - File mode to set via `chmod` (e.g. `"0755"`).
   * @param options.owner - User owner to set on the downloaded file via `chown`.
   * @param options.group - Group owner to set on the downloaded file via `chown`.
   * @returns A Module that manages the GitHub release download.
   */
  github(
    destination: string,
    options: {
      /** GitHub release asset filename (e.g. `"terraform_1.5.0_linux_amd64.zip"`). */
      asset: string
      /** GitHub repository in `owner/repo` format (e.g. `"hashicorp/terraform"`). */
      repo: string
      /** Release tag (e.g. `"v1.5.0"`). */
      tag: string
      /** GitHub Personal Access Token for private repositories. */
      token?: string
    } & BaseDownloadOptions
  ): Module {
    validateDownloadDestination("download.github", destination)
    const parts = validateGithubOptions(options)
    if (options.sha256 != null) validateSha256(options.sha256)
    validateIntegrityConfiguration("download.github", options)

    const url = `https://github.com/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}/releases/download/${encodeURIComponent(options.tag)}/${encodeURIComponent(options.asset)}`
    const headers: Record<string, string> = {}

    if (options.token != null) {
      headers.Authorization = `token ${options.token}`
      headers.Accept = "application/octet-stream"
    }

    // R-0000701: surface newline-injection and other malformed header pairs
    // synchronously at module construction so playbook build fails fast
    // instead of only erroring once the deferred curl invocation runs.
    validateHeadersFailFast(headers)

    const { allowUnverifiedDownload, group, mode, owner, sha256 } = options
    const downloadParameters: DownloadParameters = {
      ...buildDownloadParameters(
        destination,
        { allowUnverifiedDownload, group, headers, mode, owner, sha256 },
        url
      ),
      secrets: options.token == null ? undefined : [options.token, ...extractUrlSecrets(url)],
    }
    const usesUnverifiedHashMarker = sha256 == null && options.allowUnverifiedDownload === true

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        const result = await performDownload(conn, downloadParameters)
        if (result.status !== "changed") return result
        if (!usesUnverifiedHashMarker || !conn) return result
        await writeUnverifiedHashMarker(conn, destination)
        return result
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        const baseResult = await checkDownload(conn, destination, options)
        if (baseResult === NEEDS_APPLY) return baseResult
        if (!usesUnverifiedHashMarker || !conn) return baseResult
        return (await compareUnverifiedHashMarker(conn, destination)) === "match"
          ? "ok"
          : NEEDS_APPLY
      },
      name: `download.github: ${options.repo}@${options.tag}/${options.asset}`,
    }
  },

  /**
   * Download a large file that should only be fetched once.
   *
   * Tracks whether the download has been performed by writing a flag file
   * under `/var/lib/paratix/flags/`. The flag name is derived from a SHA-256
   * hash of the URL. When `sha256` is provided, the check additionally verifies
   * the remote file's digest, and the downloaded file is verified after transfer.
   *
   * @param destination - Absolute path on the remote server where the file is saved.
   * @param url - The URL to download from.
   * @param options - Optional settings for ownership, permissions, and headers.
   * @param options.allowInsecureHttp - Allow unencrypted `http://` downloads explicitly.
   * @param options.allowInsecureHttpHeaders - Allow sending sensitive headers over unencrypted `http://` explicitly.
   * @param options.connectTimeout - Maximum time to establish the curl connection, in milliseconds.
   * @param options.group - Group owner to set on the downloaded file via `chown`.
   * @param options.mode - File mode to set via `chmod` (e.g. `"0755"`).
   * @param options.owner - User owner to set on the downloaded file via `chown`.
   * @param options.sha256 - Expected SHA-256 hex digest for integrity verification.
   * @param options.timeout - Maximum time for the full curl transfer, in milliseconds.
   * @param options.allowUnverifiedDownload - Explicitly opt out of integrity verification.
   * @param options.headers - Additional HTTP headers sent with the curl request.
   * @returns A Module that manages the large file download.
   */
  large(
    destination: string,
    url: string,
    options?: {
      /** Allow unencrypted `http://` downloads explicitly. */
      allowInsecureHttp?: boolean
      /** Allow sending sensitive headers over unencrypted `http://` explicitly. */
      allowInsecureHttpHeaders?: boolean
      /** Explicitly opt out of integrity verification for trusted sources. */
      allowUnverifiedDownload?: boolean
      /** Maximum time to establish the curl connection, in milliseconds. */
      connectTimeout?: number
      /** Group owner to set on the downloaded file via `chown`. */
      group?: string
      /** Additional HTTP headers sent with the curl request. */
      headers?: Record<string, string>
      /** File mode to set via `chmod` (e.g. `"0755"`). */
      mode?: string
      /** User owner to set on the downloaded file via `chown`. */
      owner?: string
      /** Expected SHA-256 hex digest for integrity verification. */
      sha256?: string
      /** Maximum time for the full curl transfer, in milliseconds. */
      timeout?: number
    }
  ): Module {
    const moduleName = "download.large"
    validateDownloadDestination(moduleName, destination)
    const resolvedOptions = options ?? {}
    validateHttpUrl(url, { allowHttp: resolvedOptions.allowInsecureHttp })
    rejectSensitiveHeadersOverHttp({
      allowInsecureHttpHeaders: resolvedOptions.allowInsecureHttpHeaders,
      headers: resolvedOptions.headers,
      moduleName,
      url,
    })
    // R-0000701: validate header pairs synchronously at module construction
    // so newline-injection attempts fail fast before any apply/check work runs.
    validateHeadersFailFast(resolvedOptions.headers)
    if (resolvedOptions.sha256 != null) validateSha256(resolvedOptions.sha256)
    validateIntegrityConfiguration(moduleName, resolvedOptions)
    const downloadParameters = buildDownloadParameters(destination, resolvedOptions, url)
    // R-0000274: use a destination-keyed prefix so older flag files for the
    // same destination (older URLs/headers) get pruned automatically by
    // setVersionedFlag, preventing unbounded accumulation in
    // /var/lib/paratix/flags/.
    const { flagName, flagPrefix } = buildLargeDownloadFlagInfo(downloadParameters)

    return {
      // R-0000708 / R-0000754: when `performDownload` returns `"ok"` the
      // content + metadata probes already vouched for the destination, so the
      // on-disk artefact matches the configured URL/headers/sha256. The flag
      // marker for that converged state is rewritten unconditionally after
      // every successful apply: the previous fast-path (`hasFlag` →
      // `setVersionedFlag`) split that bookkeeping into two RTTs, so a
      // concurrent process that wiped the flag between the probe and the
      // returning apply could leave the destination converged but the marker
      // missing. `setVersionedFlag` is idempotent (its `find -delete + touch`
      // pipeline produces the same on-disk state regardless of pre-existing
      // entries), so persisting unconditionally trades a redundant probe for a
      // single atomic write.
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[download.large: ${destination}] SSH connection is required`)

        return applyWithFlagLock(conn, {
          async apply() {
            const result = await performDownload(conn, downloadParameters)

            if (result.status === "failed") return result

            // R-0000754: persist the versioned flag unconditionally after a
            // successful apply (status === "ok" or "changed"). The previous
            // `hasFlag` skip created a non-atomic check/write pair: between
            // the probe and the return path, a concurrent run could clear the
            // flag, leaving the destination converged with no marker. By
            // dropping the pre-check we guarantee the marker exists whenever
            // we report success.
            // R-0000273: setVersionedFlag returns a typed `ModuleResult |
            // null` instead of throwing on EROFS/EPERM/ENOSPC. Surface the
            // failed result on the standard failure path so the runner can
            // render stdout/stderr instead of an uncaught exception.
            // R-0000274: switch from setFlag to setVersionedFlag so older
            // flag files keyed to the same destination (e.g. a previous
            // URL or header set) are evicted on each successful download
            // instead of leaking onto disk forever.
            const flagFailure = await setVersionedFlag(conn, flagName, flagPrefix)
            if (flagFailure) return flagFailure
            // R-0000156: respect the original result.status (e.g. "ok" when
            // performDownload skipped the download because content + metadata
            // already matched). Always forcing "changed" would falsely
            // re-trigger signal targets like service.restart on direct apply
            // invocations that did no actual work.
            return result
          },
          flagName,
          async shouldApply() {
            return (
              (await checkLargeDownload(conn, {
                destination,
                flagName,
                options: resolvedOptions,
              })) === NEEDS_APPLY
            )
          },
        })
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY
        return checkLargeDownload(conn, { destination, flagName, options: resolvedOptions })
      },
      name: `download.large: ${destination}`,
    }
  },

  /**
   * Download a file from a URL to the remote server via `curl -fsSL`.
   *
   * Idempotency is determined by SHA-256 comparison (when `sha256` is
   * provided), file existence (when no digest is given), or skipped entirely
   * when `force` is `true`.
   *
   * R-0000805: when `allowUnverifiedDownload: true` is set, paratix stores
   * the sha256 of the downloaded payload in a sibling marker file
   * `<destination>.sha256` (mode 0o444) and re-verifies the destination
   * against the marker on subsequent runs. The marker is a tampering
   * detector, not a tampering preventer: an attacker with write access to
   * the destination directory and root privileges can swap both the
   * payload and the marker simultaneously, and the next `check` will then
   * conclude the file is "in sync". The read-only mode raises the bar for
   * an unprivileged attacker but does not substitute for a verified
   * `sha256` digest. Provide `sha256` whenever an authoritative digest is
   * known.
   *
   * @param destination - Absolute path on the remote server where the file is saved.
   * @param url - The URL to download from.
   * @param options - Optional settings for integrity, ownership, and headers.
   * @param options.allowInsecureHttp - Allow unencrypted `http://` downloads explicitly.
   * @param options.allowInsecureHttpHeaders - Allow sending sensitive headers over unencrypted `http://` explicitly.
   * @param options.allowUnverifiedDownload - Explicitly opt out of integrity verification.
   * @returns A Module that manages the file download.
   */
  url(
    destination: string,
    url: string,
    options?: {
      /** Allow unencrypted `http://` downloads explicitly. */
      allowInsecureHttp?: boolean
      /** Allow sending sensitive headers over unencrypted `http://` explicitly. */
      allowInsecureHttpHeaders?: boolean
      /** Explicitly opt out of integrity verification for trusted sources. */
      allowUnverifiedDownload?: boolean
      /** Force re-download even if the file already exists. */
      force?: boolean
      /** Additional HTTP headers sent with the curl request. */
      headers?: Record<string, string>
    } & BaseDownloadOptions
  ): Module {
    const moduleName = "download.url"
    validateDownloadDestination(moduleName, destination)
    const resolvedOptions = options ?? {}
    validateHttpUrl(url, { allowHttp: resolvedOptions.allowInsecureHttp })
    rejectSensitiveHeadersOverHttp({
      allowInsecureHttpHeaders: resolvedOptions.allowInsecureHttpHeaders,
      headers: resolvedOptions.headers,
      moduleName,
      url,
    })
    // R-0000701: validate header pairs synchronously at module construction
    // so newline-injection attempts fail fast before any apply/check work runs.
    validateHeadersFailFast(resolvedOptions.headers)
    if (resolvedOptions.sha256 != null) validateSha256(resolvedOptions.sha256)
    validateIntegrityConfiguration(moduleName, resolvedOptions)
    const downloadParameters = buildDownloadParameters(destination, resolvedOptions, url)
    // R-0000167: when the operator opted into unverified downloads (no a-priori
    // sha256 digest), Paratix records `<destination>.sha256` after a
    // successful download and re-checks it on subsequent runs so post-write
    // tampering or stale URLs are detected even without a known digest.
    const usesUnverifiedHashMarker =
      resolvedOptions.sha256 == null && resolvedOptions.allowUnverifiedDownload === true

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        const result = await performDownload(conn, downloadParameters)
        if (result.status !== "changed") return result
        if (!usesUnverifiedHashMarker || !conn) return result
        await writeUnverifiedHashMarker(conn, destination)
        return result
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        const baseResult = await checkDownload(conn, destination, resolvedOptions)
        if (baseResult === NEEDS_APPLY) return baseResult
        if (!usesUnverifiedHashMarker || !conn) return baseResult
        // R-0000167: file exists and metadata matches; cross-check the hash
        // marker so out-of-band edits (or a missing marker from a pre-R-0000167
        // run) trigger a fresh download instead of silently masking drift.
        return (await compareUnverifiedHashMarker(conn, destination)) === "match"
          ? "ok"
          : NEEDS_APPLY
      },
      name: `download.url: ${destination}`,
    }
  },
}
