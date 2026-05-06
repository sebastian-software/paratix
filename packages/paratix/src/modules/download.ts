import { createHash, timingSafeEqual } from "node:crypto"
import { posix as path } from "node:path"

/* eslint-disable max-lines */
import { failed } from "../moduleFailure.js"
import { withRegisteredSecrets } from "../secretSink.js"
import { shellQuote, validateMktempPath, validateMode } from "../ssh.js"
import { maskSecrets } from "../sshHelpers.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  buildCurlArgvHeaderFlags,
  buildCurlConfigPayload as buildSharedCurlConfigPayload,
  hasSensitiveQueryParameters,
} from "./curlHelpers.js"
import { renderChownCommand } from "./fileMetadataHelpers.js"
import { applyWithFlagLock, hasFlag, setFlag } from "./moduleHelpers.js"
import { validateHttpUrl } from "./netHelpers.js"

/**
 * Options shared by all download methods.
 */
type BaseDownloadOptions = {
  /** Allow unencrypted `http://` downloads explicitly. */
  allowInsecureHttp?: boolean
  /** Explicitly opt out of integrity verification for trusted sources. */
  allowUnverifiedDownload?: boolean
  /** Group owner to set on the downloaded file via `chown`. */
  group?: string
  /** File mode to set via `chmod` (e.g. `"0755"`). */
  mode?: string
  /** User owner to set on the downloaded file via `chown`. */
  owner?: string
  /** Expected SHA-256 hex digest for integrity verification. */
  sha256?: string
}

/**
 * Full set of parameters for the internal download helpers.
 * Combines {@link BaseDownloadOptions} with the required download coordinates.
 */
type DownloadParameters = {
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

function buildLargeDownloadFlagName(
  parameters: Pick<DownloadParameters, "destination" | "headers" | "url">
): string {
  const flagKey = JSON.stringify({
    destination: parameters.destination,
    headers: canonicalizeHeaders(parameters.headers),
    url: parameters.url,
  })
  const flagHash = createHash("sha256").update(flagKey).digest("hex")
  return `download-${flagHash}`
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

async function readDownloadOwnership(
  conn: SshConnection,
  destination: string
): Promise<DownloadOwnership> {
  const raw = await conn.output(`stat -c '%a %U %G' ${shellQuote(destination)}`)
  const [mode = "", owner = "", group = ""] = raw.trim().split(" ")
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
  const destinationExists = await conn.exists(destination)

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
  return `mktemp "$(dirname ${shellQuote(destination)})/${DOWNLOAD_TEMPORARY_PREFIX}.XXXXXX"`
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
  return {
    command: `curl -fsSL -o ${shellQuote(parameters.destination)} ${protocolFlags} ${headerPart}--config -`,
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
 */
async function applyFileAttributes(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<void> {
  if (parameters.mode != null) {
    validateMode(parameters.mode)
    await conn.exec(`chmod ${shellQuote(parameters.mode)} ${shellQuote(parameters.destination)}`, {
      silent: true,
    })
  }
  if (parameters.owner != null || parameters.group != null) {
    const ownerSpec = `${parameters.owner ?? ""}:${parameters.group ?? ""}`
    await conn.exec(renderChownCommand(ownerSpec, parameters.destination), {
      silent: true,
    })
  }
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

async function applyDriftedFileAttributes(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<boolean> {
  if (parameters.mode == null && parameters.owner == null && parameters.group == null) {
    return false
  }

  const current = await readDownloadOwnership(conn, parameters.destination)
  let changed = false

  if (parameters.mode != null && downloadModeDrifted(current, parameters)) {
    validateMode(parameters.mode)
    await conn.exec(`chmod ${shellQuote(parameters.mode)} ${shellQuote(parameters.destination)}`, {
      silent: true,
    })
    changed = true
  }

  if (downloadOwnerDrifted(current, parameters)) {
    const ownerSpec = `${parameters.owner ?? ""}:${parameters.group ?? ""}`
    await conn.exec(renderChownCommand(ownerSpec, parameters.destination), {
      silent: true,
    })
    changed = true
  }

  return changed
}

async function cleanupTemporaryDownloadFile(
  conn: SshConnection,
  parameters: Pick<DownloadParameters, "destination" | "secrets">
): Promise<void> {
  try {
    await conn.exec(`rm -f ${shellQuote(parameters.destination)}`, { silent: true })
  } catch (cleanupError) {
    process.stderr.write(
      `Warning: failed to remove temp file ${parameters.destination}: ${maskSecrets(String(cleanupError), parameters.secrets ?? [])}\n`
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
 */
async function executeCurlDownload(
  conn: SshConnection,
  downloadParameters: DownloadParameters
): Promise<void> {
  const { command: curlCommand, input: curlConfig } = buildCurlCommand(downloadParameters)
  await conn.exec(curlCommand, {
    input: curlConfig,
    secrets: downloadParameters.secrets,
    silent: true,
  })
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
  const exists = await conn.exists(parameters.destination)
  if (!exists) return false
  const actualHash = await conn.sha256(parameters.destination)
  return hashMatches(actualHash, parameters.sha256)
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
      const changed = await applyDriftedFileAttributes(conn, parameters)
      return { status: changed ? "changed" : "ok" }
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
async function runCurlDownload(
  conn: SshConnection,
  parameters: DownloadParameters
): Promise<ModuleResult> {
  await conn.exec(`mkdir -p "$(dirname ${shellQuote(parameters.destination)})"`, {
    silent: true,
  })
  const rawTemporaryDestination = await conn.output(
    buildTemporaryDownloadPathCommand(parameters.destination)
  )
  // R-0000107: validate the mktemp output before any subcommand consumes
  // it. Reuses the shared validateMktempPath helper from ssh.ts (already
  // applied in aptKeyHelpers.ts and archive.ts/allocateRemoteUploadPath).
  const temporaryDestination = validateTemporaryDownloadPath(
    parameters.destination,
    rawTemporaryDestination
  )
  const downloadParameters = { ...parameters, destination: temporaryDestination }
  let shouldCleanupTemporaryFile = true

  try {
    await executeCurlDownload(conn, downloadParameters)

    if (!(await verifyChecksum(conn, downloadParameters))) {
      return failed(`[download] checksum verification failed for ${parameters.destination}`)
    }
    await applyFileAttributes(conn, downloadParameters)
    await conn.exec(
      `mv ${shellQuote(downloadParameters.destination)} ${shellQuote(parameters.destination)}`,
      { silent: true }
    )
    shouldCleanupTemporaryFile = false

    return { status: "changed" }
  } finally {
    if (shouldCleanupTemporaryFile) {
      await cleanupTemporaryDownloadFile(conn, downloadParameters)
    }
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

  if (options.sha256 != null) {
    const actualHash = await conn.sha256(destination)
    if (!hashMatches(actualHash, options.sha256)) return NEEDS_APPLY
    return (await metadataMatches(conn, destination, options)) ? "ok" : NEEDS_APPLY
  }

  const fileExists = await conn.exists(destination)
  if (!fileExists) return NEEDS_APPLY
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
    const parts = validateGithubOptions(options)
    if (options.sha256 != null) validateSha256(options.sha256)
    validateIntegrityConfiguration("download.github", options)

    const url = `https://github.com/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}/releases/download/${encodeURIComponent(options.tag)}/${encodeURIComponent(options.asset)}`
    const headers: Record<string, string> = {}

    if (options.token != null) {
      headers.Authorization = `token ${options.token}`
      headers.Accept = "application/octet-stream"
    }

    const { group, mode, owner, sha256 } = options
    const downloadParameters: DownloadParameters = {
      ...buildDownloadParameters(destination, { group, headers, mode, owner, sha256 }, url),
      secrets: options.token == null ? undefined : [options.token, ...extractUrlSecrets(url)],
    }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        return performDownload(conn, downloadParameters)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        return checkDownload(conn, destination, options)
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
   * @param options.group - Group owner to set on the downloaded file via `chown`.
   * @param options.mode - File mode to set via `chmod` (e.g. `"0755"`).
   * @param options.owner - User owner to set on the downloaded file via `chown`.
   * @param options.sha256 - Expected SHA-256 hex digest for integrity verification.
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
      /** Explicitly opt out of integrity verification for trusted sources. */
      allowUnverifiedDownload?: boolean
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
    }
  ): Module {
    const resolvedOptions = options ?? {}
    validateHttpUrl(url, { allowHttp: resolvedOptions.allowInsecureHttp })
    if (resolvedOptions.sha256 != null) validateSha256(resolvedOptions.sha256)
    validateIntegrityConfiguration("download.large", resolvedOptions)
    const downloadParameters = buildDownloadParameters(destination, resolvedOptions, url)
    const flagName = buildLargeDownloadFlagName(downloadParameters)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[download.large: ${destination}] SSH connection is required`)

        return applyWithFlagLock(conn, {
          async apply() {
            const result = await performDownload(conn, downloadParameters)

            if (result.status === "failed") return result

            await setFlag(conn, flagName)
            return { ...result, status: "changed" }
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
   * @param destination - Absolute path on the remote server where the file is saved.
   * @param url - The URL to download from.
   * @param options - Optional settings for integrity, ownership, and headers.
   * @param options.allowUnverifiedDownload - Explicitly opt out of integrity verification.
   * @returns A Module that manages the file download.
   */
  url(
    destination: string,
    url: string,
    options?: {
      /** Allow unencrypted `http://` downloads explicitly. */
      allowInsecureHttp?: boolean
      /** Explicitly opt out of integrity verification for trusted sources. */
      allowUnverifiedDownload?: boolean
      /** Force re-download even if the file already exists. */
      force?: boolean
      /** Additional HTTP headers sent with the curl request. */
      headers?: Record<string, string>
    } & BaseDownloadOptions
  ): Module {
    validateHttpUrl(url, { allowHttp: options?.allowInsecureHttp })
    if (options?.sha256 != null) validateSha256(options.sha256)
    const resolvedOptions = options ?? {}
    validateIntegrityConfiguration("download.url", resolvedOptions)
    const downloadParameters = buildDownloadParameters(destination, resolvedOptions, url)

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        return performDownload(conn, downloadParameters)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        return checkDownload(conn, destination, resolvedOptions)
      },
      name: `download.url: ${destination}`,
    }
  },
}
