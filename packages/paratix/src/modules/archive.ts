import { posix as pathPosix } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  archiveMemberDestinationPaths,
  archiveMemberPathsWithAncestors,
  destinationPathWithAncestors,
  validateExtractDestination,
  validateNoSymlinkPaths,
} from "./archiveDestinationValidation.js"
import {
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
} from "./archiveMemberValidation.js"
import { localSha256, sha256String } from "./fileHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const
const FLAGS_DIR = "/var/lib/paratix/flags"
const ARCHIVE_MARKER_MODE = "0644"

/**
 * Derive the marker file path from the source and destination paths.
 *
 * @param source - The source archive path used as part of the stable key.
 * @param destination - The extraction target path used as part of the stable key.
 * @returns The absolute path to the marker file.
 */
function markerPath(source: string, destination: string): string {
  const hash = sha256String(`${source}\n${destination}`)
  return `${FLAGS_DIR}/archive-${hash}.sha256`
}

/**
 * Build a descriptive error for a marker file that exists but cannot be
 * read. The `cat` stderr is preferred over the exit code when available.
 *
 * @param result - The result of the marker `cat` invocation.
 * @param result.code - The exit code from `cat`.
 * @param result.stderr - The stderr emitted by `cat`.
 * @returns An Error describing why the marker is unreadable.
 */
function buildMarkerUnreadableError(result: { code: number; stderr: string }): Error {
  const reason = result.stderr.trim() || `cat exited with code ${result.code}`
  return new Error(`[archive.extract] marker file unreadable: ${reason}`)
}

/**
 * Build the extract command based on the file extension of the original source.
 *
 * @param source - The original archive path used for format detection.
 * @param archivePath - The actual archive path on the remote host.
 * @param destination - The target directory for extraction.
 * @returns The shell command to extract the archive, or null if unsupported.
 */
// R-0000067: harden tar invocations with `--no-same-owner` and
// `--no-overwrite-dir` so an extraction cannot grant ownership of an
// existing directory to a UID embedded in the archive and cannot replace a
// pre-existing directory mode wholesale.
const TAR_HARDEN_FLAGS = "--no-same-owner --no-overwrite-dir"

function extractCommand(source: string, archivePath: string, destination: string): null | string {
  const lower = source.toLowerCase()
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return `tar ${TAR_HARDEN_FLAGS} -xzf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar.bz2")) {
    return `tar ${TAR_HARDEN_FLAGS} -xjf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar.xz")) {
    return `tar ${TAR_HARDEN_FLAGS} -xJf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar")) {
    return `tar ${TAR_HARDEN_FLAGS} -xf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".zip")) {
    return `unzip -o ${shellQuote(archivePath)} -d ${shellQuote(destination)}`
  }
  return null
}

// R-0000106: prefix used by `mktemp` for archive uploads. Reused for both
// the template and the post-mktemp path validation so a locale-induced
// warning, multi-line stdout or a tampered `mktemp` cannot smuggle an
// unexpected path into the subsequent uploadFile / extract / rm pipeline.
const ARCHIVE_UPLOAD_PREFIX = "paratix-upload"
const ARCHIVE_UPLOAD_DIRECTORY = "/tmp"

/**
 * Allocate a unique remote upload path via `mktemp`.
 *
 * Using a process-unique path prevents two paratix runs against the same
 * host from clobbering each other's uploads when both happen to share the
 * same local source path. The previous implementation hashed the source
 * path itself, which produced the same destination across runs and made
 * concurrent uploads with different content prone to silent corruption.
 *
 * R-0000106: every byte that comes back from `mktemp` is fed through
 * {@link validateMktempPath} before any subcommand consumes it. This is
 * the same defensive pattern used by `aptKeyHelpers.ts` and the generic
 * `createRemoteTempPath` helper in `ssh.ts`. Without this guard, a
 * locale warning ("mktemp: Warnung: ...\n/tmp/paratix-upload.AbCdEfGh")
 * or any other extra line would be silently passed to `uploadFile`,
 * `tar -xzf` and `rm -f` as if it were the temp path.
 *
 * @param conn - The SSH connection.
 * @returns The unique remote temporary path produced by `mktemp`.
 */
async function allocateRemoteUploadPath(conn: SshConnection): Promise<string> {
  const remoteSource = await conn.output(
    `mktemp ${ARCHIVE_UPLOAD_DIRECTORY}/${ARCHIVE_UPLOAD_PREFIX}.XXXXXXXX`
  )
  if (remoteSource.length === 0) {
    throw new Error("[archive.extract] mktemp did not return a remote path for the upload")
  }
  try {
    return validateMktempPath(ARCHIVE_UPLOAD_DIRECTORY, remoteSource, ARCHIVE_UPLOAD_PREFIX)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(`[archive.extract] mktemp produced an unexpected path: ${reason}`, {
      cause: error,
    })
  }
}

/**
 * Resolve the remote archive path, uploading a local file if needed.
 *
 * @param conn - The SSH connection.
 * @param source - The source archive path.
 * @param upload - Whether to upload the local file first.
 * @returns The remote path to the archive.
 */
async function resolveRemoteSource(
  conn: SshConnection,
  source: string,
  upload: boolean
): Promise<string> {
  if (!upload) return source
  const remoteSource = await allocateRemoteUploadPath(conn)
  await conn.uploadFile(source, remoteSource)
  return remoteSource
}

/**
 * Write the marker file using the SHA256 of the (possibly uploaded) remote archive.
 *
 * The cleanup of an uploaded temp file is intentionally **not** part of this
 * helper — the caller owns the lifecycle of the temp upload via try/finally so
 * the temp file is removed on every code path, including failures.
 *
 * @param conn - The SSH connection.
 * @param remoteSource - The remote archive path.
 * @param options - Marker path.
 * @param options.marker - The marker file path.
 * @returns True if the marker was written successfully.
 */
async function writeMarker(
  conn: SshConnection,
  remoteSource: string,
  options: { marker: string }
): Promise<boolean> {
  const sha = await conn.sha256(remoteSource)
  if (sha === null) return false
  await conn.exec(`mkdir -p ${shellQuote(FLAGS_DIR)}`, SILENT)
  await conn.writeFile(options.marker, sha, { mode: ARCHIVE_MARKER_MODE })
  return true
}

/** Parameters for the apply helper. */
type ApplyParameters = {
  /** The destination directory on the remote host. */
  destination: string
  /** The marker file path. */
  marker: string
  /** Optional owner for extracted archive members. */
  owner: string | undefined
  /** The source archive path. */
  source: string
  /** Whether to upload a local file first. */
  upload: boolean
}

/**
 * R-0000067: list the archive members and reject any entry whose
 * normalized path is absolute or escapes the destination via `..`. For
 * tar entries also reject linkname targets that would point outside the
 * destination. This is the runtime defense against the classic zip-slip /
 * tar-slip attack.
 *
 * @param conn - The SSH connection.
 * @param parameters - Listing inputs.
 * @param parameters.archivePath - The remote path to the archive.
 * @param parameters.source - The original source path (for format detection).
 * @returns Either a failure {@link ModuleResult} or null when all members are safe.
 */
async function validatedArchiveMembers(
  conn: SshConnection,
  parameters: { archivePath: string; source: string }
): Promise<ArchiveMember[] | ModuleResult> {
  const listing = await listArchiveMembers(conn, parameters)
  if ("failureReason" in listing) {
    return failed(`[archive.extract] ${listing.failureReason}`)
  }
  const unsafe = listing.members
    .map((member: ArchiveMember) => archiveMemberUnsafeReason(member))
    .find((reason): reason is string => reason !== null)
  if (unsafe !== undefined) {
    return failed(`[archive.extract] refusing to extract ${parameters.source}: ${unsafe}`)
  }
  return listing.members
}

async function applyExtractedMemberOwner(
  conn: SshConnection,
  parameters: { destination: string; members: ArchiveMember[]; owner?: string }
): Promise<void> {
  const { destination, members, owner } = parameters
  if (owner == null || owner === "") return
  await Promise.all(
    archiveMemberDestinationPaths(destination, members).map(async (path) =>
      conn.exec(`chown -h ${shellQuote(owner)} ${shellQuote(path)}`, SILENT)
    )
  )
}

async function prepareExtractDestination(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<{ destination: string } | ModuleResult> {
  const validatedDestination = validateExtractDestination(parameters.destination)
  if ("status" in validatedDestination) return validatedDestination
  const unsafeDestinationAncestor = await validateNoSymlinkPaths(conn, {
    paths: destinationPathWithAncestors(validatedDestination.destination),
    source: parameters.source,
  })
  if (unsafeDestinationAncestor !== null) return unsafeDestinationAncestor
  await conn.exec(`mkdir -p ${shellQuote(validatedDestination.destination)}`, SILENT)
  return validatedDestination
}

async function validateMembersForExtraction(
  conn: SshConnection,
  parameters: { destination: string; remoteSource: string; source: string }
): Promise<ArchiveMember[] | ModuleResult> {
  const { destination, remoteSource, source } = parameters
  const members = await validatedArchiveMembers(conn, { archivePath: remoteSource, source })
  if (!Array.isArray(members)) return members
  const unsafeMemberPath = await validateNoSymlinkPaths(conn, {
    paths: archiveMemberPathsWithAncestors(destination, members),
    source,
  })
  return unsafeMemberPath ?? members
}

/**
 * Run the extraction proper, after the (possibly uploaded) archive is in place.
 *
 * @param conn - The SSH connection.
 * @param parameters - Destination, marker, owner, source, upload (see {@link ApplyParameters}).
 * @param remoteSource - The remote archive path (uploaded temp file or original remote path).
 * @returns The module result.
 */
async function runExtraction(
  conn: SshConnection,
  parameters: ApplyParameters,
  remoteSource: string
): Promise<ModuleResult> {
  const { destination, marker, owner, source } = parameters

  const validatedDestination = await prepareExtractDestination(conn, { destination, source })
  if ("status" in validatedDestination) return validatedDestination

  const cmd = extractCommand(source, remoteSource, validatedDestination.destination)
  if (cmd === null) return failed(`[archive.extract] unsupported archive format for ${source}`)

  // R-0000067: validate every archive member before we hand the archive to
  // tar/unzip. This must happen after `mkdir -p` (so the destination
  // exists) but before the actual extract command runs, otherwise a
  // malicious archive could already have written a file outside the
  // destination by the time we notice.
  const members = await validateMembersForExtraction(conn, {
    destination: validatedDestination.destination,
    remoteSource,
    source,
  })
  if (!Array.isArray(members)) return members

  const result = await conn.exec(cmd, EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[archive.extract] failed to extract ${source}`, result)
  }

  await applyExtractedMemberOwner(conn, {
    destination: validatedDestination.destination,
    members,
    owner,
  })

  const markerWritten = await writeMarker(conn, remoteSource, { marker })
  return markerWritten
    ? { status: "changed" }
    : failed(`[archive.extract] failed to write marker for ${source}`)
}

/**
 * Execute the archive extraction on the remote host.
 *
 * Uploads the archive to a per-run unique remote path (via `mktemp`) when
 * `upload` is set, then guarantees the temp file is removed in `finally`
 * regardless of which code path succeeds or fails. This prevents concurrent
 * paratix runs from clobbering each other's uploads.
 *
 * @param conn - The SSH connection.
 * @param parameters - The extraction parameters.
 * @returns The module result.
 */
async function applyExtract(
  conn: SshConnection,
  parameters: ApplyParameters
): Promise<ModuleResult> {
  const { source, upload } = parameters

  const remoteSource = await resolveRemoteSource(conn, source, upload)

  try {
    return await runExtraction(conn, parameters, remoteSource)
  } finally {
    if (upload) {
      try {
        await conn.exec(`rm -f ${shellQuote(remoteSource)}`, SILENT)
      } catch {
        // best effort: cleanup must not mask the original result
      }
    }
  }
}

function ownerMatchesStat(stdout: string, owner: string): boolean {
  const [actualUser = "", actualGroup = ""] = stdout.trim().split(/\s+/v, 2)
  const [expectedUser = "", expectedGroup = ""] = owner.split(":", 2)
  if (expectedUser !== "" && actualUser !== expectedUser) return false
  if (expectedGroup !== "" && actualGroup !== expectedGroup) return false
  return true
}

async function extractedMemberOwnerMatches(
  conn: SshConnection,
  parameters: { owner: string; path: string }
): Promise<boolean> {
  const { owner, path } = parameters
  const exists = await conn.exec(
    `[ -e ${shellQuote(path)} ] || [ -L ${shellQuote(path)} ]`,
    EXEC_OPTS
  )
  if (exists.code !== 0) return false
  const stat = await conn.exec(`stat -c '%U %G' -- ${shellQuote(path)}`, EXEC_OPTS)
  if (stat.code !== 0) return false
  return ownerMatchesStat(stat.stdout, owner)
}

async function archiveOwnerMatches(
  conn: SshConnection,
  parameters: { destination: string; owner?: string; source: string; upload: boolean }
): Promise<boolean> {
  const { destination, owner, source, upload } = parameters
  if (owner == null || owner === "") return true
  if (upload) return true
  const members = await validatedArchiveMembers(conn, { archivePath: source, source })
  if (!Array.isArray(members)) return false
  const matches = await Promise.all(
    archiveMemberDestinationPaths(destination, members).map(async (path) =>
      extractedMemberOwnerMatches(conn, { owner, path })
    )
  )
  return matches.every(Boolean)
}

async function archiveMarkerMatches(
  conn: SshConnection,
  parameters: { marker: string; source: string; upload: boolean }
): Promise<boolean> {
  const { marker, source, upload } = parameters
  const markerResult = await conn.exec(`cat ${shellQuote(marker)}`, EXEC_OPTS)
  if (markerResult.code !== 0) {
    if (/no such file/iv.test(markerResult.stderr)) return false
    throw buildMarkerUnreadableError(markerResult)
  }
  const markerContent = markerResult.stdout.trim()

  if (upload) {
    const localHash = await localSha256(source)
    return localHash === markerContent
  }

  const remoteSha = await conn.sha256(source)
  return remoteSha === markerContent
}

/**
 * Modules for managing archive extraction on the remote host.
 */
export const archive = {
  /**
   * Extract an archive to a destination directory on the remote host.
   *
   * Supports tar, tar.gz, tgz, tar.bz2, tar.xz, and zip formats.
   * Uses a marker file with SHA256 checksum for idempotency.
   *
   * @param source - Path to the archive (remote path, or local path when upload is true).
   * @param destination - The destination directory on the remote host.
   * @param options - Optional settings.
   * @param options.owner - Set ownership on extracted archive members after extraction.
   * @param options.upload - Upload a local file to the remote host before extracting.
   * @returns A Module that manages the archive extraction.
   */
  extract(
    source: string,
    destination: string,
    options?: { owner?: string; upload?: boolean }
  ): Module {
    const normalizedDestination = destination.startsWith("/")
      ? pathPosix.normalize(destination)
      : destination
    const marker = markerPath(source, normalizedDestination)
    const upload = options?.upload === true
    const owner = options?.owner
    const parameters: ApplyParameters = {
      destination: normalizedDestination,
      marker,
      owner,
      source,
      upload,
    }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) {
          return failed(`[archive.extract] SSH connection is required for ${normalizedDestination}`)
        }
        return applyExtract(conn, parameters)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        // 1. Does the destination directory exist?
        const destinationExists = await conn.test(`test -d ${shellQuote(normalizedDestination)}`)
        if (!destinationExists) return NEEDS_APPLY

        // 2. Does the marker file exist?
        const markerExists = await conn.test(`test -f ${shellQuote(marker)}`)
        if (!markerExists) return NEEDS_APPLY
        if (
          !(await archiveOwnerMatches(conn, {
            destination: normalizedDestination,
            owner,
            source,
            upload,
          }))
        ) {
          return NEEDS_APPLY
        }

        // 3. Compare SHA256 of the archive with the marker file content.
        // R-0000105: distinguish between "marker is genuinely missing" and
        // "marker exists but cat could not read it" (e.g. permission denied
        // after the test -f succeeded for root vs. a downgraded apply step).
        // Without this differentiation a transient permission error would
        // collapse markerResult.stdout to "" and force an unnecessary
        // re-extraction of a potentially very large archive.
        return (await archiveMarkerMatches(conn, { marker, source, upload })) ? "ok" : NEEDS_APPLY
      },
      name: `archive.extract: ${normalizedDestination}`,
    }
  },
}
