import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  type ArchiveMember,
  listArchiveMembers,
  memberEscapesDestination,
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

/**
 * Allocate a unique remote upload path via `mktemp`.
 *
 * Using a process-unique path prevents two paratix runs against the same
 * host from clobbering each other's uploads when both happen to share the
 * same local source path. The previous implementation hashed the source
 * path itself, which produced the same destination across runs and made
 * concurrent uploads with different content prone to silent corruption.
 *
 * @param conn - The SSH connection.
 * @returns The unique remote temporary path produced by `mktemp`.
 */
async function allocateRemoteUploadPath(conn: SshConnection): Promise<string> {
  const remoteSource = await conn.output("mktemp /tmp/paratix-upload.XXXXXXXX")
  if (remoteSource.length === 0) {
    throw new Error("[archive.extract] mktemp did not return a remote path for the upload")
  }
  return remoteSource
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
  /** Optional owner for chown -R. */
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
async function rejectUnsafeArchiveMembers(
  conn: SshConnection,
  parameters: { archivePath: string; source: string }
): Promise<ModuleResult | null> {
  const listing = await listArchiveMembers(conn, parameters)
  if ("failureReason" in listing) {
    return failed(`[archive.extract] ${listing.failureReason}`)
  }
  const unsafe = listing.members.find((member: ArchiveMember) => memberEscapesDestination(member))
  if (unsafe !== undefined) {
    const detail =
      unsafe.linkTarget === null
        ? `member ${JSON.stringify(unsafe.path)}`
        : `member ${JSON.stringify(unsafe.path)} -> ${JSON.stringify(unsafe.linkTarget)}`
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: ${detail} would escape destination`
    )
  }
  return null
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

  await conn.exec(`mkdir -p ${shellQuote(destination)}`, SILENT)

  const cmd = extractCommand(source, remoteSource, destination)
  if (cmd === null) return failed(`[archive.extract] unsupported archive format for ${source}`)

  // R-0000067: validate every archive member before we hand the archive to
  // tar/unzip. This must happen after `mkdir -p` (so the destination
  // exists) but before the actual extract command runs, otherwise a
  // malicious archive could already have written a file outside the
  // destination by the time we notice.
  const unsafe = await rejectUnsafeArchiveMembers(conn, { archivePath: remoteSource, source })
  if (unsafe !== null) return unsafe

  const result = await conn.exec(cmd, EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[archive.extract] failed to extract ${source}`, result)
  }

  if (owner !== undefined && owner !== "") {
    await conn.exec(`chown -R ${shellQuote(owner)} ${shellQuote(destination)}`, SILENT)
  }

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
   * @param options.owner - Run chown -R after extraction.
   * @param options.upload - Upload a local file to the remote host before extracting.
   * @returns A Module that manages the archive extraction.
   */
  extract(
    source: string,
    destination: string,
    options?: { owner?: string; upload?: boolean }
  ): Module {
    const marker = markerPath(source, destination)
    const upload = options?.upload === true
    const owner = options?.owner
    const parameters: ApplyParameters = { destination, marker, owner, source, upload }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) return failed(`[archive.extract] SSH connection is required for ${destination}`)
        return applyExtract(conn, parameters)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

        // 1. Does the destination directory exist?
        const destinationExists = await conn.test(`test -d ${shellQuote(destination)}`)
        if (!destinationExists) return NEEDS_APPLY

        // 2. Does the marker file exist?
        const markerExists = await conn.test(`test -f ${shellQuote(marker)}`)
        if (!markerExists) return NEEDS_APPLY

        // 3. Compare SHA256 of the archive with the marker file content.
        const markerResult = await conn.exec(`cat ${shellQuote(marker)}`, SILENT)
        const markerContent = markerResult.stdout.trim()

        if (upload) {
          // Compute local SHA256 without uploading.
          const localHash = await localSha256(source)
          return localHash === markerContent ? "ok" : NEEDS_APPLY
        }

        const remoteSha = await conn.sha256(source)
        return remoteSha === markerContent ? "ok" : NEEDS_APPLY
      },
      name: `archive.extract: ${destination}`,
    }
  },
}
