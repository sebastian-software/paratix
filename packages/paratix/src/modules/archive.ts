import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import { localSha256, sha256String } from "./fileHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const
const FLAGS_DIR = "/var/lib/paratix/flags"

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
function extractCommand(source: string, archivePath: string, destination: string): null | string {
  const lower = source.toLowerCase()
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return `tar xzf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar.bz2")) {
    return `tar xjf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar.xz")) {
    return `tar xJf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar")) {
    return `tar xf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".zip")) {
    return `unzip -o ${shellQuote(archivePath)} -d ${shellQuote(destination)}`
  }
  return null
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
  const uploadHash = sha256String(source)
  const remoteSource = `/tmp/paratix-upload-${uploadHash}`
  await conn.uploadFile(source, remoteSource)
  return remoteSource
}

/**
 * Write the marker file and optionally clean up the uploaded archive.
 *
 * @param conn - The SSH connection.
 * @param remoteSource - The remote archive path.
 * @param options - Marker path and upload flag.
 * @param options.marker - The marker file path.
 * @param options.upload - Whether a temporary upload file should be removed.
 * @returns True if the marker was written successfully.
 */
async function writeMarkerAndCleanup(
  conn: SshConnection,
  remoteSource: string,
  options: { marker: string; upload: boolean }
): Promise<boolean> {
  const sha = await conn.sha256(remoteSource)
  if (sha === null) return false
  await conn.exec(`mkdir -p ${shellQuote(FLAGS_DIR)}`, SILENT)
  await conn.writeFile(options.marker, sha)
  if (options.upload) {
    await conn.exec(`rm -f ${shellQuote(remoteSource)}`, SILENT)
  }
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
 * Execute the archive extraction on the remote host.
 *
 * @param conn - The SSH connection.
 * @param parameters - The extraction parameters.
 * @returns The module result.
 */
async function applyExtract(
  conn: SshConnection,
  parameters: ApplyParameters
): Promise<ModuleResult> {
  const { destination, marker, owner, source, upload } = parameters

  const remoteSource = await resolveRemoteSource(conn, source, upload)
  await conn.exec(`mkdir -p ${shellQuote(destination)}`, SILENT)

  const cmd = extractCommand(source, remoteSource, destination)
  if (cmd === null) {
    if (upload) await conn.exec(`rm -f ${shellQuote(remoteSource)}`, SILENT)
    return failed(`[archive.extract] unsupported archive format for ${source}`)
  }
  const result = await conn.exec(cmd, EXEC_OPTS)
  if (result.code !== 0) {
    if (upload) await conn.exec(`rm -f ${shellQuote(remoteSource)}`, SILENT)
    return failedCommand(`[archive.extract] failed to extract ${source}`, result)
  }

  if (owner !== undefined && owner !== "") {
    await conn.exec(`chown -R ${shellQuote(owner)} ${shellQuote(destination)}`, SILENT)
  }

  const markerWritten = await writeMarkerAndCleanup(conn, remoteSource, { marker, upload })
  return markerWritten
    ? { status: "changed" }
    : failed(`[archive.extract] failed to write marker for ${source}`)
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
