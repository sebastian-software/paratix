/* eslint-disable max-lines -- archive module keeps extraction and idempotency helpers together */
import { failed, failedCommand } from "../moduleFailure.js"
import { maskRegisteredSecrets } from "../secretSink.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  archiveMemberDestinationPaths,
  archiveMemberPathsWithAncestors,
  createExtractDestinationDirectory,
  destinationPathWithAncestors,
  validateExistingExtractDestination,
  validateExtractDestination,
  validateNoSymlinkPaths,
  validateResolvedDestinationPath,
} from "./archiveDestinationValidation.js"
import {
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
  normalizeArchiveMemberPath,
} from "./archiveMemberValidation.js"
import { localSha256, sha256String } from "./fileHelpers.js"
import { renderChownSymlinkCommand } from "./fileMetadataHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const
const FLAGS_DIR = "/var/lib/paratix/flags"
const ARCHIVE_MARKER_MODE = "0644"
const ARCHIVE_OWNER_MEMBER_CONCURRENCY = 8

type StagingMergeParameters = {
  destination: string
  guardPaths: string[]
  staging: string
}

async function mapWithConcurrencyLimit<TItem, TResult>(
  items: TItem[],
  limit: number,
  mapper: (item: TItem, index: number) => Promise<TResult>
): Promise<TResult[]> {
  if (items.length === 0) return []

  const results: TResult[] = []
  let nextIndex = 0

  async function worker(): Promise<void> {
    for (;;) {
      const index = nextIndex
      nextIndex += 1
      if (index >= items.length) return
      // eslint-disable-next-line no-await-in-loop -- each worker intentionally runs one bounded queue slot at a time
      results[index] = await mapper(items[index], index)
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      await worker()
    })
  )
  return results
}

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

function ownerPathsMarkerPath(marker: string): string {
  return `${marker}.owner-paths`
}

function membersMarkerPath(marker: string): string {
  return `${marker}.members`
}

type ExtractedArchiveMember = {
  kind: "directory" | "file" | "hardlink" | "symlink"
  path: string
}

/**
 * Build the extract command based on the file extension of the original source.
 *
 * @param source - The original archive path used for format detection.
 * @param archivePath - The actual archive path on the remote host.
 * @param destination - The target directory for extraction.
 * @returns The shell command to extract the archive, or null if unsupported.
 */
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

// R-0000162: prefix for the per-extract staging directory created via
// `mktemp -d` *under the destination*. Extracting into a paratix-controlled,
// freshly-created sub-directory and then atomically moving the contents into
// the destination closes the TOCTOU window between symlink validation and
// `tar -xzf` / `unzip -o` execution. An attacker with write access below
// `destination` can no longer race a symlink between the validation step and
// the extract command, because the extract no longer writes into a path the
// attacker can influence.
const ARCHIVE_STAGE_PREFIX = ".paratix-stage"

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
 * Allocate a fresh per-extract staging directory under the destination via
 * `mktemp -d`. The directory is on the same filesystem as the destination so
 * that the subsequent move into the destination is `rename(2)`-cheap, and it
 * inherits the destination's parent permissions so non-root attackers cannot
 * inject symlinks between extraction and move. The returned path is verified
 * via {@link validateMktempPath} to defend against locale-induced multi-line
 * `mktemp` output.
 *
 * @param conn - The SSH connection.
 * @param destination - The (already validated, absolute) destination directory.
 * @returns The absolute path to the staging directory.
 */
async function allocateExtractStagingDirectory(
  conn: SshConnection,
  destination: string
): Promise<string> {
  const template = `${destination}/${ARCHIVE_STAGE_PREFIX}.XXXXXXXX`
  const stagingPath = await conn.output(`mktemp -d ${shellQuote(template)}`)
  if (stagingPath.length === 0) {
    throw new Error("[archive.extract] mktemp -d did not return a staging path for extraction")
  }
  try {
    return validateMktempPath(destination, stagingPath, ARCHIVE_STAGE_PREFIX)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(`[archive.extract] mktemp -d produced an unexpected staging path: ${reason}`, {
      cause: error,
    })
  }
}

/**
 * Move the extracted archive contents from the paratix-controlled staging
 * directory into the destination using per-entry `cp -aT` so existing
 * destination directories are merged conflict-free. R-0000221: per-entry
 * `mv -f` cannot merge into pre-existing subdirectories with the same name and
 * aborts mid-way on the first conflict, leaving the destination in a partial
 * state. Copying each top-level staging entry with `cp -aT` recurses into
 * existing entries, replacing regular files in place while preserving
 * owner/group/mode/timestamps. The staging directory itself is removed by
 * {@link cleanupStagingDirectory} after this helper returns successfully.
 *
 * @param conn - The SSH connection.
 * @param parameters - Staging merge inputs.
 * @param parameters.destination - The final destination directory.
 * @param parameters.guardPaths - Destination paths that must not be symlinks during merge.
 * @param parameters.staging - The staging directory holding the freshly extracted files.
 * @returns Either a failure {@link ModuleResult} or null on success.
 */
async function moveExtractedContentsIntoDestination(
  conn: SshConnection,
  parameters: StagingMergeParameters
): Promise<ModuleResult | null> {
  const { destination, staging } = parameters
  const guardPaths = [...new Set(parameters.guardPaths)].join("\n")
  // R-0000801: the staging merge inspects unsafe attacker-controlled paths
  // emitted by the archive. We assemble the shell snippet as String.raw
  // segments so the embedded quoting is readable, and we reject any
  // extracted path that contains a literal newline before `cp` ever
  // touches it. Newlines in extracted filenames are extremely unusual and
  // would otherwise corrupt the `printf | while read` loop that processes
  // `guard_paths`.
  const mergeScript = [
    String.raw`destination=$1; expected_destination=$2; guard_paths=$3; shift 3; `,
    String.raw`for source_path do `,
    String.raw`case "$source_path" in *"$(printf '\n')"*) `,
    String.raw`echo "[archive.extract] refusing staging merge: extracted path contains a newline" >&2; `,
    String.raw`exit 64;; esac; `,
    String.raw`resolved_destination=$(readlink -f -- "$destination") || { `,
    String.raw`echo "[archive.extract] failed to resolve destination path $destination before staging merge" >&2; `,
    String.raw`exit 64; }; `,
    String.raw`if [ "$resolved_destination" != "$expected_destination" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $destination resolves to $resolved_destination" >&2; `,
    String.raw`exit 64; fi; `,
    String.raw`printf "%s\n" "$guard_paths" | while IFS= read -r guarded_path; do `,
    String.raw`[ -z "$guarded_path" ] && continue; `,
    String.raw`if [ -L "$guarded_path" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $guarded_path is a symlink" >&2; `,
    String.raw`exit 64; fi; `,
    String.raw`done || exit $?; `,
    `target_path="$destination/$\{source_path##*/}"; `,
    String.raw`if [ -L "$target_path" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $target_path is a symlink" >&2; `,
    String.raw`exit 64; fi; `,
    String.raw`cp -aT --no-dereference --remove-destination "$source_path" "$target_path" || exit $?; `,
    String.raw`done`,
  ].join("")
  // R-0000751: defense-in-depth — `[ -L "$target_path" ]` runs immediately
  // before the `cp -aT` so a symlink planted between the first probe and
  // the copy cannot smuggle the merge through to an attacker-controlled
  // location. Mirrors R-0000677's recheck-just-before-write pattern in
  // net.ts.
  // R-0000563: copy with `--no-dereference` so a symlink planted at any
  // ancestor of `target_path` between the guard checks above and the `cp`
  // invocation is preserved (and refused by the in-tree handling) instead
  // of being silently followed to an attacker-controlled location.
  const copyCommand = [
    `find ${shellQuote(staging)} -mindepth 1 -maxdepth 1 -exec sh -c`,
    shellQuote(mergeScript),
    "sh",
    shellQuote(destination),
    shellQuote(destination),
    shellQuote(guardPaths),
    "{} +",
  ].join(" ")
  const copyResult = await conn.exec(copyCommand, EXEC_OPTS)
  if (copyResult.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to copy extracted files into ${destination}`,
      copyResult
    )
  }
  return null
}

async function cleanupStagingDirectory(conn: SshConnection, staging: string): Promise<void> {
  try {
    // R-0000565: pass `--` so a refactor that loosens the staging prefix
    // cannot let an attacker-controlled path that starts with `-` be
    // interpreted as an `rm` option.
    const result = await conn.exec(`rm -rf -- ${shellQuote(staging)}`, {
      ...SILENT,
      ignoreExitCode: true,
    })
    if (result.code !== 0) {
      // R-0000808: a staging cleanup failure used to be discarded silently,
      // which left orphaned `paratix-staging.*` directories on the remote
      // host with no operator-visible trace. Surface a masked warning on
      // stderr so the operator can investigate without overwriting the
      // module's original result. `maskRegisteredSecrets` covers paths that
      // were derived from a registered secret (e.g. token-bearing
      // destinations).
      const detail = result.stderr.trim() || result.stdout.trim() || `exit ${String(result.code)}`
      const message = `[archive.extract] staging cleanup failed for ${staging}: ${detail}`
      process.stderr.write(`${maskRegisteredSecrets(message)}\n`)
    }
  } catch (error) {
    // R-0000808: even a thrown SSH error must not be swallowed silently —
    // it indicates the staging directory may persist on the remote host.
    const reason = error instanceof Error ? error.message : String(error)
    const message = `[archive.extract] staging cleanup raised for ${staging}: ${reason}`
    process.stderr.write(`${maskRegisteredSecrets(message)}\n`)
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
 * @returns Null when the marker was written, otherwise a structured failure.
 */
async function writeMarker(
  conn: SshConnection,
  remoteSource: string,
  options: { marker: string }
): Promise<ModuleResult | null> {
  const sha = await conn.sha256(remoteSource)
  if (sha === null) return failed(`[archive.extract] failed to calculate marker hash`)
  const flagsDirectory = await conn.exec(`mkdir -p ${shellQuote(FLAGS_DIR)}`, EXEC_OPTS)
  if (flagsDirectory.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to create archive marker directory`,
      flagsDirectory
    )
  }
  try {
    await conn.writeFile(options.marker, sha, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive marker ${options.marker}: ${reason}`)
  }
  return null
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
  parameters: { destination: string; members: ArchiveMember[]; owner?: string; source: string }
): Promise<ModuleResult | null> {
  if (parameters.owner == null || parameters.owner === "") return null
  const owner = parameters.owner
  // R-0000267: chown errors (EPERM, ENOENT, quota) under the previous
  // `{ silent: true }` would surface as unguarded CommandError exceptions
  // through Promise.all in mapWithConcurrencyLimit and bypass the
  // failedCommand pipeline. Run with `ignoreExitCode` and surface the first
  // non-zero exit as a maskable failedCommand result with stdout/stderr.
  const results = await mapWithConcurrencyLimit(
    archiveMemberDestinationPaths(parameters.destination, parameters.members),
    ARCHIVE_OWNER_MEMBER_CONCURRENCY,
    async (path) => ({
      path,
      result: await conn.exec(renderChownSymlinkCommand(owner, path), EXEC_OPTS),
    })
  )
  const failure = results.find(({ result }) => result.code !== 0)
  if (failure !== undefined) {
    return failedCommand(
      `[archive.extract: ${parameters.source}] chown failed for ${failure.path}`,
      failure.result
    )
  }
  return null
}

async function writeOwnerPathsMarker(
  conn: SshConnection,
  parameters: {
    destination: string
    marker: string
    members: ArchiveMember[]
    owner?: string
    upload: boolean
  }
): Promise<ModuleResult | null> {
  if (parameters.owner == null || parameters.owner === "") return null
  // R-0000166: persist the member list in *both* upload and non-upload mode.
  // The previous implementation only stored the list when `upload === true`
  // and re-derived it from the live archive (`tar -tvzf <source>`) in the
  // non-upload check. If the source archive was modified or removed between
  // apply and the next check, the re-derived list no longer matched what
  // was extracted, which produced false drift reports — or, worse, hid real
  // owner drift on disk because the per-path stat operated on the wrong
  // file list. Writing the marker on every successful apply ties the owner
  // re-check to the same paths the extract actually touched.
  const paths = archiveMemberDestinationPaths(parameters.destination, parameters.members)
  const marker = ownerPathsMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, JSON.stringify(paths), {
      mode: ARCHIVE_MARKER_MODE,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive owner marker ${marker}: ${reason}`)
  }
  return null
}

function extractedArchiveMembers(
  destination: string,
  members: ArchiveMember[]
): ExtractedArchiveMember[] {
  const extractedMembers = new Map<string, ExtractedArchiveMember>()
  for (const member of members) {
    const memberPath = normalizeArchiveMemberPath(member.path)
    if (memberPath === null) continue
    const path = memberPath === "" ? destination : `${destination}/${memberPath}`
    if (member.kind === "special") continue
    extractedMembers.set(path, { kind: member.kind, path })
  }
  return [...extractedMembers.values()]
}

async function writeMembersMarker(
  conn: SshConnection,
  parameters: { destination: string; marker: string; members: ArchiveMember[] }
): Promise<ModuleResult | null> {
  const marker = membersMarkerPath(parameters.marker)
  try {
    await conn.writeFile(
      marker,
      JSON.stringify(extractedArchiveMembers(parameters.destination, parameters.members)),
      { mode: ARCHIVE_MARKER_MODE }
    )
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive members marker ${marker}: ${reason}`)
  }
  return null
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
  const createDestinationFailure = await createExtractDestinationDirectory(
    conn,
    validatedDestination.destination
  )
  if (createDestinationFailure !== null) return createDestinationFailure
  const unsafeResolvedDestination = await validateResolvedDestinationPath(conn, {
    destination: validatedDestination.destination,
    source: parameters.source,
  })
  if (unsafeResolvedDestination !== null) return unsafeResolvedDestination
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

async function validateTargetsForStagingMerge(
  conn: SshConnection,
  parameters: { destination: string; members: ArchiveMember[]; source: string }
): Promise<ModuleResult | null> {
  const unsafeResolvedDestination = await validateResolvedDestinationPath(conn, {
    destination: parameters.destination,
    source: parameters.source,
  })
  if (unsafeResolvedDestination !== null) return unsafeResolvedDestination
  return validateNoSymlinkPaths(conn, {
    paths: [
      ...destinationPathWithAncestors(parameters.destination),
      ...archiveMemberPathsWithAncestors(parameters.destination, parameters.members),
    ],
    source: parameters.source,
  })
}

/**
 * Run the extraction proper, after the (possibly uploaded) archive is in place.
 *
 * @param conn - The SSH connection.
 * @param parameters - Destination, marker, owner, source, upload (see {@link ApplyParameters}).
 * @param remoteSource - The remote archive path (uploaded temp file or original remote path).
 * @returns The module result.
 */
/**
 * R-0000162: extract into a paratix-controlled staging sub-directory, then
 * move the result into the destination atomically. This closes the TOCTOU
 * window between `validateNoSymlinkPaths` and the actual `tar -xzf` /
 * `unzip -o` invocation: an attacker with write access below `destination`
 * can no longer plant a symlink that the extract command then follows.
 *
 * @param conn - The SSH connection.
 * @param parameters - Inputs for the staged extraction.
 * @param parameters.destination - The validated destination directory.
 * @param parameters.members - The validated archive members.
 * @param parameters.remoteSource - The remote archive path (uploaded or original).
 * @param parameters.source - The source archive path (used for format detection).
 */
async function extractViaStagingDirectory(
  conn: SshConnection,
  parameters: {
    destination: string
    members: ArchiveMember[]
    remoteSource: string
    source: string
  }
): Promise<ModuleResult | null> {
  const { destination, members, remoteSource, source } = parameters

  // The unsupported-format check happens before staging-dir allocation so we
  // never create (or have to clean up) a staging directory we can't use.
  const probeCmd = extractCommand(source, remoteSource, destination)
  if (probeCmd === null) return failed(`[archive.extract] unsupported archive format for ${source}`)

  const staging = await allocateExtractStagingDirectory(conn, destination)
  try {
    const cmd = extractCommand(source, remoteSource, staging)
    if (cmd === null) return failed(`[archive.extract] unsupported archive format for ${source}`)

    const extractResult = await conn.exec(cmd, EXEC_OPTS)
    if (extractResult.code !== 0) {
      return failedCommand(`[archive.extract] failed to extract ${source}`, extractResult)
    }

    const unsafeMergeTarget = await validateTargetsForStagingMerge(conn, {
      destination,
      members,
      source,
    })
    if (unsafeMergeTarget !== null) return unsafeMergeTarget

    return await moveExtractedContentsIntoDestination(conn, {
      destination,
      guardPaths: [
        ...destinationPathWithAncestors(destination),
        ...archiveMemberPathsWithAncestors(destination, members),
      ],
      staging,
    })
  } finally {
    await cleanupStagingDirectory(conn, staging)
  }
}

async function finalizeExtraction(
  conn: SshConnection,
  parameters: { members: ArchiveMember[]; remoteSource: string } & ApplyParameters
): Promise<ModuleResult> {
  const { destination, marker, members, owner, remoteSource, source } = parameters

  const ownerFailure = await applyExtractedMemberOwner(conn, {
    destination,
    members,
    owner,
    source,
  })
  if (ownerFailure !== null) return ownerFailure

  const markerFailure = await writeMarker(conn, remoteSource, { marker })
  if (markerFailure !== null) return markerFailure
  const membersMarkerFailure = await writeMembersMarker(conn, { destination, marker, members })
  if (membersMarkerFailure !== null) return membersMarkerFailure
  const ownerPathsMarkerFailure = await writeOwnerPathsMarker(conn, {
    destination,
    marker,
    members,
    owner,
    upload: parameters.upload,
  })
  if (ownerPathsMarkerFailure !== null) return ownerPathsMarkerFailure
  return { status: "changed" }
}

async function runExtraction(
  conn: SshConnection,
  parameters: ApplyParameters,
  remoteSource: string
): Promise<ModuleResult> {
  const { destination, source } = parameters

  const validatedDestination = await prepareExtractDestination(conn, { destination, source })
  if ("status" in validatedDestination) return validatedDestination

  // R-0000067: validate every archive member before we hand the archive to
  // tar/unzip. This must happen after guarded destination creation (so the
  // destination exists) but before the actual extract command runs, otherwise a
  // malicious archive could already have written a file outside the
  // destination by the time we notice.
  const members = await validateMembersForExtraction(conn, {
    destination: validatedDestination.destination,
    remoteSource,
    source,
  })
  if (!Array.isArray(members)) return members

  const stagedFailure = await extractViaStagingDirectory(conn, {
    destination: validatedDestination.destination,
    members,
    remoteSource,
    source,
  })
  if (stagedFailure !== null) return stagedFailure

  return finalizeExtraction(conn, {
    ...parameters,
    destination: validatedDestination.destination,
    members,
    remoteSource,
  })
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
        // R-0000565: pass `--` so the uploaded archive path cannot be
        // misinterpreted as an `rm` option after a future refactor.
        await conn.exec(`rm -f -- ${shellQuote(remoteSource)}`, SILENT)
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

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
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
  parameters: {
    destination: string
    marker: string
    owner?: string
    source: string
    upload: boolean
  }
): Promise<boolean> {
  const { destination, marker, owner, source, upload } = parameters
  if (owner == null || owner === "") return true

  // R-0000166: prefer the marker for both upload and non-upload archives.
  // The marker pins the exact member list the last apply extracted, so the
  // owner re-check stays deterministic even when the source archive is
  // mutated, replaced or removed between apply and the next check.
  const paths = await readOwnerPathsMarker(conn, marker)
  if (paths !== null) return ownerMatchesPaths(conn, { owner, paths })

  // Backwards compatibility: previous paratix versions only wrote the
  // marker when `upload === true`, so a host extracted by an older release
  // may have a content marker but no owner-paths marker. In upload mode
  // the missing marker is a real failure (the archive content is not
  // available locally to re-derive the list); in non-upload mode we can
  // safely fall back to listing the source archive on the host.
  if (upload) return false
  const members = await validatedArchiveMembers(conn, { archivePath: source, source })
  if (!Array.isArray(members)) return false
  return ownerMatchesPaths(conn, {
    owner,
    paths: archiveMemberDestinationPaths(destination, members),
  })
}

function isExtractedArchiveMember(value: unknown): value is ExtractedArchiveMember {
  if (typeof value !== "object" || value === null) return false
  const member = value as { kind?: unknown; path?: unknown }
  return (
    typeof member.path === "string" &&
    (member.kind === "directory" ||
      member.kind === "file" ||
      member.kind === "hardlink" ||
      member.kind === "symlink")
  )
}

async function readMembersMarker(
  conn: SshConnection,
  marker: string
): Promise<ExtractedArchiveMember[] | null> {
  const markerResult = await conn.exec(`cat ${shellQuote(membersMarkerPath(marker))}`, EXEC_OPTS)
  if (markerResult.code !== 0) return null
  try {
    const members: unknown = JSON.parse(markerResult.stdout)
    return Array.isArray(members) && members.every((member) => isExtractedArchiveMember(member))
      ? members
      : []
  } catch {
    return []
  }
}

function memberTypeCheckCommand(member: ExtractedArchiveMember): string {
  const path = shellQuote(member.path)
  switch (member.kind) {
    case "directory": {
      return `[ -d ${path} ] && [ ! -L ${path} ]`
    }
    case "file":
    case "hardlink": {
      return `[ -f ${path} ] && [ ! -L ${path} ]`
    }
    case "symlink": {
      return `[ -L ${path} ]`
    }
  }
}

async function extractedMembersMatch(conn: SshConnection, marker: string): Promise<boolean> {
  const members = await readMembersMarker(conn, marker)
  if (members === null) return true
  const matches = await mapWithConcurrencyLimit(
    members,
    ARCHIVE_OWNER_MEMBER_CONCURRENCY,
    async (member) => {
      const result = await conn.exec(memberTypeCheckCommand(member), EXEC_OPTS)
      return result.code === 0
    }
  )
  return matches.every(Boolean)
}

async function ownerMatchesPaths(
  conn: SshConnection,
  parameters: { owner: string; paths: string[] }
): Promise<boolean> {
  const { owner, paths } = parameters
  const matches = await mapWithConcurrencyLimit(
    paths,
    ARCHIVE_OWNER_MEMBER_CONCURRENCY,
    async (path) => extractedMemberOwnerMatches(conn, { owner, path })
  )
  return matches.every(Boolean)
}

async function readOwnerPathsMarker(conn: SshConnection, marker: string): Promise<null | string[]> {
  const markerResult = await conn.exec(`cat ${shellQuote(ownerPathsMarkerPath(marker))}`, EXEC_OPTS)
  if (markerResult.code !== 0) {
    // R-0000276: previously a non-"no such file" stderr (e.g. permission
    // denied after a flag-dir mode drift, or a transient truncate race) raised
    // an exception that propagated past archiveOwnerMatches and aborted the
    // whole run. Falling through to NEEDS_APPLY lets apply heal the marker,
    // mirroring the recovery path used by download.ts:compareUnverifiedHashMarker.
    return null
  }
  try {
    const paths: unknown = JSON.parse(markerResult.stdout)
    return isStringArray(paths) ? paths : null
  } catch {
    return null
  }
}

async function archiveMarkerMatches(
  conn: SshConnection,
  parameters: { marker: string; source: string; upload: boolean }
): Promise<boolean> {
  const { marker, source, upload } = parameters
  const markerResult = await conn.exec(`cat ${shellQuote(marker)}`, EXEC_OPTS)
  if (markerResult.code !== 0) {
    // R-0000276: any non-zero cat result (missing file, permission denied,
    // concurrent truncate) is treated as "marker does not match" so check
    // returns NEEDS_APPLY and the apply path heals the marker. Throwing here
    // would abort the entire run on a recoverable flag-dir hiccup.
    return false
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
    // R-0000700 / R-0000706: validate the destination synchronously at module
    // construction so invalid destinations (control characters, relative
    // paths, "/") fail fast before any marker path is derived or async
    // apply/check work is scheduled.
    const validatedDestination = validateExtractDestination(destination)
    if ("status" in validatedDestination) {
      const reason = validatedDestination.error?.message ?? "invalid destination"
      throw new Error(reason)
    }
    const normalizedDestination = validatedDestination.destination
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

        const unsafeDestination = await validateExistingExtractDestination(conn, {
          destination: normalizedDestination,
          source,
        })
        if (unsafeDestination !== null) return NEEDS_APPLY

        const markerExists = await conn.test(`test -f ${shellQuote(marker)}`)
        if (!markerExists) return NEEDS_APPLY
        if (!(await extractedMembersMatch(conn, marker))) return NEEDS_APPLY
        if (
          !(await archiveOwnerMatches(conn, {
            destination: normalizedDestination,
            marker,
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
