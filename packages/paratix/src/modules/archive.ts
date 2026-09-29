/* eslint-disable max-lines -- archive module keeps extraction and idempotency helpers together */
import { failed, failedCommand } from "../moduleFailure.js"
import { maskRegisteredSecrets } from "../secretSink.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  enforceSymlinkContainment,
  validateMergedSymlinkContainment,
} from "./archiveContainmentEnforcement.js"
import {
  archiveMemberDestinationPaths,
  archiveMemberGuardPaths,
  createExtractDestinationDirectory,
  destinationPathWithAncestors,
  validateExistingExtractDestination,
  validateExtractDestination,
  validateNoSymlinkPaths,
  validatePreStagingPaths,
  validateResolvedDestinationPath,
} from "./archiveDestinationValidation.js"
import { archiveLinkUnsafeReason } from "./archiveLinkValidation.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
  normalizeArchiveMemberPath,
} from "./archiveMemberValidation.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  encodeMemberTypeEntry,
  encodeNulPayload,
  OWNERSHIP_PROBE_FIELD_COUNT,
  runBatchedProbe,
} from "./archiveProbe.js"
import { localSha256, sha256String } from "./fileHelpers.js"
import {
  ownershipComponentMatches,
  renderBatchedChownSymlinkCommand,
} from "./fileMetadataHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const ARCHIVE_CAPTURE_EXEC_OPTS = {
  ...EXEC_OPTS,
  maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
} as const
const SILENT = { silent: true } as const
const FLAGS_DIR = "/var/lib/paratix/flags"
const ARCHIVE_MARKER_MODE = "0644"
/**
 * Issue #219: body of the containment flag; only its presence is read. The
 * flag is written before every merge and removed only after a fully
 * successful apply, so it stands for "apply in progress or containment
 * failed".
 */
const CONTAINMENT_FLAG_CONTENT = "archive apply in progress or symlink containment check failed\n"
/** Columns emitted by the member ownership probe: `%U %G %u %g`. */
const ARCHIVE_STAT_OWNERSHIP_FIELDS = 4
const MISSING_OWNER_PATHS_MARKER_PATTERN = /no such file or directory/iv

type StagingMergeParameters = {
  destination: string
  guardPaths: string[]
  staging: string
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

/**
 * Issue #219: derive the containment-failure flag path from the destination.
 *
 * The flag is keyed by destination only, unlike the marker: an escaping link
 * is a property of the destination tree, so it must force `check` to report
 * needs-apply for every source that extracts there, including an earlier
 * source whose marker still matches after a rollback.
 *
 * @param destination - The normalized extraction target path.
 * @returns The absolute path to the flag file.
 */
function containmentFailureFlagPath(destination: string): string {
  return `${FLAGS_DIR}/archive-containment-${sha256String(destination)}.failed`
}

/**
 * Issue #219: build the `check` test that the marker exists and no
 * containment-failure flag is present. Folding both into one `test` keeps the
 * exec count of `check` unchanged. A dangling symlink at the flag path counts
 * as present, so only a genuinely absent flag lets `check` continue.
 *
 * @param marker - The marker file path.
 * @param flag - The containment-failure flag path.
 * @returns The shell test command.
 */
function markerWithoutContainmentFailureCommand(marker: string, flag: string): string {
  const quotedFlag = shellQuote(flag)
  return `test -f ${shellQuote(marker)} && test ! -e ${quotedFlag} && test ! -L ${quotedFlag}`
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

type MembersMarkerReadResult = "invalid" | ExtractedArchiveMember[] | null

type ArchiveMarkerPayloads = {
  members: string
  ownerPaths: null | string
}

type OwnerPathsMarkerReadResult =
  { kind: "invalid" } | { kind: "missing" } | { kind: "valid"; paths: string[] }

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
 * Build the `sh -c` snippet that merges one batch of staging entries into the
 * destination.
 *
 * The script reads `destination`, `expected_destination` and `guard_paths` from
 * `$1`–`$3` and the staging entries from the remaining positional arguments, so
 * it is free of interpolated paths and can be executed verbatim against a real
 * `/bin/sh` in a test. Issue #178 showed why that matters: a guard that reads
 * correctly can still be inert at run time, and only executing it proves
 * otherwise.
 *
 * @returns The merge script as a single shell command string.
 */
export function buildStagingMergeScript(): string {
  // R-0000801: the staging merge inspects unsafe attacker-controlled paths
  // emitted by the archive. We assemble the shell snippet as String.raw
  // segments so the embedded quoting is readable, and we reject any
  // extracted path that contains a literal newline before `cp` ever
  // touches it. Newlines in extracted filenames are extremely unusual and
  // would otherwise corrupt the `printf | while read` loop that processes
  // `guard_paths`.
  // R-0000801 addendum: capture the newline via a sacrificial `x` that is
  // stripped afterwards. A bare `$(printf '\n')` is useless as a guard —
  // command substitution strips *all* trailing newlines, so it expands to the
  // empty string, the pattern degrades from `*"\n"*` to `*""*` (i.e. `*`) and
  // the guard refuses every path. Appending `x` gives the substitution a
  // non-newline byte to keep, and `${nl%x}` removes it again.
  return [
    // Not `String.raw`: that suppresses escape processing but not `${…}`
    // interpolation, so a raw literal would evaluate `nl % x` in JavaScript.
    // `$\{` is the same escape the `target_path` line below uses to emit a
    // literal shell parameter expansion from a template literal.
    `nl=$(printf '\\nx'); nl=$\{nl%x}; `,
    String.raw`destination=$1; expected_destination=$2; guard_paths=$3; shift 3; `,
    String.raw`for source_path do `,
    String.raw`case "$source_path" in *"$nl"*) `,
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
    // Issue #219: a destination symlink may only be replaced by a staged
    // symlink. Refusing it unconditionally failed every later run of an
    // archive with a top-level symlink, because that link from the previous
    // run was still in place. `cp -aT --no-dereference --remove-destination`
    // removes the old link and never writes through it; a symlink where the
    // archive has a directory or file is still refused.
    String.raw`if [ -L "$target_path" ] && [ ! -L "$source_path" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $target_path is a symlink" >&2; `,
    String.raw`exit 64; fi; `,
    String.raw`cp -aT --no-dereference --remove-destination "$source_path" "$target_path" || exit $?; `,
    String.raw`done`,
  ].join("")
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
  const mergeScript = buildStagingMergeScript()
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

/**
 * Issue #219: establish the containment flag before the merge. The flag is
 * written like the markers — `mkdir -p` of the flags directory and
 * `writeFile`, which stages a temp file and moves it into place with its
 * symlink guards. Writing it before anything is copied means every way the
 * apply can end early — a refusal, a failed merge, a crash — leaves `check`
 * at needs-apply, even when a marker from an earlier source still matches.
 *
 * @param conn - The SSH connection.
 * @param flag - The containment-failure flag path.
 * @returns Null when the flag is in place, otherwise why it could not be written.
 */
async function writeContainmentFailureFlag(
  conn: SshConnection,
  flag: string
): Promise<null | string> {
  try {
    const flagsDirectory = await conn.exec(`mkdir -p ${shellQuote(FLAGS_DIR)}`, EXEC_OPTS)
    if (flagsDirectory.code !== 0) {
      const detail =
        flagsDirectory.stderr.trim() ||
        flagsDirectory.stdout.trim() ||
        `exit code ${String(flagsDirectory.code)}`
      return `failed to create archive marker directory for containment-failure flag ${flag}: ${detail}`
    }
    await conn.writeFile(flag, CONTAINMENT_FLAG_CONTENT, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return `failed to write containment-failure flag ${flag}: ${reason}`
  }
  return null
}

/**
 * Issue #219: remove the containment-failure flag after a fully successful
 * apply. A removal failure fails the apply: a flag left behind would make
 * every later `check` report needs-apply without end.
 *
 * @param conn - The SSH connection.
 * @param flag - The containment-failure flag path.
 * @returns Null when the flag is gone, otherwise a structured failure.
 */
async function clearContainmentFailureFlag(
  conn: SshConnection,
  flag: string
): Promise<ModuleResult | null> {
  // `--` keeps the path from being read as an option; `-f` makes an absent
  // flag the normal case rather than an error.
  const result = await conn.exec(`rm -f -- ${shellQuote(flag)}`, EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to remove containment-failure flag ${flag}`,
      result
    )
  }
  return null
}

/** Parameters for the apply helper. */
type ApplyParameters = {
  /** Issue #219: the destination's containment-failure flag path. */
  containmentFlag: string
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
 * Issue #219: after the per-member checks, the archive-level link rules of
 * `archiveLinkUnsafeReason` run over the whole listing.
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
  // Issue #219: links are judged against the whole archive once every member
  // passed on its own — whether a relative symlink stays inside depends on the
  // other symlinks its target passes through.
  const unsafeLinks = unsafe ?? archiveLinkUnsafeReason(listing.members)
  if (unsafeLinks !== null) {
    return failed(`[archive.extract] refusing to extract ${parameters.source}: ${unsafeLinks}`)
  }
  return listing.members
}

async function applyExtractedMemberOwner(
  conn: SshConnection,
  parameters: { destination: string; members: ArchiveMember[]; owner?: string; source: string }
): Promise<ModuleResult | null> {
  if (parameters.owner == null || parameters.owner === "") return null
  const owner = parameters.owner
  const paths = archiveMemberDestinationPaths(parameters.destination, parameters.members)
  if (paths.length === 0) return null
  // R-0000267: chown errors (EPERM, ENOENT, quota) must reach the
  // `failedCommand` pipeline rather than escaping as CommandError exceptions,
  // hence `ignoreExitCode` plus an explicit non-zero check.
  // Issue #180: one batched `chown -h` instead of one exec per member. `chown`
  // names every path it could not change on stderr, so the diagnostic is wider
  // than the previous first-failure-only message rather than narrower.
  const result = await conn.exec(renderBatchedChownSymlinkCommand(owner), {
    ...EXEC_OPTS,
    input: encodeNulPayload(paths),
  })
  if (result.code !== 0) {
    return failedCommand(
      `[archive.extract: ${parameters.source}] chown failed for one or more extracted members`,
      result
    )
  }
  return null
}

async function writeOwnerPathsMarker(
  conn: SshConnection,
  parameters: {
    content: null | string
    marker: string
  }
): Promise<ModuleResult | null> {
  if (parameters.content === null) return null
  // R-0000166: persist the member list in *both* upload and non-upload mode.
  // The previous implementation only stored the list when `upload === true`
  // and re-derived it from the live archive (`tar -tvzf <source>`) in the
  // non-upload check. If the source archive was modified or removed between
  // apply and the next check, the re-derived list no longer matched what
  // was extracted, which produced false drift reports — or, worse, hid real
  // owner drift on disk because the per-path stat operated on the wrong
  // file list. Writing the marker on every successful apply ties the owner
  // re-check to the same paths the extract actually touched.
  const marker = ownerPathsMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, parameters.content, {
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

function serializeArchiveMarkerPayloads(parameters: {
  destination: string
  members: ArchiveMember[]
  owner?: string
  source: string
}): ArchiveMarkerPayloads | ModuleResult {
  const members = JSON.stringify(
    extractedArchiveMembers(parameters.destination, parameters.members)
  )
  const membersBytes = Buffer.byteLength(members, "utf8")
  if (membersBytes > ARCHIVE_CAPTURE_LIMIT_BYTES) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: archive members marker payload is ${String(membersBytes)} bytes and exceeds the limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`
    )
  }

  if (parameters.owner == null || parameters.owner === "") {
    return { members, ownerPaths: null }
  }
  const ownerPaths = JSON.stringify(
    archiveMemberDestinationPaths(parameters.destination, parameters.members)
  )
  const ownerPathsBytes = Buffer.byteLength(ownerPaths, "utf8")
  if (ownerPathsBytes > ARCHIVE_CAPTURE_LIMIT_BYTES) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: archive owner-paths marker payload is ${String(ownerPathsBytes)} bytes and exceeds the limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`
    )
  }
  return { members, ownerPaths }
}

async function writeMembersMarker(
  conn: SshConnection,
  parameters: { content: string; marker: string }
): Promise<ModuleResult | null> {
  const marker = membersMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, parameters.content, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive members marker ${marker}: ${reason}`)
  }
  return null
}

async function preflightExtractDestination(
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
  return validatedDestination
}

async function createAndValidateExtractDestination(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const createDestinationFailure = await createExtractDestinationDirectory(
    conn,
    parameters.destination
  )
  if (createDestinationFailure !== null) return createDestinationFailure
  const unsafeResolvedDestination = await validateResolvedDestinationPath(conn, {
    destination: parameters.destination,
    source: parameters.source,
  })
  if (unsafeResolvedDestination !== null) return unsafeResolvedDestination
  return null
}

async function validateMembersForExtraction(
  conn: SshConnection,
  parameters: { remoteSource: string; source: string }
): Promise<ArchiveMember[] | ModuleResult> {
  const { remoteSource, source } = parameters
  return validatedArchiveMembers(conn, { archivePath: remoteSource, source })
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
      ...archiveMemberGuardPaths(parameters.destination, parameters.members),
    ],
    source: parameters.source,
  })
}

/**
 * Issue #219: outcome of {@link extractViaStagingDirectory}. `mergeStarted`
 * is true once the staging merge was invoked, whether it succeeded or not:
 * from then on the destination may already hold copied entries, so the
 * post-merge containment backstop has to run.
 */
type StagedExtraction = { failure: ModuleResult | null; mergeStarted: boolean }

/**
 * Run the staging merge and turn a thrown error from its exec into a failure
 * result, so the caller still runs the post-merge backstop.
 *
 * @param conn - The SSH connection.
 * @param parameters - Staging merge inputs.
 * @returns The merge failure, or null when the merge succeeded.
 */
async function runStagingMerge(
  conn: SshConnection,
  parameters: StagingMergeParameters
): Promise<ModuleResult | null> {
  try {
    return await moveExtractedContentsIntoDestination(conn, parameters)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(
      `[archive.extract] failed to copy extracted files into ${parameters.destination}: ${reason}`
    )
  }
}

function mergeNotStarted(failure: ModuleResult): StagedExtraction {
  return { failure, mergeStarted: false }
}

/** Inputs of the staged extraction. */
type StagedExtractionParameters = {
  /** The validated destination directory. */
  destination: string
  /** The validated archive members. */
  members: ArchiveMember[]
  /** The remote archive path (uploaded or original). */
  remoteSource: string
  /** The source archive path (used for format detection). */
  source: string
}

/**
 * Extract the archive into an allocated staging directory, re-check the merge
 * targets and run the merge. The caller owns the staging directory's cleanup.
 *
 * @param conn - The SSH connection.
 * @param parameters - Inputs for the staged extraction.
 * @param staging - The allocated staging directory.
 * @returns The failure of extraction or merge and whether the merge was started.
 */
async function extractAndMergeStaging(
  conn: SshConnection,
  parameters: StagedExtractionParameters,
  staging: string
): Promise<StagedExtraction> {
  const { destination, members, remoteSource, source } = parameters
  const cmd = extractCommand(source, remoteSource, staging)
  if (cmd === null) {
    return mergeNotStarted(failed(`[archive.extract] unsupported archive format for ${source}`))
  }

  const extractResult = await conn.exec(cmd, EXEC_OPTS)
  if (extractResult.code !== 0) {
    return mergeNotStarted(
      failedCommand(`[archive.extract] failed to extract ${source}`, extractResult)
    )
  }

  const unsafeMergeTarget = await validateTargetsForStagingMerge(conn, {
    destination,
    members,
    source,
  })
  if (unsafeMergeTarget !== null) return mergeNotStarted(unsafeMergeTarget)

  const failure = await runStagingMerge(conn, {
    destination,
    guardPaths: [
      ...destinationPathWithAncestors(destination),
      ...archiveMemberGuardPaths(destination, members),
    ],
    staging,
  })
  return { failure, mergeStarted: true }
}

/**
 * R-0000162: extract into a paratix-controlled staging sub-directory, then
 * move the result into the destination atomically. This closes the TOCTOU
 * window between `validateNoSymlinkPaths` and the actual `tar -xzf` /
 * `unzip -o` invocation: an attacker with write access below `destination`
 * can no longer plant a symlink that the extract command then follows.
 *
 * @param conn - The SSH connection.
 * @param parameters - Inputs for the staged extraction (see {@link StagedExtractionParameters}).
 * @returns The failure of extraction or merge (null on success) and whether
 *   the merge was started.
 */
async function extractViaStagingDirectory(
  conn: SshConnection,
  parameters: StagedExtractionParameters
): Promise<StagedExtraction> {
  const { destination, remoteSource, source } = parameters

  // The unsupported-format check happens before staging-dir allocation so we
  // never create (or have to clean up) a staging directory we can't use.
  const probeCmd = extractCommand(source, remoteSource, destination)
  if (probeCmd === null) {
    return mergeNotStarted(failed(`[archive.extract] unsupported archive format for ${source}`))
  }

  const staging = await allocateExtractStagingDirectory(conn, destination)
  try {
    return await extractAndMergeStaging(conn, parameters, staging)
  } finally {
    await cleanupStagingDirectory(conn, staging)
  }
}

async function finalizeExtraction(
  conn: SshConnection,
  parameters: {
    markerPayloads: ArchiveMarkerPayloads
    members: ArchiveMember[]
    remoteSource: string
  } & ApplyParameters
): Promise<ModuleResult> {
  const {
    containmentFlag,
    destination,
    marker,
    markerPayloads,
    members,
    owner,
    remoteSource,
    source,
  } = parameters

  const ownerFailure = await applyExtractedMemberOwner(conn, {
    destination,
    members,
    owner,
    source,
  })
  if (ownerFailure !== null) return ownerFailure

  const markerFailure = await writeMarker(conn, remoteSource, { marker })
  if (markerFailure !== null) return markerFailure
  const membersMarkerFailure = await writeMembersMarker(conn, {
    content: markerPayloads.members,
    marker,
  })
  if (membersMarkerFailure !== null) return membersMarkerFailure
  const ownerPathsMarkerFailure = await writeOwnerPathsMarker(conn, {
    content: markerPayloads.ownerPaths,
    marker,
  })
  if (ownerPathsMarkerFailure !== null) return ownerPathsMarkerFailure
  // Issue #219: only now is the apply fully successful. A crash before this
  // point leaves the flag in place, which keeps `check` at needs-apply.
  const flagFailure = await clearContainmentFailureFlag(conn, containmentFlag)
  if (flagFailure !== null) return flagFailure
  return { status: "changed" }
}

/**
 * Issue #219: combine the merge failure and the backstop failure into one
 * result; either may be null.
 *
 * @param mergeFailure - The failure of the staging merge, or null.
 * @param backstopFailure - The failure of the post-merge backstop, or null.
 * @returns Null when both are null, the one failure, or both messages joined.
 */
function combineMergeFailures(
  mergeFailure: ModuleResult | null,
  backstopFailure: ModuleResult | null
): ModuleResult | null {
  if (mergeFailure === null) return backstopFailure
  if (backstopFailure === null) return mergeFailure
  const mergeMessage = mergeFailure.error?.message ?? "[archive.extract] staging merge failed"
  const backstopMessage =
    backstopFailure.error?.message ?? "[archive.extract] symlink containment check failed"
  return failed(`${mergeMessage}; ${backstopMessage}`)
}

/**
 * Establish the containment flag, check the combined host and archive links,
 * run the staged extraction and then enforce that no symlink under the
 * destination resolves outside it.
 *
 * Issue #219: the flag is written first, before the pre-merge listing and
 * before any staging directory exists; if it cannot be written, nothing else
 * runs. Every later failure — a pre-merge refusal, a failed listing, extract
 * or merge, a backstop violation, a thrown error — leaves the flag set, so
 * `check` reports needs-apply even when a marker from an earlier source still
 * matches. Only `finalizeExtraction` removes it, after owner handling and all
 * marker writes succeeded.
 *
 * @param conn - The SSH connection.
 * @param parameters - Inputs for the staged extraction (see {@link extractViaStagingDirectory}).
 * @param parameters.containmentFlag - The destination's containment-failure flag path.
 * @param parameters.destination - The validated destination directory.
 * @param parameters.members - The validated archive members.
 * @param parameters.remoteSource - The remote archive path (uploaded or original).
 * @param parameters.source - The source archive path.
 * @returns A failure `ModuleResult` if the flag write, extraction, merge or the
 *   containment backstop fails, or `null` on success.
 */
async function extractAndValidateSymlinkContainment(
  conn: SshConnection,
  parameters: {
    containmentFlag: string
    destination: string
    members: ArchiveMember[]
    remoteSource: string
    source: string
  }
): Promise<ModuleResult | null> {
  const flagFailure = await writeContainmentFailureFlag(conn, parameters.containmentFlag)
  if (flagFailure !== null) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: ${flagFailure}; the flag must be in place before anything is copied`
    )
  }

  // Issue #219: resolve the host's existing links together with this archive's
  // links before any staging directory exists. A refusal here runs no merge,
  // no chown and writes no marker; the flag written above stays set.
  const unsafeMergedLinks = await validateMergedSymlinkContainment(conn, parameters)
  if (unsafeMergedLinks !== null) return unsafeMergedLinks

  const staged = await extractViaStagingDirectory(conn, parameters)
  if (!staged.mergeStarted) return staged.failure

  // Issue #219: links from separate runs can combine — a link that stayed
  // inside when it was written may resolve outside once a later archive places
  // a link on its path. `validateMergedSymlinkContainment` already refused such
  // a combination before the merge, from a listing of the host's links. This
  // enforcement over the whole tree after the merge is the backstop for host
  // changes that landed between that listing and the merge, and for a merge
  // that failed half-way after copying some entries: it runs whenever the
  // merge started, removes every escaping link it finds and fails the run.
  // The caller runs it before `finalizeExtraction`, so a refused extraction
  // performs no chown and writes no marker file, and the flag stays set.
  // Staging has already been cleaned up here; a leftover staging directory
  // lies inside the destination, so its links resolve inside as well and need
  // no pruning.
  const backstopFailure = await enforceSymlinkContainment(conn, {
    destination: parameters.destination,
    source: parameters.source,
  })
  return combineMergeFailures(staged.failure, backstopFailure)
}

async function runExtraction(
  conn: SshConnection,
  parameters: ApplyParameters,
  remoteSource: string
): Promise<ModuleResult> {
  const { destination, source } = parameters

  const validatedDestination = await preflightExtractDestination(conn, { destination, source })
  if ("status" in validatedDestination) return validatedDestination

  // R-0000067: validate every archive member before we hand the archive to
  // tar/unzip. Static member validation and marker-payload sizing intentionally
  // happen before destination creation so an invalid or oversized archive
  // cannot mutate the destination tree before it is rejected.
  const members = await validateMembersForExtraction(conn, {
    remoteSource,
    source,
  })
  if (!Array.isArray(members)) return members

  const markerPayloads = serializeArchiveMarkerPayloads({
    destination: validatedDestination.destination,
    members,
    owner: parameters.owner,
    source,
  })
  if ("status" in markerPayloads) return markerPayloads

  const destinationFailure = await createAndValidateExtractDestination(conn, {
    destination: validatedDestination.destination,
    source,
  })
  if (destinationFailure !== null) return destinationFailure

  // Issue #219: one batched probe covers the member guard paths, the host
  // paths that the archive's symlink targets pass through without the archive
  // shipping them, and the member paths whose host type the merge cannot merge
  // over (a directory where the archive has a non-directory, or the other way
  // round). A refusal here happens before the containment flag is written and
  // before anything is staged.
  const unsafeMemberPath = await validatePreStagingPaths(conn, {
    destination: validatedDestination.destination,
    members,
    source,
  })
  if (unsafeMemberPath !== null) return unsafeMemberPath

  // Issue #219: the containment flag, the pre-merge check of the combined host
  // and archive links, the staged merge and the whole-tree symlink containment
  // backstop all run before `finalizeExtraction`; see
  // `extractAndValidateSymlinkContainment`.
  const stagedFailure = await extractAndValidateSymlinkContainment(conn, {
    containmentFlag: parameters.containmentFlag,
    destination: validatedDestination.destination,
    members,
    remoteSource,
    source,
  })
  if (stagedFailure !== null) return stagedFailure

  return finalizeExtraction(conn, {
    ...parameters,
    destination: validatedDestination.destination,
    markerPayloads,
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

/**
 * Compare a declared `owner`/`owner:group` spec against `stat -c '%U %G %u %g'`
 * output through the shared ownership comparison, so an extracted member is
 * matched by name or by numeric id exactly like every other drift check.
 *
 * @param stdout - Raw stdout of the `stat -c '%U %G %u %g'` probe.
 * @param owner - The declared `owner` or `owner:group` spec.
 * @returns `true` when every declared component matches by name or by id.
 */
function ownerMatchesStat(stdout: string, owner: string): boolean {
  const [actualUser = "", actualGroup = "", actualUserId = "", actualGroupId = ""] = stdout
    .trim()
    .split(/\s+/v, ARCHIVE_STAT_OWNERSHIP_FIELDS)
  const [expectedUser = "", expectedGroup = ""] = owner.split(":", 2)
  return (
    ownershipComponentMatches(expectedUser, actualUser, actualUserId) &&
    ownershipComponentMatches(expectedGroup, actualGroup, actualGroupId)
  )
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
}

// Issue #180: `extractedMemberOwnerMatches` used to run two execs per path — an
// existence test and a `stat`. Both now happen inside the batched ownership
// probe; see `ownerMatchesPaths`.

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
  if (paths.kind === "valid") return ownerMatchesPaths(conn, { owner, paths: paths.paths })
  if (paths.kind === "invalid") return false

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
): Promise<MembersMarkerReadResult> {
  const markerResult = await conn.exec(
    `cat ${shellQuote(membersMarkerPath(marker))}`,
    ARCHIVE_CAPTURE_EXEC_OPTS
  )
  if (markerResult.code !== 0) return null
  if (
    markerResult.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    markerResult.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return "invalid"
  }
  try {
    const members: unknown = JSON.parse(markerResult.stdout)
    return Array.isArray(members) && members.every((member) => isExtractedArchiveMember(member))
      ? members
      : "invalid"
  } catch {
    return "invalid"
  }
}

/**
 * Map a recorded member kind onto the probe's single-letter code.
 *
 * The codes stand for exactly the checks the previous per-member commands ran:
 * `d` a directory that is not a symlink, `f` a regular file that is not a
 * symlink, `l` a symlink. A hardlink is recorded as a regular file, as before.
 *
 * @param kind - The recorded member kind.
 * @returns The probe kind code.
 */
function memberTypeProbeCode(kind: ExtractedArchiveMember["kind"]): string {
  switch (kind) {
    case "directory": {
      return "d"
    }
    case "file":
    case "hardlink": {
      return "f"
    }
    case "symlink": {
      return "l"
    }
  }
}

async function extractedMembersMatch(conn: SshConnection, marker: string): Promise<boolean> {
  const members = await readMembersMarker(conn, marker)
  if (members === null) return false
  if (members === "invalid") return false
  // Issue #180: one probe for every member instead of one exec per member. The
  // marker read stays a separate call so the marker format is not coupled to
  // the probe script for the sake of one saved round trip.
  const outcome = await runBatchedProbe(conn, {
    entries: members.map((member) =>
      encodeMemberTypeEntry(memberTypeProbeCode(member.kind), member.path)
    ),
    script: buildMemberTypeProbeScript(),
  })
  // A probe that could not run proves nothing, so it counts as drift and lets
  // apply heal the destination — never as a silent match.
  if (outcome.kind === "failed") return false
  return outcome.fields.length === 0
}

async function ownerMatchesPaths(
  conn: SshConnection,
  parameters: { owner: string; paths: string[] }
): Promise<boolean> {
  const { owner, paths } = parameters
  const [expectedUser = "", expectedGroup = ""] = owner.split(":", 2)
  const outcome = await runBatchedProbe(conn, {
    entries: paths,
    script: buildOwnershipProbeScript(expectedUser, expectedGroup),
  })
  if (outcome.kind === "failed") return false
  // The script only pre-filters; `ownerMatchesStat` remains the authority so
  // the name-or-numeric-id rule of `ownershipComponentMatches` lives in exactly
  // one place. Anything the script reported is re-decided here, and a path it
  // could not `stat` arrives with empty fields and therefore never matches.
  for (
    let index = 0;
    index + OWNERSHIP_PROBE_FIELD_COUNT <= outcome.fields.length;
    index += OWNERSHIP_PROBE_FIELD_COUNT
  ) {
    const [, user = "", group = "", userId = "", groupId = ""] = outcome.fields.slice(
      index,
      index + OWNERSHIP_PROBE_FIELD_COUNT
    )
    if (!ownerMatchesStat(`${user} ${group} ${userId} ${groupId}`, owner)) return false
  }
  return true
}

async function readOwnerPathsMarker(
  conn: SshConnection,
  marker: string
): Promise<OwnerPathsMarkerReadResult> {
  const markerResult = await conn.exec(`cat ${shellQuote(ownerPathsMarkerPath(marker))}`, {
    ...ARCHIVE_CAPTURE_EXEC_OPTS,
    env: { LC_ALL: "C" },
  })
  if (markerResult.code !== 0) {
    // R-0000276: previously a non-"no such file" stderr (e.g. permission
    // denied after a flag-dir mode drift, or a transient truncate race) raised
    // an exception that propagated past archiveOwnerMatches and aborted the
    // whole run. Such failures remain recoverable drift, but only a genuine
    // missing-file diagnostic may use the legacy live-archive fallback.
    return MISSING_OWNER_PATHS_MARKER_PATTERN.test(markerResult.stderr)
      ? { kind: "missing" }
      : { kind: "invalid" }
  }
  if (
    markerResult.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    markerResult.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return { kind: "invalid" }
  }
  try {
    const paths: unknown = JSON.parse(markerResult.stdout)
    return isStringArray(paths) ? { kind: "valid", paths } : { kind: "invalid" }
  } catch {
    return { kind: "invalid" }
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
    const containmentFlag = containmentFailureFlagPath(normalizedDestination)
    const upload = options?.upload === true
    const owner = options?.owner
    const parameters: ApplyParameters = {
      containmentFlag,
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

        // Issue #219: a containment flag means the last apply did not finish
        // successfully — it was refused, failed or is still running after the
        // flag was written before its merge; a marker from an earlier source
        // may still match, so the flag alone forces needs-apply until an apply
        // succeeds.
        const markerExists = await conn.test(
          markerWithoutContainmentFailureCommand(marker, containmentFlag)
        )
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
