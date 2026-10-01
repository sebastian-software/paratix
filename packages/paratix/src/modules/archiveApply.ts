/**
 * The apply mode of `archive.extract`: resolve the source, validate destination and members,
 * establish the own containment entry, run the contained extraction, apply the owner and write the
 * markers, and finally clear the containment entries.
 */

import type { ModuleResult, SshConnection } from "../types.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import {
  extractAndValidateSymlinkContainment,
  NOTHING_PUBLISHED,
  recordAfterThrow,
} from "./archiveContainedExtraction.js"
import {
  clearContainmentEntries,
  recordContainmentFailure,
  recordContainmentFailureAfterThrow,
} from "./archiveContainmentEntries.js"
import {
  type ContainmentFlagRecord,
  type ContainmentLedger,
  establishContainmentEntry,
  newContainmentEntryName,
} from "./archiveContainmentFlag.js"
import {
  archiveMemberDestinationPaths,
  createExtractDestinationDirectory,
  destinationPathWithAncestors,
  validateExtractDestination,
  validateNoSymlinkPaths,
  validatePreStagingPaths,
  validateResolvedDestinationPath,
} from "./archiveDestinationValidation.js"
import { validatedArchiveMembers } from "./archiveListingValidation.js"
import {
  type ArchiveExtractParameters,
  type ArchiveMarkerPayloads,
  serializeArchiveMarkerPayloads,
  writeMarker,
  writeMembersMarker,
  writeOwnerPathsMarker,
} from "./archiveMarker.js"
import { encodeNulPayload } from "./archiveProbe.js"
import { containmentProgress, type ContainmentProgress } from "./archiveStagingMerge.js"
import { renderBatchedChownSymlinkCommand } from "./fileMetadataHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const

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

/**
 * Apply the owner and write the markers after a verified extraction.
 *
 * Issue #219: the containment entries are cleared by the caller afterwards,
 * so a failure here is recorded in the own entry like every other failed
 * apply.
 *
 * @param conn - The SSH connection.
 * @param parameters - The apply inputs with the validated members, the marker
 *   payloads and the remote archive path.
 * @returns A failure, or null when owner and markers are in place.
 */
async function finalizeExtraction(
  conn: SshConnection,
  parameters: {
    markerPayloads: ArchiveMarkerPayloads
    members: ArchiveMember[]
    remoteSource: string
  } & ArchiveExtractParameters
): Promise<ModuleResult | null> {
  const { destination, marker, markerPayloads, members, owner, remoteSource, source } = parameters

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
  return writeOwnerPathsMarker(conn, {
    content: markerPayloads.ownerPaths,
    marker,
  })
}

/** Issue #219: the inputs of {@link extractUnderContainmentEntry}. */
type EntryExtractionParameters = {
  /** What the establish exec read, and where the own entry is. */
  ledger: ContainmentLedger
  /** The serialized marker payloads. */
  markerPayloads: ArchiveMarkerPayloads
  /** The validated archive members. */
  members: ArchiveMember[]
  /** How far the apply got, for a thrown error. */
  progress: ContainmentProgress
  /** The remote archive path (uploaded or original). */
  remoteSource: string
} & ArchiveExtractParameters

/**
 * Issue #219: create and validate the destination, probe it, extract, verify
 * and finalize, with the own `in-progress` containment entry in place. Every
 * failure records its outcome in the own entry (see
 * {@link extractAndValidateSymlinkContainment}); a failure after the backstop
 * passed — owner, markers, the clear exec itself — records no links. Only a
 * fully successful apply removes the entries it read and its own.
 *
 * Every refusal here depends on host state (destination creation or
 * validation, the pre-staging probe, the pre-merge check, the merge, the
 * backstop) and leaves the own entry in place, so `check` reports needs-apply
 * even when a marker from an earlier source still matches.
 *
 * @param conn - The SSH connection.
 * @param parameters - The apply inputs with the validated destination.
 * @returns The module result.
 */
async function extractUnderContainmentEntry(
  conn: SshConnection,
  parameters: EntryExtractionParameters
): Promise<ModuleResult> {
  const { destination, ledger, members, progress, remoteSource, source } = parameters
  const fail = async (
    failure: ModuleResult,
    record: ContainmentFlagRecord
  ): Promise<ModuleResult> =>
    recordContainmentFailure(conn, { failure, ownEntry: ledger.ownEntry, record })

  const destinationFailure = await createAndValidateExtractDestination(conn, {
    destination,
    source,
  })
  if (destinationFailure !== null) return fail(destinationFailure, NOTHING_PUBLISHED)

  // Issue #219: one batched probe covers the member guard paths, the host
  // paths that the archive's symlink targets pass through without the archive
  // shipping them, and the member paths whose host type the merge cannot merge
  // over (a directory where the archive has a non-directory, or the other way
  // round). A refusal here happens before anything is staged; the own entry
  // stays and records that nothing was published.
  const unsafeMemberPath = await validatePreStagingPaths(conn, { destination, members, source })
  if (unsafeMemberPath !== null) return fail(unsafeMemberPath, NOTHING_PUBLISHED)

  // Issue #219: the pre-merge check of the combined host and archive links,
  // the staged merge and the post-merge symlink containment backstop all run
  // before `finalizeExtraction`; see `extractAndValidateSymlinkContainment`.
  const staged = await extractAndValidateSymlinkContainment(conn, {
    destination,
    ledger,
    members,
    progress,
    remoteSource,
    source,
  })
  if (staged.failure !== null) return fail(staged.failure, staged.record)
  progress.advance("verified")

  // Issue #219: only after the finalize steps is the apply fully successful.
  // A crash before the clear exec leaves the own entry in place, which keeps
  // `check` at needs-apply. The clear exec is the last command: it removes
  // only the entries this apply read and verified that are still unchanged,
  // then its own.
  const finalizeFailure =
    (await finalizeExtraction(conn, parameters)) ?? (await clearContainmentEntries(conn, ledger))
  if (finalizeFailure !== null) return fail(finalizeFailure, { links: [], state: "failed" })
  return { status: "changed" }
}

async function runExtraction(
  conn: SshConnection,
  parameters: ArchiveExtractParameters,
  remoteSource: string
): Promise<ModuleResult> {
  const { containment, destination, source } = parameters

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

  // Issue #219: read every containment entry and create the own
  // `in-progress` entry, in one exec, before the destination is created,
  // resolved or probed. The only host checks that ran before it — the symlink
  // preflight of the destination and its ancestors — are repeated by `check`
  // itself, so a refusal there needs no entry. Containment state that cannot
  // be read, or an own entry that cannot be created, refuses the apply here,
  // before anything else is written. An entry without a usable list of
  // offending links does not: the apply runs and its post-merge backstop
  // verifies the whole destination before that entry is removed.
  const ledger = await establishContainmentEntry(conn, {
    ownEntryName: newContainmentEntryName(),
    paths: containment,
    source,
  })
  if ("status" in ledger) return ledger

  const progress = containmentProgress()
  try {
    return await extractUnderContainmentEntry(conn, {
      ...parameters,
      destination: validatedDestination.destination,
      ledger,
      markerPayloads,
      members,
      progress,
      remoteSource,
    })
  } catch (error) {
    // Issue #219: best effort; the error is rethrown whatever the write does.
    await recordContainmentFailureAfterThrow(conn, ledger.ownEntry, recordAfterThrow(progress))
    throw error
  }
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
export async function applyExtract(
  conn: SshConnection,
  parameters: ArchiveExtractParameters
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
