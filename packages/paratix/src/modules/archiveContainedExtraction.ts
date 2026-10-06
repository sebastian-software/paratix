/**
 * The containment phase of an `archive.extract` apply: the pre-merge link check, the staged
 * extraction, the post-merge backstop, and what a failure records in the apply's own containment
 * entry.
 */

import type { ModuleResult, SshConnection } from "../types.js"
import type { ContainmentLedger } from "./archiveContainmentEstablish.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { failed } from "../moduleFailure.js"
import {
  type ContainmentBackstopOutcome,
  runSymlinkContainmentBackstop,
} from "./archiveContainmentBackstop.js"
import { validateMergedSymlinkContainment } from "./archiveContainmentEnforcement.js"
import {
  type ContainmentFlagRecord,
  UNIDENTIFIED_OFFENDING_LINKS,
} from "./archiveContainmentFlag.js"
import { containmentPathsFor } from "./archiveMarker.js"
import {
  type ContainmentProgress,
  extractViaStagingDirectory,
  type StagedExtractionParameters,
} from "./archiveStagingMerge.js"

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
 * Issue #219: run the post-merge backstop and turn a thrown error into a
 * failure result, so the caller can still join it with the merge failure and
 * neither message is lost. A thrown backstop identified no offending links.
 *
 * @param conn - The SSH connection.
 * @param parameters - Backstop inputs.
 * @param parameters.destination - The validated destination directory.
 * @param parameters.members - Issue #219: the validated archive members; they
 *   decide which links the backstop judges.
 * @param parameters.recordedLinks - Issue #219: the links earlier failed
 *   applies recorded in their containment entries; the backstop re-verifies
 *   them.
 * @param parameters.source - The source archive path, for the failure message.
 * @param parameters.verifyWholeDestination - Issue #219: a containment entry
 *   held no usable list, so the backstop judges every symlink under the
 *   destination.
 * @returns The backstop failure (null when every judged symlink stays inside)
 *   and the offending link keys.
 */
async function runContainmentBackstop(
  conn: SshConnection,
  parameters: {
    destination: string
    members: ArchiveMember[]
    recordedLinks: readonly string[]
    source: string
    verifyWholeDestination: boolean
  }
): Promise<ContainmentBackstopOutcome> {
  const { destination, members, recordedLinks, source, verifyWholeDestination } = parameters
  try {
    return await runSymlinkContainmentBackstop(conn, {
      destination,
      entryDirectory: containmentPathsFor(destination).entryDirectory,
      legacyFlag: containmentPathsFor(destination).legacyFlag,
      members,
      recordedLinks,
      source,
      verifyWholeDestination,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return {
      failure: failed(
        `[archive.extract] refusing to complete extraction of ${source}: symlink containment check failed: ${reason}`
      ),
      offendingLinks: "unidentified",
    }
  }
}

/**
 * Issue #219: the record of a failed apply whose merge started, from the
 * offending links the backstop identified.
 *
 * @param offendingLinks - The backstop's offending link keys.
 * @returns A `failed` record with those links, or `unknown`.
 */
function recordAfterMerge(
  offendingLinks: ContainmentBackstopOutcome["offendingLinks"]
): ContainmentFlagRecord {
  return offendingLinks === "unidentified"
    ? { reason: UNIDENTIFIED_OFFENDING_LINKS, state: "unknown" }
    : { links: offendingLinks, state: "failed" }
}

/**
 * Issue #219: the outcome of {@link extractAndValidateSymlinkContainment}: its
 * failure, if any, and what a failure records in the own containment entry.
 */
type ContainedExtraction = { failure: ModuleResult | null; record: ContainmentFlagRecord }

/**
 * Issue #219: what a failure records when the apply's own merge published
 * nothing — before the merge, or after a throw before it. Entries of other
 * applies persist on their own, so nothing needs carrying: an empty `failed`
 * list only keeps `check` at needs-apply until an apply succeeds.
 */
export const NOTHING_PUBLISHED: ContainmentFlagRecord = { links: [], state: "failed" }

/**
 * Check the combined host and archive links, run the staged extraction and
 * then enforce that no symlink this archive can affect, and no symlink an
 * earlier failed apply recorded, resolves outside the destination — or, when
 * a containment entry held no usable list, no symlink under the destination
 * at all.
 *
 * Issue #219: the caller has already created its own `in-progress`
 * containment entry, before the destination was created or probed, and
 * records the returned `record` in it when this fails. A failure before the
 * merge started published nothing, so it records an empty `failed` list.
 * Once the merge started, it records the offending links the backstop
 * identified — carried links it judged fine drop out, carried links still
 * offending stay — or `unknown` when the backstop could not identify them.
 * Only after a successful return and the finalize steps does the caller
 * remove the entries.
 *
 * @param conn - The SSH connection.
 * @param parameters - Inputs for the staged extraction (see {@link extractViaStagingDirectory}).
 * @param parameters.ledger - What the establish exec read: the carried links
 *   and whether the whole destination has to be verified.
 * @param parameters.destination - The validated destination directory.
 * @param parameters.members - The validated archive members.
 * @param parameters.progress - Updated to `merge-started` right before the merge.
 * @param parameters.remoteSource - The remote archive path (uploaded or original).
 * @param parameters.source - The source archive path.
 * @returns The failure of the extraction, merge or containment backstop
 *   (null on success) and what it records.
 */
export async function extractAndValidateSymlinkContainment(
  conn: SshConnection,
  parameters: { ledger: ContainmentLedger } & StagedExtractionParameters
): Promise<ContainedExtraction> {
  const { ledger } = parameters
  // Issue #219: resolve the host's existing links together with this archive's
  // links before any staging directory exists. A refusal here runs no merge,
  // no chown and writes no marker; the own entry stays and records that
  // nothing was published.
  const unsafeMergedLinks = await validateMergedSymlinkContainment(conn, parameters)
  if (unsafeMergedLinks !== null) return { failure: unsafeMergedLinks, record: NOTHING_PUBLISHED }

  const staged = await extractViaStagingDirectory(conn, parameters)
  if (!staged.mergeStarted) return { failure: staged.failure, record: NOTHING_PUBLISHED }

  // Issue #219: links from separate runs can combine — a link that stayed
  // inside when it was written may resolve outside once a later archive places
  // a link on its path. `validateMergedSymlinkContainment` already refused such
  // a combination before the merge, from a listing of the host's links. This
  // enforcement after the merge is the backstop for host changes that landed
  // between that listing and the merge, and for a merge that failed half-way
  // after copying some entries: it runs whenever the merge started, judges the
  // archive's links and every link whose resolution passes through a path the
  // archive writes, reports every such escaping link and fails the run. An
  // archive without symlink members cannot change how a path resolves, so it
  // runs no exec there. It removes and changes nothing; the offending links
  // stay until they are cleaned up manually, and the own entry records them.
  // Issue #219: the backstop also re-verifies the links the entries of
  // earlier failed applies recorded, from the same listing; with recorded
  // links even an archive without symlink members runs that listing. When an
  // entry held no usable list, it judges every symlink that listing reports,
  // so a link an unfinished or unrecorded apply published anywhere under the
  // destination is found before that entry is removed.
  // The caller runs it before `finalizeExtraction`, so a refused extraction
  // performs no chown and writes no marker file, and the own entry stays and
  // records the offending links the backstop identified.
  // Staging has already been cleaned up here; a leftover staging directory
  // lies inside the destination, so its links resolve inside as well and need
  // no pruning.
  const backstop = await runContainmentBackstop(conn, {
    ...parameters,
    recordedLinks: ledger.carried,
    verifyWholeDestination: ledger.verifyWholeDestination,
  })
  return {
    failure: combineMergeFailures(staged.failure, backstop.failure),
    record: recordAfterMerge(backstop.offendingLinks),
  }
}

/**
 * Issue #219: what a thrown error records in the own entry, by how far the
 * apply got: an empty `failed` list before the merge (nothing was
 * published), `stopped` with the scope digest once the merge started (the
 * merge published at most what that scope covers, Issue #227), and no links
 * once the backstop passed. The merge-started case is written too, not left
 * to the `in-progress` body: a concurrent clean apply may have removed that
 * entry meanwhile (race 1), and only a write creates it again. The `stopped`
 * body differs from the `in-progress` one, so its hash changes, and a
 * concurrent apply that read the `in-progress` body keeps the rewritten entry
 * instead of removing it.
 *
 * @param progress - How far the apply got.
 * @param scopeDigest - The digest of the apply's containment scope.
 * @returns What to write into the own entry.
 */
export function recordAfterThrow(
  progress: ContainmentProgress,
  scopeDigest: string
): ContainmentFlagRecord {
  switch (progress.phase()) {
    case "before-merge": {
      return NOTHING_PUBLISHED
    }
    case "merge-started": {
      return { scope: scopeDigest, state: "stopped" }
    }
    case "verified": {
      return { links: [], state: "failed" }
    }
  }
}
