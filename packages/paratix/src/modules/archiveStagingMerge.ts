/**
 * The execution of the `archive.extract` staging merge: allocate the staging directory under the
 * destination, extract into it, re-check the merge targets, run the bounded merge and clean up, and
 * track how far an apply got for its containment entry.
 */

import type { ModuleResult, SshConnection } from "../types.js"
import type { ArchiveMember } from "./archiveMemberValidation.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { maskRegisteredSecrets } from "../secretSink.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import {
  archiveMemberGuardPaths,
  destinationPathWithAncestors,
  validateNoSymlinkPaths,
  validateResolvedDestinationPath,
} from "./archiveDestinationValidation.js"
import {
  boundedStagingMergeCommand,
  buildStagingMergeExec,
  extractCommand,
  STAGING_MERGE_TIME_LIMITS,
  type StagingMergeParameters,
} from "./archiveStagingMergeScript.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const SILENT = { silent: true } as const

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

/** GNU `timeout` exits 124 when it stopped the command with `SIGTERM`. */
const TIMEOUT_EXIT_CODE = 124
/**
 * When the `-k` `SIGKILL` was needed, `timeout` signals its own process group
 * and dies with it, so the shell reports 128 + 9.
 */
const TIMEOUT_KILLED_EXIT_CODE = 137

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
 * Issue #219: the merge is bounded on the host by
 * {@link boundedStagingMergeCommand} and on the client by
 * {@link STAGING_MERGE_TIME_LIMITS}; a merge the host stopped is reported with
 * that reason. The guard paths travel on stdin, not as an argument (see
 * {@link buildStagingMergeExec}); the merge is still one exec.
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
  const { destination } = parameters
  // R-0000751: defense-in-depth — `[ -L "$target_path" ]` runs immediately
  // before the `cp -aT` so a symlink planted between the first probe and
  // the copy cannot smuggle the merge through to an attacker-controlled
  // location. Mirrors R-0000677's recheck-just-before-write pattern in
  // net.ts.
  // R-0000563: copy with `--no-dereference` so a symlink planted at any
  // ancestor of `target_path` between the guard checks above and the `cp`
  // invocation is preserved (and refused by the in-tree handling) instead
  // of being silently followed to an attacker-controlled location.
  const merge = buildStagingMergeExec(parameters)
  const copyResult = await conn.exec(boundedStagingMergeCommand(merge.command), {
    ...EXEC_OPTS,
    input: merge.input,
    timeout: STAGING_MERGE_TIME_LIMITS.clientTimeoutMs,
  })
  if (copyResult.code !== 0) {
    const stopped =
      copyResult.code === TIMEOUT_EXIT_CODE || copyResult.code === TIMEOUT_KILLED_EXIT_CODE
        ? `: the merge was stopped on the host after ${String(STAGING_MERGE_TIME_LIMITS.timeoutSeconds)} seconds`
        : ""
    return failedCommand(
      `[archive.extract] failed to copy extracted files into ${destination}${stopped}`,
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

/**
 * Issue #219: how far an apply got since it created its `in-progress`
 * containment entry, so a thrown error can still be recorded. Before the merge nothing
 * was published; once the merge started, only the backstop can tell what was;
 * once the backstop passed, only the finalize steps remain.
 */
type ContainmentPhase = "before-merge" | "merge-started" | "verified"

/** Issue #219: the phase of an apply, advanced as it goes. */
export type ContainmentProgress = {
  advance: (phase: ContainmentPhase) => void
  phase: () => ContainmentPhase
}

/**
 * Issue #219: track the phase of an apply, starting before the merge.
 *
 * @returns The tracker.
 */
export function containmentProgress(): ContainmentProgress {
  let current: ContainmentPhase = "before-merge"
  return {
    advance(phase) {
      current = phase
    },
    phase: () => current,
  }
}

/** Inputs of the staged extraction. */
export type StagedExtractionParameters = {
  /** The validated destination directory. */
  destination: string
  /** The validated archive members. */
  members: ArchiveMember[]
  /** Issue #219: updated to `merge-started` right before the merge runs. */
  progress: ContainmentProgress
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

  parameters.progress.advance("merge-started")
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
export async function extractViaStagingDirectory(
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
