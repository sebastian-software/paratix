/**
 * The check mode of `archive.extract`: compare the destination, its containment state, the
 * extracted members, their owner and the archive hash with what the last successful apply recorded.
 */

import type { ContainmentPaths } from "./archiveContainmentFlag.js"

import { shellQuote } from "../ssh.js"
import { NEEDS_APPLY, type SshConnection } from "../types.js"
import { noContainmentEntriesCommand } from "./archiveContainmentEntries.js"
import {
  archiveMemberDestinationPaths,
  validateExistingExtractDestination,
} from "./archiveDestinationValidation.js"
import { validatedArchiveMembers } from "./archiveListingValidation.js"
import {
  type ArchiveExtractParameters,
  type ExtractedArchiveMember,
  readMembersMarker,
  readOwnerPathsMarker,
} from "./archiveMarker.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  encodeMemberTypeEntry,
  OWNERSHIP_PROBE_FIELD_COUNT,
  runBatchedProbe,
} from "./archiveProbe.js"
import { localSha256 } from "./fileHelpers.js"
import { ownershipComponentMatches } from "./fileMetadataHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
/** Columns emitted by the member ownership probe: `%U %G %u %g`. */
const ARCHIVE_STAT_OWNERSHIP_FIELDS = 4

/**
 * Issue #219: build the `check` test that the marker exists and no
 * containment entry is present. Folding both into one `test` exec keeps the
 * exec count of `check` unchanged. A dangling symlink at the old flag path or
 * as an entry counts as present, and an entry directory that is a symlink,
 * not a directory or unreadable fails the test, so only a genuinely absent
 * state lets `check` continue.
 *
 * @param marker - The marker file path.
 * @param paths - The destination's containment paths.
 * @returns The shell test command.
 */
function markerWithoutContainmentFailureCommand(marker: string, paths: ContainmentPaths): string {
  return `test -f ${shellQuote(marker)} && ${noContainmentEntriesCommand(paths)}`
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
 * Decide whether archive.extract must run on the remote host.
 *
 * Checks in order: the destination validates, the marker exists without any
 * containment entry, the extracted members and their types still match, the
 * owner matches, and finally the archive's SHA256 equals the marker content.
 * The first failing check returns `needs-apply`.
 *
 * @param conn - The SSH connection.
 * @param parameters - The extraction parameters.
 * @returns `ok` when the extraction is current, otherwise `needs-apply`.
 */
export async function checkExtract(
  conn: SshConnection,
  parameters: ArchiveExtractParameters
): Promise<"needs-apply" | "ok"> {
  const {
    containment,
    destination: normalizedDestination,
    marker,
    owner,
    source,
    upload,
  } = parameters

  const unsafeDestination = await validateExistingExtractDestination(conn, {
    destination: normalizedDestination,
    source,
  })
  if (unsafeDestination !== null) return NEEDS_APPLY

  // Issue #219: a containment entry (or the old flag file) means an
  // apply did not finish successfully — it was refused, failed or is
  // still running after it created its entry before its merge; a marker
  // from an earlier source may still match, so any entry alone forces
  // needs-apply until an apply of any source has re-verified the links
  // it records and succeeded. Only presence is tested here, not bodies.
  const markerExists = await conn.test(markerWithoutContainmentFailureCommand(marker, containment))
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
}
