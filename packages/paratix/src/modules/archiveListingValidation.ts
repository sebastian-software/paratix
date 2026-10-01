/**
 * The archive listing validation that apply and check of `archive.extract` share: list the members,
 * judge every member on its own and then the links of the whole archive.
 */

import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { archiveLinkUnsafeReason } from "./archiveLinkValidation.js"
import {
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
} from "./archiveMemberValidation.js"

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
export async function validatedArchiveMembers(
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
