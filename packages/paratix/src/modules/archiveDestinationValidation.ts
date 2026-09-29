import { posix as pathPosix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  archiveSymlinkTargetPrefixes,
  mergedArchiveSymlinks,
  type MergedSymlink,
  type MergedSymlinkViolation,
  mergedSymlinkViolations,
  type SymlinkWalkTarget,
} from "./archiveLinkValidation.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  type ArchiveMember,
  normalizeArchiveMemberPath,
} from "./archiveMemberValidation.js"
import {
  buildSymlinkContainmentProbeScript,
  buildSymlinkListingProbeScript,
  buildSymlinkProbeScript,
  runBatchedProbe,
} from "./archiveProbe.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

// R-0000672: control characters (\x00-\x1F) in extract destinations are
// rejected before any further validation. `moveExtractedContentsIntoDestination`
// transports the guard-paths list as a newline-separated string, so a literal
// `\n` in the destination would split that list and let a crafted invocation
// bypass the symlink probes that protect ancestor paths. NUL would terminate
// the path early when interpolated into a shell argument. Reject the full
// control-character range up front, mirroring `archiveMemberValidation.ts`.
/* eslint-disable-next-line regexp/no-control-character -- matching control characters is the explicit purpose of this guard */ /* oxlint-disable-next-line no-control-regex */
const EXTRACT_DESTINATION_CONTROL_CHARACTER_PATTERN = /[\x00-\x1F]/v

export function validateExtractDestination(
  destination: string
): { destination: string } | ModuleResult {
  if (EXTRACT_DESTINATION_CONTROL_CHARACTER_PATTERN.test(destination)) {
    return failed(
      `[archive.extract] destination must not contain control characters: ${JSON.stringify(destination)}`
    )
  }
  if (!destination.startsWith("/")) {
    return failed(`[archive.extract] destination must be an absolute path: ${destination}`)
  }
  const normalized = pathPosix.normalize(destination)
  if (normalized === "/") {
    return failed(`[archive.extract] refusing to extract to destructive destination /`)
  }
  return { destination: normalized }
}

function pathWithAncestors(path: string): string[] {
  const paths: string[] = []
  let current = pathPosix.normalize(path)
  while (current !== "/") {
    paths.push(current)
    current = pathPosix.dirname(current)
  }
  return paths.reverse()
}

// Issue #180: `pathIsSymlink` used to be one exec per path. The probe is now
// batched through `archiveProbe.ts`; see `validateNoSymlinkPaths`.

export function destinationPathWithAncestors(destination: string): string[] {
  return pathWithAncestors(destination)
}

function renderGuardedCreateDirectoryCommand(destination: string): string {
  const quotedDestination = shellQuote(destination)
  return [
    `if [ -L ${quotedDestination} ]; then`,
    `  printf '%s\\n' 'destination path is a symlink' >&2`,
    `  exit 1`,
    `fi`,
    `if [ -e ${quotedDestination} ] && [ ! -d ${quotedDestination} ]; then`,
    `  printf '%s\\n' 'destination path exists and is not a directory' >&2`,
    `  exit 1`,
    `fi`,
    `if [ ! -d ${quotedDestination} ]; then`,
    `  mkdir -- ${quotedDestination}`,
    `fi`,
  ].join("\n")
}

export async function createExtractDestinationDirectory(
  conn: SshConnection,
  destination: string
): Promise<ModuleResult | null> {
  for (const directory of destinationPathWithAncestors(destination)) {
    // eslint-disable-next-line no-await-in-loop -- parent directories must be created before children
    const result = await conn.exec(renderGuardedCreateDirectoryCommand(directory), EXEC_OPTS)
    if (result.code !== 0) {
      return failedCommand(
        `[archive.extract] failed to create destination directory ${destination}`,
        result
      )
    }
  }
  return null
}

function memberDestinationPath(destination: string, member: ArchiveMember): null | string {
  const memberPath = normalizeArchiveMemberPath(member.path)
  if (memberPath === null) return null
  if (memberPath === "") return destination
  return `${destination}/${memberPath}`
}

export function archiveMemberDestinationPaths(
  destination: string,
  members: ArchiveMember[]
): string[] {
  const paths = new Set<string>()
  for (const member of members) {
    const destinationPath = memberDestinationPath(destination, member)
    if (destinationPath !== null) paths.add(destinationPath)
  }
  return [...paths]
}

/**
 * Issue #219: list the destination paths that must not be symlinks while an
 * archive is extracted — every member path with all of its ancestors, except
 * the leaf path of an archive symlink member.
 *
 * The leaf used to be included, so an archive that ships symlinks tripped its
 * own guard: during the merge as soon as an earlier top-level entry had copied
 * the link, and on every later run because the link from the previous run was
 * still there. The merge replaces such a leaf with `cp --remove-destination`
 * and never writes through it. Ancestors of symlink members stay guarded, and
 * `archiveLinkUnsafeReason` rejects any member below an archive symlink, so no
 * guarded path can be reached through an omitted leaf.
 *
 * @param destination - The validated destination directory.
 * @param members - The validated archive members.
 * @returns The guarded absolute paths, including the destination and its ancestors.
 */
export function archiveMemberGuardPaths(destination: string, members: ArchiveMember[]): string[] {
  const paths = new Set<string>()
  for (const member of members) {
    const destinationPath = memberDestinationPath(destination, member)
    if (destinationPath === null) continue
    const chain = pathWithAncestors(destinationPath)
    const guarded = member.kind === "symlink" ? chain.slice(0, -1) : chain
    for (const path of guarded) paths.add(path)
  }
  return [...paths]
}

/**
 * Issue #219: map the non-member paths visited while resolving the archive's
 * symlink targets to absolute destination paths, each with the raw path of the
 * symlink member that visited it, for {@link validateNoSymlinkPaths}.
 *
 * @param destination - The validated destination directory.
 * @param members - The validated archive members.
 * @returns Absolute host path to the raw path of the symlink member.
 */
export function archiveSymlinkTargetProbePaths(
  destination: string,
  members: ArchiveMember[]
): Map<string, string> {
  const paths = new Map<string, string>()
  for (const prefix of archiveSymlinkTargetPrefixes(members)) {
    paths.set(`${destination}/${prefix.path}`, prefix.symlink)
  }
  return paths
}

function symlinkProbeViolation(
  unsafe: string,
  parameters: { linkTargets?: ReadonlyMap<string, string>; paths: string[] }
): string {
  const symlinkMember = parameters.paths.includes(unsafe)
    ? undefined
    : parameters.linkTargets?.get(unsafe)
  if (symlinkMember === undefined) return `destination path ${JSON.stringify(unsafe)} is a symlink`
  return `link target of member ${JSON.stringify(symlinkMember)} passes through existing host symlink ${JSON.stringify(unsafe)}`
}

/**
 * Refuse the extraction when any of the given host paths is a symlink, with
 * one batched probe.
 *
 * Issue #219: `linkTargets` adds the paths that archive symlink targets pass
 * through (see {@link archiveSymlinkTargetProbePaths}) to the same probe. A
 * hit there is reported against the symlink member it belongs to; a path in
 * `paths` keeps the plain destination-path message.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.linkTargets - Optional link-target paths mapped to their symlink member.
 * @param parameters.paths - Absolute destination paths that must not be symlinks.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when a probed path is a symlink or the probe failed, otherwise null.
 */
export async function validateNoSymlinkPaths(
  conn: SshConnection,
  parameters: { linkTargets?: ReadonlyMap<string, string>; paths: string[]; source: string }
): Promise<ModuleResult | null> {
  const paths = [...new Set([...parameters.paths, ...(parameters.linkTargets?.keys() ?? [])])]
  const outcome = await runBatchedProbe(conn, {
    entries: paths,
    script: buildSymlinkProbeScript(),
  })
  // A probe that could not run is not a clean result. Reporting it as a failure
  // keeps the guard fail-closed; treating the empty output of a crashed script
  // as "no symlinks" would silently disable it.
  if (outcome.kind === "failed") {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: symlink probe failed: ${outcome.detail}`
    )
  }
  if (outcome.fields.length === 0) return null
  const [unsafe] = outcome.fields
  return failed(
    `[archive.extract] refusing to extract ${parameters.source}: ${symlinkProbeViolation(unsafe, parameters)}`
  )
}

/**
 * Classify a raw host symlink target for the resolver.
 *
 * A relative target is walked from the link's parent. An absolute target equal
 * to or below the canonical destination restarts at the destination root; any
 * other absolute target counts as escaping, consistent with the post-merge
 * check's fail-closed stance on pre-existing links that point outside. The
 * prefix comparison is literal, so an absolute target that reaches the
 * destination through a non-canonical spelling is judged conservatively as
 * outside.
 *
 * @param destination - The validated, canonical destination directory.
 * @param target - The target exactly as `readlink` reported it.
 * @returns How the resolver walks the target: from the link's parent, from the
 *   destination root, or not at all because it lies outside.
 */
function hostSymlinkWalkTarget(destination: string, target: string): SymlinkWalkTarget {
  if (!target.startsWith("/")) return { anchor: "parent", path: target }
  if (target === destination) return { anchor: "root", path: "" }
  if (target.startsWith(`${destination}/`)) {
    return { anchor: "root", path: target.slice(destination.length + 1) }
  }
  return { anchor: "outside" }
}

/**
 * Turn the `(link, target)` pairs of the listing probe into host links keyed
 * by destination-relative path, or explain why the output cannot be trusted.
 *
 * @param destination - The validated, canonical destination directory.
 * @param fields - The decoded probe fields.
 * @returns The host links, or a reason the framing is broken.
 */
function hostSymlinksFromListing(
  destination: string,
  fields: readonly string[]
): Map<string, MergedSymlink> | string {
  // An odd field count means the pair framing broke somewhere; pairing the
  // rest anyway could attach a target to the wrong link.
  if (fields.length % 2 !== 0) {
    return `probe returned ${String(fields.length)} fields, expected (link, target) pairs`
  }
  const prefix = `${destination}/`
  const links = new Map<string, MergedSymlink>()
  for (let index = 0; index < fields.length; index += 2) {
    const link = fields[index]
    const stored = fields[index + 1]
    if (!link.startsWith(prefix) || link.length === prefix.length) {
      return `probe reported ${JSON.stringify(link)}, which is not below the destination`
    }
    links.set(link.slice(prefix.length), {
      stored,
      target: hostSymlinkWalkTarget(destination, stored),
    })
  }
  return links
}

/**
 * Refuse an extraction before the staging merge when the links already under
 * the destination and the links this archive ships would, together, resolve
 * outside the destination.
 *
 * Issue #219: whether a relative link stays inside depends on the links its
 * target passes through, and those can come from an earlier run. Run 1 may
 * ship `a/esc -> up/..` (inside while `a/up` is missing) and run 2
 * `a/up -> ..` (inside on its own); merged, `a/esc` resolves above the
 * destination. This check lists every existing symlink with its stored target
 * in one batched exec ({@link buildSymlinkListingProbeScript}), builds the
 * combined post-merge link set ({@link mergedArchiveSymlinks}) and resolves
 * every link of it with the archive resolver. A link that escapes or exceeds
 * the resolution limit refuses the extraction, so nothing is copied into the
 * destination. {@link validateSymlinkContainment} stays in place after the
 * merge as the backstop for host changes that land between this listing and
 * the merge.
 *
 * Host link paths and targets are split on `/` only, so spaces and newlines in
 * them are handled faithfully. A probe failure (including a `find` traversal
 * error or an unreadable link), a truncated capture and output that is not
 * made of `(link, target)` pairs below the destination all fail closed.
 *
 * @param conn - The SSH connection.
 * @param parameters - Check inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.members - The validated archive members.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when the merged links would escape or the check could not run, otherwise null.
 */
export async function validateMergedSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; members: readonly ArchiveMember[]; source: string }
): Promise<ModuleResult | null> {
  const { destination, members, source } = parameters
  const prefix = `[archive.extract] refusing to extract ${source}`
  // The listing grows with the number of links on the host (a `node_modules`
  // tree has many), not with violations, so it gets the archive capture cap
  // instead of the 1 MiB default. Truncation still fails closed.
  const outcome = await runBatchedProbe(conn, {
    entries: [destination],
    maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
    script: buildSymlinkListingProbeScript(),
  })
  if (outcome.kind === "failed") {
    return failed(`${prefix}: symlink listing before the merge failed: ${outcome.detail}`)
  }
  const hostLinks = hostSymlinksFromListing(destination, outcome.fields)
  if (typeof hostLinks === "string") {
    return failed(`${prefix}: symlink listing before the merge failed: ${hostLinks}`)
  }
  const merged = mergedArchiveSymlinks(hostLinks, members)
  const violations = mergedSymlinkViolations(merged)
  if (violations.length === 0) return null
  return failed(`${prefix}: ${mergedSymlinkRefusal({ destination, merged, violations })}`)
}

/**
 * Describe the first violation of the combined link set, naming the link by
 * absolute path with its stored target, plus how many more there are.
 *
 * @param parameters - Refusal inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.merged - The combined post-merge link set.
 * @param parameters.violations - The non-empty violations of `merged`.
 * @returns The refusal reason without the `[archive.extract]` prefix.
 */
function mergedSymlinkRefusal(parameters: {
  destination: string
  merged: ReadonlyMap<string, MergedSymlink>
  violations: readonly MergedSymlinkViolation[]
}): string {
  const { destination, merged, violations } = parameters
  const [{ key, kind }] = violations
  const linkPath = `${destination}/${key}`
  const link = `symlink ${JSON.stringify(linkPath)} -> ${JSON.stringify(merged.get(key)?.stored ?? "")}`
  const violation =
    kind === "escape"
      ? `${link} would resolve outside destination ${JSON.stringify(destination)}`
      : `${link} would exceed the symlink resolution limit`
  const more = violations.length - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return `${violation} once this archive is merged; existing symlinks under the destination are checked together with the archive's links before anything is copied${suffix}`
}

/**
 * Refuse to complete an extraction when any symlink below the destination
 * resolves outside it, with one batched probe over the whole tree.
 *
 * Issue #219: {@link validateMergedSymlinkContainment} already refuses an
 * escaping combination of host and archive links before the merge. This check
 * runs after the merge as the backstop: it covers every symlink under the
 * destination as it actually is, including links this archive did not ship
 * and links the host changed between the pre-merge listing and the merge. A
 * probe failure, an output that is not made of `(link, resolved)` pairs, or a
 * link that could not be resolved all fail closed.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.destination - The validated, canonical destination directory.
 * @param parameters.source - The archive source, for the failure message.
 * @returns A failure when a symlink escapes the destination or the check could not run, otherwise null.
 */
export async function validateSymlinkContainment(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const { destination, source } = parameters
  const prefix = `[archive.extract] refusing to complete extraction of ${source}`
  const outcome = await runBatchedProbe(conn, {
    entries: [destination],
    script: buildSymlinkContainmentProbeScript(),
  })
  if (outcome.kind === "failed") {
    return failed(`${prefix}: symlink containment check failed: ${outcome.detail}`)
  }
  const { fields } = outcome
  // An odd field count means the pair framing broke somewhere; pairing the
  // rest anyway could attach a resolved path to the wrong link.
  if (fields.length % 2 !== 0) {
    return failed(
      `${prefix}: symlink containment check failed: probe returned ${String(fields.length)} fields, expected (link, resolved) pairs`
    )
  }
  if (fields.length === 0) return null
  const [link, resolved] = fields
  const violation =
    resolved === ""
      ? `symlink ${JSON.stringify(link)} could not be resolved`
      : `symlink ${JSON.stringify(link)} resolves to ${JSON.stringify(resolved)}, outside destination ${JSON.stringify(destination)}`
  const more = fields.length / 2 - 1
  const suffix = more > 0 ? ` (and ${String(more)} more)` : ""
  return failed(
    `${prefix}: ${violation}; every symlink under the destination is checked after the merge, including links this archive did not ship${suffix}`
  )
}

export async function validateResolvedDestinationPath(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const resolved = await conn.exec(
    `readlink -f -- ${shellQuote(parameters.destination)}`,
    EXEC_OPTS
  )
  if (resolved.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to resolve destination path ${parameters.destination}`,
      resolved
    )
  }
  const resolvedPath = resolved.stdout.trim()
  if (resolvedPath === parameters.destination) return null
  return failed(
    `[archive.extract] refusing to extract ${parameters.source}: destination path ${JSON.stringify(parameters.destination)} resolves to ${JSON.stringify(resolvedPath)}`
  )
}

export async function validateExistingExtractDestination(
  conn: SshConnection,
  parameters: { destination: string; source: string }
): Promise<ModuleResult | null> {
  const validatedDestination = validateExtractDestination(parameters.destination)
  if ("status" in validatedDestination) return validatedDestination

  const destinationExists = await conn.exec(
    `[ -d ${shellQuote(validatedDestination.destination)} ] && [ ! -L ${shellQuote(validatedDestination.destination)} ]`,
    EXEC_OPTS
  )
  if (destinationExists.code !== 0) {
    return failed(
      `[archive.extract] destination path ${JSON.stringify(validatedDestination.destination)} is not an existing non-symlink directory`
    )
  }

  const unsafeDestinationAncestor = await validateNoSymlinkPaths(conn, {
    paths: destinationPathWithAncestors(validatedDestination.destination),
    source: parameters.source,
  })
  if (unsafeDestinationAncestor !== null) return unsafeDestinationAncestor

  return validateResolvedDestinationPath(conn, {
    destination: validatedDestination.destination,
    source: parameters.source,
  })
}
