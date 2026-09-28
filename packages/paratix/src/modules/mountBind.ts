import { posix } from "node:path"

import type { ModuleResult, SshConnection } from "../types.js"
import type { BindSource, LiveMount } from "./mountTypes.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { parseFindmntPairs } from "./mountProbe.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

const CONTAINING_MOUNT_COLUMNS = ["TARGET", "MAJ:MIN", "SOURCE", "FSROOT"] as const

export type BindSourceResolution =
  { failure: ModuleResult; kind: "failed" } | { kind: "resolved"; source: BindSource }

/**
 * Whether `child` lies strictly below `parent` (both absolute, normalized).
 *
 * @param parent - The ancestor candidate.
 * @param child - The descendant candidate.
 * @returns `true` when `child` is a proper descendant of `parent`.
 */
function isStrictlyBelow(parent: string, child: string): boolean {
  const relative = posix.relative(parent, child)
  if (relative === "" || posix.isAbsolute(relative)) return false
  return relative !== ".." && !relative.startsWith("../")
}

/**
 * Construction-time validation of a bind/rbind `src`. The source must be an
 * absolute, `posix.normalize`d path, and must not lie strictly below the
 * mountpoint: such a source would be hidden by the bind itself and the
 * desired identity could never converge. A self-bind (`src === path`) is
 * accepted; its check is deliberately degraded (see `mount.present`).
 *
 * @param caller - The module name used in the error message.
 * @param src - The configured bind source.
 * @param path - The configured mountpoint path.
 */
export function validateBindSource(caller: string, src: string, path: string): void {
  if (!posix.isAbsolute(src) || src !== posix.normalize(src)) {
    throw new Error(
      `${caller}: bind src must be an absolute, normalized path: ${JSON.stringify(src)}`
    )
  }
  if (isStrictlyBelow(path, src)) {
    throw new Error(`${caller}: bind src must not be below the mount path: ${src} is below ${path}`)
  }
}

/**
 * Build the read-only lookup of the mount that contains a resolved bind
 * source.
 *
 * @param resolved - The source path as resolved by `readlink -f`.
 * @returns The `findmnt` command string.
 */
export function buildContainingMountCommand(resolved: string): string {
  return `findmnt --noheadings --pairs --nofsroot --output ${CONTAINING_MOUNT_COLUMNS.join(",")} --target ${shellQuote(resolved)}`
}

/**
 * Compute the FSROOT a bind of `resolved` shows at its target: the FSROOT of
 * the containing mount joined with the path of `resolved` below that mount's
 * TARGET. Returns `null` when the lookup output is inconsistent.
 *
 * @param containing - The containing mount's TARGET and FSROOT.
 * @param containing.fsroot - FSROOT of the containing mount.
 * @param containing.target - TARGET of the containing mount.
 * @param resolved - The resolved source path.
 * @returns The desired FSROOT, or `null`.
 */
function desiredBindFsroot(
  containing: { fsroot: string; target: string },
  resolved: string
): null | string {
  if (!posix.isAbsolute(containing.fsroot) || !posix.isAbsolute(containing.target)) return null
  if (containing.target !== resolved && !isStrictlyBelow(containing.target, resolved)) return null
  return posix.join(containing.fsroot, posix.relative(containing.target, resolved))
}

async function readlinkBindSource(
  ssh: SshConnection,
  label: string,
  src: string
): Promise<BindSourceResolution | string> {
  const readlinkResult = await ssh.exec(`readlink -f -- ${shellQuote(src)}`, EXEC_OPTS)
  const resolved = readlinkResult.stdout.trim()
  if (readlinkResult.code !== 0 || resolved.length === 0) {
    return { failure: failed(`${label} bind source does not exist: ${src}`), kind: "failed" }
  }
  if (!posix.isAbsolute(resolved) || resolved.includes("\n")) {
    return {
      failure: failed(`${label} bind source could not be resolved: ${src} -> ${resolved}`),
      kind: "failed",
    }
  }
  return resolved
}

async function ensureBindSourceDirectory(
  ssh: SshConnection,
  label: string,
  parameters: { resolved: string; src: string }
): Promise<BindSourceResolution | null> {
  const { resolved, src } = parameters
  const directoryResult = await ssh.exec(`test -d ${shellQuote(resolved)}`, EXEC_OPTS)
  if (directoryResult.code === 0) return null
  const existsResult = await ssh.exec(`test -e ${shellQuote(resolved)}`, EXEC_OPTS)
  if (existsResult.code !== 0) {
    return { failure: failed(`${label} bind source does not exist: ${src}`), kind: "failed" }
  }
  return {
    failure: failed(
      `${label} bind source is not a directory: ${src} (bind sources must be directories)`
    ),
    kind: "failed",
  }
}

/**
 * Parse the containing-mount lookup into the desired bind identity.
 *
 * @param stdout - Output of {@link buildContainingMountCommand}.
 * @param resolved - The source path as resolved by `readlink -f`.
 * @returns The resolved bind source, or `null` for malformed output.
 */
function parseContainingMount(stdout: string, resolved: string): BindSource | null {
  const containing = parseFindmntPairs(stdout, CONTAINING_MOUNT_COLUMNS)?.at(-1)
  if (containing == null) return null
  const column = (name: (typeof CONTAINING_MOUNT_COLUMNS)[number]): string =>
    containing.get(name) ?? ""
  const majMin = column("MAJ:MIN")
  const fsroot = desiredBindFsroot({ fsroot: column("FSROOT"), target: column("TARGET") }, resolved)
  if (majMin.length === 0 || fsroot == null) return null
  return { fsroot, majMin, resolved, source: column("SOURCE") }
}

/**
 * Look up the mount that contains a resolved bind source and derive the
 * `MAJ:MIN` and FSROOT a bind of it shows at the target. With several lines
 * (unexpected for `--target`) the last one is used.
 *
 * @param ssh - Active SSH connection.
 * @param label - `[module: path]` prefix for failure messages.
 * @param parameters - The resolved and the configured source.
 * @param parameters.resolved - The source path as resolved by `readlink -f`.
 * @param parameters.src - The configured bind source (for messages).
 * @returns The resolved bind source, or a failure.
 */
async function lookupContainingMount(
  ssh: SshConnection,
  label: string,
  parameters: { resolved: string; src: string }
): Promise<BindSourceResolution> {
  const { resolved, src } = parameters
  const findmntResult = await ssh.exec(buildContainingMountCommand(resolved), EXEC_OPTS)
  if (findmntResult.code !== 0) {
    return {
      failure: failedCommand(
        `${label} findmnt failed while resolving bind source ${src}`,
        findmntResult
      ),
      kind: "failed",
    }
  }
  const source = parseContainingMount(findmntResult.stdout, resolved)
  if (source == null) {
    return {
      failure: failed(
        `${label} findmnt returned malformed output while resolving bind source ${src}`
      ),
      kind: "failed",
    }
  }
  return { kind: "resolved", source }
}

/**
 * Resolve the desired identity of a bind source with read-only commands
 * only: `readlink -f -- <src>`, `test -d` (plus `test -e` to tell a missing
 * source from a non-directory), and a `findmnt --target` lookup of the
 * containing mount. Check and apply both use it, and apply runs it before
 * probing or touching the live mount, so a missing or wrong source can never
 * leave the mountpoint empty.
 *
 * @param ssh - Active SSH connection.
 * @param moduleName - Module label for failure messages.
 * @param parameters - The mountpoint and the configured bind source.
 * @param parameters.path - The configured mountpoint path.
 * @param parameters.src - The configured bind source.
 * @returns The resolved bind source, or a failure naming the source.
 */
export async function resolveBindSource(
  ssh: SshConnection,
  moduleName: string,
  parameters: { path: string; src: string }
): Promise<BindSourceResolution> {
  const { path, src } = parameters
  const label = `[${moduleName}: ${path}]`
  const resolved = await readlinkBindSource(ssh, label, src)
  if (typeof resolved !== "string") return resolved
  if (isStrictlyBelow(path, resolved)) {
    return {
      failure: failed(
        `${label} bind source ${src} resolves to ${resolved}, which is below the mount path`
      ),
      kind: "failed",
    }
  }

  const directoryFailure = await ensureBindSourceDirectory(ssh, label, { resolved, src })
  if (directoryFailure != null) return directoryFailure

  return lookupContainingMount(ssh, label, { resolved, src })
}

/**
 * Decide whether the live top-most mount is the desired mount, ignoring
 * options. For a bind mount the identity is the live `MAJ:MIN` plus FSROOT
 * against the resolved source (SOURCE and fstype are ignored: SOURCE does not
 * identify tmpfs/overlay instances, and findmnt reports the backing fstype).
 * For any other mount it is SOURCE plus fstype, and the live FSROOT must be
 * `/` so a bind or subvolume at the path never counts as the desired mount.
 *
 * @param live - The live top-most mount.
 * @param desired - The desired mount identity inputs.
 * @param desired.bindSource - The resolved bind source, or `null` for a non-bind mount.
 * @param desired.fstype - Desired filesystem type.
 * @param desired.src - Desired mount source.
 * @returns `true` when the identity matches and only options may differ.
 */
export function liveMountIdentityMatches(
  live: LiveMount,
  desired: { bindSource: BindSource | null; fstype: string; src: string }
): boolean {
  if (desired.bindSource != null) {
    return live.majMin === desired.bindSource.majMin && live.fsroot === desired.bindSource.fsroot
  }
  return live.fsroot === "/" && live.source === desired.src && live.fstype === desired.fstype
}
