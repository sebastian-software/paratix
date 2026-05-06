import { posix } from "node:path"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { mountOptionsMatch } from "./mountOptions.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const FSTAB_PATH = "/etc/fstab"
const FSTAB_MODE = "0644"
const MOUNT_PRESENT = "mount.present"
const WHITESPACE_PATTERN = /\s/v

/**
 * Reject mount paths that would be destructive or are obviously malformed.
 *
 * Mirrors `validateAbsentPath` in `file.ts`, but is stricter because mount
 * commands take a single positional path argument: an empty string, `/`, a
 * non-normalized path, or a path containing newline / carriage-return
 * characters could either target the wrong filesystem (e.g. `umount /`) or
 * smuggle additional shell tokens. Throws synchronously so misuse is caught
 * at module construction time, before any SSH activity.
 *
 * @param caller - The module name used in the error message (e.g.
 *   `"mount.absent"`).
 * @param path - The mountpoint path supplied by the caller.
 */
function validateMountPath(caller: string, path: string): void {
  if (path.length === 0) {
    throw new Error(`${caller}: mount path must not be empty`)
  }
  if (WHITESPACE_PATTERN.test(path)) {
    throw new Error(`${caller}: mount path is invalid: ${JSON.stringify(path)}`)
  }
  if (!posix.isAbsolute(path)) {
    throw new Error(`${caller}: mount path is invalid: ${JSON.stringify(path)}`)
  }
  if (path !== posix.normalize(path)) {
    throw new Error(`${caller}: mount path is invalid: ${path}`)
  }
  if (path === "/") {
    throw new Error(`${caller}: refusing to operate on destructive path: ${path}`)
  }
}

function validateFstabField(caller: string, fieldName: string, value: string): void {
  if (value.length === 0) {
    throw new Error(`${caller}: ${fieldName} fstab field must not be empty`)
  }
  if (fieldName === "src" && value.startsWith("-")) {
    throw new Error(`${caller}: ${fieldName} fstab field must not start with '-'`)
  }
  if (WHITESPACE_PATTERN.test(value)) {
    throw new Error(`${caller}: ${fieldName} fstab field must not contain whitespace`)
  }
}

/**
 * Build a single fstab line from the given mount parameters.
 *
 * @param entry - The mount entry fields.
 * @param entry.fstype - The filesystem type.
 * @param entry.opts - The mount options string.
 * @param entry.path - The mountpoint path.
 * @param entry.src - The device or virtual filesystem source.
 * @returns A formatted fstab line with dump and pass fields set to `0`.
 */
function buildFstabLine(entry: {
  fstype: string
  opts: string
  path: string
  src: string
}): string {
  return `${entry.src} ${entry.path} ${entry.fstype} ${entry.opts} 0 0`
}

/**
 * Check whether a given fstab line already exists in the fstab content.
 *
 * @param fstabContent - The full contents of `/etc/fstab`.
 * @param path - The mountpoint to search for.
 * @returns The matching fstab line, or `null` if no entry exists for this mountpoint.
 */
function findFstabEntry(fstabContent: string, path: string): null | string {
  const lines = fstabContent.split("\n")
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const fields = trimmed.split(/\s+/v)
    if (fields[1] === path) return trimmed
  }
  return null
}

/**
 * Replace or append a fstab entry for the given mountpoint.
 *
 * @param fstabContent - The current full contents of `/etc/fstab`.
 * @param path - The mountpoint to match against.
 * @param newLine - The new fstab line to insert or replace with.
 * @returns The updated fstab content.
 */
function upsertFstabEntry(fstabContent: string, path: string, newLine: string): string {
  const lines = fstabContent.split("\n")
  const index = lines.findIndex((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return false
    const fields = trimmed.split(/\s+/v)
    return fields[1] === path
  })

  if (index === -1) {
    while (lines.length > 0 && lines.at(-1)?.trim() === "") {
      lines.pop()
    }
    lines.push(newLine)
  } else {
    lines[index] = newLine
  }

  return `${lines.join("\n")}\n`
}

/**
 * Remove the fstab entry for the given mountpoint.
 *
 * @param fstabContent - The current full contents of `/etc/fstab`.
 * @param path - The mountpoint whose entry should be removed.
 * @returns The updated fstab content with the entry removed.
 */
function removeFstabEntry(fstabContent: string, path: string): string {
  const lines = fstabContent.split("\n")
  const result = lines.filter((line) => {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) return true
    const fields = trimmed.split(/\s+/v)
    return fields[1] !== path
  })
  return `${result.join("\n")}\n`
}

async function removePersistedMountIfPresent(ssh: SshConnection, path: string): Promise<boolean> {
  const fstabContent = await ssh.readFile(FSTAB_PATH)
  const entry = findFstabEntry(fstabContent, path)
  if (entry === null) return false
  const newContent = removeFstabEntry(fstabContent, path)
  await guardedWriteFile(ssh, {
    mode: FSTAB_MODE,
    newContent,
    originalContent: fstabContent,
    remotePath: FSTAB_PATH,
  })
  return true
}

type MountConvergenceParameters = {
  fstype: string
  live: LiveMount
  opts: string
  path: string
  src: string
}

/**
 * Converge a drifted live mount to the desired src / fstype / opts.
 *
 * When only the options drifted and the source / fstype match, run
 * `mount -o remount,<opts>` for a non-disruptive in-place adjustment. When
 * the source or fstype drifted, fall back to `umount` + a fresh `mount`
 * because remount cannot change those.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - Desired mount values plus the live snapshot.
 * @returns A failure `ModuleResult` when the convergence command failed,
 *   or `null` on success.
 */
async function applyMountConvergence(
  ssh: SshConnection,
  parameters: MountConvergenceParameters
): Promise<ModuleResult | null> {
  const { fstype, live, opts, path, src } = parameters
  const onlyOptionsDrifted = live.source === src && live.fstype === fstype

  if (onlyOptionsDrifted) {
    const remountResult = await ssh.exec(
      `mount -o remount,${shellQuote(opts)} -- ${shellQuote(src)} ${shellQuote(path)}`,
      EXEC_OPTS
    )
    if (remountResult.code === 0) return null
    return failedCommand(`[mount.present: ${path}] mount -o remount failed`, remountResult)
  }

  const umountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (umountResult.code !== 0) {
    return failedCommand(`[mount.present: ${path}] umount before remount failed`, umountResult)
  }
  const mountResult = await ssh.exec(
    `mount -t ${shellQuote(fstype)} -o ${shellQuote(opts)} -- ${shellQuote(src)} ${shellQuote(path)}`,
    EXEC_OPTS
  )
  if (mountResult.code !== 0) {
    const restoreCommand = `mount -t ${shellQuote(live.fstype)} -o ${shellQuote(live.options)} -- ${shellQuote(live.source)} ${shellQuote(path)}`
    const restoreResult = await ssh.exec(restoreCommand, EXEC_OPTS)
    if (restoreResult.code !== 0) {
      const replacementDetail = mountResult.stderr.trim() || mountResult.stdout.trim()
      const replacementSummary =
        replacementDetail.length > 0 ? `; replacement failure: ${replacementDetail}` : ""
      const message =
        `[mount.present: ${path}] mount after umount failed and ` +
        `restoring previous mount failed${replacementSummary}`
      return failedCommand(
        message,
        restoreResult
      )
    }
    return failedCommand(`[mount.present: ${path}] mount after umount failed`, mountResult)
  }
  return null
}

type EnsureLiveMountParameters = {
  fstype: string
  opts: string
  path: string
  src: string
}

/**
 * Ensure the live mount at `path` matches the desired source / fstype /
 * options. Mounts when nothing is mounted yet, remounts when only options
 * drifted, or unmounts and remounts when source / fstype drifted.
 *
 * @param ssh - Active SSH connection.
 * @param parameters - Desired mount values.
 * @returns A failure `ModuleResult` when a command failed, `true` when a
 *   change was applied, or `false` when the live mount already matched.
 */
async function ensureLiveMount(
  ssh: SshConnection,
  parameters: EnsureLiveMountParameters
): Promise<boolean | ModuleResult> {
  const { fstype, opts, path, src } = parameters
  const live = await readLiveMount(ssh, path)

  if (live == null) {
    const mountResult = await ssh.exec(
      `mount -t ${shellQuote(fstype)} -o ${shellQuote(opts)} -- ${shellQuote(src)} ${shellQuote(path)}`,
      EXEC_OPTS
    )
    if (mountResult.code !== 0) {
      return failedCommand(`[mount.present: ${path}] mount failed`, mountResult)
    }
    return true
  }

  if (liveMountMatchesDesired(live, { fstype, opts, src })) return false

  // R-0000049: live mount drifted — converge via remount or umount + mount.
  const failure = await applyMountConvergence(ssh, { fstype, live, opts, path, src })
  if (failure != null) return failure
  return true
}

async function unmountIfNeeded(ssh: SshConnection, path: string): Promise<boolean | ModuleResult> {
  const isMounted = await ssh.test(`findmnt --noheadings ${shellQuote(path)}`)
  if (!isMounted) return false

  const umountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (umountResult.code !== 0) {
    return failedCommand(`[mount.absent: ${path}] umount failed`, umountResult)
  }
  return true
}

/**
 * Ensure the fstab entry for a mount matches the desired line.
 * Reads, compares, and writes back only when a change is needed.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param path - The mountpoint to match against.
 * @param desiredLine - The expected fstab line.
 * @returns `true` if the fstab was updated, `false` if it already matched.
 */
async function ensureFstabEntry(
  ssh: SshConnection,
  path: string,
  desiredLine: string
): Promise<boolean> {
  const fstabContent = await ssh.readFile(FSTAB_PATH)
  const existingEntry = findFstabEntry(fstabContent, path)
  if (existingEntry === desiredLine) return false
  const newContent = upsertFstabEntry(fstabContent, path, desiredLine)
  await guardedWriteFile(ssh, {
    mode: FSTAB_MODE,
    newContent,
    originalContent: fstabContent,
    remotePath: FSTAB_PATH,
  })
  return true
}

type LiveMount = {
  fstype: string
  options: string
  source: string
}

/**
 * Read the live mount attributes for a mountpoint via
 * `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS`.
 *
 * @param ssh - Active SSH connection to the remote host.
 * @param path - The mountpoint to inspect.
 * @returns The live attributes when the path is mounted, or `null` when it
 *   is not mounted (findmnt exits non-zero).
 */
// findmnt --output SOURCE,FSTYPE,OPTIONS prints exactly three columns; the
// helper below uses this constant when validating that the parsed output
// has enough fields to populate every LiveMount property.
const LIVE_MOUNT_FIELD_COUNT = 3

async function readLiveMount(ssh: SshConnection, path: string): Promise<LiveMount | null> {
  const findmntResult = await ssh.exec(
    `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS ${shellQuote(path)}`,
    EXEC_OPTS
  )
  if (findmntResult.code !== 0) return null

  // findmnt prints SOURCE FSTYPE OPTIONS separated by whitespace.
  const fields = findmntResult.stdout.trim().split(/\s+/v)
  if (fields.length < LIVE_MOUNT_FIELD_COUNT) return null
  return {
    fstype: fields[1] ?? "",
    options: fields[2] ?? "",
    source: fields[0] ?? "",
  }
}

/**
 * Decide whether the live mount attributes match the desired source,
 * filesystem type, and options. The options string is compared as a
 * normalized comma-separated set so superficial ordering differences and
 * expanded defaults do not cause spurious drift.
 *
 * @param live - The live mount attributes parsed from findmnt.
 * @param desired - The desired source, fstype and opts.
 * @param desired.fstype - Desired filesystem type.
 * @param desired.opts - Desired mount options string (comma-separated).
 * @param desired.src - Desired mount source.
 * @returns `true` when source, fstype and options all match.
 */
function liveMountMatchesDesired(
  live: LiveMount,
  desired: { fstype: string; opts: string; src: string }
): boolean {
  if (live.source !== desired.src) return false
  if (live.fstype !== desired.fstype) return false
  return mountOptionsMatch(live.options, desired.opts)
}

/**
 * Modules for managing filesystem mounts and `/etc/fstab` entries on a remote host.
 */
export const mount = {
  /**
   * Ensure a mountpoint is not mounted. Optionally removes the `/etc/fstab` entry.
   *
   * The check phase verifies both whether the path is currently mounted and, when
   * `persist` is `true`, whether a corresponding fstab entry exists. The apply
   * phase always returns `"changed"` even if only one of the two conditions required
   * action.
   *
   * @param options - Configuration for unmounting.
   * @param options.path - The mountpoint to unmount.
   * @param options.persist - When `true` (default), also remove the fstab entry.
   * @returns A Module that ensures the mountpoint is absent.
   */
  absent(options: { path: string; persist?: boolean }): Module {
    const { path, persist = true } = options
    validateMountPath("mount.absent", path)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[mount.absent: ${path}] SSH connection is required`)

        let changed = false

        const unmountResult = await unmountIfNeeded(ssh, path)
        if (typeof unmountResult !== "boolean") {
          return unmountResult
        }
        if (unmountResult) {
          changed = true
        }

        if (persist && (await removePersistedMountIfPresent(ssh, path))) {
          changed = true
        }

        return { status: changed ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const isMounted = await ssh.test(`findmnt --noheadings ${shellQuote(path)}`)
        if (isMounted) return NEEDS_APPLY

        if (persist) {
          const fstabContent = await ssh.readFile(FSTAB_PATH)
          const entry = findFstabEntry(fstabContent, path)
          if (entry !== null) return NEEDS_APPLY
        }

        return "ok"
      },
      name: `mount.absent: ${path}`,
    }
  },

  /**
   * Ensure a filesystem is mounted at the given path. Creates the mountpoint
   * directory if it does not exist. Optionally persists the mount in `/etc/fstab`.
   *
   * The check phase verifies that the mountpoint is active (via `findmnt`), that
   * its live source / filesystem type / normalized options match the desired
   * values, and, when `persist` is `true`, that the fstab entry matches the
   * desired line exactly.
   *
   * @param options - Configuration for the mount.
   * @param options.fstype - The filesystem type (e.g. `"ext4"`, `"tmpfs"`, `"nfs"`).
   * @param options.opts - Mount options string (e.g. `"noexec,nosuid,nodev,size=512m"`).
   * @param options.path - The mountpoint path.
   * @param options.persist - When `true` (default), add or update the fstab entry.
   * @param options.src - The device or virtual filesystem source (e.g. `"tmpfs"`, `"/dev/sdb1"`).
   * @returns A Module that ensures the filesystem is mounted.
   */
  present(options: {
    fstype: string
    opts: string
    path: string
    persist?: boolean
    src: string
  }): Module {
    const { fstype, opts, path, persist = true, src } = options
    validateMountPath(MOUNT_PRESENT, path)
    validateFstabField(MOUNT_PRESENT, "src", src)
    validateFstabField(MOUNT_PRESENT, "fstype", fstype)
    validateFstabField(MOUNT_PRESENT, "opts", opts)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[mount.present: ${path}] SSH connection is required`)

        let changed = false

        const mkdirResult = await ssh.exec(`mkdir -p ${shellQuote(path)}`, EXEC_OPTS)
        if (mkdirResult.code !== 0) {
          return failedCommand(`[mount.present: ${path}] mkdir -p failed`, mkdirResult)
        }

        const liveResult = await ensureLiveMount(ssh, { fstype, opts, path, src })
        if (typeof liveResult !== "boolean") return liveResult
        if (liveResult) changed = true

        if (persist) {
          const desiredLine = buildFstabLine({ fstype, opts, path, src })
          if (await ensureFstabEntry(ssh, path, desiredLine)) changed = true
        }

        return { status: changed ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const live = await readLiveMount(ssh, path)
        if (live == null) return NEEDS_APPLY
        // R-0000049: compare the live source / fstype / options against
        // the desired values so a drifted mount triggers needs-apply.
        if (!liveMountMatchesDesired(live, { fstype, opts, src })) return NEEDS_APPLY

        if (persist) {
          const fstabContent = await ssh.readFile(FSTAB_PATH)
          const desiredLine = buildFstabLine({ fstype, opts, path, src })
          const existingEntry = findFstabEntry(fstabContent, path)
          if (existingEntry !== desiredLine) return NEEDS_APPLY
        }

        return "ok"
      },
      name: `mount.present: ${path}`,
    }
  },
}
