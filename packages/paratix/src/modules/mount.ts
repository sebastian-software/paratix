/* eslint-disable max-lines -- mount.present and mount.absent share fstab helpers and the mutex-locked persistence flow; splitting them further would scatter behaviour across modules */
import { posix } from "node:path"

import type { LiveMount } from "./mountTypes.js"

import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { withMutexLock } from "./moduleHelpers.js"
import { applyMountConvergence } from "./mountConvergence.js"
import { liveMountOptionsMatch } from "./mountOptions.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const FSTAB_PATH = "/etc/fstab"
const FSTAB_MODE = "0644"
// Lock identifier serializing read-modify-write on /etc/fstab across
// concurrent Paratix runs sharing this remote host.
const FSTAB_FILE_MUTEX = "etc-fstab-mutex"
const MOUNT_PRESENT = "mount.present"
const MOUNT_ABSENT = "mount.absent"
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

function buildMountPathSymlinkGuard(path: string): string {
  // R-0000596: probe the symlink with `[ -L "$current" ]` only. The previous
  // `[ -e "$current" ] && [ -L "$current" ]` short-circuited via `[ -e ]`
  // following symlinks, which returns false for dangling links and skipped
  // the `[ -L ]` check entirely. Using `[ -L ]` alone matches both live and
  // dangling symlinks without an exploitable TOCTOU gap.
  return [
    `mount_path=${shellQuote(path)}`,
    'current="$mount_path"',
    'while [ "$current" != "/" ]; do',
    'if [ -L "$current" ]; then',
    `printf '%s\\n' "mount path contains symlink: $current" >&2`,
    "exit 1",
    "fi",
    'current=$(dirname "$current")',
    "done",
  ].join("; ")
}

async function ensureNoMountPathSymlink(
  ssh: SshConnection,
  moduleName: string,
  path: string
): Promise<ModuleResult | null> {
  const result = await ssh.exec(buildMountPathSymlinkGuard(path), EXEC_OPTS)
  if (result.code === 0) return null
  return failedCommand(`[${moduleName}: ${path}] mount path symlink check failed`, result)
}

/**
 * R-0000224: re-resolve `path` via `readlink -f` after the symlink guard ran
 * and verify it matches the operator-supplied path. Catches the small TOCTOU
 * window where a privileged attacker could swap an ancestor for a symlink
 * between the guard and the mount/mkdir call. This is best-effort defense in
 * depth — full atomic isolation would require running mount in a private mount
 * namespace via `unshare --mount`, which Paratix deliberately does not do
 * because the operator uses these modules to converge the host's primary
 * namespace.
 *
 * Returns `null` on success; a failure ModuleResult when the resolved path no
 * longer matches the configured one (likely a TOCTOU swap or a previously
 * existing symlink that was overlooked by the per-component guard).
 *
 * @param ssh - The SSH connection.
 * @param moduleName - Module label for the error message (e.g. "mount.present").
 * @param path - The configured mountpoint path.
 * @returns A `failed` ModuleResult on mismatch, or `null` when the resolved path matches.
 */
async function ensureMountPathRealpathMatches(
  ssh: SshConnection,
  moduleName: string,
  path: string
): Promise<ModuleResult | null> {
  const result = await ssh.exec(
    `readlink -f -- ${shellQuote(path)} 2>/dev/null || printf '%s\\n' ${shellQuote(path)}`,
    EXEC_OPTS
  )
  // readlink may fail (path does not yet exist before mkdir) — that's fine,
  // there is nothing to verify in that case.
  if (result.code !== 0) return null
  const resolved = result.stdout.trim()
  if (resolved === "" || resolved === path) return null
  return failed(
    `[${moduleName}: ${path}] resolved path differs after symlink guard: ${resolved} (TOCTOU race?)`
  )
}

/**
 * R-0000755: build the shell snippet that creates one mountpoint component
 * while keeping the symlink-guard semantics from R-0000673. The previous
 * `mkdir -p` would silently follow an attacker-planted symlink at any
 * not-yet-existing ancestor of the mountpoint and create directories outside
 * the operator-supplied tree. Walking the path components top-down with this
 * snippet ensures every level is either a real existing directory or freshly
 * created with plain `mkdir` (no `-p`), and re-checks for symlinks both
 * before and after the create to close the TOCTOU window.
 *
 * Output contract:
 *   - exit 0 on success (component is now a real directory)
 *   - exit 1 with a stderr message when the component is or becomes a symlink
 *   - exit 1 with a stderr message when the component exists but is not a
 *     directory or when `mkdir` failed
 *
 * @param component - Absolute path of the component to ensure.
 * @returns The shell command string suitable for `ssh.exec`.
 */
function buildMountPathComponentMkdirCommand(component: string): string {
  const quoted = shellQuote(component)
  return (
    `if [ -L ${quoted} ]; then ` +
    `printf 'mount path component is symlink: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi; ` +
    `if [ ! -e ${quoted} ]; then ` +
    `mkdir -- ${quoted} || exit 1; ` +
    `if [ -L ${quoted} ]; then ` +
    `printf 'mount path component became symlink after mkdir: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi; ` +
    `elif [ ! -d ${quoted} ]; then ` +
    `printf 'mount path component exists but is not a directory: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi`
  )
}

/**
 * R-0000755: enumerate every path component of `mountPath`, top-down, so the
 * caller can `mkdir` each one through the symlink-guarded shell snippet.
 *
 * @param mountPath - Absolute mountpoint path (already normalized).
 * @returns The list of absolute path components from the topmost ancestor
 *   below `/` down to (and including) `mountPath`.
 */
function mountPathComponentsTopDown(mountPath: string): string[] {
  const components: string[] = []
  let current = mountPath
  const seen = new Set<string>()
  while (current !== "/" && current !== "." && !seen.has(current)) {
    seen.add(current)
    components.push(current)
    current = posix.dirname(current)
  }
  return components.reverse()
}

/**
 * Run the symlink guard, ensure the mountpoint directory exists by walking
 * its path components top-down with a per-step symlink recheck (R-0000755),
 * then re-verify the resolved path with {@link ensureMountPathRealpathMatches}.
 * Used by {@link mount.present.apply} so the pre-mount checks live in a
 * single helper and the apply body stays under the statement budget.
 *
 * @param ssh - The SSH connection.
 * @param path - The configured mountpoint path.
 * @returns A failure ModuleResult on any check failure, or `null` on success.
 */
async function preparePresentMountpoint(
  ssh: SshConnection,
  path: string
): Promise<ModuleResult | null> {
  const symlinkFailure = await ensureNoMountPathSymlink(ssh, MOUNT_PRESENT, path)
  if (symlinkFailure != null) return symlinkFailure

  // R-0000755: replace `mkdir -p` with a per-component top-down walk. The
  // previous single-call `mkdir -p` would happily follow an attacker-planted
  // symlink at any not-yet-existing ancestor and create directories outside
  // the operator-supplied tree (the same hazard fixed for `download.large`
  // ancestors in R-0000673). Walking explicitly with plain `mkdir` and a
  // `[ ! -L ]` recheck per component keeps the create within the mountpoint
  // tree and trips an early failure on a planted symlink.
  for (const component of mountPathComponentsTopDown(path)) {
    // eslint-disable-next-line no-await-in-loop -- component walk is sequential by nature
    const mkdirResult = await ssh.exec(buildMountPathComponentMkdirCommand(component), EXEC_OPTS)
    if (mkdirResult.code !== 0) {
      return failedCommand(`[${MOUNT_PRESENT}: ${path}] mkdir at ${component} failed`, mkdirResult)
    }
  }

  // R-0000224: after the per-component walk, re-resolve the path via
  // `readlink -f` and verify it still matches. Catches the TOCTOU window
  // between the per-component symlink guard above and the mount() syscall
  // below. This is best-effort defense in depth: a privileged attacker can
  // still race between this check and the mount call. The residual risk is
  // acceptable because mount.present is a privileged operator tool, not a
  // sandboxed primitive.
  return ensureMountPathRealpathMatches(ssh, MOUNT_PRESENT, path)
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

async function removePersistedMountIfPresent(
  ssh: SshConnection,
  path: string
): Promise<boolean | ModuleResult> {
  // R-0000169: serialize read-modify-write on /etc/fstab so concurrent
  // Paratix runs cannot lose competing fstab edits between the read and the
  // write step.
  // R-0000757: `withMutexLock` now returns a structured result, so the outer
  // try/catch is replaced with a `kind === "failed"` branch.
  const lockResult = await withMutexLock(ssh, {
    failureMessage: `[${MOUNT_ABSENT}: ${path}] failed to update ${FSTAB_PATH}`,
    lockName: FSTAB_FILE_MUTEX,
    async section() {
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
    },
  })
  return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
}

type EnsureLiveMountParameters = {
  fstype: string
  opts: string
  path: string
  src: string
}

type EnsureLiveMountResult = {
  changed: boolean
  previousLive: LiveMount | null
}

type UnmountIfNeededResult = {
  changed: boolean
  previousLive: LiveMount | null
}

function buildMountCommand(parameters: {
  fstype: string
  opts: string
  path: string
  src: string
}): string {
  return `mount -t ${shellQuote(parameters.fstype)} -o ${shellQuote(parameters.opts)} -- ${shellQuote(parameters.src)} ${shellQuote(parameters.path)}`
}

function appendLiveRollbackFailure(
  fstabFailure: ModuleResult,
  rollbackFailure: ModuleResult | null
): ModuleResult {
  if (rollbackFailure == null) return fstabFailure
  const fstabMessage = fstabFailure.error?.message ?? "failed to update /etc/fstab"
  const rollbackMessage =
    rollbackFailure.error?.message ?? "failed to roll back live mount after fstab update failure"
  return failed(`${fstabMessage}\n${rollbackMessage}`)
}

async function rollbackLiveMountAfterFstabFailure(
  ssh: SshConnection,
  path: string,
  previousLive: LiveMount | null
): Promise<ModuleResult | null> {
  const unmountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (unmountResult.code !== 0) {
    return failedCommand(
      `[${MOUNT_PRESENT}: ${path}] failed to roll back live mount after fstab update failure`,
      unmountResult
    )
  }

  if (previousLive == null) return null

  const restoreResult = await ssh.exec(
    buildMountCommand({
      fstype: previousLive.fstype,
      opts: previousLive.options,
      path,
      src: previousLive.source,
    }),
    EXEC_OPTS
  )
  return restoreResult.code === 0
    ? null
    : failedCommand(
        `[${MOUNT_PRESENT}: ${path}] failed to restore previous live mount after fstab update failure`,
        restoreResult
      )
}

async function restoreLiveMountAfterFstabFailure(
  ssh: SshConnection,
  path: string,
  previousLive: LiveMount
): Promise<ModuleResult | null> {
  const restoreResult = await ssh.exec(
    buildMountCommand({
      fstype: previousLive.fstype,
      opts: previousLive.options,
      path,
      src: previousLive.source,
    }),
    EXEC_OPTS
  )
  return restoreResult.code === 0
    ? null
    : failedCommand(
        `[${MOUNT_ABSENT}: ${path}] failed to restore live mount after fstab update failure`,
        restoreResult
      )
}

async function ensurePersistedMountAfterLiveChange(
  ssh: SshConnection,
  parameters: {
    desiredLine: string
    liveResult: EnsureLiveMountResult
    path: string
  }
): Promise<boolean | ModuleResult> {
  const fstabResult = await ensureFstabEntry(ssh, parameters.path, parameters.desiredLine)
  if (typeof fstabResult === "boolean") return fstabResult
  if (!parameters.liveResult.changed) return fstabResult

  const rollbackFailure = await rollbackLiveMountAfterFstabFailure(
    ssh,
    parameters.path,
    parameters.liveResult.previousLive
  )
  return appendLiveRollbackFailure(fstabResult, rollbackFailure)
}

async function removePersistedMountAfterLiveChange(
  ssh: SshConnection,
  path: string,
  unmountResult: UnmountIfNeededResult
): Promise<boolean | ModuleResult> {
  const fstabResult = await removePersistedMountIfPresent(ssh, path)
  if (typeof fstabResult === "boolean") return fstabResult

  const rollbackFailure =
    unmountResult.changed && unmountResult.previousLive != null
      ? await restoreLiveMountAfterFstabFailure(ssh, path, unmountResult.previousLive)
      : null
  return appendLiveRollbackFailure(fstabResult, rollbackFailure)
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
): Promise<EnsureLiveMountResult | ModuleResult> {
  const { fstype, opts, path, src } = parameters
  const live = await readLiveMount(ssh, path)

  if (live == null) {
    const mountResult = await ssh.exec(buildMountCommand({ fstype, opts, path, src }), EXEC_OPTS)
    if (mountResult.code !== 0) {
      return failedCommand(`[mount.present: ${path}] mount failed`, mountResult)
    }
    return { changed: true, previousLive: null }
  }

  if (liveMountMatchesDesired(live, { fstype, opts, src })) {
    return { changed: false, previousLive: live }
  }

  // R-0000049: live mount drifted — converge via remount or umount + mount.
  const failure = await applyMountConvergence(ssh, { fstype, live, opts, path, src })
  if (failure != null) return failure
  return { changed: true, previousLive: live }
}

async function unmountIfNeeded(
  ssh: SshConnection,
  path: string,
  snapshotLiveMount: boolean
): Promise<ModuleResult | UnmountIfNeededResult> {
  const isMounted = await ssh.test(`findmnt --noheadings ${shellQuote(path)}`)
  if (!isMounted) return { changed: false, previousLive: null }

  let previousLive: LiveMount | null = null
  if (snapshotLiveMount) {
    previousLive = await readLiveMount(ssh, path)
    if (previousLive == null) {
      return failed(`[${MOUNT_ABSENT}: ${path}] failed to snapshot live mount before unmount`)
    }
  }

  const umountResult = await ssh.exec(`umount ${shellQuote(path)}`, EXEC_OPTS)
  if (umountResult.code !== 0) {
    return failedCommand(`[mount.absent: ${path}] umount failed`, umountResult)
  }
  return { changed: true, previousLive }
}

/**
 * Ensure the fstab entry for a mount matches the desired line.
 * Reads, compares, and writes back only when a change is needed.
 *
 * @param ssh - The SSH connection to the remote host.
 * @param path - The mountpoint to match against.
 * @param desiredLine - The expected fstab line.
 * @returns `true` if the fstab was updated, `false` if it already matched,
 *   or a failed ModuleResult when the locked mutation failed.
 */
async function ensureFstabEntry(
  ssh: SshConnection,
  path: string,
  desiredLine: string
): Promise<boolean | ModuleResult> {
  // R-0000169: serialize read-modify-write on /etc/fstab so concurrent
  // Paratix runs cannot lose competing fstab edits between the read and the
  // write step.
  // R-0000757: `withMutexLock` now returns a structured result; the outer
  // try/catch is replaced by a `kind === "failed"` branch.
  const lockResult = await withMutexLock(ssh, {
    failureMessage: `[${MOUNT_PRESENT}: ${path}] failed to update ${FSTAB_PATH}`,
    lockName: FSTAB_FILE_MUTEX,
    async section() {
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
    },
  })
  return lockResult.kind === "ok" ? lockResult.value : lockResult.failure
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

function parseLiveMount(stdout: string): LiveMount | null {
  const fields = stdout.trim().split(/\s+/v)
  if (fields.length < LIVE_MOUNT_FIELD_COUNT) return null
  return {
    fstype: fields[1] ?? "",
    options: fields[2] ?? "",
    source: fields[0] ?? "",
  }
}

async function readLiveMount(ssh: SshConnection, path: string): Promise<LiveMount | null> {
  const findmntResult = await ssh.exec(
    `findmnt --noheadings --output SOURCE,FSTYPE,OPTIONS ${shellQuote(path)}`,
    EXEC_OPTS
  )
  if (findmntResult.code !== 0) return null

  // findmnt prints SOURCE FSTYPE OPTIONS separated by whitespace.
  return parseLiveMount(findmntResult.stdout)
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
  return liveMountOptionsMatch(live.options, desired.opts)
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
    validateMountPath(MOUNT_ABSENT, path)

    return {
      async apply(ssh: null | SshConnection): Promise<ModuleResult> {
        if (!ssh) return failed(`[mount.absent: ${path}] SSH connection is required`)

        const symlinkFailure = await ensureNoMountPathSymlink(ssh, MOUNT_ABSENT, path)
        if (symlinkFailure != null) return symlinkFailure
        // R-0000224: defense-in-depth realpath re-check between the guard and
        // the unmount/fstab mutation closes the most accessible TOCTOU window.
        const realpathFailure = await ensureMountPathRealpathMatches(ssh, MOUNT_ABSENT, path)
        if (realpathFailure != null) return realpathFailure

        const unmountResult = await unmountIfNeeded(ssh, path, persist)
        if ("status" in unmountResult) return unmountResult
        let changed = unmountResult.changed

        if (persist) {
          const fstabResult = await removePersistedMountAfterLiveChange(ssh, path, unmountResult)
          if (typeof fstabResult !== "boolean") return fstabResult
          changed ||= fstabResult
        }

        return { status: changed ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const symlinkGuard = await ssh.exec(buildMountPathSymlinkGuard(path), EXEC_OPTS)
        if (symlinkGuard.code !== 0) return NEEDS_APPLY
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

        const preFailure = await preparePresentMountpoint(ssh, path)
        if (preFailure != null) return preFailure

        let changed = false
        const liveResult = await ensureLiveMount(ssh, { fstype, opts, path, src })
        if ("status" in liveResult) return liveResult
        if (liveResult.changed) changed = true

        if (persist) {
          const desiredLine = buildFstabLine({ fstype, opts, path, src })
          const fstabResult = await ensurePersistedMountAfterLiveChange(ssh, {
            desiredLine,
            liveResult,
            path,
          })
          if (typeof fstabResult !== "boolean") {
            return fstabResult
          }
          if (fstabResult) changed = true
        }

        return { status: changed ? "changed" : "ok" }
      },
      async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!ssh) return NEEDS_APPLY

        const symlinkGuard = await ssh.exec(buildMountPathSymlinkGuard(path), EXEC_OPTS)
        if (symlinkGuard.code !== 0) return NEEDS_APPLY
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
