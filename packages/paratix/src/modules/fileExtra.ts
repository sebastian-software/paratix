/* eslint-disable max-lines -- file extra modules are grouped for discoverability */
import { readFile } from "node:fs/promises"

import { environmentToMetaEntries } from "../meta.js"
import { failed, failedCommand } from "../moduleFailure.js"
import { shellQuote, validateMode } from "../ssh.js"
import {
  guardedWriteFile,
  type Module,
  type ModuleResult,
  NEEDS_APPLY,
  type SshConnection,
} from "../types.js"
import { hexHashesEqual, sha256String } from "./fileHelpers.js"
import { ownershipMatches, readOwnership, renderChownCommand } from "./fileMetadataHelpers.js"
import { assertValidGroupName, assertValidUserName } from "./posixNames.js"
import { isRegularFileWithoutSymlink, isSymlink } from "./remoteFileChecks.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/** Index where the file-type field starts in `stat -c '%s %a %U %G %F %Y'` output. */
const STAT_TYPE_START_INDEX = 4
const DEFAULT_FILE_WRITE_MODE = "0644"

async function concatFragments(fragments: string[]): Promise<string> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- paths from module config, not user input
  const contents = await Promise.all(fragments.map(async (f) => readFile(f, "utf8")))
  return contents.join("")
}

/**
 * R-0000527: surface fragment-read failures (ENOENT, EACCES, EISDIR, …) as a
 * failed module result instead of letting the raw `fs.readFile` rejection
 * propagate out of `assemble.apply` / `assemble.check`. The caller passes a
 * label describing the failing operation so the message identifies the
 * remote target without leaking secrets.
 *
 * @param remotePath - Remote destination path used to scope the message.
 * @param fragments - Local fragment paths to concatenate.
 * @returns Either the concatenated content or a failed {@link ModuleResult}.
 */
async function concatFragmentsSafely(
  remotePath: string,
  fragments: string[]
): Promise<{ content: string } | ModuleResult> {
  try {
    return { content: await concatFragments(fragments) }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[file.assemble: ${remotePath}] reading fragment failed: ${reason}`)
  }
}

function normalizeMode(mode: string): string {
  return mode.startsWith("0") ? mode : `0${mode}`
}

async function resolveWriteMode(
  ssh: SshConnection,
  remotePath: string,
  explicitMode?: string
): Promise<string> {
  if (explicitMode != null) return explicitMode
  const exists = await ssh.exists(remotePath)
  if (!exists) return DEFAULT_FILE_WRITE_MODE
  // R-0000558: route the stat call through ssh.exec with ignoreExitCode so a
  // race between the existence probe and the mode read (file unlinked,
  // EACCES, EIO, …) does not surface as a raw CommandError. Fall back to the
  // default write mode in that case, matching the "no existing file" branch.
  const result = await ssh.exec(`stat -c '%a' ${shellQuote(remotePath)}`, EXEC_OPTS)
  if (result.code !== 0) return DEFAULT_FILE_WRITE_MODE
  return normalizeMode(result.stdout.trim())
}

type BlockMarkers = { begin: string; end: string; full: string }
type ParsedManagedBlock =
  | { content: string; endIndex: number; startIndex: number; status: "present" }
  | { reason: string; status: "invalid" }
  | { status: "absent" }

function parseManagedBlock(text: string, markers: BlockMarkers): ParsedManagedBlock {
  const lines = text.split("\n")
  const beginIndexes: number[] = []
  const endIndexes: number[] = []
  for (const [index, line] of lines.entries()) {
    if (line.includes(markers.begin)) beginIndexes.push(index)
    if (line.includes(markers.end)) endIndexes.push(index)
  }

  if (beginIndexes.length === 0 && endIndexes.length === 0) return { status: "absent" }
  if (beginIndexes.length !== 1 || endIndexes.length !== 1) {
    return { reason: "expected exactly one begin marker and one end marker", status: "invalid" }
  }

  const [startIndex] = beginIndexes
  const [endIndex] = endIndexes
  if (startIndex >= endIndex) {
    return { reason: "begin marker must appear before end marker", status: "invalid" }
  }

  return {
    content: lines.slice(startIndex + 1, endIndex).join("\n"),
    endIndex,
    startIndex,
    status: "present",
  }
}

function replaceBlock(
  text: string,
  markers: BlockMarkers,
  parsedBlock: ParsedManagedBlock
): string {
  if (parsedBlock.status !== "present") return text
  const lines = text.split("\n")
  const result = [
    ...lines.slice(0, parsedBlock.startIndex),
    markers.full,
    ...lines.slice(parsedBlock.endIndex + 1),
  ]
  return result.join("\n")
}

async function applyBlockToExistingFile(parameters: {
  existing: string
  fullBlock: string
  markers: BlockMarkers
  remotePath: string
  resourceLabel: string
  ssh: SshConnection
}): Promise<ModuleResult | null> {
  const { existing, fullBlock, markers, remotePath, resourceLabel, ssh } = parameters
  const parsedBlock = parseManagedBlock(existing, markers)

  if (parsedBlock.status === "invalid") {
    return failed(`[file.block: ${resourceLabel}] invalid marker pair: ${parsedBlock.reason}`)
  }

  const newContent =
    parsedBlock.status === "present"
      ? replaceBlock(existing, markers, parsedBlock)
      : `${existing}${existing.endsWith("\n") ? "" : "\n"}${fullBlock}\n`
  await guardedWriteFile(ssh, {
    mode: await resolveWriteMode(ssh, remotePath),
    newContent,
    originalContent: existing,
    remotePath,
  })
  return null
}

/** Options for the {@link block} module. */
export type BlockOptions = {
  /** The desired content between the markers. */
  content: string
  /** Unique identifier for the managed block. Used in the marker comment lines. */
  name: string
  /** Comment prefix for the marker lines (default `"#"`). */
  prefix?: string
}

// R-0000268: chmod failures (read-only fs, EPERM after a SELinux
// relabel, immutable bits) must not bubble out of apply as an
// unguarded CommandError. Capture the exit code and return a
// failedCommand result so the runner can report stdout/stderr.
async function applyAssembleChmod(
  ssh: SshConnection,
  remotePath: string,
  mode: string
): Promise<ModuleResult | null> {
  validateMode(mode)
  const chmodResult = await ssh.exec(
    `chmod ${shellQuote(mode)} ${shellQuote(remotePath)}`,
    EXEC_OPTS
  )
  if (chmodResult.code !== 0) {
    return failedCommand(`[file.assemble: ${remotePath}] chmod failed`, chmodResult)
  }
  return null
}

async function applyAssembleChown(
  ssh: SshConnection,
  remotePath: string,
  owner: string
): Promise<ModuleResult | null> {
  const chownResult = await ssh.exec(renderChownCommand(owner, remotePath), EXEC_OPTS)
  if (chownResult.code !== 0) {
    return failedCommand(`[file.assemble: ${remotePath}] chown failed`, chownResult)
  }
  return null
}

// Symmetric symlink-guard with check() (which uses isRegularFileWithoutSymlink).
// Refuse to write through a symlink — would silently overwrite the link target
// with attacker-controlled content. Aligned with R-0000192 (compose) and R-0000134
// (apt.key).
//
// R-0000527: surface fragment read errors (ENOENT, EACCES, EISDIR, …)
// as a failed module result instead of letting the raw fs rejection
// bubble out of apply.
async function writeAssembledFragments(
  ssh: SshConnection,
  parameters: { fragments: string[]; mode?: string; remotePath: string }
): Promise<ModuleResult | null> {
  const { fragments, mode, remotePath } = parameters
  if (await isSymlink(ssh, remotePath)) {
    return failed(
      `[file.assemble: ${remotePath}] refuses to write through symlink — path must be a regular file`
    )
  }
  const concatResult = await concatFragmentsSafely(remotePath, fragments)
  if ("status" in concatResult) return concatResult
  await ssh.writeFile(remotePath, concatResult.content, {
    mode: await resolveWriteMode(ssh, remotePath, mode),
  })
  return null
}

async function finalizeAssembledFile(
  ssh: SshConnection,
  parameters: { options?: { mode?: string; owner?: string }; remotePath: string }
): Promise<ModuleResult> {
  const { options, remotePath } = parameters
  if (options?.mode != null) {
    const chmodFailure = await applyAssembleChmod(ssh, remotePath, options.mode)
    if (chmodFailure) return chmodFailure
  }
  if (options?.owner != null) {
    const chownFailure = await applyAssembleChown(ssh, remotePath, options.owner)
    if (chownFailure) return chownFailure
  }
  return { status: "changed" }
}

/**
 * Concatenate local fragment files and write the result to the remote host.
 * The file is only transferred when the remote SHA-256 differs from the
 * combined local fragments.
 *
 * @param remotePath - Destination path on the remote host.
 * @param fragments - Array of local file paths whose contents are concatenated.
 * @param options - Optional file attributes.
 * @param options.mode - Optional chmod mode string (e.g. `"0644"`).
 * @param options.owner - Optional chown owner string (e.g. `"www-data:www-data"`).
 * @returns A Module that assembles the fragments on the remote host.
 */
export function assemble(
  remotePath: string,
  fragments: string[],
  options?: { mode?: string; owner?: string }
): Module {
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[file.assemble: ${remotePath}] SSH connection is required`)
      const writeFailure = await writeAssembledFragments(ssh, {
        fragments,
        mode: options?.mode,
        remotePath,
      })
      if (writeFailure) return writeFailure
      return finalizeAssembledFile(ssh, { options, remotePath })
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) return NEEDS_APPLY

      // R-0000527: when a fragment cannot be read in check (ENOENT, EACCES,
      // …) we cannot compute the desired hash. Defer the failure to apply by
      // returning NEEDS_APPLY so apply surfaces the same condition as a
      // properly formatted failed module result.
      const concatResult = await concatFragmentsSafely(remotePath, fragments)
      if ("status" in concatResult) return NEEDS_APPLY
      const localHash = sha256String(concatResult.content)
      const remoteHash = await ssh.sha256(remotePath)
      if (!hexHashesEqual(remoteHash, localHash)) return NEEDS_APPLY

      // Mirror apply semantics: without an explicit mode, assemble preserves
      // the existing file mode instead of enforcing 0644.
      const metadataMatches = ownershipMatches(await readOwnership(ssh, remotePath), options)
      return metadataMatches ? "ok" : NEEDS_APPLY
    },
    name: `file.assemble: ${remotePath}`,
  }
}

/**
 * Ensure a managed block of text is present in a remote file.
 * The block is delimited by marker comments of the form
 * `<prefix> BEGIN paratix: <name>` / `<prefix> END paratix: <name>`.
 * If the markers are not yet present, the block is appended to the file.
 * If the markers already exist, the content between them is replaced in place.
 *
 * @param remotePath - Path to the file on the remote host.
 * @param options - Block configuration.
 * @param options.content - The desired content between the begin and end markers.
 * @param options.name - Unique identifier for the managed block, used in the marker lines.
 * @param options.prefix - Comment prefix for the marker lines (default `"#"`).
 * @returns A Module that ensures the block is present with the correct content.
 */
export function block(remotePath: string, options: BlockOptions): Module {
  const prefix = options.prefix ?? "#"
  const beginMarker = `${prefix} BEGIN paratix: ${options.name}`
  const endMarker = `${prefix} END paratix: ${options.name}`

  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh)
        return failed(`[file.block: ${remotePath} (${options.name})] SSH connection is required`)

      const fullBlock = `${beginMarker}\n${options.content}\n${endMarker}`
      const exists = await ssh.exists(remotePath)

      if (exists) {
        if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) {
          return failed(
            `[file.block: ${remotePath} (${options.name})] path must be a regular file and not a symlink`
          )
        }
        const existing = await ssh.readFile(remotePath)
        const markers: BlockMarkers = { begin: beginMarker, end: endMarker, full: fullBlock }
        const failure = await applyBlockToExistingFile({
          existing,
          fullBlock,
          markers,
          remotePath,
          resourceLabel: `${remotePath} (${options.name})`,
          ssh,
        })
        if (failure != null) return failure
      } else {
        // R-0000526: no separate isSymlink check is needed before this
        // writeFile. ssh.writeFile finalizes via finalizeRemoteTempFile which
        // evaluates a `[ ! -d ... ] && [ ! -L ... ]` guard at mv-time,
        // atomically refusing to replace a path that became a symlink between
        // the earlier `ssh.exists` probe and the actual rename. The TOCTOU
        // window is therefore closed at the SSH layer rather than by an
        // additional round-trip here.
        await ssh.writeFile(remotePath, `${fullBlock}\n`, {
          mode: await resolveWriteMode(ssh, remotePath),
        })
      }

      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      const exists = await ssh.exists(remotePath)
      if (!exists) return NEEDS_APPLY
      if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) return NEEDS_APPLY

      const hasBeginMarker = await ssh.test(
        `grep -qF ${shellQuote(beginMarker)} ${shellQuote(remotePath)}`
      )
      const hasEndMarker = await ssh.test(
        `grep -qF ${shellQuote(endMarker)} ${shellQuote(remotePath)}`
      )
      if (!hasBeginMarker && !hasEndMarker) return NEEDS_APPLY

      const fileContent = await ssh.readFile(remotePath)
      const parsedBlock = parseManagedBlock(fileContent, {
        begin: beginMarker,
        end: endMarker,
        full: `${beginMarker}\n${options.content}\n${endMarker}`,
      })
      return parsedBlock.status === "present" && parsedBlock.content === options.content
        ? "ok"
        : NEEDS_APPLY
    },
    name: `file.block: ${remotePath} (${options.name})`,
  }
}

/**
 * Read the current mode/owner/group triple from `stat -c '%a %U %G'`.
 *
 * @param ssh - The SSH connection.
 * @param remotePath - Path to the file or directory on the remote host.
 * @returns The trimmed `mode`, `owner`, `group` fields as parsed from stat.
 */
async function readPropertiesState(
  ssh: SshConnection,
  remotePath: string
): Promise<{ group: string; mode: string; owner: string }> {
  // R-0000558: route the stat call through ssh.exec with ignoreExitCode so a
  // transient stat failure (file removed between the symlink probe and the
  // metadata read, EACCES, EIO, …) does not propagate as a raw CommandError
  // out of check/apply. Empty fields make the subsequent drift-comparison
  // treat the file as needing re-apply, mirroring crontab/R-0000272.
  const result = await ssh.exec(`stat -c '%a %U %G' ${shellQuote(remotePath)}`, EXEC_OPTS)
  if (result.code !== 0) return { group: "", mode: "", owner: "" }
  const [mode = "", owner = "", group = ""] = result.stdout.trim().split(/\s+/v)
  return { group, mode, owner }
}

/**
 * Compare the current mode against the desired mode, treating `"0644"` and
 * `"644"` as equivalent (stat omits the leading zero).
 *
 * @param current - The mode reported by stat.
 * @param desired - The desired mode (with or without leading zeros).
 * @returns `true` when both modes match.
 */
function modeMatches(current: string, desired: string): boolean {
  return current === desired.replace(/^0+/v, "")
}

/** State observed by {@link applyOwnershipDrift}. */
type PropertiesState = { group: string; mode: string; owner: string }

/** Desired settings passed by the caller. */
type PropertiesOptions = { group?: string; mode?: string; owner?: string }

type DriftContext = {
  current: PropertiesState
  options: PropertiesOptions
  remotePath: string
  ssh: SshConnection
}

function assertValidPropertiesOptions(options: PropertiesOptions): void {
  if (options.mode != null) validateMode(options.mode)
  if (options.owner != null) assertValidUserName(options.owner)
  if (options.group != null) assertValidGroupName(options.group)
}

/** Result of a drift step: a failure result, "changed", or "unchanged". */
type DriftStepResult = boolean | ModuleResult

function isDriftFailure(result: DriftStepResult): result is ModuleResult {
  return typeof result !== "boolean"
}

/**
 * Apply mode drift via `chmod` only when the desired mode differs from the
 * current mode reported by stat. R-0000269: failures bubble up as a
 * failedCommand result instead of an unguarded CommandError.
 *
 * @param context - The drift context (ssh, remotePath, current, options).
 * @returns `true` if a `chmod` was issued, `false` if no change was needed,
 *   or a failed {@link ModuleResult} if `chmod` exited non-zero.
 */
async function applyModeDrift(context: DriftContext): Promise<DriftStepResult> {
  const { current, options, remotePath, ssh } = context
  if (options.mode == null || modeMatches(current.mode, options.mode)) return false
  const result = await ssh.exec(
    `chmod -- ${shellQuote(options.mode)} ${shellQuote(remotePath)}`,
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(`[file.properties: ${remotePath}] chmod failed`, result)
  }
  return true
}

/**
 * Issue a combined `chown owner:group` when both fields differ.
 *
 * @param context - The drift context.
 * @returns `true` if a combined `chown` was issued, `false` if no change was
 *   required, or a failed {@link ModuleResult} when `chown` exited non-zero.
 */
async function maybeApplyCombinedChown(context: DriftContext): Promise<DriftStepResult> {
  const { current, options, remotePath, ssh } = context
  const ownerNeedsUpdate = options.owner != null && current.owner !== options.owner
  const groupNeedsUpdate = options.group != null && current.group !== options.group
  if (!ownerNeedsUpdate || !groupNeedsUpdate || options.owner == null || options.group == null) {
    return false
  }
  const ownerGroup = `${options.owner}:${options.group}`
  const result = await ssh.exec(renderChownCommand(ownerGroup, remotePath), EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[file.properties: ${remotePath}] chown failed`, result)
  }
  return true
}

/**
 * Issue a `chown owner` when only the owner differs.
 *
 * @param context - The drift context.
 * @returns `true` if a single-field `chown` was issued, `false` if no change
 *   was required, or a failed {@link ModuleResult} when `chown` exited non-zero.
 */
async function maybeApplySingleChown(context: DriftContext): Promise<DriftStepResult> {
  const { current, options, remotePath, ssh } = context
  if (options.owner == null || current.owner === options.owner) return false
  const result = await ssh.exec(renderChownCommand(options.owner, remotePath), EXEC_OPTS)
  if (result.code !== 0) {
    return failedCommand(`[file.properties: ${remotePath}] chown failed`, result)
  }
  return true
}

/**
 * Issue a `chgrp group` when only the group differs.
 *
 * @param context - The drift context.
 * @returns `true` if a `chgrp` was issued, `false` if no change was required,
 *   or a failed {@link ModuleResult} when `chgrp` exited non-zero.
 */
async function maybeApplySingleChgrp(context: DriftContext): Promise<DriftStepResult> {
  const { current, options, remotePath, ssh } = context
  if (options.group == null || current.group === options.group) return false
  const result = await ssh.exec(
    `chgrp -- ${shellQuote(options.group)} ${shellQuote(remotePath)}`,
    EXEC_OPTS
  )
  if (result.code !== 0) {
    return failedCommand(`[file.properties: ${remotePath}] chgrp failed`, result)
  }
  return true
}

/**
 * Apply owner/group drift, combining `chown owner:group` when both differ and
 * falling back to individual `chown` / `chgrp` calls when only one differs.
 *
 * @param context - Current state, desired options, ssh handle, and remote path.
 * @returns `true` if any of `chown` / `chgrp` was issued, `false` if nothing
 *   changed, or a failed {@link ModuleResult} when any step exited non-zero.
 */
async function applyOwnershipDrift(context: DriftContext): Promise<DriftStepResult> {
  const combined = await maybeApplyCombinedChown(context)
  if (isDriftFailure(combined)) return combined
  if (combined) return true
  const ownerResult = await maybeApplySingleChown(context)
  if (isDriftFailure(ownerResult)) return ownerResult
  const groupResult = await maybeApplySingleChgrp(context)
  if (isDriftFailure(groupResult)) return groupResult
  return ownerResult || groupResult
}

/**
 * Set file or directory ownership and permissions on the remote host.
 * Only the attributes specified in `options` are checked and applied. Drift
 * is detected via `stat -c '%a %U %G'` so `apply` only invokes the relevant
 * `chmod`/`chown`/`chgrp` for fields that actually differ from the desired
 * state. When all desired fields already match, `apply` returns `status: "ok"`
 * instead of falsely reporting a change.
 *
 * @param remotePath - Path to the file or directory on the remote host.
 * @param options - Attributes to enforce.
 * @param options.group - Optional group name.
 * @param options.mode - Optional chmod mode string (e.g. `"0644"`).
 * @param options.owner - Optional owner name.
 * @returns A Module that ensures the properties match.
 */
export function properties(remotePath: string, options: PropertiesOptions): Module {
  assertValidPropertiesOptions(options)

  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[file.properties: ${remotePath}] SSH connection is required`)

      // R-0000133: chmod/chown/chgrp follow symlinks, so file.properties on a
      // symlinked path would silently rewrite mode and ownership of the link
      // target. Refuse the operation up-front before any mutation.
      if (await isSymlink(ssh, remotePath)) {
        return failed(
          `[file.properties: ${remotePath}] refuses to operate through symlink — chmod/chown/chgrp would follow the link`
        )
      }

      const current = await readPropertiesState(ssh, remotePath)
      const context: DriftContext = { current, options, remotePath, ssh }
      const modeResult = await applyModeDrift(context)
      if (isDriftFailure(modeResult)) return modeResult
      const ownershipResult = await applyOwnershipDrift(context)
      if (isDriftFailure(ownershipResult)) return ownershipResult
      const changed = modeResult || ownershipResult

      return { status: changed ? "changed" : "ok" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY
      // R-0000133: symlinks are never "ok" because apply will refuse to follow
      // them. Defer the failure to apply so the dedicated error surfaces.
      if (await isSymlink(ssh, remotePath)) return NEEDS_APPLY

      const { group, mode, owner } = await readPropertiesState(ssh, remotePath)

      if (options.mode != null && !modeMatches(mode, options.mode)) return NEEDS_APPLY
      if (options.owner != null && owner !== options.owner) return NEEDS_APPLY
      if (options.group != null && group !== options.group) return NEEDS_APPLY

      return "ok"
    },
    name: `file.properties: ${remotePath}`,
  }
}

/**
 * Replace all occurrences of a regex pattern in a remote file.
 * `check` reads the file, applies the same replacement that `apply` would
 * perform, and reports `needs-apply` only when the resulting content differs
 * from the current content. This makes the module idempotent for cases where
 * the replacement string still matches the pattern (e.g. pattern `"foo"` and
 * replacement `"foobar"`).
 * `apply` reads the file, performs the replacement in TypeScript and writes it back.
 *
 * @param remotePath - Path to the file on the remote host.
 * @param pattern - Extended regex pattern to match.
 * @param replacement - Replacement string.
 * @returns A Module that performs the substitution.
 */
export function replace(remotePath: string, pattern: string, replacement: string): Module {
  // R-0000564: `String.prototype.replaceAll` interprets `$1`, `$&`, `$$`
  // etc. inside the replacement string as substitution patterns. Callers
  // pass `replacement` as a literal substring and do not expect
  // backreference evaluation. Escape every `$` to `$$` so the value is
  // applied verbatim regardless of pattern captures.
  const literalReplacement = replacement.replaceAll("$", "$$$$")
  return {
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[file.replace: ${remotePath}] SSH connection is required`)
      if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) {
        return failed(`[file.replace: ${remotePath}] path must be a regular file and not a symlink`)
      }

      const content = await ssh.readFile(remotePath)
      // eslint-disable-next-line security/detect-non-literal-regexp -- pattern from module config, not user input
      const updated = content.replaceAll(new RegExp(pattern, "gu"), literalReplacement)
      // R-0000075: short-circuit when the regex produces no replacement so
      // apply does not flag the run as "changed" or issue an unnecessary
      // SFTP write. Mirrors the no-op return that R-0000002 / R-0000013 /
      // R-0000028 added to timer.applyPresent, ssh.knownHosts.absent and
      // file.properties.apply.
      if (updated === content) return { status: "ok" }
      await guardedWriteFile(ssh, {
        mode: await resolveWriteMode(ssh, remotePath),
        newContent: updated,
        originalContent: content,
        remotePath,
      })

      return { status: "changed" }
    },
    async check(ssh: null | SshConnection): Promise<"needs-apply" | "ok"> {
      if (!ssh) return NEEDS_APPLY

      const exists = await ssh.exists(remotePath)
      if (!exists) return NEEDS_APPLY
      if (!(await isRegularFileWithoutSymlink(ssh, remotePath))) return NEEDS_APPLY

      const content = await ssh.readFile(remotePath)
      // eslint-disable-next-line security/detect-non-literal-regexp -- pattern from module config, not user input
      const updated = content.replaceAll(new RegExp(pattern, "gu"), literalReplacement)
      return updated === content ? "ok" : NEEDS_APPLY
    },
    name: `file.replace: ${remotePath}`,
  }
}

/**
 * Read metadata about a remote file via `stat`.
 * This is a read-only module: `check` always reports `"needs-apply"` so the runner
 * invokes `apply`, which populates the result's `meta` map with the following keys:
 * - `file.stat.size` — file size in bytes
 * - `file.stat.mode` — octal permission bits (e.g. `"644"`)
 * - `file.stat.owner` — owning user name
 * - `file.stat.group` — owning group name
 * - `file.stat.type` — file type string (e.g. `"regular file"`, `"directory"`)
 * - `file.stat.mtime` — last modification time as a Unix timestamp string
 *
 * @param remotePath - Path to the file on the remote host.
 * @returns A Module that reads file metadata into `result.meta`.
 */
export function stat(remotePath: string): Module {
  return {
    _dryRunMetaProducer: true,
    async apply(ssh: null | SshConnection): Promise<ModuleResult> {
      if (!ssh) return failed(`[file.stat: ${remotePath}] SSH connection is required`)

      const raw = await ssh.output(`stat -c '%s %a %U %G %F %Y' ${shellQuote(remotePath)}`)
      const parts = raw.trim().split(/\s+/v)
      const [size, mode, owner, group] = parts
      const mtime = parts.at(-1)
      const type = parts.slice(STAT_TYPE_START_INDEX, -1).join(" ")

      return {
        meta: environmentToMetaEntries({
          "file.stat.group": group,
          "file.stat.mode": mode,
          "file.stat.mtime": mtime ?? "",
          "file.stat.owner": owner,
          "file.stat.size": size,
          "file.stat.type": type,
        }),
        status: "ok",
      }
    },
    // eslint-disable-next-line @typescript-eslint/require-await
    async check(): Promise<"needs-apply" | "ok"> {
      return NEEDS_APPLY
    },
    name: `file.stat: ${remotePath}`,
  }
}
