/* eslint-disable max-lines -- archive module keeps extraction and idempotency helpers together */
import { failed, failedCommand } from "../moduleFailure.js"
import { maskRegisteredSecrets } from "../secretSink.js"
import { shellQuote, validateMktempPath } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import { type Module, type ModuleResult, NEEDS_APPLY, type SshConnection } from "../types.js"
import {
  type ContainmentBackstopOutcome,
  runSymlinkContainmentBackstop,
} from "./archiveContainmentBackstop.js"
import { validateMergedSymlinkContainment } from "./archiveContainmentEnforcement.js"
import {
  clearContainmentEntries,
  type ContainmentFlagRecord,
  type ContainmentLedger,
  type ContainmentPaths,
  establishContainmentEntry,
  newContainmentEntryName,
  noContainmentEntriesCommand,
  recordContainmentFailure,
  recordContainmentFailureAfterThrow,
  STOPPED_AFTER_MERGE_STARTED,
  UNIDENTIFIED_OFFENDING_LINKS,
} from "./archiveContainmentFlag.js"
import {
  archiveMemberDestinationPaths,
  archiveMemberGuardPaths,
  createExtractDestinationDirectory,
  destinationPathWithAncestors,
  validateExistingExtractDestination,
  validateExtractDestination,
  validateNoSymlinkPaths,
  validatePreStagingPaths,
  validateResolvedDestinationPath,
} from "./archiveDestinationValidation.js"
import { archiveLinkUnsafeReason } from "./archiveLinkValidation.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  type ArchiveMember,
  archiveMemberUnsafeReason,
  listArchiveMembers,
  normalizeArchiveMemberPath,
} from "./archiveMemberValidation.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  encodeMemberTypeEntry,
  encodeNulPayload,
  OWNERSHIP_PROBE_FIELD_COUNT,
  runBatchedProbe,
} from "./archiveProbe.js"
import { localSha256, sha256String } from "./fileHelpers.js"
import {
  ownershipComponentMatches,
  renderBatchedChownSymlinkCommand,
} from "./fileMetadataHelpers.js"

const EXEC_OPTS = { ignoreExitCode: true, silent: true } as const
const ARCHIVE_CAPTURE_EXEC_OPTS = {
  ...EXEC_OPTS,
  maxOutputBytes: ARCHIVE_CAPTURE_LIMIT_BYTES,
} as const
const SILENT = { silent: true } as const
const FLAGS_DIR = "/var/lib/paratix/flags"
const ARCHIVE_MARKER_MODE = "0644"
/** Columns emitted by the member ownership probe: `%U %G %u %g`. */
const ARCHIVE_STAT_OWNERSHIP_FIELDS = 4
const MISSING_OWNER_PATHS_MARKER_PATTERN = /no such file or directory/iv

/**
 * Derive the marker file path from the source and destination paths.
 *
 * @param source - The source archive path used as part of the stable key.
 * @param destination - The extraction target path used as part of the stable key.
 * @returns The absolute path to the marker file.
 */
function markerPath(source: string, destination: string): string {
  const hash = sha256String(`${source}\n${destination}`)
  return `${FLAGS_DIR}/archive-${hash}.sha256`
}

/**
 * Issue #219: derive where the containment state of a destination lives.
 *
 * It is keyed by destination only, unlike the marker: an escaping link is a
 * property of the destination tree, so it must force `check` to report
 * needs-apply for every source that extracts there, including an earlier
 * source whose marker still matches after a rollback. Every apply owns one
 * entry in the entry directory `archive-containment-<sha256>.d`, whose body
 * records the offending links (see `archiveContainmentFlag.ts`); `check` only
 * tests whether any entry, or the single `.failed` flag file of older paratix
 * versions, exists.
 *
 * @param destination - The normalized extraction target path.
 * @returns The flags directory, the entry directory and the old flag file.
 */
function containmentPathsFor(destination: string): ContainmentPaths {
  const base = `${FLAGS_DIR}/archive-containment-${sha256String(destination)}`
  return { directory: FLAGS_DIR, entryDirectory: `${base}.d`, legacyFlag: `${base}.failed` }
}

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

function ownerPathsMarkerPath(marker: string): string {
  return `${marker}.owner-paths`
}

function membersMarkerPath(marker: string): string {
  return `${marker}.members`
}

type ExtractedArchiveMember = {
  kind: "directory" | "file" | "hardlink" | "symlink"
  path: string
}

type MembersMarkerReadResult = "invalid" | ExtractedArchiveMember[] | null

type ArchiveMarkerPayloads = {
  members: string
  ownerPaths: null | string
}

type OwnerPathsMarkerReadResult =
  { kind: "invalid" } | { kind: "missing" } | { kind: "valid"; paths: string[] }

/**
 * Build the extract command based on the file extension of the original source.
 *
 * @param source - The original archive path used for format detection.
 * @param archivePath - The actual archive path on the remote host.
 * @param destination - The target directory for extraction.
 * @returns The shell command to extract the archive, or null if unsupported.
 */
const TAR_HARDEN_FLAGS = "--no-same-owner --no-overwrite-dir"

function extractCommand(source: string, archivePath: string, destination: string): null | string {
  const lower = source.toLowerCase()
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) {
    return `tar ${TAR_HARDEN_FLAGS} -xzf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar.bz2")) {
    return `tar ${TAR_HARDEN_FLAGS} -xjf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar.xz")) {
    return `tar ${TAR_HARDEN_FLAGS} -xJf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".tar")) {
    return `tar ${TAR_HARDEN_FLAGS} -xf ${shellQuote(archivePath)} -C ${shellQuote(destination)}`
  }
  if (lower.endsWith(".zip")) {
    return `unzip -o ${shellQuote(archivePath)} -d ${shellQuote(destination)}`
  }
  return null
}

// R-0000106: prefix used by `mktemp` for archive uploads. Reused for both
// the template and the post-mktemp path validation so a locale-induced
// warning, multi-line stdout or a tampered `mktemp` cannot smuggle an
// unexpected path into the subsequent uploadFile / extract / rm pipeline.
const ARCHIVE_UPLOAD_PREFIX = "paratix-upload"
const ARCHIVE_UPLOAD_DIRECTORY = "/tmp"

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

/**
 * Build the `sh -c` snippet that merges one batch of staging entries into the
 * destination.
 *
 * The script reads `destination`, `expected_destination` and `guard_file` from
 * `$1`–`$3` and the staging entries from the remaining positional arguments, so
 * it is free of interpolated paths and can be executed verbatim against a real
 * `/bin/sh` in a test. Issue #178 showed why that matters: a guard that reads
 * correctly can still be inert at run time, and only executing it proves
 * otherwise.
 *
 * Issue #219: `guard_file` names a file holding the guard paths, each
 * terminated by a NUL byte, as {@link buildStagingMergeExec} writes it on the
 * host. Before every staged entry is copied, the script re-reads the file with
 * `xargs -0` and refuses the merge (exit 64) when any guard path is a symlink
 * or the check itself fails. An empty file checks nothing and passes.
 *
 * @returns The merge script as a single shell command string.
 */
export function buildStagingMergeScript(): string {
  // R-0000801: the staging merge inspects unsafe attacker-controlled paths
  // emitted by the archive. We assemble the shell snippet as String.raw
  // segments so the embedded quoting is readable, and we reject any
  // extracted path that contains a literal newline before `cp` ever
  // touches it. Newlines in extracted filenames are extremely unusual and
  // would otherwise corrupt the `printf | while read` loop that processes
  // `guard_paths`.
  // Issue #219: the guard paths no longer travel as one newline-separated
  // argument but NUL-terminated in a file (see `buildStagingMergeExec`), so
  // that loop is gone. The newline refusal for staged entries stays: it costs
  // nothing, and a newline in an extracted name would still garble the
  // refusal messages that quote it.
  // R-0000801 addendum: capture the newline via a sacrificial `x` that is
  // stripped afterwards. A bare `$(printf '\n')` is useless as a guard —
  // command substitution strips *all* trailing newlines, so it expands to the
  // empty string, the pattern degrades from `*"\n"*` to `*""*` (i.e. `*`) and
  // the guard refuses every path. Appending `x` gives the substitution a
  // non-newline byte to keep, and `${nl%x}` removes it again.
  return [
    // Not `String.raw`: that suppresses escape processing but not `${…}`
    // interpolation, so a raw literal would evaluate `nl % x` in JavaScript.
    // `$\{` is the same escape the `target_path` line below uses to emit a
    // literal shell parameter expansion from a template literal.
    `nl=$(printf '\\nx'); nl=$\{nl%x}; `,
    String.raw`destination=$1; expected_destination=$2; guard_file=$3; shift 3; `,
    String.raw`for source_path do `,
    String.raw`case "$source_path" in *"$nl"*) `,
    String.raw`echo "[archive.extract] refusing staging merge: extracted path contains a newline" >&2; `,
    String.raw`exit 64;; esac; `,
    String.raw`resolved_destination=$(readlink -f -- "$destination") || { `,
    String.raw`echo "[archive.extract] failed to resolve destination path $destination before staging merge" >&2; `,
    String.raw`exit 64; }; `,
    String.raw`if [ "$resolved_destination" != "$expected_destination" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $destination resolves to $resolved_destination" >&2; `,
    String.raw`exit 64; fi; `,
    // Issue #219: the guard check runs again for every staged entry, right
    // before its `cp`. `xargs -0` splits the file only at NUL bytes and
    // batches the paths below the host's argument limits, however many there
    // are. A batch exits 1 on its first symlink, so `xargs` exits non-zero
    // (123 with GNU `xargs`) after the remaining batches; any non-zero `xargs`
    // status, including a missing or unreadable guard file, refuses the merge.
    String.raw`xargs -0 sh -c 'for guarded_path do if [ -L "$guarded_path" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $guarded_path is a symlink" >&2; `,
    String.raw`exit 1; fi; done' sh < "$guard_file" || { `,
    String.raw`echo "[archive.extract] refusing staging merge: the guard path check failed" >&2; `,
    String.raw`exit 64; }; `,
    `target_path="$destination/$\{source_path##*/}"; `,
    // Issue #219: a destination symlink may only be replaced by a staged
    // symlink. Refusing it unconditionally failed every later run of an
    // archive with a top-level symlink, because that link from the previous
    // run was still in place. `cp -aT --no-dereference --remove-destination`
    // removes the old link and never writes through it; a symlink where the
    // archive has a directory or file is still refused.
    String.raw`if [ -L "$target_path" ] && [ ! -L "$source_path" ]; then `,
    String.raw`echo "[archive.extract] refusing staging merge: destination path $target_path is a symlink" >&2; `,
    String.raw`exit 64; fi; `,
    String.raw`cp -aT --no-dereference --remove-destination "$source_path" "$target_path" || exit $?; `,
    String.raw`done`,
  ].join("")
}

/**
 * Issue #219: the outer `sh -c` script of the staging merge exec. It stores
 * the NUL-terminated guard paths from stdin in a private temporary file and
 * runs the merge with that file as `$3` of {@link buildStagingMergeScript}.
 *
 * Positional parameters: `$1` staging directory, `$2` merge script, `$3`
 * destination, `$4` expected number of guard paths. The count check refuses a
 * truncated stdin, which would otherwise silently drop guard paths.
 *
 * The file comes from `mktemp` (mode 0600, owned by the merge user, i.e. root
 * under sudo) below `$TMPDIR` or `/tmp`. The `EXIT` trap removes it on every
 * exit the shell sees, and the `HUP`/`INT`/`TERM` traps turn those signals
 * into such an exit — including the `SIGTERM` of the host timeout. Only a
 * `SIGKILL` (the timeout's kill-after stage) leaves the file behind: a
 * harmless root-owned list of destination paths that the next run does not
 * read. `find` is not the last command (`; exit $?`), so the shell cannot
 * `exec` it and skip the trap.
 *
 * Issue #219: a signal sent to the merge shell alone takes effect only after
 * the running foreground command (normally `find`) returns, because a shell
 * runs a trap only once the foreground command it waits for has completed.
 * The process-group signal of the host timeout also reaches `find` and its
 * `sh -c`/`cp` children, so there the traps run promptly. `find` deliberately
 * stays in the foreground instead of `find … & wait`: as an asynchronous
 * command of a non-interactive shell it would start with `SIGINT` and
 * `SIGQUIT` ignored, so an `INT` to the process group would no longer stop it
 * or its children, and once the shell had exited, the timeout would see its
 * child gone and stop signalling the group, leaving `find` copying unbounded.
 */
const STAGING_MERGE_GUARD_FILE_SCRIPT = [
  String.raw`guard_file=; `,
  String.raw`trap '[ -z "$guard_file" ] || rm -f -- "$guard_file"' EXIT; `,
  String.raw`trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; `,
  // Not `String.raw`: `$\{` emits a literal shell parameter expansion.
  `guard_file=$(mktemp "$\{TMPDIR:-/tmp}/paratix-merge-guards.XXXXXXXX") && [ -f "$guard_file" ] || { `,
  String.raw`echo "[archive.extract] refusing staging merge: failed to create the guard path file" >&2; `,
  String.raw`exit 64; }; `,
  String.raw`cat > "$guard_file" || { `,
  String.raw`echo "[archive.extract] refusing staging merge: failed to store the guard paths" >&2; `,
  String.raw`exit 64; }; `,
  String.raw`guard_count=$(LC_ALL=C tr -cd '\000' < "$guard_file" | wc -c | tr -d ' '); `,
  String.raw`[ "$guard_count" = "$4" ] || { `,
  String.raw`echo "[archive.extract] refusing staging merge: received $guard_count of $4 guard paths" >&2; `,
  String.raw`exit 64; }; `,
  String.raw`find "$1" -mindepth 1 -maxdepth 1 -exec sh -c "$2" sh "$3" "$3" "$guard_file" {} +; `,
  String.raw`exit $?`,
].join("")

/** Issue #219: staging merge inputs. */
export type StagingMergeParameters = {
  /** The final destination directory; also its expected `readlink -f` resolution. */
  destination: string
  /** Destination paths that must not be symlinks during the merge; duplicates are dropped. */
  guardPaths: string[]
  /** The staging directory holding the freshly extracted files. */
  staging: string
}

/** Issue #219: the staging merge exec: its command and its stdin. */
export type StagingMergeExec = {
  /** The unbounded merge command; a simple command, see {@link boundedStagingMergeCommand}. */
  command: string
  /** The deduplicated guard paths, each terminated by a NUL byte. */
  input: string
}

/**
 * Issue #219: build the staging merge exec.
 *
 * The guard paths travel NUL-terminated on stdin (the framing of the batched
 * probes, see `encodeNulPayload`), not as an argument. As one
 * newline-separated argument they failed with `E2BIG` on Linux, which caps a
 * single argument at 128 KiB: a Node.js tarball with about 6,000 members
 * yields about 750 KB of guard paths, so the merge failed for an archive that
 * validation had accepted. The command now carries only the two scripts, the
 * staging and destination paths and the guard count, and stays a few KiB
 * whatever the archive holds. Like the probes, the exec needs passwordless
 * sudo when it runs through sudo: the SSH layer refuses stdin input when sudo
 * would read a password from it.
 *
 * @param parameters - Staging merge inputs.
 * @returns The command, to be bounded with {@link boundedStagingMergeCommand},
 *   and its stdin.
 */
export function buildStagingMergeExec(parameters: StagingMergeParameters): StagingMergeExec {
  const guardPaths = [...new Set(parameters.guardPaths)]
  const command = [
    "sh -c",
    shellQuote(STAGING_MERGE_GUARD_FILE_SCRIPT),
    "sh",
    shellQuote(parameters.staging),
    shellQuote(buildStagingMergeScript()),
    shellQuote(parameters.destination),
    String(guardPaths.length),
  ].join(" ")
  return { command, input: encodeNulPayload(guardPaths) }
}

/**
 * Issue #219: time limits of the staging merge exec.
 *
 * Invariant: `(timeoutSeconds + killAfterSeconds) * 1000 < clientTimeoutMs`.
 * The client gives up after `clientTimeoutMs` and closes the channel, but
 * closing the channel does not stop the remote processes: a merge that was
 * still copying kept running on the host after the run had already reported
 * a failure, and could publish links after the post-merge backstop looked.
 * With the remote bound strictly below the client timeout, GNU `timeout` has
 * stopped the whole merge (with `SIGTERM`, then `SIGKILL`) before the client
 * stops waiting.
 */
export type StagingMergeTimeLimits = {
  /** Client-side timeout of the merge exec in milliseconds. */
  clientTimeoutMs: number
  /** Seconds GNU `timeout` waits after `SIGTERM` before it sends `SIGKILL`. */
  killAfterSeconds: number
  /** Seconds after which GNU `timeout` sends `SIGTERM` to the merge. */
  timeoutSeconds: number
}

/**
 * Issue #219: the limits the staging merge runs with. The client timeout is
 * the SSH default of 120 s, passed explicitly so the invariant documented on
 * {@link StagingMergeTimeLimits} does not silently depend on it; 100 s + 10 s
 * leaves 10 s for the exit status to travel back.
 */
export const STAGING_MERGE_TIME_LIMITS: Readonly<StagingMergeTimeLimits> = {
  clientTimeoutMs: 120_000,
  killAfterSeconds: 10,
  timeoutSeconds: 100,
}

/** GNU `timeout` exits 124 when it stopped the command with `SIGTERM`. */
const TIMEOUT_EXIT_CODE = 124
/**
 * When the `-k` `SIGKILL` was needed, `timeout` signals its own process group
 * and dies with it, so the shell reports 128 + 9.
 */
const TIMEOUT_KILLED_EXIT_CODE = 137

/**
 * Issue #219: bound a staging merge command on the host with GNU `timeout`.
 *
 * The merge already requires GNU coreutils (`cp -aT --no-dereference
 * --remove-destination`), which ships `timeout`. `command -p` looks it up on
 * the default system PATH, like `readlink` in the symlink listing. Without
 * `--foreground`, `timeout` puts itself and the command into their own
 * process group and signals the whole group, so the `sh -c` batches `find`
 * spawns and their `cp` children receive the `SIGTERM` too. Neither the merge
 * script nor `cp` ignores it. The `-k` `SIGKILL` follows only while `find`
 * itself is still running: a descendant that ignored `SIGTERM` after `find`
 * exited would not be killed, and a process blocked in uninterruptible I/O
 * cannot be stopped by any signal.
 *
 * Issue #219: since the guard paths moved to stdin, the bounded command is
 * the outer `sh -c` of {@link buildStagingMergeExec}, which runs `find` as its
 * child. The same process group covers it: the outer shell turns the
 * `SIGTERM` into an exit that removes its guard file, and the `SIGKILL`
 * follows while that shell still waits for `find`.
 *
 * The trailing `; exit $?` keeps the remote shell from replacing itself with
 * `timeout` (shells `exec` the last simple command of `sh -c`). When the
 * `SIGKILL` stage is needed, `timeout` dies with its own process group; the
 * surviving shell then reports exit status 137 instead of the whole channel
 * ending with a signal, which the SSH layer would turn into a thrown error.
 *
 * Failure mode: fail closed. When `timeout` is unavailable the shell exits 127
 * before `find` runs, so nothing is copied and the merge is reported as
 * failed. A stopped merge exits 124 (`SIGTERM`) or 137 (`SIGKILL` after the
 * kill-after grace period), which the caller reports as stopped on the host.
 *
 * @param mergeCommand - The complete merge command, starting with the program
 *   to run (e.g. `sh -c …` from {@link buildStagingMergeExec}); it must not be
 *   a shell compound command.
 * @param limits - The time limits; defaults to {@link STAGING_MERGE_TIME_LIMITS}.
 * @returns The command as `command -p timeout -k <K> <S> <mergeCommand>; exit $?`.
 */
export function boundedStagingMergeCommand(
  mergeCommand: string,
  limits: Readonly<StagingMergeTimeLimits> = STAGING_MERGE_TIME_LIMITS
): string {
  const { killAfterSeconds, timeoutSeconds } = limits
  return `command -p timeout -k ${String(killAfterSeconds)} ${String(timeoutSeconds)} ${mergeCommand}; exit $?`
}

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

/**
 * Write the marker file using the SHA256 of the (possibly uploaded) remote archive.
 *
 * The cleanup of an uploaded temp file is intentionally **not** part of this
 * helper — the caller owns the lifecycle of the temp upload via try/finally so
 * the temp file is removed on every code path, including failures.
 *
 * @param conn - The SSH connection.
 * @param remoteSource - The remote archive path.
 * @param options - Marker path.
 * @param options.marker - The marker file path.
 * @returns Null when the marker was written, otherwise a structured failure.
 */
async function writeMarker(
  conn: SshConnection,
  remoteSource: string,
  options: { marker: string }
): Promise<ModuleResult | null> {
  const sha = await conn.sha256(remoteSource)
  if (sha === null) return failed(`[archive.extract] failed to calculate marker hash`)
  const flagsDirectory = await conn.exec(`mkdir -p ${shellQuote(FLAGS_DIR)}`, EXEC_OPTS)
  if (flagsDirectory.code !== 0) {
    return failedCommand(
      `[archive.extract] failed to create archive marker directory`,
      flagsDirectory
    )
  }
  try {
    await conn.writeFile(options.marker, sha, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive marker ${options.marker}: ${reason}`)
  }
  return null
}

/** Parameters for the apply helper. */
type ApplyParameters = {
  /** Issue #219: where the destination's containment entries live. */
  containment: ContainmentPaths
  /** The destination directory on the remote host. */
  destination: string
  /** The marker file path. */
  marker: string
  /** Optional owner for extracted archive members. */
  owner: string | undefined
  /** The source archive path. */
  source: string
  /** Whether to upload a local file first. */
  upload: boolean
}

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
async function validatedArchiveMembers(
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

async function writeOwnerPathsMarker(
  conn: SshConnection,
  parameters: {
    content: null | string
    marker: string
  }
): Promise<ModuleResult | null> {
  if (parameters.content === null) return null
  // R-0000166: persist the member list in *both* upload and non-upload mode.
  // The previous implementation only stored the list when `upload === true`
  // and re-derived it from the live archive (`tar -tvzf <source>`) in the
  // non-upload check. If the source archive was modified or removed between
  // apply and the next check, the re-derived list no longer matched what
  // was extracted, which produced false drift reports — or, worse, hid real
  // owner drift on disk because the per-path stat operated on the wrong
  // file list. Writing the marker on every successful apply ties the owner
  // re-check to the same paths the extract actually touched.
  const marker = ownerPathsMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, parameters.content, {
      mode: ARCHIVE_MARKER_MODE,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive owner marker ${marker}: ${reason}`)
  }
  return null
}

function extractedArchiveMembers(
  destination: string,
  members: ArchiveMember[]
): ExtractedArchiveMember[] {
  const extractedMembers = new Map<string, ExtractedArchiveMember>()
  for (const member of members) {
    const memberPath = normalizeArchiveMemberPath(member.path)
    if (memberPath === null) continue
    const path = memberPath === "" ? destination : `${destination}/${memberPath}`
    if (member.kind === "special") continue
    extractedMembers.set(path, { kind: member.kind, path })
  }
  return [...extractedMembers.values()]
}

function serializeArchiveMarkerPayloads(parameters: {
  destination: string
  members: ArchiveMember[]
  owner?: string
  source: string
}): ArchiveMarkerPayloads | ModuleResult {
  const members = JSON.stringify(
    extractedArchiveMembers(parameters.destination, parameters.members)
  )
  const membersBytes = Buffer.byteLength(members, "utf8")
  if (membersBytes > ARCHIVE_CAPTURE_LIMIT_BYTES) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: archive members marker payload is ${String(membersBytes)} bytes and exceeds the limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`
    )
  }

  if (parameters.owner == null || parameters.owner === "") {
    return { members, ownerPaths: null }
  }
  const ownerPaths = JSON.stringify(
    archiveMemberDestinationPaths(parameters.destination, parameters.members)
  )
  const ownerPathsBytes = Buffer.byteLength(ownerPaths, "utf8")
  if (ownerPathsBytes > ARCHIVE_CAPTURE_LIMIT_BYTES) {
    return failed(
      `[archive.extract] refusing to extract ${parameters.source}: archive owner-paths marker payload is ${String(ownerPathsBytes)} bytes and exceeds the limit of ${String(ARCHIVE_CAPTURE_LIMIT_BYTES)} bytes`
    )
  }
  return { members, ownerPaths }
}

async function writeMembersMarker(
  conn: SshConnection,
  parameters: { content: string; marker: string }
): Promise<ModuleResult | null> {
  const marker = membersMarkerPath(parameters.marker)
  try {
    await conn.writeFile(marker, parameters.content, { mode: ARCHIVE_MARKER_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return failed(`[archive.extract] failed to write archive members marker ${marker}: ${reason}`)
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
type ContainmentProgress = {
  advance: (phase: ContainmentPhase) => void
  phase: () => ContainmentPhase
}

/**
 * Issue #219: track the phase of an apply, starting before the merge.
 *
 * @returns The tracker.
 */
function containmentProgress(): ContainmentProgress {
  let current: ContainmentPhase = "before-merge"
  return {
    advance(phase) {
      current = phase
    },
    phase: () => current,
  }
}

/** Inputs of the staged extraction. */
type StagedExtractionParameters = {
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
async function extractViaStagingDirectory(
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
  } & ApplyParameters
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
const NOTHING_PUBLISHED: ContainmentFlagRecord = { links: [], state: "failed" }

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
async function extractAndValidateSymlinkContainment(
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
 * published), `unknown` once the merge started (nobody knows what it
 * published), and no links once the backstop passed. The merge-started case
 * is written too, not left to the `in-progress` body: a concurrent clean
 * apply may have removed that entry meanwhile (race 1), and only a write
 * creates it again.
 *
 * @param progress - How far the apply got.
 * @returns What to write into the own entry.
 */
function recordAfterThrow(progress: ContainmentProgress): ContainmentFlagRecord {
  switch (progress.phase()) {
    case "before-merge": {
      return NOTHING_PUBLISHED
    }
    case "merge-started": {
      return { reason: STOPPED_AFTER_MERGE_STARTED, state: "unknown" }
    }
    case "verified": {
      return { links: [], state: "failed" }
    }
  }
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
} & ApplyParameters

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
  parameters: ApplyParameters,
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
async function applyExtract(
  conn: SshConnection,
  parameters: ApplyParameters
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

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
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

function isExtractedArchiveMember(value: unknown): value is ExtractedArchiveMember {
  if (typeof value !== "object" || value === null) return false
  const member = value as { kind?: unknown; path?: unknown }
  return (
    typeof member.path === "string" &&
    (member.kind === "directory" ||
      member.kind === "file" ||
      member.kind === "hardlink" ||
      member.kind === "symlink")
  )
}

async function readMembersMarker(
  conn: SshConnection,
  marker: string
): Promise<MembersMarkerReadResult> {
  const markerResult = await conn.exec(
    `cat ${shellQuote(membersMarkerPath(marker))}`,
    ARCHIVE_CAPTURE_EXEC_OPTS
  )
  if (markerResult.code !== 0) return null
  if (
    markerResult.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    markerResult.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return "invalid"
  }
  try {
    const members: unknown = JSON.parse(markerResult.stdout)
    return Array.isArray(members) && members.every((member) => isExtractedArchiveMember(member))
      ? members
      : "invalid"
  } catch {
    return "invalid"
  }
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

async function readOwnerPathsMarker(
  conn: SshConnection,
  marker: string
): Promise<OwnerPathsMarkerReadResult> {
  const markerResult = await conn.exec(`cat ${shellQuote(ownerPathsMarkerPath(marker))}`, {
    ...ARCHIVE_CAPTURE_EXEC_OPTS,
    env: { LC_ALL: "C" },
  })
  if (markerResult.code !== 0) {
    // R-0000276: previously a non-"no such file" stderr (e.g. permission
    // denied after a flag-dir mode drift, or a transient truncate race) raised
    // an exception that propagated past archiveOwnerMatches and aborted the
    // whole run. Such failures remain recoverable drift, but only a genuine
    // missing-file diagnostic may use the legacy live-archive fallback.
    return MISSING_OWNER_PATHS_MARKER_PATTERN.test(markerResult.stderr)
      ? { kind: "missing" }
      : { kind: "invalid" }
  }
  if (
    markerResult.stdout.endsWith(CAPTURE_TRUNCATION_MARKER) ||
    markerResult.stderr.endsWith(CAPTURE_TRUNCATION_MARKER)
  ) {
    return { kind: "invalid" }
  }
  try {
    const paths: unknown = JSON.parse(markerResult.stdout)
    return isStringArray(paths) ? { kind: "valid", paths } : { kind: "invalid" }
  } catch {
    return { kind: "invalid" }
  }
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
 * Modules for managing archive extraction on the remote host.
 */
export const archive = {
  /**
   * Extract an archive to a destination directory on the remote host.
   *
   * Supports tar, tar.gz, tgz, tar.bz2, tar.xz, and zip formats.
   * Uses a marker file with SHA256 checksum for idempotency.
   *
   * @param source - Path to the archive (remote path, or local path when upload is true).
   * @param destination - The destination directory on the remote host.
   * @param options - Optional settings.
   * @param options.owner - Set ownership on extracted archive members after extraction.
   * @param options.upload - Upload a local file to the remote host before extracting.
   * @returns A Module that manages the archive extraction.
   */
  extract(
    source: string,
    destination: string,
    options?: { owner?: string; upload?: boolean }
  ): Module {
    // R-0000700 / R-0000706: validate the destination synchronously at module
    // construction so invalid destinations (control characters, relative
    // paths, "/") fail fast before any marker path is derived or async
    // apply/check work is scheduled.
    const validatedDestination = validateExtractDestination(destination)
    if ("status" in validatedDestination) {
      const reason = validatedDestination.error?.message ?? "invalid destination"
      throw new Error(reason)
    }
    const normalizedDestination = validatedDestination.destination
    const marker = markerPath(source, normalizedDestination)
    const containment = containmentPathsFor(normalizedDestination)
    const upload = options?.upload === true
    const owner = options?.owner
    const parameters: ApplyParameters = {
      containment,
      destination: normalizedDestination,
      marker,
      owner,
      source,
      upload,
    }

    return {
      async apply(conn: null | SshConnection): Promise<ModuleResult> {
        if (!conn) {
          return failed(`[archive.extract] SSH connection is required for ${normalizedDestination}`)
        }
        return applyExtract(conn, parameters)
      },
      async check(conn: null | SshConnection): Promise<"needs-apply" | "ok"> {
        if (!conn) return NEEDS_APPLY

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
        const markerExists = await conn.test(
          markerWithoutContainmentFailureCommand(marker, containment)
        )
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
      },
      name: `archive.extract: ${normalizedDestination}`,
    }
  },
}
