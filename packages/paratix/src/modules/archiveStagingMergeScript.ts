/**
 * The shell text of the `archive.extract` staging merge: the extract command, the merge script, its
 * guard-file wrapper and the GNU `timeout` bound around it. It runs nothing itself, so the scripts
 * can be read, tested and executed against a real shell on their own.
 */

import { shellQuote } from "../ssh.js"
import { encodeNulPayload } from "./archiveProbe.js"

/**
 * Build the extract command based on the file extension of the original source.
 *
 * @param source - The original archive path used for format detection.
 * @param archivePath - The actual archive path on the remote host.
 * @param destination - The target directory for extraction.
 * @returns The shell command to extract the archive, or null if unsupported.
 */
const TAR_HARDEN_FLAGS = "--no-same-owner --no-overwrite-dir"

export function extractCommand(
  source: string,
  archivePath: string,
  destination: string
): null | string {
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

/**
 * Build the `sh -c` snippet that merges one batch of staging entries into the
 * destination.
 *
 * The script reads `destination`, `expected_destination`, `guard_file` and
 * `failure_file` from `$1`–`$4` and the staging entries from the remaining
 * positional arguments, so it is free of interpolated paths and can be
 * executed verbatim against a real `/bin/sh` in a test. Issue #178 showed why
 * that matters: a guard that reads correctly can still be inert at run time,
 * and only executing it proves otherwise.
 *
 * Issue #219: `guard_file` names a file holding the guard paths, each
 * terminated by a NUL byte, as {@link buildStagingMergeExec} writes it on the
 * host. Before every staged entry is copied, the script re-reads the file with
 * `xargs -0` and refuses the merge (exit 64) when any guard path is a symlink
 * or the check itself fails. An empty file checks nothing and passes.
 *
 * `failure_file` records a failed batch in-band, because not every `find`
 * passes on the exit status of a batch that `-exec … {} +` ran before the last
 * one. An `EXIT` trap appends a byte to it whenever the batch exits non-zero
 * (a refusal, a failed guard check or a failed `cp`), and a batch that finds
 * the file non-empty exits 64 before copying anything, so no later batch
 * continues a merge that already failed. The outer script checks the file
 * after `find` (see {@link buildStagingMergeExec}).
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
    String.raw`destination=$1; expected_destination=$2; guard_file=$3; failure_file=$4; shift 4; `,
    // The trap keeps the batch's own exit status and only records that it
    // failed; the check after it stops a batch that runs after a failed one.
    String.raw`trap 'merge_status=$?; [ "$merge_status" -eq 0 ] || printf x >> "$failure_file"; exit "$merge_status"' EXIT; `,
    String.raw`if [ -s "$failure_file" ]; then exit 64; fi; `,
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
 * A second, separate `mktemp` file is passed as `$4`, the failure file the
 * merge batches append to when they fail. It is created on its own rather
 * than derived from the guard file's name, so it is just as private and
 * unique as the guard file. After `find`, a non-zero `find` status
 * is passed on unchanged; otherwise a non-empty failure file ends the merge
 * with 64, so a failed batch is reported even when `find` exits 0. That code
 * is never 124 or 137, which the caller reads as the host timeout.
 *
 * Positional parameters: `$1` staging directory, `$2` merge script, `$3`
 * destination, `$4` expected number of guard paths. The count check refuses a
 * truncated stdin, which would otherwise silently drop guard paths.
 *
 * Both files come from `mktemp` (mode 0600, owned by the merge user, i.e.
 * root under sudo) below `$TMPDIR` or `/tmp`. The `EXIT` trap removes them on
 * every exit the shell sees, and the `HUP`/`INT`/`TERM` traps turn those
 * signals into such an exit — including the `SIGTERM` of the host timeout.
 * Only a `SIGKILL` (the timeout's kill-after stage) leaves the files behind: a
 * harmless root-owned list of destination paths and a failure marker that the
 * next run does not read. `find` is not the last command, so the shell cannot
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
  String.raw`guard_file=; failure_file=; `,
  String.raw`trap '[ -z "$guard_file" ] || rm -f -- "$guard_file"; [ -z "$failure_file" ] || rm -f -- "$failure_file"' EXIT; `,
  String.raw`trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; `,
  // Not `String.raw`: `$\{` emits a literal shell parameter expansion.
  `guard_file=$(mktemp "$\{TMPDIR:-/tmp}/paratix-merge-guards.XXXXXXXX") && [ -f "$guard_file" ] || { `,
  String.raw`echo "[archive.extract] refusing staging merge: failed to create the guard path file" >&2; `,
  String.raw`exit 64; }; `,
  `failure_file=$(mktemp "$\{TMPDIR:-/tmp}/paratix-merge-failed.XXXXXXXX") && [ -f "$failure_file" ] || { `,
  String.raw`echo "[archive.extract] refusing staging merge: failed to create the merge failure file" >&2; `,
  String.raw`exit 64; }; `,
  String.raw`cat > "$guard_file" || { `,
  String.raw`echo "[archive.extract] refusing staging merge: failed to store the guard paths" >&2; `,
  String.raw`exit 64; }; `,
  String.raw`guard_count=$(LC_ALL=C tr -cd '\000' < "$guard_file" | wc -c | tr -d ' '); `,
  String.raw`[ "$guard_count" = "$4" ] || { `,
  String.raw`echo "[archive.extract] refusing staging merge: received $guard_count of $4 guard paths" >&2; `,
  String.raw`exit 64; }; `,
  String.raw`find "$1" -mindepth 1 -maxdepth 1 -exec sh -c "$2" sh "$3" "$3" "$guard_file" "$failure_file" {} +; `,
  String.raw`find_status=$?; [ "$find_status" -eq 0 ] || exit "$find_status"; `,
  String.raw`if [ -s "$failure_file" ]; then `,
  String.raw`echo "[archive.extract] staging merge failed: a merge batch failed although find reported success; later batches copied nothing" >&2; `,
  String.raw`exit 64; fi; `,
  String.raw`exit 0`,
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
