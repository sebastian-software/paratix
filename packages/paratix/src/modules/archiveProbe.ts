import type { ExecResult, SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER, DEFAULT_MAX_OUTPUT_BYTES } from "../sshHelpers.js"

/**
 * Batched remote probes for `archive.extract`.
 *
 * Issue #180: the symlink sweeps, the member type checks and the ownership
 * checks used to issue one `exec` per path. Each `exec` is its own SSH session
 * channel, and since issue #178 those are capped at four concurrent per
 * connection, so a 1000-member archive spent 3041 round trips — 2030 in
 * `apply` and 1011 in every subsequent `check`.
 *
 * All three now share one transport: the path list travels NUL-delimited on
 * stdin, a small POSIX script fans it out locally with `xargs -0`, and only
 * **violations** come back. A converged run therefore produces empty output
 * regardless of member count, which keeps the result far below the 1 MiB
 * captured-output cap without any chunk size to choose or tune.
 *
 * NUL delimiting is deliberate rather than incidental: it removes every
 * question about newlines inside paths, which is exactly the defect class that
 * produced #178.
 */

const PROBE_EXEC_OPTS = { ignoreExitCode: true, silent: true, strictUtf8Stdout: true } as const

/** Shared prefix: read the NUL payload from stdin and hand it to a POSIX `sh`. */
const XARGS_PREFIX = "xargs -0 sh -c '"

/**
 * Split a tagged entry `$a` of the form `<kind>:<path>` into `$k` and `$p` and
 * open a `case` on the kind. Only the first colon separates, so a path may
 * contain colons. `$\{` keeps the shell parameter expansion literal; a bare
 * `${` would be read as JavaScript interpolation.
 */
const TAGGED_ENTRY_DISPATCH = `k=$\{a%%:*}; p=$\{a#*:}; case $k in `

/** Closes the per-entry `case` and loop of a probe script and exits 0. */
const CASE_LOOP_END = "esac; done; exit 0"

/**
 * Encode entries as a NUL-terminated payload for `xargs -0`.
 *
 * @param entries - The entries to transport.
 * @returns Each entry followed by a NUL byte.
 */
export function encodeNulPayload(entries: string[]): string {
  return entries.map((entry) => `${entry}\0`).join("")
}

/**
 * Split NUL-terminated output back into fields.
 *
 * Only the trailing empty fragment after the final NUL is dropped — interior
 * empty fields are meaningful, because the ownership probe emits them for a
 * path whose `stat` failed.
 *
 * @param stdout - Raw probe output.
 * @returns The transported fields in order.
 */
function decodeNulFields(stdout: string): string[] {
  const fields = stdout.split("\0")
  if (fields.at(-1) === "") fields.pop()
  return fields
}

/**
 * Issue #219: `truncated` marks a failure because the output hit the
 * captured-output cap, so a caller can say what that means for its probe.
 */
export type BatchedProbeOutcome =
  { detail: string; kind: "failed"; truncated?: true } | { fields: string[]; kind: "ok" }

/**
 * Run one batched probe and return the reported violations.
 *
 * A non-zero exit is reported as `failed` rather than as an empty violation
 * list. That distinction is the whole safety property here: these probes back
 * symlink guards (R-0000162, R-0000563, R-0000751), and a crashed script whose
 * silence was read as "no violations" would disable them without a trace.
 *
 * Issue #219: every probe decodes its stdout as strict UTF-8
 * (`strictUtf8Stdout`). The output carries host paths, and a lossy decode maps
 * different invalid byte sequences to the same U+FFFD, so two distinct host
 * paths could collapse into one string. With the strict decode every accepted
 * string maps back to exactly the host's bytes; output that is not valid UTF-8
 * makes the exec reject, which is reported as `failed` like any other
 * rejected exec.
 *
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.entries - The NUL-transported entries; an empty list runs nothing.
 * @param parameters.maxOutputBytes - Optional captured-output cap for probes whose output grows
 *   with the host tree rather than with violations; the SSH default applies when omitted.
 * @param parameters.script - The remote script to execute.
 * @returns The decoded fields, or a failure with its diagnostic detail.
 */
export async function runBatchedProbe(
  conn: SshConnection,
  parameters: { entries: string[]; maxOutputBytes?: number; script: string }
): Promise<BatchedProbeOutcome> {
  if (parameters.entries.length === 0) return { fields: [], kind: "ok" }
  const { maxOutputBytes } = parameters
  let result: ExecResult
  try {
    result = await conn.exec(parameters.script, {
      ...PROBE_EXEC_OPTS,
      input: encodeNulPayload(parameters.entries),
      ...(maxOutputBytes === undefined ? {} : { maxOutputBytes }),
    })
  } catch (error) {
    return { detail: error instanceof Error ? error.message : String(error), kind: "failed" }
  }
  if (result.code !== 0) {
    const detail =
      result.stderr.trim() || result.stdout.trim() || `exit code ${String(result.code)}`
    return { detail, kind: "failed" }
  }
  // R-0000668, as `readFile` and `sha256` apply it in `ssh.ts`: the captured
  // output silently carries the truncation marker once it hits the byte cap.
  // Parsing a cut-off list here would make the result depend on where the cut
  // landed — the symlink and member-type probes stay fail-closed by the shape
  // of their output, but the ownership probe drops a trailing partial record
  // and can report a match it never verified. Rejecting truncation gives the
  // whole transport one rule instead of three accidental ones.
  if (result.stdout.endsWith(CAPTURE_TRUNCATION_MARKER)) {
    return {
      detail: `probe output exceeded the captured-output cap of ${String(maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES)} bytes; refusing to evaluate a truncated result`,
      kind: "failed",
      truncated: true,
    }
  }
  return { fields: decodeNulFields(result.stdout), kind: "ok" }
}

/**
 * Probe script reporting every path that is a symlink.
 *
 * A path that does not exist is not a violation, matching the `test ! -L`
 * semantics of the per-path probe this replaces.
 *
 * @returns The remote script.
 */
export function buildSymlinkProbeScript(): string {
  return [
    XARGS_PREFIX,
    'for p do if [ -L "$p" ]; then printf "%s\\0" "$p"; fi; done; exit 0',
    "' sh",
  ].join("")
}

/**
 * Issue #219: shell function `e` that emits one listing field, NUL-terminated.
 *
 * A field made only of printable ASCII (0x20–0x7E) is printed unchanged. Any
 * other field — with a control character, DEL or any byte above 0x7F — is
 * printed as the marker byte 0x01 followed by the lowercase hex of its bytes,
 * from one `od` per such field. A plain field never contains 0x01, so the
 * marker is unambiguous, and the whole output stays printable ASCII plus the
 * marker and NUL: valid UTF-8 whatever bytes the host names hold, so the probe
 * keeps `strictUtf8Stdout`. The scripts run under `LC_ALL=C`, so the `case`
 * test sees bytes, not characters of some locale. `command -p od` is looked up
 * on the default system PATH like `readlink`; a failing `od` exits 1, which
 * fails the listing. `$\{` keeps the shell parameter expansion literal.
 */
const SYMLINK_LISTING_FIELD_FUNCTION = [
  "e() { case $1 in ",
  "*[![:print:]]*) h=$(printf '%s' \"$1\" | command -p od -A n -v -t x1) || exit 1; ",
  // Unquoted `$h` splits the `od` columns on whitespace; `printf '%s'` joins them.
  "h=$(printf '%s' $h); printf '\\001%s\\0' \"$h\";; ",
  "*) printf '%s\\0' \"$1\";; ",
  "esac; }; ",
].join("")

/**
 * Per-batch body of {@link buildSymlinkListingProbeScript}: `$1` is the record
 * kind (`l` for symlinks, `u` for unreadable directories), `$2` the
 * destination, and the remaining arguments are the paths `find` found.
 *
 * - Issue #219: every path is emitted relative to the destination
 *   (`$\{l#"$d"/}`), which keeps the listing small; the decoder refuses any
 *   path that is not a normalized relative path.
 * - Plain `readlink` without `-f` prints the stored target unchanged. It exists
 *   in GNU coreutils, busybox and the BSDs, and `command -p` looks it up on the
 *   default system PATH so a hijacked PATH cannot substitute it (R-0000693).
 * - The `printf x` sentinel keeps a target that ends in newlines intact; only
 *   the single newline `readlink` itself appends is removed.
 * - Issue #219: a link that vanished between `find` and `readlink` (the read
 *   fails and `[ -L ]` is now false) is skipped: it is no longer there to
 *   judge. A link whose target cannot be read although it still exists makes
 *   the batch exit 1; `find` then exits non-zero, so the listing fails closed
 *   instead of silently omitting that link.
 * - Issue #219: a missing or unusable `readlink` takes the same path: `command
 *   -p` exits 127 when it finds no `readlink`, the substitution fails, the link
 *   still exists and the batch exits 1. The post-merge backstop relies on
 *   this, because a link it never saw is a link it can neither judge nor
 *   report.
 */
const SYMLINK_LISTING_INNER_SCRIPT = [
  SYMLINK_LISTING_FIELD_FUNCTION,
  // `nl` holds one newline; the trailing `x` survives command substitution.
  "nl=$(printf '\\nx'); ",
  // `$\{` keeps the shell parameter expansion literal; a bare `${` would be
  // read as JavaScript interpolation.
  `nl=$\{nl%x}; k=$1; d=$2; shift 2; `,
  "for l do ",
  `r=$\{l#"$d"/}; `,
  "case $k in ",
  "u) printf 'u\\0'; e \"$r\";; ",
  "l) ",
  't=$(command -p readlink -- "$l" && printf x) || { if [ -L "$l" ]; then exit 1; fi; continue; }; ',
  `t=$\{t%x}; t=$\{t%"$nl"}; `,
  'printf \'l\\0\'; e "$r"; e "$t";; ',
  '*) echo "unknown symlink listing batch kind" >&2; exit 64;; ',
  CASE_LOOP_END,
].join("")

/**
 * Issue #219: the per-batch body of {@link buildSymlinkListingProbeScript} on
 * its own, so a smoke test can run one batch against paths it chooses (for
 * example a link that vanished after `find` reported it).
 *
 * @returns The script `find -exec sh -c <script> sh <kind> <destination> {} +` runs.
 */
export function symlinkListingBatchScript(): string {
  return SYMLINK_LISTING_INNER_SCRIPT
}

/**
 * Issue #219: the kinds of entry {@link buildSymlinkListingProbeScript} takes.
 *
 * - `r`: a destination root; every symlink below it is listed with its target.
 * - `n`: the destination path of a non-directory archive member; it is
 *   reported when it is an existing directory that is not a symlink, because
 *   the merge cannot replace such a directory with the member.
 */
export type SymlinkListingEntryKind = "n" | "r"

/**
 * Issue #219: encode one entry for {@link buildSymlinkListingProbeScript}.
 *
 * Kind and path share a single argument for the same reason as in
 * {@link encodeMemberTypeEntry}: `xargs` may split its argument list anywhere,
 * so separate arguments could be re-paired against the wrong path.
 *
 * @param kind - The entry kind, see {@link SymlinkListingEntryKind}.
 * @param path - The absolute host path.
 * @returns The encoded entry.
 */
export function encodeSymlinkListingEntry(kind: SymlinkListingEntryKind, path: string): string {
  return `${kind}:${path}`
}

/**
 * Outer body of {@link buildSymlinkListingProbeScript}: `$1` is the inner
 * script, the remaining arguments are the tagged entries from stdin (see
 * {@link encodeSymlinkListingEntry}).
 *
 * `find` without `-L` never follows a symlink, so the walk stays inside the
 * destination tree. A traversal error, or a batch of the inner script that
 * exited non-zero, makes `find` exit non-zero, which the `|| exit $?` turns
 * into a failed probe rather than a partial listing read as complete. An entry
 * with an unknown kind exits non-zero as well, so a framing mistake on the
 * sending side fails closed.
 *
 * Issue #219: with GNU find — detected in the same exec by `find <dest>
 * -maxdepth 0 -readable`, which other finds reject as an unknown primary — a
 * directory below the destination that the probing user cannot read or search
 * (`! -readable -o ! -executable`) is pruned and reported as a `u` record
 * instead of failing the whole listing, and `-ignore_readdir_race` keeps an
 * entry that vanishes during the walk from counting as an error. Without GNU
 * find (busybox, the BSDs) the listing keeps failing closed on any traversal
 * error, an unreadable directory included.
 *
 * Issue #219: an `n` entry that is an existing real directory is emitted as an
 * `n` record with the path as it was sent.
 */
const SYMLINK_LISTING_OUTER_SCRIPT = [
  "LC_ALL=C; export LC_ALL; ",
  SYMLINK_LISTING_FIELD_FUNCTION,
  "inner=$1; shift; for a do ",
  TAGGED_ENTRY_DISPATCH,
  'r) if find "$p" -maxdepth 0 -readable >/dev/null 2>&1; then ',
  'find "$p" -ignore_readdir_race -mindepth 1 ',
  '-type d \\( ! -readable -o ! -executable \\) -prune -exec sh -c "$inner" sh u "$p" {} + ',
  '-o -type l -exec sh -c "$inner" sh l "$p" {} + || exit $?; ',
  'else find "$p" -type l -exec sh -c "$inner" sh l "$p" {} + || exit $?; fi;; ',
  'n) if [ -d "$p" ] && [ ! -L "$p" ]; then printf \'n\\0\'; e "$p"; fi;; ',
  '*) echo "unknown symlink listing entry kind" >&2; exit 64;; ',
  CASE_LOOP_END,
].join("")

/**
 * Probe script listing every symlink below a destination together with its
 * raw stored target, and reporting which non-directory archive member paths
 * are existing real directories on the host.
 *
 * Issue #219: the pre-merge containment check needs the links an earlier run
 * or the host left in the destination, because a link this archive ships can
 * redirect one of them (or the other way round). With this listing the
 * combined post-merge link set is resolved before anything is copied, so an
 * escaping combination is refused instead of being published and detected
 * only afterwards. The post-merge backstop reads the tree with the same
 * listing, with a single `r` entry, and judges it with the same resolver, so
 * both checks share one set of resolution semantics and neither ever asks the
 * host to resolve a link. That matters because GNU `realpath` (in every mode,
 * `readlink -f` included) never terminates on a self-extending loop such as
 * `b -> b/..`, and a merge that failed half-way can leave one behind;
 * `readlink` without `-f` only reads the stored target. Which of the listed
 * links are then judged is decided in TypeScript (see
 * `mergedSymlinkResolutions`): the listing itself is complete, because a link
 * that the archive can affect may live anywhere below the destination.
 *
 * The directory hits let the model refuse a member that the merge could not
 * put in place: `cp -aT --remove-destination` cannot replace
 * a directory with a non-directory, still copies the rest of that top-level
 * entry and exits non-zero, so modelling such a member as a replacement would
 * resolve paths through a link that never lands. It is meant for
 * {@link runBatchedProbe} with one `r` entry for the destination plus one `n`
 * entry per non-directory member (see {@link encodeSymlinkListingEntry}), so it
 * costs exactly one `exec` regardless of member count.
 *
 * The composed command is `xargs -0 sh -c <outer> sh <inner>`: `xargs`
 * appends the NUL-delimited stdin entries after `<inner>`, so the outer script
 * receives the inner script as `$1` and the entries after it. Both bodies
 * contain single quotes and are therefore composed with `shellQuote` instead
 * of the literal `XARGS_PREFIX`. Link paths travel as arguments and results
 * come back NUL-framed, so spaces and newlines in link names and targets are
 * transported faithfully.
 *
 * Failure mode: fail closed. A traversal error (other than an unreadable
 * directory with GNU find), an unreadable target of an existing link, an
 * unknown entry kind or a failing `sh`/`xargs`/`od` makes the exec exit
 * non-zero; the caller treats that, a truncated capture and any output that
 * is not made of well-formed records as "containment cannot be proven".
 *
 * @returns The remote script. Its output is a flat list of NUL-terminated
 *   fields forming records: `l, <link>, <target>` per symlink with the link
 *   path relative to the destination and the raw target exactly as stored,
 *   `u, <directory>` per unreadable directory relative to the destination
 *   (GNU find only), and `n, <path>` per `n` entry that is an existing real
 *   directory, with the path as sent. Every path and target field is plain
 *   printable ASCII or 0x01 followed by the hex of its bytes. A tree without
 *   symlinks, unreadable directories and such directory hits produces no
 *   output.
 */
export function buildSymlinkListingProbeScript(): string {
  return `xargs -0 sh -c ${shellQuote(SYMLINK_LISTING_OUTER_SCRIPT)} sh ${shellQuote(SYMLINK_LISTING_INNER_SCRIPT)}`
}

/**
 * Encode one member for {@link buildMemberTypeProbeScript}.
 *
 * Kind and path share a single argument on purpose. `xargs` splits its argument
 * list wherever `ARG_MAX` requires, so two separate arguments could be torn
 * apart between invocations and silently re-paired against the wrong path.
 *
 * @param kind - Single-letter kind code: `d`, `f` or `l`.
 * @param path - The absolute destination path.
 * @returns The encoded entry.
 */
export function encodeMemberTypeEntry(kind: string, path: string): string {
  return `${kind}:${path}`
}

/**
 * Probe script reporting every member whose type does not match its record.
 *
 * The kind codes mirror the previous per-member commands exactly: `d` requires
 * a directory that is not a symlink, `f` a regular file that is not a symlink,
 * and `l` a symlink. An unknown code is reported rather than skipped.
 *
 * @returns The remote script.
 */
export function buildMemberTypeProbeScript(): string {
  return [
    XARGS_PREFIX,
    "for a do ",
    TAGGED_ENTRY_DISPATCH,
    'd) [ -d "$p" ] && [ ! -L "$p" ] || printf "%s\\0" "$p" ;; ',
    'f) [ -f "$p" ] && [ ! -L "$p" ] || printf "%s\\0" "$p" ;; ',
    'l) [ -L "$p" ] || printf "%s\\0" "$p" ;; ',
    '*) printf "%s\\0" "$p" ;; ',
    "esac; ",
    "done; exit 0",
    "' sh",
  ].join("")
}

/** Fields the ownership probe emits per reported path. */
export const OWNERSHIP_PROBE_FIELD_COUNT = 5

/**
 * Probe script reporting ownership for every path it cannot cheaply prove to
 * match.
 *
 * This is deliberately a **conservative pre-filter, not the decision**.
 * `ownershipComponentMatches` accepts either the name or the numeric id per
 * component, and reimplementing that rule in shell is precisely the divergence
 * class that produced #178 — a guard that reads correctly and does nothing. The
 * script therefore only removes paths that obviously match, and TypeScript
 * makes the authoritative call on whatever comes back. It may over-report; it
 * must never under-report. A path whose `stat` fails is emitted with empty
 * fields so the caller sees it rather than losing it.
 *
 * @param expectedUser - The declared user component.
 * @param expectedGroup - The declared group component, empty when unspecified.
 * @returns The remote script.
 */
export function buildOwnershipProbeScript(expectedUser: string, expectedGroup: string): string {
  const script = [
    XARGS_PREFIX,
    "eu=$1; eg=$2; shift 2; ",
    "for p do ",
    's=$(stat -c "%U %G %u %g" -- "$p" 2>/dev/null) || ',
    '{ printf "%s\\0\\0\\0\\0\\0" "$p"; continue; }; ',
    // Pure parameter expansion: `set --` would clobber the positional
    // parameters the enclosing `for p do` is still iterating over.
    `un=$\{s%% *}; r=$\{s#* }; gn=$\{r%% *}; r2=$\{r#* }; ui=$\{r2%% *}; gi=$\{r2#* }; `,
    "ok=0; ",
    'if [ "$un" = "$eu" ] || [ "$ui" = "$eu" ]; then ',
    'if [ -z "$eg" ] || [ "$gn" = "$eg" ] || [ "$gi" = "$eg" ]; then ok=1; fi; ',
    "fi; ",
    '[ "$ok" = 1 ] || printf "%s\\0%s\\0%s\\0%s\\0%s\\0" "$p" "$un" "$gn" "$ui" "$gi"; ',
    "done; exit 0",
    "' sh ",
  ].join("")
  return `${script}${shellQuote(expectedUser)} ${shellQuote(expectedGroup)}`
}

/**
 * Issue #219: the checks {@link buildPreStagingProbeScript} runs per entry.
 *
 * - `l`: the path must not be a symlink (the guard and link-target paths of
 *   the former symlink-only probe).
 * - `n`: the path of a non-directory member (file, hardlink, symlink) must not
 *   be an existing directory that is not a symlink.
 * - `d`: the path of a directory member, or of an implicit ancestor directory
 *   of any member, must not exist as a non-directory that is not a symlink.
 */
export type PreStagingCheck = "d" | "l" | "n"

/**
 * Issue #219: encode one entry for {@link buildPreStagingProbeScript}.
 *
 * Check and path share a single argument for the same reason as in
 * {@link encodeMemberTypeEntry}: `xargs` may split its argument list anywhere,
 * so separate arguments could be re-paired against the wrong path.
 *
 * @param check - The check to run, see {@link PreStagingCheck}.
 * @param path - The absolute destination path.
 * @returns The encoded entry.
 */
export function encodePreStagingEntry(check: PreStagingCheck, path: string): string {
  return `${check}:${path}`
}

/**
 * Probe script for the pre-staging check of `archive.extract`: every guarded
 * path that is a symlink, and every member path whose existing host type the
 * staging merge cannot merge over.
 *
 * Issue #219: `cp -aT --no-dereference --remove-destination` cannot replace a
 * directory with a non-directory, nor merge a directory over a file. Such a
 * conflict used to surface only as a failed merge after other entries had
 * already been copied, and the pre-merge link model assumed the member had
 * replaced whatever the host had there. The checks run in the same single
 * `exec` as the symlink guard, so the probe count stays independent of the
 * member count.
 *
 * Entries are encoded with {@link encodePreStagingEntry}. Paths that do not
 * exist are never violations. An unknown check code is reported with the
 * kind `?`, so the caller fails closed instead of skipping the entry.
 *
 * @returns The remote script. Its output is a flat list of `(check, path)`
 *   field pairs, one pair per violation, NUL-framed; a clean set produces no
 *   output.
 */
export function buildPreStagingProbeScript(): string {
  const report = 'printf "%s\\0%s\\0"'
  return [
    XARGS_PREFIX,
    "for a do ",
    TAGGED_ENTRY_DISPATCH,
    `l) if [ -L "$p" ]; then ${report} l "$p"; fi ;; `,
    `n) if [ -d "$p" ] && [ ! -L "$p" ]; then ${report} n "$p"; fi ;; `,
    `d) if [ ! -L "$p" ] && [ -e "$p" ] && [ ! -d "$p" ]; then ${report} d "$p"; fi ;; `,
    `*) ${report} "?" "$p" ;; `,
    CASE_LOOP_END,
    "' sh",
  ].join("")
}
