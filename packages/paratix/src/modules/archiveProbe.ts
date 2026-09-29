import { posix as pathPosix } from "node:path"

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

export type BatchedProbeOutcome =
  { detail: string; kind: "failed" } | { fields: string[]; kind: "ok" }

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
 * Per-batch body of {@link buildSymlinkListingProbeScript}: the arguments are
 * the symlinks `find` found.
 *
 * - Plain `readlink` without `-f` prints the stored target unchanged. It exists
 *   in GNU coreutils, busybox and the BSDs, and `command -p` looks it up on the
 *   default system PATH so a hijacked PATH cannot substitute it (R-0000693).
 * - The `printf x` sentinel keeps a target that ends in newlines intact; only
 *   the single newline `readlink` itself appends is removed.
 * - A link whose target cannot be read (it vanished, or `readlink` failed)
 *   makes the batch exit 1. `find` then exits non-zero, so the listing fails
 *   closed instead of silently omitting that link.
 * - Issue #219: a missing or unusable `readlink` takes the same path: `command
 *   -p` exits 127 when it finds no `readlink`, the substitution fails and the
 *   batch exits 1. The post-merge backstop relies on this, because a link it
 *   never saw is a link it can neither judge nor remove.
 */
const SYMLINK_LISTING_INNER_SCRIPT = [
  // `nl` holds one newline; the trailing `x` survives command substitution.
  "nl=$(printf '\\nx'); ",
  // `$\{` keeps the shell parameter expansion literal; a bare `${` would be
  // read as JavaScript interpolation.
  `nl=$\{nl%x}; `,
  "for l do ",
  't=$(command -p readlink -- "$l" && printf x) || exit 1; ',
  `t=$\{t%x}; t=$\{t%"$nl"}; `,
  'printf \'%s\\0%s\\0\' "$l" "$t"; done; exit 0',
].join("")

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
 * Issue #219: an `n` entry that is an existing real directory is emitted as
 * the pair `("", path)`. A link path is never empty, so the empty first field
 * tells a directory hit apart from a `(link, target)` pair.
 */
const SYMLINK_LISTING_OUTER_SCRIPT = [
  "inner=$1; shift; for a do ",
  TAGGED_ENTRY_DISPATCH,
  'r) find "$p" -type l -exec sh -c "$inner" sh {} + || exit $?;; ',
  'n) if [ -d "$p" ] && [ ! -L "$p" ]; then printf \'%s\\0%s\\0\' "" "$p"; fi;; ',
  '*) echo "unknown symlink listing entry kind" >&2; exit 64;; ',
  "esac; done; exit 0",
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
 * `readlink` without `-f` only reads the stored target.
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
 * Failure mode: fail closed. A traversal error, an unreadable link target, an
 * unknown entry kind or a failing `sh`/`xargs` makes the exec exit non-zero;
 * the caller treats that, a truncated capture and any output that is not made
 * of pairs with paths below the destination as "containment cannot be
 * proven".
 *
 * @returns The remote script. Its output is a flat list of field pairs: a
 *   `(link, target)` pair per symlink, with the absolute link path and the raw
 *   target exactly as stored, and a `("", path)` pair per `n` entry that is an
 *   existing real directory. A tree without symlinks and without such
 *   directories produces no output.
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
    "esac; done; exit 0",
    "' sh",
  ].join("")
}

/**
 * Outcome value {@link buildSymlinkRemovalScript} reports for a link it
 * removed. `removed:<path>` means the same, with the quarantine directory
 * `<path>` (relative to the destination) left behind; `restored` and
 * `quarantined:<path>` are the two outcomes for an entry that was no longer a
 * symlink once it was in quarantine (see {@link buildSymlinkRemovalScript}).
 * Every other outcome value is the reason the link was left alone.
 */
export const SYMLINK_REMOVED_OUTCOME = "removed"

/** Issue #219: outcome of an entry that was put back at its path unchanged. */
export const SYMLINK_RESTORED_OUTCOME = "restored"

/** Issue #219: prefix of the outcome of an entry left in quarantine. */
export const SYMLINK_QUARANTINED_OUTCOME_PREFIX = "quarantined:"

/**
 * Issue #219: the quarantine steps of {@link buildSymlinkRemovalScript}. They
 * run in the verified parent directory of the link, with `$n` the link's own
 * name, `$p` its parent below the destination and `o` the function that
 * prints the outcome and ends the per-link subshell. `\${` keeps the shell
 * parameter expansion literal.
 *
 * 1. `mktemp -d` creates a fresh directory next to the link (mode 0700), so
 *    the rename below stays on one filesystem and cannot overwrite anything.
 * 2. Inside that private directory the script checks once that `mv -n` moves
 *    to a free name and refuses to replace an existing one. It inspects the
 *    resulting entries instead of trusting the exit status: GNU coreutils,
 *    busybox and the BSDs all accept `-n`, but whether a refused move exits
 *    non-zero differs between versions. Without a working `mv -n` nothing is
 *    touched. It also checks whether `mv -n -T` renames onto a free name
 *    without moving into an existing directory (GNU coreutils, recent
 *    busybox); only then may an entry be moved back later.
 * 3. `mv` renames the link into the private directory. A rename never follows
 *    the link, and the name that was checked is now out of reach of anyone
 *    who can write to the parent directory.
 * 4. If the quarantined entry is a symlink, `rm -f` unlinks it and the empty
 *    directory is removed.
 * 5. Otherwise another entry replaced the link after the listing. It is never
 *    deleted: with `mv -n -T` it is moved back under its name unless that name
 *    was taken again meanwhile, else it stays in quarantine and its path is
 *    reported. Plain `mv` onto a name that is a directory, or a symlink to
 *    one, would move the entry into that directory, which is why the move
 *    back needs `-T`. On coreutils versions whose `mv -n` checks and renames
 *    in two steps, a name created in between can still be replaced.
 */
const SYMLINK_QUARANTINE_SCRIPT = [
  "q=$(mktemp -d ./.paratix-quarantine.XXXXXXXX 2>/dev/null) || ",
  'o "quarantine directory could not be created"; ',
  'case $q in ./.paratix-quarantine.*/*|*"$nl"*) o "quarantine directory could not be created";; ',
  './.paratix-quarantine.?*) ;; *) o "quarantine directory could not be created";; esac; ',
  '[ -d "$q" ] && [ ! -L "$q" ] || o "quarantine directory could not be created"; ',
  `qr=$\{p:+$p/}$\{q#./}; `,
  // Step 2: `mv -n` must move to a free name and must not replace an entry.
  ': > "$q/1" && : > "$q/2" && mv -n -- "$q/1" "$q/3" 2>/dev/null; ',
  'mv -n -- "$q/3" "$q/2" 2>/dev/null; ',
  'if [ ! -e "$q/1" ] && [ -e "$q/2" ] && [ -e "$q/3" ]; then k=1; else k=0; fi; ',
  // `mv -n -T` must not move into an existing directory and must move to a free name.
  'mkdir -- "$q/t" 2>/dev/null && mv -n -T -- "$q/3" "$q/t" 2>/dev/null; ',
  'mv -n -T -- "$q/3" "$q/4" 2>/dev/null; ',
  'if [ ! -e "$q/t/3" ] && [ ! -e "$q/3" ] && [ -e "$q/4" ]; then b=1; else b=0; fi; ',
  'rm -f -- "$q/1" "$q/2" "$q/3" "$q/4" "$q/t/3" 2>/dev/null; rmdir -- "$q/t" 2>/dev/null; ',
  '[ "$k" = 1 ] || { rmdir -- "$q" 2>/dev/null; o "mv -n is unavailable"; }; ',
  // Step 3: rename the link into the private directory.
  'mv -- "./$n" "$q/entry" 2>/dev/null || { rmdir -- "$q" 2>/dev/null; ',
  'o "moving the link into quarantine failed; it was left in place"; }; ',
  // Step 4: a symlink is unlinked.
  'if [ -L "$q/entry" ]; then rm -f -- "$q/entry" 2>/dev/null; ',
  'if [ -e "$q/entry" ] || [ -L "$q/entry" ]; then o "rm failed; the symlink is left in quarantine as $qr/entry"; fi; ',
  `rmdir -- "$q" 2>/dev/null || o "${SYMLINK_REMOVED_OUTCOME}:$qr"; o ${SYMLINK_REMOVED_OUTCOME}; fi; `,
  // Step 5: anything else is moved back, or left in quarantine.
  '[ "$b" = 1 ] && mv -n -T -- "$q/entry" "./$n" 2>/dev/null; ',
  `if [ -e "$q/entry" ] || [ -L "$q/entry" ]; then o "${SYMLINK_QUARANTINED_OUTCOME_PREFIX}$qr/entry"; fi; `,
  `rmdir -- "$q" 2>/dev/null; o ${SYMLINK_RESTORED_OUTCOME}`,
].join("")

/**
 * Per-link body of {@link buildSymlinkRemovalScript}. `$1` is the destination,
 * the remaining arguments are the links from stdin.
 *
 * Issue #219: `unset CDPATH` comes first. A `CDPATH` from the target's
 * environment would let `cd` pick a directory outside the destination for a
 * relative operand and makes `cd` print that directory to stdout, which would
 * corrupt the NUL framing. The `./` prefix on the relative `cd` below keeps
 * `CDPATH` out of play as well.
 */
const SYMLINK_REMOVAL_SCRIPT = [
  "unset CDPATH; ",
  // `nl` holds one newline; the trailing `x` survives command substitution.
  "nl=$(printf '\\nx'); ",
  // `$\{` keeps the shell parameter expansion literal; a bare `${` would be
  // read as JavaScript interpolation.
  `nl=$\{nl%x}; `,
  "d=$1; shift; ",
  "for l do ",
  'case $l in "$d"/?*) ;; *) printf "%s\\0%s\\0" "$l" "not below the destination"; continue;; esac; ',
  // Issue #219: the check above is lexical, so `<destination>/../x` would pass
  // it. Refuse any link whose part below the destination has an empty, `.` or
  // `..` segment (including a trailing `/`) before anything else looks at it.
  `case $\{l#"$d"/} in /*|*/|*//*|.|..|./*|../*|*/.|*/..|*/./*|*/../*) `,
  'printf "%s\\0%s\\0" "$l" "not normalized"; continue;; esac; ',
  // Issue #219: everything below runs in a subshell per link, so the `cd`
  // never leaks into the next link. `r` is the destination-relative path, `n`
  // the link's own name, `p` its parent below the destination (empty for a
  // top-level link) and `e` the canonical parent path `pwd -P` must report.
  // `o` prints the outcome and ends the subshell.
  `( o() { printf "%s\\0%s\\0" "$l" "$1"; exit 0; }; r=$\{l#"$d"/}; n=$\{r##*/}; `,
  `case $r in */*) p=$\{r%/*}; e=$d/$p;; *) p=; e=$d;; esac; `,
  'a="an ancestor directory is missing or a symlink"; ',
  'cd -P -- "$d" 2>/dev/null || o "$a"; ',
  'if [ -n "$p" ]; then cd -P -- "./$p" 2>/dev/null || o "$a"; fi; ',
  // Same sentinel as `nl`: only the single newline `pwd` appends is removed,
  // so a directory name that ends in a newline still compares faithfully.
  'w=$(pwd -P && printf x) || o "$a"; ',
  `w=$\{w%x}; w=$\{w%"$nl"}; `,
  '[ "$w" = "$e" ] || o "$a"; ',
  // From here on every operation is relative to the verified working
  // directory and names only the link itself, never a path through an
  // ancestor. The `[ -L ]` check is only a shortcut; the quarantine steps
  // decide what is removed.
  '[ -L "$n" ] || o "no longer a symlink"; ',
  SYMLINK_QUARANTINE_SCRIPT,
  " ); done; exit 0",
].join("")

/**
 * Script that removes escaping symlinks the post-merge containment check
 * reported, without ever following them.
 *
 * Issue #219: the post-merge backstop used to only record a flag, which left
 * a live escaping link in the destination until the next apply. This script
 * unlinks exactly the links it receives on stdin (NUL-delimited, via
 * {@link runBatchedProbe}); the destination is a fixed argument and never
 * travels on stdin. Per link it requires the path to lie strictly below the
 * destination with no empty, `.` or `..` segment below it (a lexical prefix
 * match alone would accept `<destination>/../x`); a path that is not
 * normalized is reported as `not normalized` and never removed.
 *
 * It then never names the link by its absolute path. In a subshell per link it
 * changes into the destination and from there into the link's parent with
 * `cd -P`, which resolves every symlink on the way, and compares `pwd -P` with
 * the canonical parent path `<destination>/<parent>` (the destination itself
 * for a top-level link). The destination is canonical, and `pwd -P` reports
 * the physical path of the directory the shell is now in, so a match proves
 * that every component from the destination down to the parent was a real
 * directory when `cd` walked it: an ancestor that was a symlink would have
 * landed the shell somewhere whose physical path differs. A failed `cd` or a
 * mismatch is reported as `an ancestor directory is missing or a symlink` and
 * removes nothing. The previous form checked the ancestors with `[ -L ]` and
 * then ran `rm` on the absolute path, so an ancestor swapped for a symlink
 * between check and `rm` redirected the `rm` outside the destination; now the
 * working directory is pinned before the check and every later operation names
 * only the final component relative to it, so no path operation ever follows
 * an ancestor.
 *
 * Issue #219: checking `[ -L <name> ]` and then running `rm -f <name>` left a
 * window in which another writer could replace the link with a different
 * entry, which `rm` would then delete. The link is therefore first renamed
 * into a fresh private quarantine directory next to it and inspected there,
 * where nobody else can swap it: a symlink is unlinked, anything else is moved
 * back or left in quarantine, never deleted. The steps and their portability
 * are described at {@link SYMLINK_QUARANTINE_SCRIPT}. Nothing is followed,
 * nothing is removed recursively, and a quarantine directory created by an
 * earlier run is never touched, because each link gets a new one.
 *
 * @param destination - The validated, canonical destination directory.
 * @returns The remote command. Its output is a flat list of `(link, outcome)`
 *   field pairs, NUL-framed, one per received link, each naming the link by the
 *   absolute path it was received as: the outcome is
 *   {@link SYMLINK_REMOVED_OUTCOME} (optionally with `:<quarantine directory>`
 *   left behind), {@link SYMLINK_RESTORED_OUTCOME},
 *   {@link SYMLINK_QUARANTINED_OUTCOME_PREFIX}`<path>` or the reason the link
 *   was left in place.
 */
export function buildSymlinkRemovalScript(destination: string): string {
  return `xargs -0 sh -c ${shellQuote(SYMLINK_REMOVAL_SCRIPT)} sh ${shellQuote(destination)}`
}

/**
 * Issue #219: what `removeEscapingSymlinks` (see `archiveContainmentEnforcement.ts`) did with the links it was
 * given. `kept` pairs each link that is still in place (or whose fate is
 * unknown) with the reason. `notes` pairs removed links with something the
 * operator should know, such as a quarantine directory that was left behind.
 */
export type SymlinkRemovalReport = {
  kept: Array<readonly [string, string]>
  notes: Array<readonly [string, string]>
  removed: string[]
}

/**
 * Issue #219: decide in TypeScript whether a link path the containment check
 * reported may be handed to the removal script at all.
 *
 * Only a path strictly below the destination that is already normalized — no
 * empty, `.` or `..` segment, equal to its `posix.normalize` form — and free of
 * NUL bytes qualifies. Anything else is never removed.
 *
 * @param destination - The validated, canonical destination directory.
 * @param link - A link path as the probe reported it.
 * @returns Null when the path may be removed, otherwise why it is left alone.
 */
export function escapingSymlinkRemovalRefusal(destination: string, link: string): null | string {
  if (link.includes("\0")) return "path contains a NUL byte"
  const prefix = `${destination}/`
  if (!link.startsWith(prefix) || link.length === prefix.length) {
    return "path is not strictly below the destination"
  }
  const segments = link.slice(prefix.length).split("/")
  const irregular = segments.some(
    (segment) => segment === "" || segment === "." || segment === ".."
  )
  if (irregular || pathPosix.normalize(link) !== link) return "path is not normalized"
  return null
}

/**
 * Issue #219: sort one link's removal outcome into the report.
 *
 * @param report - The report being built, updated in place.
 * @param link - The link the outcome belongs to.
 * @param outcome - The outcome the removal script printed, if any.
 */
function recordRemovalOutcome(
  report: SymlinkRemovalReport,
  link: string,
  outcome: string | undefined
): void {
  const leftoverPrefix = `${SYMLINK_REMOVED_OUTCOME}:`
  if (outcome === SYMLINK_REMOVED_OUTCOME) {
    report.removed.push(link)
  } else if (outcome?.startsWith(leftoverPrefix) === true) {
    report.removed.push(link)
    const leftover = outcome.slice(leftoverPrefix.length)
    report.notes.push([
      link,
      `quarantine directory ${JSON.stringify(leftover)} below the destination was left behind`,
    ])
  } else if (outcome === SYMLINK_RESTORED_OUTCOME) {
    report.kept.push([link, "no longer a symlink; restored at its path"])
  } else if (outcome?.startsWith(SYMLINK_QUARANTINED_OUTCOME_PREFIX) === true) {
    const path = outcome.slice(SYMLINK_QUARANTINED_OUTCOME_PREFIX.length)
    report.kept.push([
      link,
      `no longer a symlink; left in quarantine as ${JSON.stringify(path)} below the destination`,
    ])
  } else {
    report.kept.push([link, outcome ?? "no outcome reported"])
  }
}

/**
 * Issue #219: turn the removal script's output into a report, failing closed.
 *
 * A failed exec, a truncated capture, an odd field count, a link that was not
 * requested or a link reported twice make every requested link's outcome
 * unknown, so all of them are reported as not removed. A requested link without
 * an outcome record is reported as not removed as well. An entry that was no
 * longer a symlink in quarantine is reported as kept, whether it was restored
 * at its path or left in quarantine.
 *
 * @param requested - The links handed to {@link buildSymlinkRemovalScript}.
 * @param outcome - The batched probe outcome of the removal exec.
 * @returns Which links were removed and which were kept, with reasons.
 */
export function symlinkRemovalReport(
  requested: readonly string[],
  outcome: BatchedProbeOutcome
): SymlinkRemovalReport {
  const unknown = (reason: string): SymlinkRemovalReport => ({
    kept: requested.map((link) => [link, `removal outcome unknown: ${reason}`] as const),
    notes: [],
    removed: [],
  })
  if (outcome.kind === "failed") return unknown(outcome.detail)
  const { fields } = outcome
  if (fields.length % 2 !== 0) {
    return unknown(
      `removal returned ${String(fields.length)} fields, expected (link, outcome) pairs`
    )
  }
  const expected = new Set(requested)
  const outcomes = new Map<string, string>()
  for (let index = 0; index < fields.length; index += 2) {
    const link = fields[index]
    if (!expected.has(link) || outcomes.has(link)) {
      return unknown(`removal reported unexpected link ${JSON.stringify(link)}`)
    }
    outcomes.set(link, fields[index + 1])
  }
  const report: SymlinkRemovalReport = { kept: [], notes: [], removed: [] }
  for (const link of requested) recordRemovalOutcome(report, link, outcomes.get(link))
  return report
}

/**
 * Issue #219: remove the given escaping links with one batched exec, never
 * following them. `archiveContainmentEnforcement.ts` re-exports it next to
 * the backstop that calls it.
 *
 * Each link is first vetted by {@link escapingSymlinkRemovalRefusal}; only the
 * vetted ones reach {@link buildSymlinkRemovalScript}, which pins its working
 * directory to the link's verified parent, moves only the final component
 * into a private quarantine directory and unlinks it there when it is still a
 * symlink.
 *
 * @param conn - The SSH connection.
 * @param destination - The validated, canonical destination directory.
 * @param links - The absolute link paths the containment check reported.
 * @returns Which links were removed and which were kept, with reasons.
 */
export async function removeEscapingSymlinks(
  conn: SshConnection,
  destination: string,
  links: readonly string[]
): Promise<SymlinkRemovalReport> {
  const refused: Array<readonly [string, string]> = []
  const vetted: string[] = []
  for (const link of new Set(links)) {
    const refusal = escapingSymlinkRemovalRefusal(destination, link)
    if (refusal === null) vetted.push(link)
    else refused.push([link, refusal])
  }
  const outcome = await runBatchedProbe(conn, {
    entries: vetted,
    script: buildSymlinkRemovalScript(destination),
  })
  const report = symlinkRemovalReport(vetted, outcome)
  return { kept: [...refused, ...report.kept], notes: report.notes, removed: report.removed }
}
