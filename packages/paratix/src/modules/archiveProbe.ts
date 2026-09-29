import type { SshConnection } from "../types.js"

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

const PROBE_EXEC_OPTS = { ignoreExitCode: true, silent: true } as const

/** Shared prefix: read the NUL payload from stdin and hand it to a POSIX `sh`. */
const XARGS_PREFIX = "xargs -0 sh -c '"

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
 * @param conn - The SSH connection.
 * @param parameters - Probe inputs.
 * @param parameters.entries - The NUL-transported entries; an empty list runs nothing.
 * @param parameters.script - The remote script to execute.
 * @returns The decoded fields, or a failure with its diagnostic detail.
 */
export async function runBatchedProbe(
  conn: SshConnection,
  parameters: { entries: string[]; script: string }
): Promise<BatchedProbeOutcome> {
  if (parameters.entries.length === 0) return { fields: [], kind: "ok" }
  const result = await conn.exec(parameters.script, {
    ...PROBE_EXEC_OPTS,
    input: encodeNulPayload(parameters.entries),
  })
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
      detail: `probe output exceeded the captured-output cap of ${String(DEFAULT_MAX_OUTPUT_BYTES)} bytes; refusing to evaluate a truncated result`,
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
 * Per-batch body of {@link buildSymlinkContainmentProbeScript}: `$1` is the
 * destination, the remaining arguments are the symlinks `find` found.
 *
 * - `command -p realpath -m` is the hardened resolver already used in `ssh.ts`
 *   and `aptKeyStaging.ts` (R-0000693): `command -p` looks `realpath` up on the
 *   default system PATH, so a hijacked PATH on the target cannot substitute it.
 * - `-m` resolves dangling links and missing intermediate components. GNU
 *   `readlink -f` fails on a dangling link with a missing non-final component,
 *   so a dangling link whose resolved path stays inside the destination passes
 *   here instead of being reported. Symlink loops also resolve under `-m`
 *   without an error.
 * - The `printf x` sentinel keeps a resolved path that ends in newlines intact.
 *   Command substitution strips every trailing newline, which could make a
 *   sibling such as `/opt/app<newline>` compare equal to `/opt/app`; only the
 *   single newline `realpath` itself appends is removed.
 * - A link that cannot be resolved at all is reported with an empty resolved
 *   field, so the caller fails closed instead of skipping it.
 * - The quoted `"$d"` in the `case` pattern is matched literally, not as a
 *   glob. The destination is already canonical (validated `readlink -f` equal
 *   to itself, and `/` is rejected by `validateExtractDestination`), so a plain
 *   prefix comparison is correct.
 */
const SYMLINK_CONTAINMENT_INNER_SCRIPT = [
  // `nl` holds one newline; the trailing `x` survives command substitution.
  "nl=$(printf '\\nx'); ",
  // `$\{` keeps the shell parameter expansion literal; a bare `${` would be
  // read as JavaScript interpolation.
  `nl=$\{nl%x}; `,
  "d=$1; shift; ",
  "for l do ",
  'r=$(command -p realpath -m -- "$l" && printf x) || { printf \'%s\\0\\0\' "$l"; continue; }; ',
  `r=$\{r%x}; r=$\{r%"$nl"}; `,
  'case $r in "$d"|"$d"/*) ;; *) printf \'%s\\0%s\\0\' "$l" "$r";; esac; done; exit 0',
].join("")

/**
 * Outer body of {@link buildSymlinkContainmentProbeScript}: `$1` is the inner
 * script, the remaining arguments are the destinations from stdin.
 *
 * `find` without `-L` never follows a symlink, so the walk stays inside the
 * destination tree. A traversal error makes `find` exit non-zero, which the
 * `|| exit $?` turns into a failed probe (fail closed) rather than a partial
 * result read as clean.
 */
const SYMLINK_CONTAINMENT_OUTER_SCRIPT =
  'inner=$1; shift; for d do find "$d" -type l -exec sh -c "$inner" sh "$d" {} + || exit $?; done; exit 0'

/**
 * Probe script reporting every symlink below a destination whose fully
 * resolved target lies outside that destination.
 *
 * Issue #219: this checks the whole tree after the merge, including links that
 * earlier runs or the host left there, because a link that was contained when
 * it was written can be redirected by a link a later archive places on its
 * path. It is meant for {@link runBatchedProbe} with the destination as the
 * single entry, so it costs exactly one `exec` regardless of member count.
 *
 * The composed command is `xargs -0 sh -c <outer> sh <inner>`: `xargs` appends
 * the NUL-delimited stdin entries after `<inner>`, so the outer script receives
 * the inner script as `$1` and the destinations after it. Both bodies contain
 * single quotes and are therefore composed with `shellQuote` instead of the
 * literal `XARGS_PREFIX`. Link paths travel as arguments and results come back
 * NUL-framed, so newlines in link names are safe.
 *
 * @returns The remote script. Its output is a flat list of `(link, resolved)`
 *   field pairs, one pair per violation; an empty `resolved` field means the
 *   link could not be resolved. A converged tree produces no output.
 */
export function buildSymlinkContainmentProbeScript(): string {
  return `xargs -0 sh -c ${shellQuote(SYMLINK_CONTAINMENT_OUTER_SCRIPT)} sh ${shellQuote(SYMLINK_CONTAINMENT_INNER_SCRIPT)}`
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
    // `$\{` keeps the shell parameter expansion literal; a bare `${` would be
    // read as JavaScript interpolation.
    `k=$\{a%%:*}; p=$\{a#*:}; `,
    "case $k in ",
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
