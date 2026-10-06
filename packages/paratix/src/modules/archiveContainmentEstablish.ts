/**
 * The establish path of the `archive.extract` containment entries: the one exec that reads every
 * entry and creates the apply's own `in-progress` entry before the destination is touched, the
 * parsing of its output into the ledger, and why a refused exec failed.
 */

import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import {
  CONTAINMENT_FLAG_BODY_LIMIT_BYTES,
  containmentEntryForScope,
  containmentFlagBody,
  type ContainmentPaths,
  IN_PROGRESS_STATE,
  parseContainmentEntryBytes,
  type ParsedContainmentFlag,
} from "./archiveContainmentFlag.js"

/**
 * Issue #219: how many entries the establish exec reads in full. It still
 * type-checks every further entry, but only reports that there are more,
 * which makes the apply verify the whole destination.
 */
export const CONTAINMENT_ENTRY_READ_LIMIT = 16

/** Issue #219: the bytes the establish exec reads of one entry: one more than the limit. */
const ENTRY_READ_BYTES = CONTAINMENT_FLAG_BODY_LIMIT_BYTES + 1

/** Issue #219: the longest file name the establish exec can report. */
const ENTRY_NAME_MAX_BYTES = 255

/** Issue #219: the hex digits of a sha256 digest. */
const SHA256_HEX_LENGTH = 64

/** Issue #219: the longest read line, `entry <name> <sha256> <hex>` and its newline. */
const ESTABLISH_LINE_MAX_BYTES =
  "entry ".length + ENTRY_NAME_MAX_BYTES + 1 + SHA256_HEX_LENGTH + 1 + 2 * ENTRY_READ_BYTES + 1
const ESTABLISH_HEADROOM_BYTES = 1024

/**
 * Issue #219: the capture cap of the establish exec: one full line per entry
 * read plus the old flag file (the hex twice the bytes read), the `more` and
 * `done` lines, and headroom. A capture within the bounds is therefore never
 * cut.
 */
export const CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES =
  (CONTAINMENT_ENTRY_READ_LIMIT + 1) * ESTABLISH_LINE_MAX_BYTES + ESTABLISH_HEADROOM_BYTES

/**
 * Issue #219: exit statuses of the establish exec, see
 * {@link buildContainmentEstablishScript}.
 */
export const CONTAINMENT_ESTABLISH_EXIT = {
  entryName: 10,
  entryNotRegular: 9,
  entrySymlink: 8,
  entryUnreadable: 11,
  flagsDirectory: 2,
  legacyNotRegular: 4,
  legacySymlink: 3,
  legacyUnreadable: 12,
  ownEntry: 13,
  storeInaccessible: 7,
  storeNotDirectory: 6,
  storeSymlink: 5,
} as const

/** Issue #219: the names the establish exec reports as entries. */
const ENTRY_NAME_PATTERN = /^run-[\dA-Za-z\-]*$/v
const SHA256_PATTERN = /^[\da-f]{64}$/v
const HEX_DIGITS_PATTERN = /^[\da-f]*$/v

/**
 * Issue #219: the POSIX `sh` function that prints one read line: its label,
 * the sha256 of the file and then the hex of its first bytes. The hash is
 * taken BEFORE the body is read: an entry replaced by a rename in between
 * then shows the old hash with the newer body, never the other way round, so
 * a removal keyed on the hash can never erase a newer record nobody read. A
 * file that vanishes between hash and body reads as an empty body, which
 * holds no usable list. `paratix_gone` tells a path that vanished apart from
 * one that is there but fails a guard.
 */
const READ_LINE_FUNCTION = [
  String.raw`paratix_read() { `,
  String.raw`h=$(sha256sum < "$2" | cut -c1-64); `,
  String.raw`case $h in ''|*[!0-9a-f]*) return 1;; esac; `,
  // Not `String.raw`: `$\{` emits a literal shell parameter expansion.
  `[ "$\{#h}" -eq 64 ] || return 1; `,
  String.raw`printf '%s %s ' "$1" "$h"; `,
  `head -c ${String(ENTRY_READ_BYTES)} < "$2" | od -An -v -tx1 | tr -d ' \\n'; `,
  String.raw`printf '\n'; }; `,
  // Issue #219: whether a path is gone, a dangling symlink counting as present.
  String.raw`paratix_gone() { [ ! -e "$1" ] && [ ! -L "$1" ]; }; `,
].join("")

/**
 * Issue #219: the establish script. Positional parameters: `$1` flags
 * directory, `$2` old flag file, `$3` entry directory, `$4` own entry (inside
 * `$3`), `$5` its body.
 *
 * In order, and nothing is created before every guard passed:
 *
 * 1. `mkdir -p` the flags directory, else exit 2.
 * 2. The old flag file: a symlink (even a dangling one) exits 3, anything
 *    else that is not a regular file 4, an unreadable one 12.
 * 3. The entry directory: a symlink exits 5; a missing one is created; one
 *    that is (still) not a directory exits 6, one that is not readable,
 *    writable and searchable 7.
 * 4. Every name matching `run-*` (sorted, the no-match literal skipped): a
 *    name with characters other than ASCII letters, digits and `-` exits 10,
 *    a symlink 8, anything else that is not a regular file 9, an unreadable
 *    one 11; the entry name goes to stderr. The first
 *    {@link CONTAINMENT_ENTRY_READ_LIMIT} are printed as
 *    `entry <name> <sha256> <hex>`, any further ones only as one `more` line.
 *    Other names — dotfiles and the `paratix-write.*` temp files of
 *    `writeFile` — are never entries.
 * 5. The old flag file, when present: `legacy <sha256> <hex>`.
 * 6. The own entry is created exclusively: an existing name (a dangling
 *    symlink included) or a failed write exits 13. `set -C` opens a missing
 *    name with `O_EXCL`, which never follows a symlink and never replaces a
 *    file.
 * 7. `done`.
 *
 * Issue #219: an entry, or the old flag file, that vanishes while the script
 * looks at it — a concurrent clear claimed it with `mv`, or its owner removed
 * it — is skipped instead of failing a guard: its claimer verified and removed
 * it, or it survives under a claim name created after this glob, which this
 * apply never touches (race 2). Without that, concurrent applies refused each
 * other at random.
 *
 * `LC_ALL=C` keeps the glob order and the name ranges byte-wise, and
 * `umask 022` makes the entry directory and the own entry world-readable, as
 * the flags have always been.
 *
 * @returns The script, identical for every destination.
 */
export function buildContainmentEstablishScript(): string {
  const exit = CONTAINMENT_ESTABLISH_EXIT
  return [
    String.raw`LC_ALL=C; export LC_ALL; umask 022; `,
    READ_LINE_FUNCTION,
    `mkdir -p -- "$1" || exit ${String(exit.flagsDirectory)}; `,
    `if [ -L "$2" ]; then exit ${String(exit.legacySymlink)}; fi; `,
    `if [ -e "$2" ] && [ ! -f "$2" ] && ! paratix_gone "$2"; then exit ${String(exit.legacyNotRegular)}; fi; `,
    `if [ -e "$2" ] && [ ! -r "$2" ] && ! paratix_gone "$2"; then exit ${String(exit.legacyUnreadable)}; fi; `,
    `if [ -L "$3" ]; then exit ${String(exit.storeSymlink)}; fi; `,
    `if [ ! -e "$3" ]; then mkdir -- "$3" 2>/dev/null || [ -d "$3" ] || exit ${String(exit.storeNotDirectory)}; fi; `,
    `if [ -L "$3" ]; then exit ${String(exit.storeSymlink)}; fi; `,
    `[ -d "$3" ] || exit ${String(exit.storeNotDirectory)}; `,
    `[ -r "$3" ] && [ -w "$3" ] && [ -x "$3" ] || exit ${String(exit.storeInaccessible)}; `,
    String.raw`n=0; more=0; `,
    String.raw`for e in "$3"/run-*; do `,
    String.raw`if [ ! -e "$e" ] && [ ! -L "$e" ]; then continue; fi; `,
    `name=$\{e##*/}; `,
    `case $name in *[!A-Za-z0-9-]*) exit ${String(exit.entryName)};; esac; `,
    `if [ -L "$e" ]; then printf '%s\\n' "$name" >&2; exit ${String(exit.entrySymlink)}; fi; `,
    `if [ ! -f "$e" ]; then paratix_gone "$e" && continue; printf '%s\\n' "$name" >&2; exit ${String(exit.entryNotRegular)}; fi; `,
    `if [ ! -r "$e" ]; then paratix_gone "$e" && continue; printf '%s\\n' "$name" >&2; exit ${String(exit.entryUnreadable)}; fi; `,
    `if [ "$n" -ge ${String(CONTAINMENT_ENTRY_READ_LIMIT)} ]; then more=1; continue; fi; `,
    String.raw`if paratix_read "entry $name" "$e"; then n=$((n + 1)); continue; fi; `,
    `paratix_gone "$e" && continue; printf '%s\\n' "$name" >&2; exit ${String(exit.entryUnreadable)}; `,
    String.raw`done; `,
    `if [ -L "$2" ]; then exit ${String(exit.legacySymlink)}; fi; `,
    `if [ -e "$2" ] && [ ! -f "$2" ] && ! paratix_gone "$2"; then exit ${String(exit.legacyNotRegular)}; fi; `,
    `if [ -f "$2" ] && ! paratix_read legacy "$2" && ! paratix_gone "$2"; then exit ${String(exit.legacyUnreadable)}; fi; `,
    String.raw`if [ "$more" = 1 ]; then printf 'more\n'; fi; `,
    `if [ -e "$4" ] || [ -L "$4" ]; then exit ${String(exit.ownEntry)}; fi; `,
    `( set -C; printf '%s' "$5" > "$4" ) || exit ${String(exit.ownEntry)}; `,
    String.raw`printf 'done\n'`,
  ].join("")
}

/**
 * Issue #227: the inputs of the establish exec and of reading its output.
 *
 * - `ownEntry`: the own entry's absolute path inside the entry directory.
 * - `scopeDigest`: the digest of this apply's containment scope, see
 *   `containmentScopeDigest`; the own entry records it, and an entry that
 *   records the same digest is covered by this apply's scoped verification.
 */
export type ContainmentEstablishInputs = {
  ownEntry: string
  scopeDigest: string
} & ContainmentPaths

/**
 * Issue #219: the establish exec as an explicit `sh -c` command with the
 * paths as positional parameters, see {@link buildContainmentEstablishScript}.
 * Issue #227: `$5` is the v2 `in-progress` body with the scope digest; its
 * size is fixed, so it stays in argv whatever the member count.
 *
 * @param parameters - Paths, the own entry and the scope digest.
 * @param parameters.directory - The flags directory.
 * @param parameters.entryDirectory - The destination's entry directory.
 * @param parameters.legacyFlag - The old single flag file.
 * @param parameters.ownEntry - The own entry's absolute path inside the entry directory.
 * @param parameters.scopeDigest - The digest of this apply's containment scope.
 * @returns The `sh -c` command line with the quoted script and parameters.
 */
export function buildContainmentEstablishCommand(parameters: ContainmentEstablishInputs): string {
  return [
    "sh -c",
    shellQuote(buildContainmentEstablishScript()),
    "sh",
    shellQuote(parameters.directory),
    shellQuote(parameters.legacyFlag),
    shellQuote(parameters.entryDirectory),
    shellQuote(parameters.ownEntry),
    shellQuote(containmentFlagBody({ scope: parameters.scopeDigest, state: IN_PROGRESS_STATE })),
  ].join(" ")
}

/**
 * Issue #219: an entry the successful apply may remove, with the sha256 its
 * content had when the establish exec read it.
 */
export type RemovableContainmentEntry = { path: string; sha256: string }

/**
 * Issue #219: what an apply learned from the entries before it touched the
 * destination, and where its own entry is.
 *
 * - `carried`: the links failed applies recorded; the post-merge backstop
 *   re-verifies them.
 * - `ownEntry`: the absolute path of this apply's own entry.
 * - `removable`: every entry read in full, the old flag file included, never
 *   the own entry; a fully successful apply removes those still unchanged.
 * - `verifyWholeDestination`: an entry held no usable list, the old flag file
 *   exists, or not every entry could be read, so the post-merge backstop
 *   judges every symlink under the destination.
 */
export type ContainmentLedger = {
  carried: readonly string[]
  ownEntry: string
  removable: readonly RemovableContainmentEntry[]
  verifyWholeDestination: boolean
}

/** Issue #219: an entry (or the old flag file) the establish exec read. */
type ReadContainmentEntry = { path: string; sha256: string; state: ParsedContainmentFlag }

/** Issue #219: one decoded line of the establish output. */
type EstablishLine =
  { kind: "done" } | ({ kind: "entry" } & ReadContainmentEntry) | { kind: "more" }

/**
 * Issue #219: decode one read line's hash and hex body.
 *
 * @param path - The absolute path of the entry that was read.
 * @param sha256 - The printed hash.
 * @param hex - The printed hex of the first bytes.
 * @returns The decoded line, or null when the fields are malformed.
 */
function readEntryLine(path: string, sha256 = "", hex = ""): EstablishLine | null {
  if (!SHA256_PATTERN.test(sha256) || !HEX_DIGITS_PATTERN.test(hex) || hex.length % 2 !== 0) {
    return null
  }
  return { kind: "entry", path, sha256, state: parseContainmentEntryBytes(Buffer.from(hex, "hex")) }
}

/**
 * Issue #219: decode one line of the establish output.
 *
 * @param line - The line, without its newline.
 * @param paths - The containment paths, to make entry paths absolute.
 * @returns The decoded line, or null when it is not one the script prints.
 */
function parseEstablishLine(line: string, paths: ContainmentPaths): EstablishLine | null {
  if (line === "done" || line === "more") return { kind: line }
  const [label, ...fields] = line.split(" ")
  if (label === "legacy" && fields.length === 2) {
    return readEntryLine(paths.legacyFlag, ...fields)
  }
  const [name = "", ...read] = fields
  if (label !== "entry" || read.length !== 2 || !ENTRY_NAME_PATTERN.test(name)) return null
  return readEntryLine(`${paths.entryDirectory}/${name}`, ...read)
}

/**
 * Issue #219: decode every line before the final `done` line.
 *
 * @param stdout - The captured stdout of a successful establish exec.
 * @param paths - The containment paths.
 * @returns The decoded lines, or null when a line is not one the script
 *   prints or `done` is missing or not last.
 */
function establishLines(stdout: string, paths: ContainmentPaths): EstablishLine[] | null {
  const doneLine = "done\n"
  if (stdout !== doneLine && !stdout.endsWith(`\n${doneLine}`)) return null
  const body = stdout.slice(0, -doneLine.length)
  const lines = body === "" ? [] : body.slice(0, -1).split("\n")
  const parsed = lines.map((line) => parseEstablishLine(line, paths))
  return parsed.every((line) => line !== null && line.kind !== "done") ? parsed : null
}

/**
 * Issue #219: turn the output of a successful establish exec into the
 * ledger. A truncated capture makes the apply verify the whole destination
 * and removes no other entry; output the script does not print, or a missing
 * `done` line, returns null (unreadable).
 *
 * Issue #227: an entry whose scope digest equals this apply's is removable,
 * carries no links and needs no destination-wide verification; one with
 * another digest counts as unknown.
 *
 * @param stdout - The captured stdout.
 * @param parameters - The containment paths, the own entry's absolute path
 *   and this apply's scope digest.
 * @returns The ledger, or null when the output cannot be trusted.
 */
export function parseContainmentEstablishOutput(
  stdout: string,
  parameters: ContainmentEstablishInputs
): ContainmentLedger | null {
  const { legacyFlag, ownEntry, scopeDigest } = parameters
  if (stdout.endsWith(CAPTURE_TRUNCATION_MARKER)) {
    return { carried: [], ownEntry, removable: [], verifyWholeDestination: true }
  }
  const lines = establishLines(stdout, parameters)
  if (lines === null) return null
  const entries = lines.flatMap((line) => (line.kind === "entry" ? [line] : []))
  if (entries.some(({ path }) => path === ownEntry)) return null
  const recorded = entries.flatMap(({ state }) => (state.kind === "recorded" ? state.links : []))
  return {
    carried: [...new Set(recorded)],
    ownEntry,
    removable: entries.map(({ path, sha256 }) => ({ path, sha256 })),
    // Issue #219: the old flag file forces a destination-wide verification
    // whatever it records, like an entry without a usable list and like
    // entries past the read limit.
    verifyWholeDestination:
      lines.some(({ kind }) => kind === "more") ||
      entries.some(
        ({ path, state }) =>
          path === legacyFlag || containmentEntryForScope(state, scopeDigest).kind === "unknown"
      ),
  }
}

/**
 * Issue #219: the entry name the establish exec wrote to stderr, as an
 * absolute path, or the entry directory when stderr names none.
 *
 * @param entryDirectory - Where the entries live.
 * @param stderr - The exec's stderr, whose last line may name the entry.
 * @returns The offending entry's absolute path, or a phrase naming the entry
 *   directory.
 */
function offendingEntryPath(entryDirectory: string, stderr: string): string {
  const name = stderr.trimEnd().split("\n").at(-1) ?? ""
  return ENTRY_NAME_PATTERN.test(name)
    ? `${entryDirectory}/${name}`
    : `an entry in ${entryDirectory}`
}

/**
 * Issue #219: why an establish exec exited non-zero. Every refusal names the
 * offending path and says to remove it where that resolves it.
 *
 * @param paths - The destination's containment paths, for the message.
 * @param result - The exec's exit code and stderr.
 * @param result.code - The exit code.
 * @param result.stderr - The captured stderr.
 * @returns The reason, without the `[archive.extract]` prefix.
 */
export function containmentEstablishFailure(
  paths: ContainmentPaths,
  result: { code: number; stderr: string }
): string {
  const { entryDirectory, legacyFlag } = paths
  const detail = result.stderr.trim() || `exit code ${String(result.code)}`
  const exit = CONTAINMENT_ESTABLISH_EXIT
  const entry = (): string => offendingEntryPath(entryDirectory, result.stderr)
  const reasons: Record<number, (() => string) | undefined> = {
    [exit.entryName]: () =>
      `containment entry directory ${entryDirectory} holds a run-* entry whose name has characters other than ASCII letters, digits and "-"; remove that entry`,
    [exit.entryNotRegular]: () =>
      `containment entry ${entry()} exists but is not a regular file; remove it`,
    [exit.entrySymlink]: () => `containment entry ${entry()} is a symlink; remove it`,
    [exit.entryUnreadable]: () => `failed to read containment entry ${entry()}`,
    [exit.flagsDirectory]: () =>
      `failed to create archive marker directory for containment entries ${entryDirectory}: ${detail}`,
    [exit.legacyNotRegular]: () =>
      `containment-failure flag ${legacyFlag} exists but is not a regular file; remove it`,
    [exit.legacySymlink]: () => `containment-failure flag ${legacyFlag} is a symlink; remove it`,
    [exit.legacyUnreadable]: () =>
      `failed to read containment-failure flag ${legacyFlag}: ${detail}`,
    [exit.ownEntry]: () => `failed to create containment entry in ${entryDirectory}: ${detail}`,
    [exit.storeInaccessible]: () =>
      `containment entry directory ${entryDirectory} is not readable, writable and searchable`,
    [exit.storeNotDirectory]: () =>
      `containment entry directory ${entryDirectory} is not a directory and cannot be created; remove it`,
    [exit.storeSymlink]: () =>
      `containment entry directory ${entryDirectory} is a symlink; remove it`,
  }
  return (
    reasons[result.code]?.() ?? `failed to read containment entries in ${entryDirectory}: ${detail}`
  )
}

/**
 * Issue #219: read every entry and create the own `in-progress` entry in ONE
 * exec, before the destination is touched; the exec count is one whatever
 * the number of entries or members.
 *
 * A guard that fails — a symlink or other non-regular old flag file or entry,
 * an entry directory that is a symlink, not a directory or not accessible, a
 * flags directory that cannot be created, a read that fails, an own entry
 * that cannot be created — refuses the apply before anything else happens,
 * and so does an exec that throws or prints what the script does not. An
 * entry without a usable list of offending links does not refuse: the apply
 * runs and verifies the whole destination after its merge. Issue #227: the
 * own entry records the scope digest, and an entry with the same digest needs
 * no destination-wide verification.
 *
 * @param conn - The SSH connection.
 * @param parameters - Establish inputs.
 * @param parameters.ownEntryName - The own entry's name, see `newContainmentEntryName` in `archiveContainmentFlag.ts`.
 * @param parameters.paths - Where the containment state lives.
 * @param parameters.scopeDigest - The digest of this apply's containment
 *   scope, see `containmentScopeDigest`.
 * @param parameters.source - The archive source, for failure messages.
 * @returns The ledger, see {@link ContainmentLedger}, or the refusal.
 */
export async function establishContainmentEntry(
  conn: SshConnection,
  parameters: { ownEntryName: string; paths: ContainmentPaths; scopeDigest: string; source: string }
): Promise<ContainmentLedger | ModuleResult> {
  const { ownEntryName, paths, scopeDigest, source } = parameters
  const refusal = (reason: string): ModuleResult =>
    failed(
      `[archive.extract] refusing to extract ${source}: ${reason}; the containment entry must be in place before the destination is touched`
    )
  const inputs = { ...paths, ownEntry: `${paths.entryDirectory}/${ownEntryName}`, scopeDigest }
  let result: Awaited<ReturnType<SshConnection["exec"]>>
  try {
    result = await conn.exec(buildContainmentEstablishCommand(inputs), {
      ignoreExitCode: true,
      maxOutputBytes: CONTAINMENT_ESTABLISH_CAPTURE_LIMIT_BYTES,
      silent: true,
    })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return refusal(`failed to read containment entries in ${paths.entryDirectory}: ${reason}`)
  }
  if (result.code !== 0) return refusal(containmentEstablishFailure(paths, result))
  const ledger = parseContainmentEstablishOutput(result.stdout, inputs)
  if (ledger === null) {
    return refusal(
      `failed to read containment entries in ${paths.entryDirectory}: unexpected output`
    )
  }
  return ledger
}
