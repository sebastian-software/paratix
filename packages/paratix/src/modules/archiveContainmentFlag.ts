/* eslint-disable max-lines -- Issue #219: the entry body format and the establish, clear and check scripts that read and write it stay together */
/**
 * The containment entries of `archive.extract` and the offending links they
 * record.
 *
 * Issue #219: every destination has one entry directory,
 * `…/archive-containment-<sha256(destination)>.d`, and every apply owns one
 * entry in it, `run-<32 lowercase hex>`. One shared flag file per destination
 * let two concurrent applies overwrite and remove each other's record: a
 * successful apply erased the failure a concurrent one had just recorded,
 * without looking at the link that caused it. An entry body is versioned
 * JSON:
 *
 * - `{"version":1,"state":"in-progress","links":[]}` is what an apply creates
 *   before it touches the destination. It reads as unknown: an apply that
 *   stopped without recording its outcome may have published links nobody
 *   checked.
 * - `{"version":1,"state":"failed","links":[…]}` is written when an apply
 *   fails and every link that still needs verification is known; the list is
 *   complete and may be empty.
 * - `{"version":1,"state":"unknown","reason":"…"}` is written when an apply
 *   fails and the offending links could not be identified, or there are too
 *   many of them to record.
 *
 * An apply reads every entry before it touches the destination (see
 * {@link establishContainmentEntry}), re-verifies the recorded links in its
 * post-merge backstop, and on full success removes the entries it read, but
 * only those whose content is unchanged since it read them, and then its own
 * (see `clearContainmentEntries` in `archiveContainmentEntries.ts`). Without a usable list — an unknown or
 * in-progress entry, the single flag file of older paratix versions, anything
 * damaged — the apply still runs, but its post-merge backstop judges every
 * symlink under the destination, not only the ones the archive can affect. A
 * failing apply rewrites only its own entry. `check` reports needs-apply while
 * any entry or the old flag file exists.
 *
 * Issue #219: remaining races, by design:
 *
 * 1. An `in-progress` entry of a live concurrent apply cannot be told apart
 *    from one a killed apply left. Another apply treats it as unknown,
 *    verifies the whole destination and removes it when that verification is
 *    clean and the entry is unchanged. If the live apply then fails, it
 *    re-creates its entry with its record; if it succeeds, it removes only its
 *    own (already removed) entry; if it is killed after that removal, links
 *    its merge published after the other apply's listing were verified by
 *    nobody. A concurrent claim right after `writeFile` renamed the record
 *    onto the entry can also make `writeFile` report a failure (its
 *    post-rename step no longer finds the file) although the record is kept,
 *    under the claim name.
 * 2. An entry created after an apply's establish read is never touched by
 *    that apply.
 * 3. A crash inside the clear exec leaves a `run-…-claim-<n>` entry, which is
 *    a normal entry: `check` stays at needs-apply and the next apply reads it.
 * 4. Old and new paratix versions running concurrently on one destination do
 *    not coordinate: old versions still use the single flag file.
 * 5. Whoever can write the root-owned flags directory can remove entries;
 *    that is outside the model.
 */
import { randomBytes } from "node:crypto"

import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER } from "../sshHelpers.js"
import { isNormalizedRelativePath } from "./archiveSymlinkListing.js"

/** Issue #219: the most offending links an entry records before it records `unknown`. */
export const CONTAINMENT_FLAG_LINK_LIMIT = 256

/** Issue #219: the largest entry body in bytes; a larger one records `unknown`. */
export const CONTAINMENT_FLAG_BODY_LIMIT_BYTES = 65_536

/**
 * Issue #219: how many entries the establish exec reads in full. It still
 * type-checks every further entry, but only reports that there are more,
 * which makes the apply verify the whole destination.
 */
export const CONTAINMENT_ENTRY_READ_LIMIT = 16

const CONTAINMENT_FLAG_VERSION = 1

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

/** Issue #219: the `unknown` reason when there are too many offending links to record. */
export const TOO_MANY_OFFENDING_LINKS = "too many offending links"

/** Issue #219: the `unknown` reason when the backstop could not identify the offending links. */
export const UNIDENTIFIED_OFFENDING_LINKS =
  "the symlink containment check could not identify the offending links"

/**
 * Issue #219: the `unknown` reason when an apply threw after its merge had
 * started, before its backstop could tell what the merge published.
 */
export const STOPPED_AFTER_MERGE_STARTED = "the apply stopped with an error after its merge started"

/**
 * Issue #219: the outcome an apply records in its own entry when it fails.
 *
 * - `failed`: the complete list of destination-relative link keys that still
 *   need verification; may be empty.
 * - `unknown`: the offending links are not known.
 */
export type ContainmentFlagRecord =
  { links: readonly string[]; state: "failed" } | { reason: string; state: "unknown" }

/** Issue #219: every entry body, including the one an apply creates first. */
type ContainmentFlagBody =
  { links: readonly string[]; state: "in-progress" } | ContainmentFlagRecord

/**
 * Issue #219: what an entry body says.
 *
 * - `recorded`: a failed apply recorded these links.
 * - `unknown`: the entry holds no usable list; `why` says why.
 */
export type ParsedContainmentFlag =
  { kind: "recorded"; links: readonly string[] } | { kind: "unknown"; why: string }

const NO_USABLE_LIST =
  "holds no usable list of offending links (it was written by an older paratix version or is damaged)"
const IN_PROGRESS =
  "records an apply that did not finish (it stopped after it started, possibly after its merge had begun, or another apply to this destination is still running)"

/**
 * Issue #219: serialize an entry body. A link list above
 * {@link CONTAINMENT_FLAG_LINK_LIMIT} entries or a body above
 * {@link CONTAINMENT_FLAG_BODY_LIMIT_BYTES} bytes becomes an `unknown` body.
 *
 * @param body - The body to write; duplicate links are dropped.
 * @returns The JSON text with a trailing newline.
 */
export function containmentFlagBody(body: ContainmentFlagBody): string {
  if (body.state === "unknown") {
    const { reason, state } = body
    return `${JSON.stringify({ reason, state, version: CONTAINMENT_FLAG_VERSION })}\n`
  }
  const links = [...new Set(body.links)]
  const text = `${JSON.stringify({ links, state: body.state, version: CONTAINMENT_FLAG_VERSION })}\n`
  if (
    links.length > CONTAINMENT_FLAG_LINK_LIMIT ||
    Buffer.byteLength(text, "utf8") > CONTAINMENT_FLAG_BODY_LIMIT_BYTES
  ) {
    return containmentFlagBody({ reason: TOO_MANY_OFFENDING_LINKS, state: "unknown" })
  }
  return text
}

/** Issue #219: the body an apply creates its own entry with. */
const IN_PROGRESS_BODY = containmentFlagBody({ links: [], state: "in-progress" })

/** Issue #219: every entry object has `version`, `state` and one more key. */
const FLAG_OBJECT_KEY_COUNT = 3

/** Issue #219: the answer for an entry without a usable list of offending links. */
const NO_USABLE_LIST_STATE = { kind: "unknown", why: NO_USABLE_LIST } as const

/**
 * Issue #219: validate a recorded link list: at most
 * {@link CONTAINMENT_FLAG_LINK_LIMIT} distinct, non-empty, normalized
 * destination-relative paths, the way the symlink listing validates its keys.
 *
 * @param links - The parsed `links` value.
 * @returns The links, or null when the list is not usable.
 */
function validRecordedLinks(links: unknown): null | string[] {
  if (!Array.isArray(links) || links.length > CONTAINMENT_FLAG_LINK_LIMIT) return null
  if (
    !links.every(
      (link): link is string =>
        typeof link === "string" && link !== "" && isNormalizedRelativePath(link)
    )
  ) {
    return null
  }
  return new Set(links).size === links.length ? links : null
}

/**
 * Issue #219: interpret an entry object with `version`, `state` and exactly
 * one more key.
 *
 * @param value - The parsed entry object.
 * @param value.state - Its `state`.
 * @returns The recorded links, or why the entry holds no usable list.
 */
function interpretFlagObject(value: { state: unknown } & object): ParsedContainmentFlag {
  if ("links" in value) {
    if (value.state === "in-progress") return { kind: "unknown", why: IN_PROGRESS }
    if (value.state !== "failed") return NO_USABLE_LIST_STATE
    const links = validRecordedLinks(value.links)
    return links === null ? NO_USABLE_LIST_STATE : { kind: "recorded", links }
  }
  if ("reason" in value && value.state === "unknown" && typeof value.reason === "string") {
    return {
      kind: "unknown",
      why: `records a failed apply whose offending links are not known (${value.reason})`,
    }
  }
  return NO_USABLE_LIST_STATE
}

/**
 * Issue #219: interpret an entry body. Only a well-formed `failed` record of
 * the current version yields links; everything else — an `in-progress` or
 * `unknown` record, the fixed text of older versions, an empty file, invalid
 * JSON, another version or shape — is unknown.
 *
 * @param text - The entry body.
 * @returns The recorded links, or why the entry holds no usable list.
 */
export function parseContainmentFlag(text: string): ParsedContainmentFlag {
  if (Buffer.byteLength(text, "utf8") > CONTAINMENT_FLAG_BODY_LIMIT_BYTES) {
    return NO_USABLE_LIST_STATE
  }
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    return NO_USABLE_LIST_STATE
  }
  if (
    typeof value !== "object" ||
    value === null ||
    !("version" in value) ||
    value.version !== CONTAINMENT_FLAG_VERSION ||
    !("state" in value) ||
    Object.keys(value).length !== FLAG_OBJECT_KEY_COUNT
  ) {
    return NO_USABLE_LIST_STATE
  }
  return interpretFlagObject(value)
}

/**
 * Issue #219: interpret the raw bytes of an entry as the establish exec read
 * them: more than {@link CONTAINMENT_FLAG_BODY_LIMIT_BYTES} bytes or bytes
 * that are not valid UTF-8 hold no usable list.
 *
 * @param bytes - The first bytes of the entry, at most one past the limit.
 * @returns The recorded links, or why the entry holds no usable list.
 */
export function parseContainmentEntryBytes(bytes: Uint8Array): ParsedContainmentFlag {
  if (bytes.byteLength > CONTAINMENT_FLAG_BODY_LIMIT_BYTES) {
    return {
      kind: "unknown",
      why: `is larger than ${String(CONTAINMENT_FLAG_BODY_LIMIT_BYTES)} bytes and ${NO_USABLE_LIST}`,
    }
  }
  let text: string
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)
  } catch {
    return { kind: "unknown", why: `is not valid UTF-8 and ${NO_USABLE_LIST}` }
  }
  return parseContainmentFlag(text)
}

/**
 * Issue #219: where the containment state of one destination lives.
 *
 * - `directory`: the flags directory, created when missing.
 * - `entryDirectory`: the destination's entry directory inside it.
 * - `legacyFlag`: the single flag file of older paratix versions, read and
 *   claimed for migration only.
 */
export type ContainmentPaths = {
  directory: string
  entryDirectory: string
  legacyFlag: string
}

/** Issue #219: the random bytes of an own entry name, 32 hex digits. */
const ENTRY_ID_BYTES = 16

/**
 * Issue #219: the name of a fresh own entry, `run-` and 32 lowercase hex
 * digits from 16 random bytes.
 *
 * @returns The entry name, without its directory.
 */
export function newContainmentEntryName(): string {
  return `run-${randomBytes(ENTRY_ID_BYTES).toString("hex")}`
}

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
 * Issue #219: the establish exec as an explicit `sh -c` command with the
 * paths as positional parameters, see {@link buildContainmentEstablishScript}.
 *
 * @param parameters - Paths and the own entry.
 * @param parameters.directory - The flags directory.
 * @param parameters.entryDirectory - The destination's entry directory.
 * @param parameters.legacyFlag - The old single flag file.
 * @param parameters.ownEntry - The own entry's absolute path inside the entry directory.
 * @returns The `sh -c` command line with the quoted script and parameters.
 */
export function buildContainmentEstablishCommand(
  parameters: { ownEntry: string } & ContainmentPaths
): string {
  return [
    "sh -c",
    shellQuote(buildContainmentEstablishScript()),
    "sh",
    shellQuote(parameters.directory),
    shellQuote(parameters.legacyFlag),
    shellQuote(parameters.entryDirectory),
    shellQuote(parameters.ownEntry),
    shellQuote(IN_PROGRESS_BODY),
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
 * @param stdout - The captured stdout.
 * @param parameters - The containment paths and the own entry's absolute path.
 * @returns The ledger, or null when the output cannot be trusted.
 */
export function parseContainmentEstablishOutput(
  stdout: string,
  parameters: { ownEntry: string } & ContainmentPaths
): ContainmentLedger | null {
  const { legacyFlag, ownEntry } = parameters
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
      entries.some(({ path, state }) => path === legacyFlag || state.kind === "unknown"),
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
 * runs and verifies the whole destination after its merge.
 *
 * @param conn - The SSH connection.
 * @param parameters - Establish inputs.
 * @param parameters.ownEntryName - The own entry's name, see {@link newContainmentEntryName}.
 * @param parameters.paths - Where the containment state lives.
 * @param parameters.source - The archive source, for failure messages.
 * @returns The ledger, see {@link ContainmentLedger}, or the refusal.
 */
export async function establishContainmentEntry(
  conn: SshConnection,
  parameters: { ownEntryName: string; paths: ContainmentPaths; source: string }
): Promise<ContainmentLedger | ModuleResult> {
  const { ownEntryName, paths, source } = parameters
  const refusal = (reason: string): ModuleResult =>
    failed(
      `[archive.extract] refusing to extract ${source}: ${reason}; the containment entry must be in place before the destination is touched`
    )
  const inputs = { ...paths, ownEntry: `${paths.entryDirectory}/${ownEntryName}` }
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
