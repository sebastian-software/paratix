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
 * `establishContainmentEntry` in `archiveContainmentEstablish.ts`), re-verifies the recorded links in its
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

import { isNormalizedRelativePath } from "./archiveSymlinkListing.js"

/** Issue #219: the most offending links an entry records before it records `unknown`. */
export const CONTAINMENT_FLAG_LINK_LIMIT = 256

/** Issue #219: the largest entry body in bytes; a larger one records `unknown`. */
export const CONTAINMENT_FLAG_BODY_LIMIT_BYTES = 65_536

const CONTAINMENT_FLAG_VERSION = 1

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
