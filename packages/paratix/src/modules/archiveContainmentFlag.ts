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
 * - `{"scope":"<64 hex>","state":"in-progress","version":2}` is what an apply
 *   creates before it touches the destination (Issue #227). `scope` is the
 *   digest of the archive's containment scope, see `containmentScopeDigest`
 *   in `archiveContainmentScope.ts`. An apply that stopped without recording
 *   its outcome may have published links nobody checked, but only links the
 *   scope covers.
 * - `{"scope":"<64 hex>","state":"stopped","version":2}` is written when an
 *   apply throws after its merge started (Issue #227): the merge may have
 *   published anything its scope covers. It differs from the `in-progress`
 *   body, so its hash changes and a concurrent apply that read the
 *   `in-progress` body keeps it (race 1).
 * - `{"version":1,"state":"failed","links":[…]}` is written when an apply
 *   fails and every link that still needs verification is known; the list is
 *   complete and may be empty.
 * - `{"version":1,"state":"unknown","reason":"…"}` is written when an apply
 *   fails and the offending links could not be identified, or there are too
 *   many of them to record.
 *
 * Each v2 body has a fixed size (about 110 bytes) whatever the member count,
 * so it stays far below {@link CONTAINMENT_FLAG_BODY_LIMIT_BYTES} and fits the
 * argv of the establish exec. The `{"version":1,"state":"in-progress","links":[…]}`
 * body of earlier versions reads as unknown, with or without links.
 *
 * An apply reads every entry before it touches the destination (see
 * `establishContainmentEntry` in `archiveContainmentEstablish.ts`), re-verifies the recorded links in its
 * post-merge backstop, and on full success removes the entries it read, but
 * only those whose content is unchanged since it read them, and then its own
 * (see `clearContainmentEntries` in `archiveContainmentEntries.ts`). Without a usable list — an unknown
 * entry, a v1 `in-progress` entry, a v2 entry whose scope digest differs from
 * the apply's own or is malformed, the single flag file of older paratix
 * versions, anything damaged — the apply still runs, but its post-merge
 * backstop judges every symlink under the destination, not only the ones the
 * archive can affect. A failing apply rewrites only its own entry. `check`
 * reports needs-apply while any entry or the old flag file exists.
 *
 * Issue #227: scoped clearing. A v2 entry whose digest equals the digest of
 * the current apply's own scope needs no destination-wide verification: the
 * interrupted apply extracted the same members, so it could only publish
 * links the current apply judges anyway — its own symlinks and every link
 * whose resolution passes through a path it writes. The current apply's
 * normal, scoped post-merge backstop therefore covers it, and a successful
 * apply removes the entry like any other it read. A digest that differs,
 * because the archive changed or the digest was derived by another paratix
 * or Unicode version, says nothing about what that apply published, so the
 * destination-wide path stays; so does every entry without a usable digest.
 * After a changed archive the manual removal therefore remains necessary when
 * the destination holds intended links that point outside it.
 *
 * Issue #227: a `.paratix-stage.*` directory a killed apply left inside the
 * destination is listed but not judged in scoped mode. Its links come from an
 * archive that passed the static link validation (`archiveLinkUnsafeReason`
 * in `archiveLinkValidation.ts`, and see the staging comment in
 * `archiveStagingMerge.ts`), which keeps every symlink target inside the archive's own
 * tree, so they resolve inside the staging directory. Such a directory is not
 * removed either; that is out of scope.
 *
 * Issue #227: mixed versions. An older paratix reads a v2 entry as another
 * version, so as unknown, and verifies the whole destination; its message
 * calls the entry written by an older version or damaged, which is misleading
 * but safe. This version reads a v1 `in-progress` entry as unknown too.
 *
 * Issue #219: remaining races, by design, as updated by issue #224, which
 * serializes the applies to one destination with a per-destination extract
 * lock (see `archiveExtractLock.ts`). The lock is taken before the own entry
 * is created and released after the clear exec:
 *
 * 1. Resolved by issue #224. An `in-progress` entry of a live concurrent apply
 *    used to be indistinguishable from one a killed apply left, so another
 *    apply could verify the destination and remove it while its owner was
 *    still merging. Under the lock, an `in-progress` entry an apply reads
 *    belongs to an apply that stopped without finishing and whose lock was
 *    reclaimed as stale; verifying the whole destination — or, Issue #227,
 *    only this apply's scope when the entry records the same scope digest —
 *    and removing it is correct. Only a live holder that lost its lock anyway
 *    — the target clock jumped forward by more than the gap between the guard
 *    and the reclaim threshold, or a merge hung in uninterruptible I/O past
 *    its timeout — can reopen the old race, and the guards in its merge and
 *    clear execs then stop it visibly: a refused merge publishes nothing, a
 *    refused clear removes nothing. Its failure record still goes through
 *    `writeFile`, which re-creates an own entry removed meanwhile; a
 *    concurrent claim right after `writeFile` renamed the record onto the
 *    entry can make `writeFile` report a failure (its post-rename step no
 *    longer finds the file) although the record is kept, under the claim
 *    name.
 * 2. An entry created after an apply's establish read is never touched by
 *    that apply. Under the lock no other apply creates an entry between this
 *    apply's establish and clear execs; the rule stays as the safety net for
 *    a lost lock.
 * 3. A crash inside the clear exec leaves a `run-…-claim-<n>` entry, which is
 *    a normal entry: `check` stays at needs-apply and the next apply reads it.
 * 4. Still unsupported: old and new paratix versions running concurrently on
 *    one destination do not coordinate. Old versions take no extract lock and
 *    still use the single flag file.
 * 5. Whoever can write the root-owned flags directory can remove entries and
 *    the extract lock; that is outside the model.
 */
import { randomBytes } from "node:crypto"

import { isNormalizedRelativePath } from "./archiveSymlinkListing.js"

/** Issue #219: the most offending links an entry records before it records `unknown`. */
export const CONTAINMENT_FLAG_LINK_LIMIT = 256

/** Issue #219: the largest entry body in bytes; a larger one records `unknown`. */
export const CONTAINMENT_FLAG_BODY_LIMIT_BYTES = 65_536

const CONTAINMENT_FLAG_VERSION = 1

/** Issue #227: the version of the bodies that record a scope digest. */
const CONTAINMENT_SCOPE_FLAG_VERSION = 2

/** Issue #219: the state of the body an apply creates its own entry with. */
export const IN_PROGRESS_STATE = "in-progress"

/** Issue #219: a sha256 digest as lowercase hex, also the form of a scope digest. */
const SHA256_PATTERN = /^[\da-f]{64}$/v

/** Issue #219: the `unknown` reason when there are too many offending links to record. */
export const TOO_MANY_OFFENDING_LINKS = "too many offending links"

/** Issue #219: the `unknown` reason when the backstop could not identify the offending links. */
export const UNIDENTIFIED_OFFENDING_LINKS =
  "the symlink containment check could not identify the offending links"

/**
 * Issue #219: the outcome an apply records in its own entry when it fails.
 *
 * - `failed`: the complete list of destination-relative link keys that still
 *   need verification; may be empty.
 * - `stopped`: Issue #227: the apply threw after its merge started; it
 *   published at most what the scope with this digest covers.
 * - `unknown`: the offending links are not known.
 */
export type ContainmentFlagRecord =
  | { links: readonly string[]; state: "failed" }
  | { reason: string; state: "unknown" }
  | { scope: string; state: "stopped" }

/**
 * Issue #219: every entry body, including the one an apply creates first;
 * Issue #227: that one records the digest of the apply's containment scope.
 */
type ContainmentFlagBody = { scope: string; state: "in-progress" } | ContainmentFlagRecord

/**
 * Issue #219: what an entry body says.
 *
 * - `recorded`: a failed apply recorded these links.
 * - `scoped`: Issue #227: an apply that did not finish recorded the digest
 *   of its containment scope; an apply with the same digest covers it.
 * - `unknown`: the entry holds no usable list; `why` says why.
 */
export type ParsedContainmentFlag =
  | { kind: "recorded"; links: readonly string[] }
  | { kind: "scoped"; scope: string }
  | { kind: "unknown"; why: string }

const NO_USABLE_LIST =
  "holds no usable list of offending links (it was written by an older paratix version or is damaged)"
const IN_PROGRESS =
  "records an apply that did not finish (it stopped after it started, possibly after its merge had begun, it lost its extract lock, or it is an apply of an older paratix version without the extract lock that is still running)"
const SCOPE_MISMATCH =
  "records an apply that did not finish whose archive scope differs from this apply's (another archive, or a scope derived by another paratix or Unicode version)"

/**
 * Issue #219: serialize an entry body. A link list above
 * {@link CONTAINMENT_FLAG_LINK_LIMIT} entries or a body above
 * {@link CONTAINMENT_FLAG_BODY_LIMIT_BYTES} bytes becomes an `unknown` body.
 *
 * @param body - The body to write; duplicate links are dropped.
 * @returns The JSON text with a trailing newline.
 */
export function containmentFlagBody(body: ContainmentFlagBody): string {
  if ("scope" in body) {
    const { scope, state } = body
    return `${JSON.stringify({ scope, state, version: CONTAINMENT_SCOPE_FLAG_VERSION })}\n`
  }
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
    if (value.state === IN_PROGRESS_STATE) return { kind: "unknown", why: IN_PROGRESS }
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
 * Issue #227: interpret a v2 entry object with `version`, `state` and
 * exactly one more key: an `in-progress` or `stopped` body with a
 * well-formed scope digest is scoped, anything else holds no usable list.
 *
 * @param value - The parsed entry object.
 * @param value.state - Its `state`.
 * @returns The scope digest, or why the entry holds no usable list.
 */
function interpretScopedFlagObject(value: { state: unknown } & object): ParsedContainmentFlag {
  if (
    "scope" in value &&
    (value.state === IN_PROGRESS_STATE || value.state === "stopped") &&
    typeof value.scope === "string" &&
    SHA256_PATTERN.test(value.scope)
  ) {
    return { kind: "scoped", scope: value.scope }
  }
  return NO_USABLE_LIST_STATE
}

/**
 * Issue #219: interpret an entry body. Only a well-formed `failed` record of
 * version 1 yields links, and (Issue #227) only a well-formed v2
 * `in-progress` or `stopped` body yields a scope digest; everything else — a
 * v1 `in-progress` or `unknown` record, the fixed text of older versions, an
 * empty file, invalid JSON, another version or shape — is unknown.
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
    !("state" in value) ||
    Object.keys(value).length !== FLAG_OBJECT_KEY_COUNT
  ) {
    return NO_USABLE_LIST_STATE
  }
  if (value.version === CONTAINMENT_SCOPE_FLAG_VERSION) return interpretScopedFlagObject(value)
  if (value.version !== CONTAINMENT_FLAG_VERSION) return NO_USABLE_LIST_STATE
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
 * Issue #227: what an entry means for an apply with the given scope digest:
 * a scoped entry with another digest holds no usable list for it.
 *
 * @param state - The parsed entry.
 * @param scopeDigest - The digest of this apply's containment scope.
 * @returns The entry, or unknown when its scope digest differs.
 */
export function containmentEntryForScope(
  state: ParsedContainmentFlag,
  scopeDigest: string
): ParsedContainmentFlag {
  return state.kind === "scoped" && state.scope !== scopeDigest
    ? { kind: "unknown", why: SCOPE_MISMATCH }
    : state
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
