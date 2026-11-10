/**
 * Pure `authorized_keys` content analysis for `ssh.authorizedKeys`.
 *
 * Content is handled as a Latin-1 string so that every byte of the remote
 * file maps to exactly one character: lines the module does not own are
 * re-emitted byte-for-byte. A managed entry is identified by its key blob
 * (algorithm plus base64 key data), not by the exact line, so a change of the
 * options or the trailing comment replaces the existing line.
 */
import {
  advancePastAuthorizedKeyOptions,
  parseAuthorizedKeyOptionEntries,
} from "./sshAuthorizedKeyOptions.js"
import { type AuthorizedKeyIdentity, isStrictBase64 } from "./sshPublicKeyValidation.js"

/** A classified `authorized_keys` line. `optionBlock` is `""` for option-free key lines. */
export type AuthorizedKeysLine =
  | { identity: AuthorizedKeyIdentity; kind: "key"; optionBlock: string }
  | { kind: "ignored" }
  | { kind: "unparseable" }

/** Desired state of the managed entry. `line` is the Latin-1 form of the target line. */
export type AuthorizedKeysTarget = {
  identity: AuthorizedKeyIdentity
  line: string
  optionsProvided: boolean
  state: "absent" | "present"
}

/** Outcome of analyzing the current content against the target. */
export type AuthorizedKeysContentPlan =
  | { content: string; kind: "rewrite" }
  | { kind: "conflict"; lineNumber: number }
  | { kind: "converged" }
  | { kind: "options-guard"; optionNames: string[] }

const LEADING_BLANKS_PATTERN = /^[ \t]+/v
const KEY_FIELDS_PATTERN = /^(?<keyType>[^ \t]+)[ \t]+(?<blob>[^ \t]+)/v
// Key type names of OpenSSH public keys and certificates (`ssh-ed25519`,
// `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`, `*-cert-v01@openssh.com`).
// A first token that does not look like a key type is read as an option block.
const KEY_TYPE_PATTERN = /^(?:ssh|ecdsa|sk|rsa-sha2)-[^\s"=,]+$/v
const ANY_WHITESPACE_PATTERN = /\s+/v
const SAFE_OPTION_NAME_PATTERN = /^[a-z0-9\-]+$/v
const UNRECOGNIZED_OPTION_SYNTAX = "(unrecognized option syntax)"
const CERT_AUTHORITY_OPTION = "cert-authority"

function readKeyFields(text: string): AuthorizedKeyIdentity | null {
  const groups = KEY_FIELDS_PATTERN.exec(text)?.groups
  if (groups === undefined) return null
  const { blob, keyType } = groups
  if (!KEY_TYPE_PATTERN.test(keyType) || !isStrictBase64(blob)) return null
  return { blob, keyType }
}

/**
 * Classify one line like sshd does: blank and `#` lines are ignored; a key
 * line is `<type> <base64> [comment]`, optionally preceded by an option block
 * that ends at the first space or tab outside double quotes.
 *
 * One trailing `\r` of a CRLF line is ignored; the caller keeps the original
 * line bytes for lines it does not replace.
 *
 * @param line - One line without its terminating `\n`.
 * @returns The classified line.
 */
export function parseAuthorizedKeysLine(line: string): AuthorizedKeysLine {
  // A CRLF line keeps one trailing `\r`, which sshd treats as a separator,
  // so `<type> <blob>\r` without a comment is still a valid key line.
  const withoutCarriageReturn = line.endsWith("\r") ? line.slice(0, -1) : line
  const text = withoutCarriageReturn.replace(LEADING_BLANKS_PATTERN, "")
  if (text.length === 0 || text.startsWith("#")) return { kind: "ignored" }
  const plainKey = readKeyFields(text)
  if (plainKey !== null) return { identity: plainKey, kind: "key", optionBlock: "" }
  const optionEnd = advancePastAuthorizedKeyOptions(text)
  if (optionEnd === null || optionEnd === 0) return { kind: "unparseable" }
  const key = readKeyFields(text.slice(optionEnd).replace(LEADING_BLANKS_PATTERN, ""))
  if (key === null) return { kind: "unparseable" }
  return { identity: key, kind: "key", optionBlock: text.slice(0, optionEnd) }
}

/**
 * Build the Latin-1 target line `<options> <key>`, or the key alone when the
 * option block is empty, so option-free lines stay byte-identical to the
 * lines earlier Paratix versions wrote.
 *
 * @param key - The public key string exactly as passed by the recipe.
 * @param optionBlock - The serialized option block.
 * @returns The target line as a Latin-1 string of its UTF-8 bytes.
 */
export function authorizedKeysTargetLine(key: string, optionBlock: string): string {
  const line = optionBlock.length === 0 ? key : `${optionBlock} ${key}`
  return Buffer.from(line, "utf8").toString("latin1")
}

/**
 * Collect the option names (never values) of an option block for diagnostics.
 *
 * @param optionBlock - A non-empty option block of an existing line.
 * @returns Lower-cased option names; malformed syntax is reported generically.
 */
function optionNamesOf(optionBlock: string): string[] {
  const entries = parseAuthorizedKeyOptionEntries(optionBlock)
  if (entries === null) return [UNRECOGNIZED_OPTION_SYNTAX]
  return entries.map(({ name }) => {
    const lowerName = name.toLowerCase()
    return SAFE_OPTION_NAME_PATTERN.test(lowerName) ? lowerName : UNRECOGNIZED_OPTION_SYNTAX
  })
}

/**
 * Whether an option block carries `cert-authority` (case-insensitive, like
 * sshd). Such a line trusts a certificate authority: sshd never uses it to
 * authorize the plain key and it does not shadow plain lines of that key, so
 * it is not an entry of the managed key.
 *
 * @param optionBlock - The option block of a parsed key line, `""` if none.
 * @returns `true` when the block parses and contains `cert-authority`.
 */
function hasCertAuthorityOption(optionBlock: string): boolean {
  if (optionBlock.length === 0) return false
  const entries = parseAuthorizedKeyOptionEntries(optionBlock)
  return entries?.some(({ name }) => name.toLowerCase() === CERT_AUTHORITY_OPTION) ?? false
}

function splitLines(content: string): { lines: string[]; trailingNewline: boolean } {
  if (content.length === 0) return { lines: [], trailingNewline: false }
  const lines = content.split("\n")
  const trailingNewline = content.endsWith("\n")
  if (trailingNewline) lines.pop()
  return { lines, trailingNewline }
}

function joinLines(lines: readonly string[], trailingNewline: boolean): string {
  if (lines.length === 0) return ""
  return `${lines.join("\n")}${trailingNewline ? "\n" : ""}`
}

type ClassifiedContent = {
  conflictIndex: null | number
  lines: string[]
  matches: Array<{ index: number; optionBlock: string }>
  trailingNewline: boolean
}

type LineRole = { kind: "conflict" } | { kind: "foreign" } | { kind: "match"; optionBlock: string }

const FOREIGN_LINE: LineRole = { kind: "foreign" }
const CONFLICT_LINE: LineRole = { kind: "conflict" }

/**
 * Decide what one line means for the managed key.
 *
 * @param line - One line without its terminating `\n`.
 * @param identity - The managed key blob.
 * @returns `match` for an entry of the key, `conflict` for a line that cannot
 *   be matched safely, and `foreign` for every other line.
 */
function lineRole(line: string, identity: AuthorizedKeyIdentity): LineRole {
  const parsed = parseAuthorizedKeysLine(line)
  if (parsed.kind === "ignored") return FOREIGN_LINE
  if (parsed.kind === "unparseable") {
    // sshd might still read an unparseable line that names the blob as a
    // token, so it cannot be matched or kept safely.
    return line.split(ANY_WHITESPACE_PATTERN).includes(identity.blob) ? CONFLICT_LINE : FOREIGN_LINE
  }
  // A `cert-authority` line is a foreign line, even for the same blob.
  if (parsed.identity.blob !== identity.blob || hasCertAuthorityOption(parsed.optionBlock)) {
    return FOREIGN_LINE
  }
  // The same blob under another key type cannot be matched safely.
  return parsed.identity.keyType === identity.keyType
    ? { kind: "match", optionBlock: parsed.optionBlock }
    : CONFLICT_LINE
}

function classifyContent(content: string, identity: AuthorizedKeyIdentity): ClassifiedContent {
  const { lines, trailingNewline } = splitLines(content)
  const matches: ClassifiedContent["matches"] = []
  let conflictIndex: null | number = null
  for (const [index, line] of lines.entries()) {
    const role = lineRole(line, identity)
    if (role.kind === "match") matches.push({ index, optionBlock: role.optionBlock })
    else if (role.kind === "conflict") conflictIndex ??= index
  }
  return { conflictIndex, lines, matches, trailingNewline }
}

/**
 * Re-join the kept lines. Every kept line keeps its own terminator: only the
 * original last line can lack the trailing newline, so the result ends
 * without `\n` only when that line is still the last one.
 *
 * @param classified - The split original content.
 * @param kept - The output lines with the index of the original line they replace.
 * @returns The new content.
 */
function joinKeptLines(
  classified: ClassifiedContent,
  kept: ReadonlyArray<{ line: string; sourceIndex: number }>
): string {
  const last = kept.at(-1)
  if (last === undefined) return ""
  const endsWithNewline =
    classified.trailingNewline || last.sourceIndex !== classified.lines.length - 1
  return joinLines(
    kept.map(({ line }) => line),
    endsWithNewline
  )
}

function presentPlan(
  classified: ClassifiedContent,
  target: AuthorizedKeysTarget
): AuthorizedKeysContentPlan {
  const { lines, matches } = classified
  const optionNames = matches.flatMap(({ optionBlock }) =>
    optionBlock.length === 0 ? [] : optionNamesOf(optionBlock)
  )
  if (!target.optionsProvided && optionNames.length > 0) {
    return { kind: "options-guard", optionNames: [...new Set(optionNames)].toSorted() }
  }
  if (matches.length === 1 && lines[matches[0].index] === target.line) return { kind: "converged" }
  if (matches.length === 0) {
    return { content: joinLines([...lines, target.line], true), kind: "rewrite" }
  }
  const [first, ...duplicates] = matches
  const duplicateIndexes = new Set(duplicates.map(({ index }) => index))
  const kept = lines.flatMap((line, sourceIndex) => {
    if (sourceIndex === first.index) return [{ line: target.line, sourceIndex }]
    return duplicateIndexes.has(sourceIndex) ? [] : [{ line, sourceIndex }]
  })
  return { content: joinKeptLines(classified, kept), kind: "rewrite" }
}

function absentPlan(classified: ClassifiedContent): AuthorizedKeysContentPlan {
  const { lines, matches } = classified
  if (matches.length === 0) return { kind: "converged" }
  const matchIndexes = new Set(matches.map(({ index }) => index))
  const kept = lines.flatMap((line, sourceIndex) =>
    matchIndexes.has(sourceIndex) ? [] : [{ line, sourceIndex }]
  )
  return { content: joinKeptLines(classified, kept), kind: "rewrite" }
}

/**
 * Decide how the current `authorized_keys` content must change.
 *
 * `present` keeps exactly one line for the key blob: the first existing line
 * is replaced in place and later lines of the same blob are removed, because
 * sshd uses the first line whose key and `from`/`expiry-time` match, so a
 * second unrestricted line would defeat `restrict`. Without explicit options
 * an existing line with options is never silently stripped. `absent` removes
 * every line of the blob. A line that may reference the blob but cannot be
 * parsed, or the same blob under another key type, blocks both states.
 * `cert-authority` lines are kept unchanged like unrelated lines.
 *
 * @param content - The current content as Latin-1 string, or `null` when the file is missing.
 * @param target - The desired entry.
 * @returns The plan; `rewrite` carries the complete new content.
 */
export function planAuthorizedKeysContent(
  content: null | string,
  target: AuthorizedKeysTarget
): AuthorizedKeysContentPlan {
  if (content === null) {
    return target.state === "present"
      ? { content: `${target.line}\n`, kind: "rewrite" }
      : { kind: "converged" }
  }
  const classified = classifyContent(content, target.identity)
  if (classified.conflictIndex !== null) {
    return { kind: "conflict", lineNumber: classified.conflictIndex + 1 }
  }
  return target.state === "present" ? presentPlan(classified, target) : absentPlan(classified)
}
