/**
 * Structured `authorized_keys` key options: construction-time validation,
 * deterministic serialization, and an OpenSSH-compatible parser for the
 * option block of existing lines.
 *
 * Quoting follows OpenSSH `opt_dequote` (`auth-options.c`): inside a quoted
 * value only the two-byte sequence `\"` is an escape and yields `"`; every
 * other backslash is kept literally. The serializer therefore escapes `"` as
 * `\"`, leaves backslashes untouched, and validation rejects values ending in
 * `\` because that backslash would escape the closing quote.
 */

/** Supported `authorized_keys` options for `ssh.authorizedKeys`. */
export type AuthorizedKeyOptions = {
  /** Emits `agent-forwarding` (re-enables agent forwarding after `restrict`). */
  agentForwarding?: boolean
  /** Emits `command="…"`, a forced command that replaces the client's command. */
  command?: string
  /**
   * Emits one `environment="NAME=value"` per entry, in insertion order. sshd
   * applies these only when `PermitUserEnvironment` allows them.
   */
  environment?: Readonly<Record<string, string>>
  /** Emits `expiry-time="…"` in the OpenSSH format `YYYYMMDD[HHMM[SS]][Z]`. */
  expiryTime?: string
  /** Emits one `from="a,b"` option with the comma-joined source patterns. */
  from?: readonly string[]
  /** Emits `no-agent-forwarding`. */
  noAgentForwarding?: boolean
  /** Emits `no-port-forwarding`. */
  noPortForwarding?: boolean
  /** Emits `no-pty`. */
  noPty?: boolean
  /** Emits `no-user-rc`. */
  noUserRc?: boolean
  /** Emits `no-X11-forwarding`. */
  noX11Forwarding?: boolean
  /** Emits one `permitlisten="…"` option per element. */
  permitListen?: readonly string[]
  /** Emits one `permitopen="…"` option per element. */
  permitOpen?: readonly string[]
  /** Emits `port-forwarding` (re-enables port forwarding after `restrict`). */
  portForwarding?: boolean
  /** Emits `pty` (re-enables PTY allocation after `restrict`). */
  pty?: boolean
  /** Emits `restrict`, which disables all forwarding, PTY and `~/.ssh/rc`. */
  restrict?: boolean
  /** Emits `user-rc` (re-enables `~/.ssh/rc` after `restrict`). */
  userRc?: boolean
  /** Emits `X11-forwarding` (re-enables X11 forwarding after `restrict`). */
  x11Forwarding?: boolean
}

/** One option of an `authorized_keys` option block; `value` is the dequoted text. */
export type AuthorizedKeyOptionEntry = {
  readonly name: string
  readonly value?: string
}

type FlagField = (typeof FLAG_FIELDS)[number]
type ListField = "from" | "permitListen" | "permitOpen"

const FLAG_FIELDS = [
  "agentForwarding",
  "noAgentForwarding",
  "noPortForwarding",
  "noPty",
  "noUserRc",
  "noX11Forwarding",
  "portForwarding",
  "pty",
  "restrict",
  "userRc",
  "x11Forwarding",
] as const

const FLAG_OPTION_NAMES: Readonly<Record<FlagField, string>> = {
  agentForwarding: "agent-forwarding",
  noAgentForwarding: "no-agent-forwarding",
  noPortForwarding: "no-port-forwarding",
  noPty: "no-pty",
  noUserRc: "no-user-rc",
  noX11Forwarding: "no-X11-forwarding",
  portForwarding: "port-forwarding",
  pty: "pty",
  restrict: "restrict",
  userRc: "user-rc",
  x11Forwarding: "X11-forwarding",
}

const VALUE_FIELDS = [
  "command",
  "environment",
  "expiryTime",
  "from",
  "permitListen",
  "permitOpen",
] as const
const SUPPORTED_FIELDS = new Set<string>([...FLAG_FIELDS, ...VALUE_FIELDS])

const CONTRADICTORY_FLAG_PAIRS: ReadonlyArray<readonly [FlagField, FlagField]> = [
  ["agentForwarding", "noAgentForwarding"],
  ["portForwarding", "noPortForwarding"],
  ["pty", "noPty"],
  ["userRc", "noUserRc"],
  ["x11Forwarding", "noX11Forwarding"],
]

const RESTRICT_OPTION_NAME = "restrict"
const CONTROL_CHARACTER_PATTERN = /\p{Cc}/v
const LIST_ELEMENT_SEPARATOR_PATTERN = /[\s,]/v
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_]\w*$/v
// A date, a date with hours and minutes, or a date with full time, as accepted by OpenSSH.
const EXPIRY_TIME_PATTERN = /^(?:\d{8}|\d{12}|\d{14})Z?$/v
const YEAR_FIELD_WIDTH = 4
const TIME_FIELD_WIDTH = 2
const MAX_MONTH = 12
const MAX_HOUR = 23
const MAX_MINUTE_OR_SECOND = 59
const ERROR_PREFIX = "ssh.authorizedKeys: options"

function optionError(message: string): Error {
  return new Error(`${ERROR_PREFIX}.${message}`)
}

/**
 * Reject values that would break the quoted option syntax. Error messages
 * name the field only, never the value: `command` and `environment` may carry
 * secrets.
 *
 * @param field - Field label used in the error message.
 * @param value - The candidate option value.
 */
function assertQuotableValue(field: string, value: string): void {
  if (CONTROL_CHARACTER_PATTERN.test(value)) {
    throw optionError(`${field} must not contain newlines, NUL or other control characters`)
  }
  if (value.endsWith("\\")) throw optionError(`${field} must not end with a backslash`)
}

function readFlag(field: FlagField, value: unknown): boolean {
  if (typeof value !== "boolean") throw optionError(`${field} must be a boolean`)
  return value
}

function readCommand(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw optionError("command must be a non-empty string")
  }
  assertQuotableValue("command", value)
  return value
}

function readList(field: ListField, value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw optionError(`${field} must be a non-empty array of strings`)
  }
  const elements: readonly unknown[] = value
  return elements.map((element, index) => {
    const label = `${field}[${index}]`
    if (typeof element !== "string" || element.length === 0) {
      throw optionError(`${label} must be a non-empty string`)
    }
    assertQuotableValue(label, element)
    if (LIST_ELEMENT_SEPARATOR_PATTERN.test(element)) {
      throw optionError(`${label} must not contain commas or whitespace`)
    }
    return element
  })
}

function isPlainRecord(value: unknown): value is object {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false
  const prototype: unknown = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function readEnvironment(value: unknown): Array<[string, string]> {
  if (!isPlainRecord(value)) throw optionError("environment must be a plain object")
  const entries: Array<[string, unknown]> = Object.entries(value)
  return entries.map(([name, entryValue]) => {
    if (!ENVIRONMENT_NAME_PATTERN.test(name)) {
      throw optionError(
        `environment name ${JSON.stringify(name)} must match [A-Za-z_][A-Za-z0-9_]*`
      )
    }
    const label = `environment.${name}`
    if (typeof entryValue !== "string") throw optionError(`${label} must be a string`)
    assertQuotableValue(label, entryValue)
    return [name, entryValue]
  })
}

function daysInMonth(year: number, month: number): number {
  const date = new Date(0)
  date.setUTCFullYear(year, month, 0)
  return date.getUTCDate()
}

function expiryTimeFields(value: string): null | number[] {
  if (!EXPIRY_TIME_PATTERN.test(value)) return null
  const digits = value.endsWith("Z") ? value.slice(0, -1) : value
  // year, month, day, hour, minute, second; missing time fields are zero.
  const widths = [
    YEAR_FIELD_WIDTH,
    TIME_FIELD_WIDTH,
    TIME_FIELD_WIDTH,
    TIME_FIELD_WIDTH,
    TIME_FIELD_WIDTH,
    TIME_FIELD_WIDTH,
  ]
  let offset = 0
  return widths.map((width) => {
    const field = digits.slice(offset, offset + width)
    offset += width
    return field.length === 0 ? 0 : Number(field)
  })
}

function isValidExpiryTime(value: string): boolean {
  const fields = expiryTimeFields(value)
  if (fields === null) return false
  const [year, month, day, hour, minute, second] = fields
  if (month < 1 || month > MAX_MONTH || day < 1 || day > daysInMonth(year, month)) return false
  return hour <= MAX_HOUR && minute <= MAX_MINUTE_OR_SECOND && second <= MAX_MINUTE_OR_SECOND
}

function readExpiryTime(value: unknown): string {
  if (typeof value !== "string" || !isValidExpiryTime(value)) {
    throw optionError("expiryTime must be a valid time in the format YYYYMMDD[HHMM[SS]][Z]")
  }
  return value
}

function readOptionFields(options: unknown): Map<string, unknown> {
  if (!isPlainRecord(options)) throw new Error(`${ERROR_PREFIX} must be a plain object`)
  const fields = new Map<string, unknown>()
  const entries: Array<[string, unknown]> = Object.entries(options)
  for (const [field, value] of entries) {
    if (!SUPPORTED_FIELDS.has(field)) {
      throw new Error(`ssh.authorizedKeys: unsupported option ${JSON.stringify(field)}`)
    }
    if (value !== undefined) fields.set(field, value)
  }
  return fields
}

function flagEntries(fields: Map<string, unknown>): AuthorizedKeyOptionEntry[] {
  const enabled = new Set(
    FLAG_FIELDS.filter((field) => fields.has(field) && readFlag(field, fields.get(field)))
  )
  for (const [positive, negative] of CONTRADICTORY_FLAG_PAIRS) {
    if (enabled.has(positive) && enabled.has(negative)) {
      throw new Error(`${ERROR_PREFIX} ${positive} and ${negative} contradict each other`)
    }
  }
  return [...enabled].map((field) => ({ name: FLAG_OPTION_NAMES[field] }))
}

const VALUE_ENTRY_READERS: Readonly<
  Record<(typeof VALUE_FIELDS)[number], (value: unknown) => AuthorizedKeyOptionEntry[]>
> = {
  command: (value) => [{ name: "command", value: readCommand(value) }],
  environment: (value) =>
    readEnvironment(value).map(([name, entryValue]) => ({
      name: "environment",
      value: `${name}=${entryValue}`,
    })),
  expiryTime: (value) => [{ name: "expiry-time", value: readExpiryTime(value) }],
  from: (value) => [{ name: "from", value: readList("from", value).join(",") }],
  permitListen: (value) =>
    readList("permitListen", value).map((element) => ({ name: "permitlisten", value: element })),
  permitOpen: (value) =>
    readList("permitOpen", value).map((element) => ({ name: "permitopen", value: element })),
}

function valueEntries(fields: Map<string, unknown>): AuthorizedKeyOptionEntry[] {
  return VALUE_FIELDS.flatMap((field) =>
    fields.has(field) ? VALUE_ENTRY_READERS[field](fields.get(field)) : []
  )
}

function compareEntryNames(
  left: AuthorizedKeyOptionEntry,
  right: AuthorizedKeyOptionEntry
): number {
  const leftName = left.name.toLowerCase()
  const rightName = right.name.toLowerCase()
  if (leftName === rightName) return 0
  if (leftName === RESTRICT_OPTION_NAME) return -1
  if (rightName === RESTRICT_OPTION_NAME) return 1
  return leftName < rightName ? -1 : 1
}

/**
 * Validate structured options and convert them to OpenSSH option entries in
 * the canonical order: `restrict` first, then alphabetical by lower-cased
 * OpenSSH option name; repeated options keep their input order (stable sort).
 *
 * @param options - Untrusted structured options from the recipe.
 * @returns The ordered option entries.
 * @throws {Error} When a field is unknown, has the wrong type, contains a
 *   control character, ends in a backslash, or contradicts another field.
 */
export function authorizedKeyOptionEntries(options: unknown): AuthorizedKeyOptionEntry[] {
  const fields = readOptionFields(options)
  return [...flagEntries(fields), ...valueEntries(fields)].toSorted(compareEntryNames)
}

/**
 * Render option entries as an `authorized_keys` option block. Only `"` is
 * escaped (`\"`), mirroring OpenSSH `opt_dequote`.
 *
 * @param entries - Ordered option entries.
 * @returns The comma-joined option block, or `""` when there are no entries.
 */
export function formatAuthorizedKeyOptionEntries(
  entries: readonly AuthorizedKeyOptionEntry[]
): string {
  return entries
    .map(({ name, value }) =>
      value === undefined ? name : `${name}="${value.replaceAll('"', '\\"')}"`
    )
    .join(",")
}

/**
 * Validate and serialize structured options deterministically: the same input
 * always yields a byte-identical option block.
 *
 * @param options - Untrusted structured options from the recipe.
 * @returns The option block, or `""` for an empty options object.
 */
export function serializeAuthorizedKeyOptions(options: unknown): string {
  return formatAuthorizedKeyOptionEntries(authorizedKeyOptionEntries(options))
}

/**
 * Find the end of a leading option block like OpenSSH
 * `sshkey_advance_past_options`: the block ends at the first space or tab
 * outside double quotes, and `\"` never toggles the quote state.
 *
 * @param text - Line text starting at the option block.
 * @returns The index just past the option block, or `null` for an
 *   unterminated quote.
 */
export function advancePastAuthorizedKeyOptions(text: string): null | number {
  let quoted = false
  let index = 0
  for (; index < text.length; index++) {
    const character = text[index]
    if (!quoted && (character === " " || character === "\t")) break
    if (character === "\\" && text[index + 1] === '"') index++
    else if (character === '"') quoted = !quoted
  }
  return quoted ? null : index
}

function dequoteOptionValue(block: string, start: number): { end: number; value: string } | null {
  if (block[start] !== '"') return null
  let value = ""
  let index = start + 1
  while (index < block.length && block[index] !== '"') {
    if (block[index] === "\\" && block[index + 1] === '"') index++
    value += block[index]
    index++
  }
  if (index >= block.length) return null
  return { end: index + 1, value }
}

function readOptionEntry(
  block: string,
  start: number
): { end: number; entry: AuthorizedKeyOptionEntry } | null {
  const nameLength = block.slice(start).search(/[=,]/v)
  const nameEnd = nameLength === -1 ? block.length : start + nameLength
  const name = block.slice(start, nameEnd)
  if (name.length === 0) return null
  if (block[nameEnd] !== "=") return { end: nameEnd, entry: { name } }
  const dequoted = dequoteOptionValue(block, nameEnd + 1)
  if (dequoted === null) return null
  return { end: dequoted.end, entry: { name, value: dequoted.value } }
}

/**
 * Split an option block into entries following the OpenSSH grammar
 * `name[="value"]` separated by `,`. Option names are returned as written.
 *
 * @param block - An option block without surrounding whitespace.
 * @returns The entries, or `null` when the block is syntactically invalid.
 */
export function parseAuthorizedKeyOptionEntries(block: string): AuthorizedKeyOptionEntry[] | null {
  const entries: AuthorizedKeyOptionEntry[] = []
  let index = 0
  while (index < block.length) {
    const option = readOptionEntry(block, index)
    if (option === null) return null
    entries.push(option.entry)
    index = option.end
    if (index === block.length) return entries
    // Options are separated by exactly one comma; a trailing comma is invalid.
    if (block[index] !== "," || index + 1 === block.length) return null
    index++
  }
  return entries.length === 0 ? null : entries
}
