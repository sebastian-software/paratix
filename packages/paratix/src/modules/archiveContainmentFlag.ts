/**
 * The containment flag of `archive.extract` and the offending links it
 * records.
 *
 * Issue #219: the flag is keyed by destination, but the post-merge backstop
 * judges only the links the current archive can affect. A fixed flag body
 * therefore let a successful apply of one source clear a flag that another
 * source's containment failure had left, without looking at the link that
 * caused it. The flag now records those links as versioned JSON:
 *
 * - `{"version":1,"state":"in-progress","links":[…]}` is written at the start
 *   of every apply, with the links carried over from the flag it replaces. It
 *   reads as unknown: an apply that stopped without recording its outcome may
 *   have published links nobody checked.
 * - `{"version":1,"state":"failed","links":[…]}` is written when an apply
 *   fails and every link that still needs verification is known; the list is
 *   complete and may be empty.
 * - `{"version":1,"state":"unknown","reason":"…"}` is written when an apply
 *   fails and the offending links could not be identified, or there are too
 *   many of them to record.
 *
 * A later apply of any source re-verifies the recorded links in its post-merge
 * backstop and clears the flag only after they and everything else passed.
 * Without a usable list — an unknown or in-progress record, a flag written by
 * an older paratix version, anything damaged — the apply refuses before it
 * touches the destination and asks for a manual check.
 */
import type { ModuleResult, SshConnection } from "../types.js"

import { failed } from "../moduleFailure.js"
import { shellQuote } from "../ssh.js"
import { CAPTURE_TRUNCATION_MARKER, InvalidUtf8OutputError } from "../sshHelpers.js"
import { isNormalizedRelativePath } from "./archiveSymlinkListing.js"

/** Issue #219: the most offending links a flag records before it records `unknown`. */
export const CONTAINMENT_FLAG_LINK_LIMIT = 256

/** Issue #219: the largest flag body in bytes; a larger one records `unknown`. */
export const CONTAINMENT_FLAG_BODY_LIMIT_BYTES = 65_536

const CONTAINMENT_FLAG_VERSION = 1
const CONTAINMENT_FLAG_MODE = "0644"

/**
 * Issue #219: the capture cap of the flag read: the body limit plus room for
 * the presence line, so a body within the limit is never cut.
 */
const FLAG_READ_HEADROOM_BYTES = 1024
const FLAG_READ_CAPTURE_LIMIT_BYTES = CONTAINMENT_FLAG_BODY_LIMIT_BYTES + FLAG_READ_HEADROOM_BYTES

/** Issue #219: the line the flag read prints before the body of a present flag. */
const FLAG_PRESENT_LINE = "present\n"

/** Issue #219: exit statuses of the flag read, see {@link buildContainmentFlagReadCommand}. */
const FLAG_READ_EXIT = { flagsDirectory: 2, notRegular: 4, symlink: 3 } as const

/** Issue #219: the `unknown` reason when there are too many offending links to record. */
export const TOO_MANY_OFFENDING_LINKS = "too many offending links"

/** Issue #219: the `unknown` reason when the backstop could not identify the offending links. */
export const UNIDENTIFIED_OFFENDING_LINKS =
  "the symlink containment check could not identify the offending links"

/**
 * Issue #219: the outcome an apply records in the flag when it fails.
 *
 * - `failed`: the complete list of destination-relative link keys that still
 *   need verification; may be empty.
 * - `unknown`: the offending links are not known.
 */
export type ContainmentFlagRecord =
  { links: readonly string[]; state: "failed" } | { reason: string; state: "unknown" }

/** Issue #219: every flag body, including the one written at the start of an apply. */
type ContainmentFlagBody =
  { links: readonly string[]; state: "in-progress" } | ContainmentFlagRecord

/**
 * Issue #219: what the flag says before an apply.
 *
 * - `absent`: no flag; nothing needs verification.
 * - `recorded`: a failed apply recorded these links.
 * - `unknown`: the flag holds no usable list; `why` says why.
 * - `unreadable`: the flag could not be read (or its directory created);
 *   `reason` says why.
 */
export type ContainmentFlagState =
  | { kind: "absent" }
  | { kind: "recorded"; links: readonly string[] }
  | { kind: "unknown"; why: string }
  | { kind: "unreadable"; reason: string }

const NO_USABLE_LIST =
  "holds no usable list of offending links (it was written by an older paratix version or is damaged)"
const IN_PROGRESS =
  "records an apply that did not finish (it stopped after it started, possibly after its merge had begun, or another apply to this destination is still running)"

/**
 * Issue #219: serialize a flag body. A link list above
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

/** Issue #219: every flag object has `version`, `state` and one more key. */
const FLAG_OBJECT_KEY_COUNT = 3

/** Issue #219: the answer for a flag without a usable list of offending links. */
const NO_USABLE_LIST_STATE = { kind: "unknown", why: NO_USABLE_LIST } as const

/** Issue #219: what {@link parseContainmentFlag} makes of a flag body. */
type ParsedContainmentFlag = Extract<ContainmentFlagState, { kind: "recorded" | "unknown" }>

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
 * Issue #219: interpret a flag object with `version`, `state` and exactly one
 * more key.
 *
 * @param value - The parsed flag object.
 * @param value.state - Its `state`.
 * @returns The recorded links, or why the flag holds no usable list.
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
 * Issue #219: interpret a flag body. Only a well-formed `failed` record of the
 * current version yields links; everything else — an `in-progress` or
 * `unknown` record, the fixed text of older versions, an empty file, invalid
 * JSON, another version or shape — is unknown.
 *
 * @param text - The flag body.
 * @returns The recorded links, or why the flag holds no usable list.
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
 * Issue #219: the flag read. It creates the flags directory (as the flag write
 * always did) and prints nothing for an absent flag, or
 * {@link FLAG_PRESENT_LINE} followed by the body for a present one, so an
 * empty flag is told apart from a missing one. A symlink at the flag path
 * (even a dangling one) exits 3, any other non-regular file 4, a failed
 * `mkdir` 2, and a failed `cat` with its own status.
 *
 * @param parameters - Paths.
 * @param parameters.directory - The flags directory.
 * @param parameters.flag - The containment flag path inside it.
 * @returns The shell command.
 */
export function buildContainmentFlagReadCommand(parameters: {
  directory: string
  flag: string
}): string {
  const flag = shellQuote(parameters.flag)
  return [
    `mkdir -p ${shellQuote(parameters.directory)} || exit ${String(FLAG_READ_EXIT.flagsDirectory)}; `,
    `if [ -L ${flag} ]; then exit ${String(FLAG_READ_EXIT.symlink)}; fi; `,
    `[ -e ${flag} ] || exit 0; `,
    `[ -f ${flag} ] || exit ${String(FLAG_READ_EXIT.notRegular)}; `,
    `printf 'present\\n' && cat -- ${flag}`,
  ].join("")
}

/**
 * Issue #219: why a flag read exited non-zero.
 *
 * @param flag - The containment flag path.
 * @param result - The read's exit code and output.
 * @param result.code - The exit code.
 * @param result.stderr - The captured stderr.
 * @returns The reason, without the `[archive.extract]` prefix.
 */
function flagReadFailure(flag: string, result: { code: number; stderr: string }): string {
  const detail = result.stderr.trim() || `exit code ${String(result.code)}`
  switch (result.code) {
    case FLAG_READ_EXIT.flagsDirectory: {
      return `failed to create archive marker directory for containment-failure flag ${flag}: ${detail}`
    }
    case FLAG_READ_EXIT.notRegular: {
      return `containment-failure flag ${flag} exists but is not a regular file`
    }
    case FLAG_READ_EXIT.symlink: {
      return `containment-failure flag ${flag} is a symlink`
    }
    default: {
      return `failed to read containment-failure flag ${flag}: ${detail}`
    }
  }
}

/**
 * Issue #219: read the containment flag in one exec, creating the flags
 * directory first. Output that is not valid UTF-8 or exceeds the capture cap
 * holds no usable list; an exec that fails or throws otherwise leaves the
 * flag unreadable, which the caller refuses.
 *
 * @param conn - The SSH connection.
 * @param parameters - Paths.
 * @param parameters.directory - The flags directory.
 * @param parameters.flag - The containment flag path.
 * @returns What the flag says.
 */
export async function readContainmentFlag(
  conn: SshConnection,
  parameters: { directory: string; flag: string }
): Promise<ContainmentFlagState> {
  const { flag } = parameters
  let result: Awaited<ReturnType<SshConnection["exec"]>>
  try {
    result = await conn.exec(buildContainmentFlagReadCommand(parameters), {
      ignoreExitCode: true,
      maxOutputBytes: FLAG_READ_CAPTURE_LIMIT_BYTES,
      silent: true,
      strictUtf8Stdout: true,
    })
  } catch (error) {
    if (error instanceof InvalidUtf8OutputError) {
      return { kind: "unknown", why: `is not valid UTF-8 and ${NO_USABLE_LIST}` }
    }
    const reason = error instanceof Error ? error.message : String(error)
    return {
      kind: "unreadable",
      reason: `failed to read containment-failure flag ${flag}: ${reason}`,
    }
  }
  if (result.code !== 0) return { kind: "unreadable", reason: flagReadFailure(flag, result) }
  if (result.stdout === "") return { kind: "absent" }
  if (!result.stdout.startsWith(FLAG_PRESENT_LINE)) {
    return {
      kind: "unreadable",
      reason: `failed to read containment-failure flag ${flag}: unexpected output`,
    }
  }
  if (result.stdout.endsWith(CAPTURE_TRUNCATION_MARKER)) {
    return {
      kind: "unknown",
      why: `is larger than ${String(CONTAINMENT_FLAG_BODY_LIMIT_BYTES)} bytes and ${NO_USABLE_LIST}`,
    }
  }
  return parseContainmentFlag(result.stdout.slice(FLAG_PRESENT_LINE.length))
}

/**
 * Issue #219: write a flag body through the guarded `writeFile`, which stages
 * a temp file and refuses to finalize onto a symlink or a directory.
 *
 * @param conn - The SSH connection.
 * @param flag - The containment flag path.
 * @param body - The body to write.
 * @returns Null when the body is in place, otherwise why it could not be written.
 */
async function writeContainmentFlag(
  conn: SshConnection,
  flag: string,
  body: ContainmentFlagBody
): Promise<null | string> {
  try {
    await conn.writeFile(flag, containmentFlagBody(body), { mode: CONTAINMENT_FLAG_MODE })
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return `failed to write containment-failure flag ${flag}: ${reason}`
  }
  return null
}

/**
 * Issue #219: the refusal for a flag without a usable list of offending links.
 *
 * @param parameters - Refusal inputs.
 * @param parameters.destination - The destination the flag belongs to.
 * @param parameters.flag - The containment flag path.
 * @param parameters.source - The archive source.
 * @param parameters.why - Why the flag holds no usable list.
 * @returns The refusal message, with the manual steps that clear the flag.
 */
export function unknownContainmentStateRefusal(parameters: {
  destination: string
  flag: string
  source: string
  why: string
}): string {
  const { destination, flag, source, why } = parameters
  return `[archive.extract] refusing to extract ${source}: the symlink containment state of ${destination} is unknown: containment flag ${flag} ${why}; check the symlinks under ${destination} manually, remove any that resolve outside it or point them inside, then remove the flag with rm -f -- ${shellQuote(flag)} and run the apply again`
}

/**
 * Issue #219: read the flag and put the `in-progress` body in place before
 * the destination is touched.
 *
 * A flag without a usable list refuses the apply before anything is written
 * and leaves the flag as it is. A flag that cannot be read, or an
 * `in-progress` body that cannot be written, refuses the apply as well.
 * Otherwise the recorded links (none for an absent flag) are carried into the
 * new body and returned, so the post-merge backstop can re-verify them.
 *
 * @param conn - The SSH connection.
 * @param parameters - Flag inputs.
 * @param parameters.destination - The validated destination directory.
 * @param parameters.directory - The flags directory.
 * @param parameters.flag - The containment flag path.
 * @param parameters.source - The archive source, for failure messages.
 * @returns The carried links, or the refusal.
 */
export async function establishContainmentFlag(
  conn: SshConnection,
  parameters: { destination: string; directory: string; flag: string; source: string }
): Promise<{ carried: readonly string[] } | ModuleResult> {
  const { destination, flag, source } = parameters
  const refusal = (reason: string): ModuleResult =>
    failed(
      `[archive.extract] refusing to extract ${source}: ${reason}; the flag must be in place before the destination is touched`
    )
  const state = await readContainmentFlag(conn, parameters)
  if (state.kind === "unreadable") return refusal(state.reason)
  if (state.kind === "unknown") {
    return failed(unknownContainmentStateRefusal({ destination, flag, source, why: state.why }))
  }
  const carried = state.kind === "recorded" ? state.links : []
  const writeFailure = await writeContainmentFlag(conn, flag, {
    links: carried,
    state: "in-progress",
  })
  if (writeFailure !== null) return refusal(writeFailure)
  return { carried }
}

/**
 * Issue #219: record a failed apply's outcome in the flag, best effort. When
 * the write fails, the `in-progress` body stays, which reads as unknown, and
 * the write failure is appended to the apply's failure.
 *
 * @param conn - The SSH connection.
 * @param parameters - Record inputs.
 * @param parameters.failure - The apply's failure.
 * @param parameters.flag - The containment flag path.
 * @param parameters.record - What to record.
 * @returns The failure, extended by a record failure if there was one.
 */
export async function recordContainmentFailure(
  conn: SshConnection,
  parameters: { failure: ModuleResult; flag: string; record: ContainmentFlagRecord }
): Promise<ModuleResult> {
  const { failure, flag, record } = parameters
  const recordFailure = await writeContainmentFlag(conn, flag, record)
  if (recordFailure === null) return failure
  const message = failure.error?.message ?? "[archive.extract] apply failed"
  return failed(
    `${message}; [archive.extract] ${recordFailure}; the flag still marks the apply as unfinished, so the next apply refuses until the symlinks are checked manually`
  )
}

/**
 * Issue #219: record a failed apply's outcome after a thrown error, ignoring
 * any failure of the write itself; the caller rethrows the error.
 *
 * @param conn - The SSH connection.
 * @param flag - The containment flag path.
 * @param record - What to record.
 */
export async function recordContainmentFailureAfterThrow(
  conn: SshConnection,
  flag: string,
  record: ContainmentFlagRecord
): Promise<void> {
  await writeContainmentFlag(conn, flag, record)
}
