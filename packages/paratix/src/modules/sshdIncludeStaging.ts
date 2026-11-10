import { posix } from "node:path"

import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { checkedIncludePatterns, expandInclude } from "./sshCertificateConfig.js"
import {
  certificateCommand,
  CertificateFileError,
  inspectCertificateFile,
} from "./sshCertificateFiles.js"
import { parseSshdConfigLine } from "./sshdConfigHelpers.js"

const MAX_INCLUDE_DEPTH = 16

/** Fixed `sshd -T -C` connection placeholders; TEST-NET-1 and a reserved TLD never resolve. */
export const SSHD_VERIFY_HOST = "paratix-verify.invalid"
export const SSHD_VERIFY_ADDRESS = "192.0.2.1"

/**
 * Replaces one parsed directive line of the staged tree. Returning `undefined`
 * keeps the original line; Include lines are always staged by the tree itself.
 */
export type SshdStagingLineRewrite = (
  parsed: { directive: string; value: string },
  line: string
) => string | undefined

/**
 * Overrides one absolute candidate path wherever an Include glob matches it.
 * A string content stages that content at the path's sorted glob position,
 * even when the real file does not exist yet; `null` omits the path.
 */
export type SshdStagingIncludeOverride = { content: null | string; path: string }

/** Input of {@link stageSshdConfigTree}. */
export type SshdStagingInput = {
  /** Content of the root configuration file. */
  content: string
  /** Creates the error thrown for cyclic or too deep Include trees (default: `CertificateFileError`). */
  createError?: (message: string) => Error
  /** Private staging directory that receives the `validation-<n>` copies. */
  directory: string
  /** Inserts or omits one candidate file wherever an Include glob matches it. */
  includeOverride?: SshdStagingIncludeOverride
  /** Rewrites individual directive lines (never Include lines). */
  rewriteLine?: SshdStagingLineRewrite
  /** Absolute path of the root configuration, used for cycle detection. */
  rootPath: string
}

type StageContext = {
  next: { value: number }
  stack: string[]
} & Pick<SshdStagingInput, "includeOverride" | "rewriteLine"> &
  Required<Pick<SshdStagingInput, "createError" | "directory">>

function escapeRegExp(text: string): string {
  return text.replaceAll(/[\\\]\[.]/gv, String.raw`\$&`)
}

// Returns the regex source and the index of the last consumed glob character.
function globToken(segment: string, index: number): { end: number; source: string } {
  const character = segment.charAt(index)
  if (character === "?") return { end: index, source: "[^/]" }
  if (character === "*") return { end: index, source: "[^/]*" }
  const end = character === "[" ? segment.indexOf("]", index + 2) : -1
  if (end === -1) return { end: index, source: escapeRegExp(character) }
  // A bracket expression; the validated alphabet has no negation or escapes.
  const members = escapeRegExp(segment.slice(index + 1, end))
  return { end, source: `[${members}]` }
}

function globSegmentPattern(segment: string): RegExp {
  let source = ""
  for (let index = 0; index < segment.length; index++) {
    const token = globToken(segment, index)
    source += token.source
    index = token.end
  }
  // eslint-disable-next-line security/detect-non-literal-regexp -- built from the validated Include alphabet
  return new RegExp(`^${source}$`, "u")
}

/**
 * Match an absolute path against an OpenSSH Include glob with glob(3) pathname
 * semantics: wildcards never cross `/`, and a leading `.` must be literal.
 * @param pattern - An absolute Include pattern from `includePatterns`.
 * @param path - The absolute candidate path.
 * @returns Whether glob(3) would expand the pattern to the path if it existed.
 */
export function includeGlobMatches(pattern: string, path: string): boolean {
  const patternSegments = posix.normalize(pattern).split("/")
  const pathSegments = posix.normalize(path).split("/")
  if (patternSegments.length !== pathSegments.length) return false
  return patternSegments.every((segment, index) => {
    const candidate = pathSegments[index] ?? ""
    if (candidate.startsWith(".") && !segment.startsWith(".")) return false
    return globSegmentPattern(segment).test(candidate)
  })
}

function byteOrder(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"))
}

async function expandWithOverride(
  ssh: SshConnection,
  pattern: string,
  context: StageContext
): Promise<Array<{ content?: string; path: string }>> {
  // A pattern such as `/etc/ssh//sshd_config.d/*.conf` expands to paths with the
  // same doubled slash; normalize them so filtering and byte-order sorting
  // compare the same spelling as the normalized candidate.
  //
  // sshd expands Include globs with glob(3), which sorts in byte order (C
  // locale). The remote shell expansion may follow another collation, so the
  // results are always sorted in byte order, whether or not an override is
  // inserted, for present, absent and host-certificate staging alike.
  const expanded = await expandInclude(ssh, pattern)
  const paths = expanded.map((path) => posix.normalize(path)).sort(byteOrder)
  const override = context.includeOverride
  if (override === undefined || !includeGlobMatches(pattern, override.path))
    return paths.map((path) => ({ path }))
  const target = posix.normalize(override.path)
  const others = paths.filter((path) => path !== target)
  if (override.content === null) return others.map((path) => ({ path }))
  // sshd sorts glob results in byte order; insert the candidate at that position.
  return [...others, target]
    .sort(byteOrder)
    .map((path) => (path === target ? { content: override.content ?? "", path } : { path }))
}

async function stageInclude(
  ssh: SshConnection,
  value: string,
  context: StageContext
): Promise<string> {
  const includes: string[] = []
  for (const pattern of await checkedIncludePatterns(ssh, value)) {
    // eslint-disable-next-line no-await-in-loop -- Include and Match order must remain unchanged
    const entries = await expandWithOverride(ssh, pattern, context)
    for (const entry of entries) {
      // eslint-disable-next-line no-await-in-loop -- stage the complete textual Include tree
      includes.push(await stageIncludedFile(ssh, entry, context))
    }
  }
  return includes.length === 0 ? "# Empty Include" : `Include ${includes.join(" ")}`
}

async function stageIncludedFile(
  ssh: SshConnection,
  entry: { content?: string; path: string },
  context: StageContext
): Promise<string> {
  if (context.stack.includes(entry.path)) throw context.createError("Cyclic sshd Include")
  let content = entry.content
  if (content === undefined) {
    await inspectCertificateFile(ssh, entry.path, { label: "sshd Include file", preserve: true })
    content = await ssh.readFile(entry.path)
  }
  return stageTree(ssh, content, { ...context, stack: [...context.stack, entry.path] })
}

async function stageLine(ssh: SshConnection, line: string, context: StageContext): Promise<string> {
  const parsed = parseSshdConfigLine(
    line.replace(/^(?<keyword>\s*[A-Za-z][A-Za-z0-9]*)\s*=\s*/v, "$<keyword> ")
  )
  if (parsed === null) return line
  if (parsed.directive.toLowerCase() === "include") return stageInclude(ssh, parsed.value, context)
  return context.rewriteLine?.(parsed, line) ?? line
}

async function stageTree(
  ssh: SshConnection,
  content: string,
  context: StageContext
): Promise<string> {
  if (context.stack.length > MAX_INCLUDE_DEPTH)
    throw context.createError("Unresolvable sshd Include depth")
  const result: string[] = []
  for (const line of content.split(/\r?\n/v)) {
    // eslint-disable-next-line no-await-in-loop -- staging preserves textual Include and Match order
    result.push(await stageLine(ssh, line, context))
  }
  const counter = context.next
  const path = `${context.directory}/validation-${String(counter.value++)}`
  await ssh.writeFile(path, result.join("\n"), { mode: "0600" })
  return path
}

/**
 * Stage a complete sshd configuration tree with every Include replaced by
 * staged copies (mode 0600, one `validation-<n>` file per included file),
 * preserving Include order and Match scope.
 * @param ssh - Connection that owns the private staging directory.
 * @param input - Root content and path, staging directory and optional hooks.
 * @returns The staged root configuration path.
 * @throws {Error} Created by `input.createError` for a cyclic Include or an Include tree deeper than the depth limit.
 */
export async function stageSshdConfigTree(
  ssh: SshConnection,
  input: SshdStagingInput
): Promise<string> {
  return stageTree(ssh, input.content, {
    createError: input.createError ?? ((message) => new CertificateFileError(message)),
    directory: input.directory,
    includeOverride: input.includeOverride,
    next: { value: 0 },
    rewriteLine: input.rewriteLine,
    stack: [input.rootPath],
  })
}

/**
 * Build the `-C` argument for `sshd -T` with the fixed placeholder address.
 * @param user - A validated literal account name.
 * @returns The shell-quoted `-C` option.
 */
export function sshdConnectionSpecArgument(user: string): string {
  const spec = `user=${user},host=${SSHD_VERIFY_HOST},addr=${SSHD_VERIFY_ADDRESS}`
  return `-C ${shellQuote(spec)}`
}

/**
 * Validate a staged tree with `sshd -t -f` and return its `sshd -T -f` output.
 * @param ssh - Connection that owns the staged tree.
 * @param input - Staged root path and optional `-C` user.
 * @param input.path - Staged root configuration path.
 * @param input.user - Optional connection user for `sshd -T -C`.
 * @returns The effective configuration printed by `sshd -T`.
 */
export async function readStagedSshdConfig(
  ssh: SshConnection,
  input: { path: string; user?: string }
): Promise<string> {
  await certificateCommand(ssh, `sshd -t -f ${shellQuote(input.path)}`)
  const connection = input.user === undefined ? "" : ` ${sshdConnectionSpecArgument(input.user)}`
  return certificateCommand(ssh, `sshd -T -f ${shellQuote(input.path)}${connection}`)
}
