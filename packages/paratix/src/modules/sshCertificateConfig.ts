import { posix } from "node:path"

import type { SshConnection } from "../types.js"

import { shellQuote } from "../ssh.js"
import { certificateCommand, CertificateFileError } from "./sshCertificateFiles.js"
import {
  applySshdSettingToContent,
  collectTopLevelSshdDirectiveValues,
  parseSshdConfigLine,
} from "./sshdConfigHelpers.js"

export const CERTIFICATE_DIRECTIVES = [
  "TrustedUserCAKeys",
  "AuthorizedPrincipalsFile",
  "RevokedKeys",
] as const
const MAX_INCLUDE_DEPTH = 32

// `match` is the Match state after the last scanned line: `true` from the first
// Match line on, until the end of the scanned file.
type Scan = { caFiles: string[]; files: string[]; match: boolean; revocations: string[] }

function unresolvableDirective(directive: string, value: string): CertificateFileError {
  return new CertificateFileError(
    `Cannot safely resolve sshd ${directive} ${value}; correct it manually`
  )
}

const ARGUMENT_SEPARATORS = " \t"

// A quote without a closing partner counts as one ordinary character here; the
// whole-token check in `directiveArguments` then rejects the token.
function rawArgumentEnd(value: string, start: number): number {
  let end = start
  while (end < value.length && !ARGUMENT_SEPARATORS.includes(value.charAt(end))) {
    const char = value.charAt(end)
    const close = char === '"' || char === "'" ? value.indexOf(char, end + 1) : -1
    end = close === -1 ? end + 1 : close + 1
  }
  return end
}

/**
 * Split a directive value the way OpenSSH 8.7+ `argv_split` does with comment
 * termination: only unquoted spaces and tabs separate arguments, quoted
 * sections may contain separators, and a token that starts with an unquoted
 * `#` ends argument parsing.
 *
 * Mid-token quotes and backslash escapes are valid for sshd but not reproduced
 * here, so such tokens fail closed instead of resolving to a different file
 * than sshd loads. Text after the comment start is not validated.
 *
 * @param directive - The directive name used in error messages.
 * @param value - The raw directive value, comment included.
 * @returns The comment text (empty without a comment) and the arguments before
 *   it, each with its raw spelling and its value after quote removal.
 * @throws {CertificateFileError} When an argument is neither a bare word nor
 *   exactly one complete quoted string, or contains a backslash, a control
 *   character or whitespace other than space and tab.
 */
function directiveArguments(
  directive: string,
  value: string
): { comment: string; tokens: Array<{ raw: string; value: string }> } {
  const tokens: Array<{ raw: string; value: string }> = []
  let index = 0
  while (index < value.length) {
    if (ARGUMENT_SEPARATORS.includes(value.charAt(index))) {
      index += 1
      continue
    }
    if (value.charAt(index) === "#") return { comment: value.slice(index), tokens }
    const end = rawArgumentEnd(value, index)
    const raw = value.slice(index, end)
    if (/[[\\\s\p{Cc}]--[ \t]]/v.test(raw) || !/^(?:"[^"]*"|'[^']*'|[^"']+)$/v.test(raw))
      throw unresolvableDirective(directive, raw)
    tokens.push({ raw, value: raw.replaceAll(/^["']|["']$/gv, "") })
    index = end
  }
  return { comment: "", tokens }
}

// The words OpenSSH 8.2-8.6 could load from a comment. Its tokenizer splits on
// whitespace, `=` and `"`, drops the quotes of a double-quoted span and keeps
// the span joined to the text directly before it. Quotes pair up in sequence,
// so the odd segments between them are the spans. The result is a superset.
function legacyCommentWords(comment: string): string[] {
  const words = comment.split(/[ \t\r\n="]+/v)
  const segments = comment.split('"')
  for (let index = 1; index < segments.length - 1; index += 2) {
    const prefix =
      segments
        .at(index - 1)
        ?.split(/[ \t\r\n=]/v)
        .at(-1) ?? ""
    words.push(`${prefix}${segments.at(index) ?? ""}`)
  }
  return [...new Set(words.filter((word) => word.length > 0))]
}

/**
 * Parse an Include value into its OpenSSH 8.7+ patterns and the comment words
 * OpenSSH 8.2-8.6 would treat as further Include arguments.
 *
 * Those versions have no trailing comments on Include lines. A comment is
 * therefore accepted only when every word stays a literal name below
 * `/etc/ssh`; callers that reach the host check those names with
 * {@link checkedIncludePatterns}.
 *
 * @param value - The raw Include value, comment included.
 * @returns The absolute patterns and the distinct comment words.
 * @throws {CertificateFileError} When an argument cannot be resolved, there is
 *   no argument, a comment contains glob syntax, a slash or a backslash, or a
 *   comment word starts with `~`.
 */
export function parseIncludeValue(value: string): { commentWords: string[]; patterns: string[] } {
  const { comment, tokens } = directiveArguments("Include", value)
  // glob(3) would expand these in a comment word, and a word with a slash or a
  // leading `~` does not resolve below /etc/ssh.
  if (/[*?\[\/\\]/v.test(comment)) throw unresolvableDirective("Include", comment)
  const commentWords = legacyCommentWords(comment)
  if (commentWords.some((word) => word.startsWith("~")))
    throw unresolvableDirective("Include", comment)
  if (tokens.length === 0) throw unresolvableDirective("Include", value)
  const patterns = tokens.map(({ raw, value: path }) => {
    // Keep shell expansion limited to OpenSSH's pathname glob syntax. More
    // elaborate/ambiguous syntax is a manual preflight conflict, never eval'd.
    // Under the OpenSSH 8.7+ rule a trailing comment starts only at a token
    // beginning with an unquoted `#`, so any `#` that reaches this check is
    // part of a path and rejected.
    if (!/^[\w.\/*?\[\]\-]+$/v.test(path)) throw unresolvableDirective("Include", raw)
    return posix.isAbsolute(path) ? path : `/etc/ssh/${path}`
  })
  return { commentWords, patterns }
}

export function includePatterns(value: string): string[] {
  return parseIncludeValue(value).patterns
}

/**
 * Resolve an Include value for callers that follow it on the host, failing
 * closed when OpenSSH 8.2-8.6 would load a file named by a comment word.
 *
 * @param ssh - Connection to the host whose configuration is read.
 * @param value - The raw Include value, comment included.
 * @param fileChanges - File existence after the planned publication or restoration.
 * @returns The absolute patterns of the Include value.
 * @throws {CertificateFileError} When the value cannot be parsed, a comment
 *   word names a planned write, an existing path or dangling symlink not being
 *   removed, or the check itself fails.
 */
export async function checkedIncludePatterns(
  ssh: SshConnection,
  value: string,
  fileChanges: ReadonlyArray<{ exists: boolean; path: string }> = []
): Promise<string[]> {
  const { commentWords, patterns } = parseIncludeValue(value)
  for (const word of commentWords) {
    const path = `/etc/ssh/${word}`
    const changed = fileChanges.find((file) => posix.normalize(file.path) === path)
    if (changed?.exists === true)
      throw unresolvableDirective("Include", `comment word ${word} (${path} is a planned write)`)
    if (changed?.exists === false) continue
    // eslint-disable-next-line no-await-in-loop -- the first match in line order is reported
    const existing = await expandInclude(ssh, shellQuote(path))
    if (existing.length > 0)
      throw unresolvableDirective("Include", `comment word ${word} (${path} exists)`)
  }
  return patterns
}

export async function expandInclude(ssh: SshConnection, pattern: string): Promise<string[]> {
  // `pattern` is either from the validated alphabet above, where quoting
  // individual literal path characters preserves only the glob operators for
  // the remote shell, or one shell-quoted literal path.
  const output = await certificateCommand(
    ssh,
    `for paratix_include in ${pattern}; do if [ -e "$paratix_include" ] || [ -L "$paratix_include" ]; then printf '%s\\n' "$paratix_include"; fi; done`
  )
  return output.length === 0 ? [] : output.split("\n")
}

type ScanParameters = {
  content: string
  /** Match state at the start of this file: `true` for a file included from inside a Match block. */
  insideMatch?: boolean
  path: string
  plannedWrites?: readonly string[]
  rejectMatch: boolean
  stack?: readonly string[]
}

async function scanCertificateIncludes(
  ssh: SshConnection,
  parameters: { value: string } & ScanParameters,
  scan: Scan
): Promise<Scan> {
  for (const pattern of await checkedIncludePatterns(
    ssh,
    parameters.value,
    parameters.plannedWrites?.map((path) => ({ exists: true, path }))
  )) {
    // eslint-disable-next-line no-await-in-loop -- Include order determines Match scope
    const includes = await expandInclude(ssh, pattern)
    for (const path of includes) {
      // An included file starts in the Match state of its Include line (an
      // Include inside a Match block is scanned as inside Match). OpenSSH's
      // server configuration parser restores the including file's Match state
      // after each included file, so a Match opened inside the included file
      // ends at that file's end and never leaks into the including file.
      // eslint-disable-next-line no-await-in-loop -- included files are scanned in Include order
      const nested = await scanIncludedConfig(ssh, {
        insideMatch: scan.match,
        path,
        plannedWrites: parameters.plannedWrites,
        rejectMatch: parameters.rejectMatch,
        stack: [...(parameters.stack ?? []), parameters.path],
      })
      scan.caFiles.push(...nested.caFiles)
      scan.files.push(...nested.files)
      scan.revocations.push(...nested.revocations)
    }
  }
  return scan
}

async function revocationPaths(
  ssh: SshConnection,
  directive: string,
  value: string
): Promise<string[]> {
  const { tokens } = directiveArguments(directive, value)
  const path = tokens.at(0)?.value ?? ""
  // sshd accepts exactly one filename argument for these directives.
  if (tokens.length !== 1 || path.length === 0) throw unresolvableDirective(directive, value)
  if (path.toLowerCase() === "none") return []
  if (!posix.isAbsolute(path)) throw unresolvableDirective(directive, value)
  const normalized = posix.normalize(path)
  const paths = [normalized]
  if (await ssh.test(`[ -e ${shellQuote(normalized)} ] || [ -L ${shellQuote(normalized)} ]`)) {
    const physicalPath = await certificateCommand(ssh, `readlink -f -- ${shellQuote(normalized)}`)
    if (physicalPath.length === 0)
      throw new CertificateFileError(
        `Cannot resolve sshd ${directive} ${normalized}; correct it manually`
      )
    paths.push(physicalPath)
  }
  return paths
}

async function scanCertificateLine(
  ssh: SshConnection,
  parameters: { line: string } & ScanParameters,
  scan: Scan
): Promise<Scan> {
  const parsed = parseSshdConfigLine(
    parameters.line.replace(/^(?<keyword>\s*[A-Za-z][A-Za-z0-9]*)\s*=\s*/v, "$<keyword> ")
  )
  if (parsed === null) {
    if (/^\s*include(?:\s|=|$)/iv.test(parameters.line))
      throw new CertificateFileError(`Unresolvable sshd Include: ${parameters.path}`)
    return scan
  }
  const directive = parsed.directive.toLowerCase()
  if (directive === "match") return { ...scan, match: true }
  if (
    scan.match &&
    parameters.rejectMatch &&
    CERTIFICATE_DIRECTIVES.some((name) => name.toLowerCase() === directive)
  ) {
    throw new CertificateFileError(
      `${parsed.directive} occurs in a Match block (${parameters.path}); correct or remove it manually`
    )
  }
  if (directive === "revokedkeys")
    scan.revocations.push(...(await revocationPaths(ssh, "RevokedKeys", parsed.value)))
  if (directive === "trustedusercakeys")
    scan.caFiles.push(...(await revocationPaths(ssh, "TrustedUserCAKeys", parsed.value)))
  if (directive === "include")
    return scanCertificateIncludes(ssh, { ...parameters, value: parsed.value }, scan)
  return scan
}

export async function scanCertificateSshdConfig(
  ssh: SshConnection,
  parameters: ScanParameters
): Promise<Scan> {
  const stack = parameters.stack ?? []
  if (stack.includes(parameters.path) || stack.length >= MAX_INCLUDE_DEPTH) {
    throw new CertificateFileError(
      `Unresolvable/cyclic sshd Include structure at ${parameters.path}`
    )
  }
  let scan: Scan = {
    caFiles: [],
    files: [parameters.path],
    match: parameters.insideMatch ?? false,
    revocations: [],
  }
  for (const line of parameters.content.split(/\r?\n/v)) {
    // eslint-disable-next-line no-await-in-loop -- directives and Includes must be scanned in source order
    scan = await scanCertificateLine(ssh, { ...parameters, line }, scan)
  }
  return {
    ...scan,
    caFiles: [...new Set(scan.caFiles)],
    files: [...new Set(scan.files)],
    revocations: [...new Set(scan.revocations)],
  }
}

async function scanIncludedConfig(
  ssh: SshConnection,
  parameters: {
    insideMatch: boolean
    path: string
    plannedWrites?: readonly string[]
    rejectMatch: boolean
    stack: readonly string[]
  }
): Promise<Scan> {
  if (
    !(await ssh.test(
      `[ -f ${shellQuote(parameters.path)} ] && [ -r ${shellQuote(parameters.path)} ]`
    ))
  ) {
    throw new CertificateFileError(`Cannot read active sshd Include: ${parameters.path}`)
  }
  const physicalPath = await certificateCommand(
    ssh,
    `readlink -f -- ${shellQuote(parameters.path)}`
  )
  if (physicalPath.length === 0)
    throw new CertificateFileError(`Cannot resolve active sshd Include: ${parameters.path}`)
  const nested = await scanCertificateSshdConfig(ssh, {
    ...parameters,
    content: await ssh.readFile(physicalPath),
    path: physicalPath,
  })
  return { ...nested, files: [...new Set([posix.normalize(parameters.path), ...nested.files])] }
}

export function buildCertificateConfig(
  content: string,
  settings: Record<string, string>,
  state: "absent" | "present"
): string {
  if (state === "present") {
    let result = content
    for (const [key, value] of Object.entries(settings))
      result = applySshdSettingToContent(result, key, value)
    return result
  }
  for (const [key, expected] of Object.entries(settings)) {
    const values = collectTopLevelSshdDirectiveValues(content, key)
    if (values.some((value) => value !== expected)) {
      throw new CertificateFileError(
        `Cannot remove foreign ${key}: expected ${expected}, found ${values.join(", ")}`
      )
    }
  }
  let match = false
  const managed = new Set(Object.keys(settings).map((key) => key.toLowerCase()))
  return content
    .split(/\r?\n/v)
    .filter((line) => {
      const parsed = parseSshdConfigLine(line)
      if (parsed?.directive.toLowerCase() === "match") match = true
      return match || parsed === null || !managed.has(parsed.directive.toLowerCase())
    })
    .join("\n")
}
