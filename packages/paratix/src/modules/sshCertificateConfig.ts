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

export function includePatterns(value: string): string[] {
  const tokens = value.match(/"[^"\r\n]*"|'[^'\r\n]*'|\S+/gv) ?? []
  return tokens.map((token) => {
    const path = token.replaceAll(/^["']|["']$/gv, "")
    // Keep shell expansion limited to OpenSSH's pathname glob syntax. More
    // elaborate/ambiguous syntax is a manual preflight conflict, never eval'd.
    if (!/^[\w.\/*?\[\]\-]+$/v.test(path)) {
      throw new CertificateFileError(
        `Cannot safely resolve sshd Include ${token}; correct it manually`
      )
    }
    return posix.isAbsolute(path) ? path : `/etc/ssh/${path}`
  })
}

export async function expandInclude(ssh: SshConnection, pattern: string): Promise<string[]> {
  // The alphabet was validated above. Quoting individual literal path
  // characters preserves only the glob operators for the remote shell.
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
  rejectMatch: boolean
  stack?: readonly string[]
}

async function scanCertificateIncludes(
  ssh: SshConnection,
  parameters: { value: string } & ScanParameters,
  scan: Scan
): Promise<Scan> {
  for (const pattern of includePatterns(parameters.value)) {
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

async function revocationPaths(ssh: SshConnection, value: string): Promise<string[]> {
  if (value === "none") return []
  const path = value.replaceAll(/^["']|["']$/gv, "")
  const normalized = posix.normalize(posix.isAbsolute(path) ? path : `/etc/ssh/${path}`)
  const paths = [normalized]
  if (await ssh.test(`[ -e ${shellQuote(normalized)} ] || [ -L ${shellQuote(normalized)} ]`)) {
    paths.push(await certificateCommand(ssh, `readlink -f -- ${shellQuote(normalized)}`))
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
    scan.revocations.push(...(await revocationPaths(ssh, parsed.value)))
  if (directive === "trustedusercakeys")
    scan.caFiles.push(...(await revocationPaths(ssh, parsed.value)))
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
  parameters: { insideMatch: boolean; path: string; rejectMatch: boolean; stack: readonly string[] }
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
