import type { SshConnection } from "../types.js"
import type { HostCertificatePolicy, ParsedHostCertificate } from "./sshHostCertificatePolicy.js"

import { shellQuote } from "../ssh.js"
import { expandInclude, includePatterns } from "./sshCertificateConfig.js"
import { certificateCommand, inspectCertificateFile } from "./sshCertificateFiles.js"
import { parseSshdConfigLine } from "./sshdConfigHelpers.js"
import { assertHostAlgorithms, HOST_SSHD_CONFIG } from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

const MAX_INCLUDE_DEPTH = 16

type StageTree = {
  certificate: string
  directory: string
  next: { value: number }
  policy: HostCertificatePolicy
  stack: string[]
}

async function stageInclude(
  ssh: SshConnection,
  value: string,
  context: StageTree
): Promise<string> {
  const includes: string[] = []
  for (const pattern of includePatterns(value)) {
    // eslint-disable-next-line no-await-in-loop -- Include and Match order must remain unchanged
    const paths = await expandInclude(ssh, pattern)
    for (const path of paths) {
      // eslint-disable-next-line no-await-in-loop -- stage the complete textual Include tree
      includes.push(await stageIncludedFile(ssh, path, context))
    }
  }
  return includes.length === 0 ? "# Empty Include" : `Include ${includes.join(" ")}`
}

async function stageIncludedFile(
  ssh: SshConnection,
  path: string,
  context: StageTree
): Promise<string> {
  if (context.stack.includes(path)) throw new HostCertificateError("Cyclic sshd Include")
  await inspectCertificateFile(ssh, path, { preserve: true })
  return stageTree(ssh, await ssh.readFile(path), { ...context, stack: [...context.stack, path] })
}

async function stageLine(ssh: SshConnection, line: string, context: StageTree): Promise<string> {
  const parsed = parseSshdConfigLine(
    line.replace(/^(?<keyword>\s*[A-Za-z][A-Za-z0-9]*)\s*=\s*/v, "$<keyword> ")
  )
  if (
    parsed?.directive.toLowerCase() === "hostcertificate" &&
    parsed.value.replaceAll(/^["']|["']$/gv, "") === context.policy.certificatePath
  )
    return `HostCertificate ${context.certificate}`
  if (parsed?.directive.toLowerCase() === "include") return stageInclude(ssh, parsed.value, context)
  return line
}

async function stageTree(ssh: SshConnection, content: string, context: StageTree): Promise<string> {
  if (context.stack.length > MAX_INCLUDE_DEPTH)
    throw new HostCertificateError("Unresolvable sshd Include depth")
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

type StagingInput = {
  certificatePath: string
  content: string
  directory: string
  policy: HostCertificatePolicy
}
async function validateTree(ssh: SshConnection, input: StagingInput): Promise<string> {
  const path = await stageTree(ssh, input.content, {
    certificate: input.certificatePath,
    directory: input.directory,
    next: { value: 0 },
    policy: input.policy,
    stack: [HOST_SSHD_CONFIG],
  })
  await certificateCommand(ssh, `sshd -t -f ${shellQuote(path)}`)
  return certificateCommand(ssh, `sshd -T -f ${shellQuote(path)}`)
}

export async function validateHostCandidate(
  ssh: SshConnection,
  input: { certificate: ParsedHostCertificate } & StagingInput
): Promise<void> {
  const effective = await validateTree(ssh, input)
  assertHostAlgorithms(effective, input.certificate, {
    policy: input.policy,
    stagedPath: input.certificatePath,
  })
}

/**
 * Validate the complete old configuration against an immutable old certificate snapshot.
 * @param ssh - Connection scoped to the current fenced commit.
 * @param input - Original configuration, immutable certificate and staging directory.
 */
export async function validateHostRollback(ssh: SshConnection, input: StagingInput): Promise<void> {
  await validateTree(ssh, input)
}
