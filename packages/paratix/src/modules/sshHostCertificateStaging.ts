import type { SshConnection } from "../types.js"
import type { HostCertificatePolicy, ParsedHostCertificate } from "./sshHostCertificatePolicy.js"

import { readStagedSshdConfig, stageSshdConfigTree } from "./sshdIncludeStaging.js"
import { hostDirectivePath } from "./sshHostCertificateConfig.js"
import { assertHostAlgorithms, HOST_SSHD_CONFIG } from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

type StagingInput = {
  certificatePath: string
  content: string
  directory: string
  policy: HostCertificatePolicy
}
async function validateTree(ssh: SshConnection, input: StagingInput): Promise<string> {
  const path = await stageSshdConfigTree(ssh, {
    content: input.content,
    createError: (message) => new HostCertificateError(message),
    directory: input.directory,
    // Only the managed HostCertificate assignment points at the staged certificate.
    rewriteLine(parsed) {
      if (parsed.directive.toLowerCase() === "hostkey") hostDirectivePath("HostKey", parsed.value)
      return parsed.directive.toLowerCase() === "hostcertificate" &&
        hostDirectivePath("HostCertificate", parsed.value) === input.policy.certificatePath
        ? `HostCertificate ${input.certificatePath}`
        : undefined
    },
    rootPath: HOST_SSHD_CONFIG,
  })
  return readStagedSshdConfig(ssh, { path })
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
