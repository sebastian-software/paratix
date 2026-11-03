import type { ModuleResult, SshConnection } from "../types.js"
import type { SshdConfigTransaction } from "./sshd.js"
import type { HostCertificatePolicy, ParsedHostCertificate } from "./sshHostCertificatePolicy.js"
import type { HostTarget } from "./sshHostCertificateTarget.js"

import { shellQuote } from "../ssh.js"
import { certificateCommand, sameState } from "./sshCertificateFiles.js"
import { withSshdConfigTransaction } from "./sshd.js"
import {
  hostPendingExists,
  pendingDirectory,
  pendingSidecar,
  type PendingState,
  prepareHostPending,
  publishHostPending,
} from "./sshHostCertificatePending.js"
import { certificateSatisfies, parseHostCertificate } from "./sshHostCertificatePolicy.js"
import {
  commitHostPending,
  controllerSeconds,
  recoverHostPending,
} from "./sshHostCertificateRecovery.js"
import { validateHostCandidate } from "./sshHostCertificateStaging.js"
import { convergedHostTarget, inspectHostTarget } from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

type CommitInput = { certificate: string; policy: HostCertificatePolicy; target: HostTarget }

async function publishValidated(
  transaction: SshdConfigTransaction,
  prepared: PendingState,
  certificate: ParsedHostCertificate
): Promise<ModuleResult> {
  const ssh = transaction.connection
  let published = false
  try {
    await validateHostCandidate(ssh, {
      certificate,
      certificatePath: pendingSidecar(prepared.manifest, "certificate", "candidate"),
      content: await ssh.readFile(pendingSidecar(prepared.manifest, "config", "candidate")),
      directory: pendingDirectory(prepared.manifest),
      policy: prepared.manifest.policy,
    })
    const pending = await publishHostPending(ssh, prepared)
    published = true
    await commitHostPending(transaction, pending)
    return { status: "changed" }
  } finally {
    if (!published && !(await hostPendingExists(ssh)))
      await certificateCommand(ssh, `rm -rf -- ${shellQuote(pendingDirectory(prepared.manifest))}`)
  }
}

async function commitUnderLease(
  transaction: SshdConfigTransaction,
  input: CommitInput
): Promise<ModuleResult> {
  const ssh = transaction.connection
  await recoverHostPending(transaction, input.policy)
  const target = await inspectHostTarget(ssh, input.policy)
  if (convergedHostTarget(target, input.policy, controllerSeconds())) return { status: "ok" }
  if (
    target.publicKey !== input.target.publicKey ||
    !sameState(target.hostKeyState, input.target.hostKeyState)
  )
    throw new HostCertificateError(
      "Host key changed during controller signing; discarding stale signer output"
    )
  const certificate = parseHostCertificate(input.certificate)
  if (
    !certificateSatisfies(certificate, {
      now: controllerSeconds(),
      policy: input.policy,
      publicKey: target.publicKey,
    })
  )
    throw new HostCertificateError(
      "Controller certificate no longer satisfies the current host policy"
    )
  await transaction.requireReloadOnly()
  const prepared = await prepareHostPending(ssh, {
    certificate: input.certificate,
    policy: input.policy,
    target,
  })
  return publishValidated(transaction, prepared, certificate)
}

export async function repairOrCommit(
  ssh: SshConnection,
  input: CommitInput
): Promise<ModuleResult> {
  return withSshdConfigTransaction(ssh, {
    allowPending: true,
    dryRun: false,
    name: "ssh.hostCertificate",
    section: async (transaction) => commitUnderLease(transaction, input),
  })
}
