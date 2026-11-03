import { randomUUID } from "node:crypto"

import type { ModuleResult, SshConnection } from "../types.js"
import type { HostCertificatePolicy } from "./sshHostCertificatePolicy.js"
import type { HostTarget } from "./sshHostCertificateTarget.js"
import type { HostCertificateRequest, HostCertificateSigner } from "./sshHostCertificateTypes.js"

import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import { withSshdConfigTransaction } from "./sshd.js"
import { repairOrCommit } from "./sshHostCertificateCommit.js"
import { hostPendingExists } from "./sshHostCertificatePending.js"
import { assertSignerCertificate } from "./sshHostCertificatePolicy.js"
import { controllerSeconds, recoverHostPending } from "./sshHostCertificateRecovery.js"
import {
  convergedHostTarget,
  inspectHostTarget,
  reusableHostCertificate,
} from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

async function recoverIfNeeded(
  ssh: SshConnection,
  policy: HostCertificatePolicy
): Promise<ModuleResult | null> {
  if (!(await hostPendingExists(ssh))) return null
  const recovery: { resumed: boolean } = { resumed: false }
  const result = await withSshdConfigTransaction(ssh, {
    allowPending: true,
    dryRun: false,
    name: "ssh.hostCertificate recovery",
    async section(transaction) {
      const outcome = await recoverHostPending(transaction, policy)
      recovery.resumed = outcome === "resumed"
      if (outcome === "cleaned")
        recovery.resumed = convergedHostTarget(
          await inspectHostTarget(transaction.connection, policy),
          policy,
          controllerSeconds()
        )
      return { status: "changed" }
    },
  })
  return result.status === "failed" || recovery.resumed ? result : null
}

async function confirmedSigningTarget(
  ssh: SshConnection,
  policy: HostCertificatePolicy
): Promise<{ result: ModuleResult; target?: HostTarget }> {
  const snapshot: { target?: HostTarget } = {}
  const result = await withSshdConfigTransaction(ssh, {
    allowPending: true,
    dryRun: false,
    name: "ssh.hostCertificate pre-sign",
    async section(transaction) {
      await recoverHostPending(transaction, policy)
      snapshot.target = await inspectHostTarget(transaction.connection, policy)
      if (convergedHostTarget(snapshot.target, policy, controllerSeconds())) return { status: "ok" }
      await transaction.requireReloadOnly()
      return { status: "changed" }
    },
  })
  return { result, target: snapshot.target }
}

async function signCertificate(
  signer: HostCertificateSigner,
  target: HostTarget,
  policy: HostCertificatePolicy
): Promise<string> {
  const validAfter = controllerSeconds()
  const signal = getRunnerAbortSignal() ?? new AbortController().signal
  const request: HostCertificateRequest = Object.freeze({
    principals: Object.freeze([...policy.principals]),
    publicKey: target.publicKey,
    requestId: randomUUID(),
    signal,
    validAfter,
    validBefore: validAfter + policy.validity,
    version: 1,
  })
  signal.throwIfAborted()
  let certificate: string
  try {
    certificate = await signer.sign(request)
  } catch {
    throw new HostCertificateError(
      "Controller host certificate signing failed; target state is unchanged and the CA request is not retried"
    )
  }
  signal.throwIfAborted()
  assertSignerCertificate(certificate, {
    now: controllerSeconds(),
    policy,
    publicKey: target.publicKey,
    request,
  })
  return certificate
}

export async function applyHostCertificate(
  ssh: SshConnection,
  signer: HostCertificateSigner,
  policy: HostCertificatePolicy
): Promise<ModuleResult> {
  const recovered = await recoverIfNeeded(ssh, policy)
  if (recovered !== null) return recovered
  const initial = await inspectHostTarget(ssh, policy)
  if (convergedHostTarget(initial, policy, controllerSeconds())) return { status: "ok" }
  const reusable = reusableHostCertificate(initial, policy, controllerSeconds())
  if (reusable !== null)
    return repairOrCommit(ssh, { certificate: reusable, policy, target: initial })
  // Reconfirm need, release the target lease, sign, then reacquire and recheck before publication.
  const confirmed = await confirmedSigningTarget(ssh, policy)
  if (confirmed.result.status !== "changed") return confirmed.result
  if (confirmed.target === undefined)
    throw new HostCertificateError("Could not confirm host certificate signing need")
  const certificate =
    reusableHostCertificate(confirmed.target, policy, controllerSeconds()) ??
    (await signCertificate(signer, confirmed.target, policy))
  return repairOrCommit(ssh, { certificate, policy, target: confirmed.target })
}
