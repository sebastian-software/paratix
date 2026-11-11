import type { SshdConfigTransaction } from "./sshd.js"

import { certificateCommand } from "./sshCertificateFiles.js"
import {
  cleanupHostPending,
  pendingDirectory,
  pendingSidecar,
  type PendingState,
  publishHostFile,
  readHostPending,
  transitionHostPending,
  verifyHostPending,
} from "./sshHostCertificatePending.js"
import {
  certificateSatisfies,
  type HostCertificatePolicy,
  parseHostCertificate,
} from "./sshHostCertificatePolicy.js"
import { validateHostCandidate, validateHostRollback } from "./sshHostCertificateStaging.js"
import { assertHostAlgorithms } from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

const MILLISECONDS_PER_SECOND = 1000

export const controllerSeconds = (): number => Math.floor(Date.now() / MILLISECONDS_PER_SECOND)

async function assertLiveConfiguration(
  transaction: SshdConfigTransaction,
  pending: PendingState
): Promise<void> {
  const ssh = transaction.connection
  await certificateCommand(ssh, "sshd -t")
  const effective = await certificateCommand(ssh, "sshd -T")
  const certificate = parseHostCertificate(
    await ssh.readFile(pending.manifest.policy.certificatePath)
  )
  if (
    !certificateSatisfies(certificate, {
      now: controllerSeconds(),
      policy: pending.manifest.policy,
      publicKey: pending.manifest.publicKey,
    })
  )
    throw new HostCertificateError("Published host certificate no longer satisfies the policy")
  assertHostAlgorithms(effective, certificate, {
    policy: pending.manifest.policy,
    stagedPath: pending.manifest.policy.certificatePath,
  })
}

async function validateRestore(
  transaction: SshdConfigTransaction,
  pending: PendingState
): Promise<void> {
  const ssh = transaction.connection
  const certificate = pending.manifest.files[0]
  const originalConfig = await ssh.readFile(pendingSidecar(pending.manifest, "config", "original"))
  await validateHostRollback(ssh, {
    certificateContent:
      certificate.original === null
        ? null
        : await ssh.readFile(pendingSidecar(pending.manifest, "certificate", "original")),
    certificatePath:
      certificate.original === null
        ? pending.manifest.policy.certificatePath
        : pendingSidecar(pending.manifest, "certificate", "original"),
    content: originalConfig,
    directory: pendingDirectory(pending.manifest),
    policy: pending.manifest.policy,
  })
}

/**
 * Repeated restoration always copies from the same immutable source set.
 * @param transaction - Fenced sshd transaction with pure reload controls.
 * @param current - Durable Pending state containing immutable restore sources.
 */
export async function restoreHostPending(
  transaction: SshdConfigTransaction,
  current: PendingState
): Promise<void> {
  const ssh = transaction.connection
  await verifyHostPending(ssh, current)
  await transaction.requireReloadOnly()
  let pending = current
  if (pending.manifest.phase !== "rollback")
    pending = await transitionHostPending(ssh, pending, "rollback")
  await validateRestore(transaction, pending)
  const [certificate, config] = pending.manifest.files
  await publishHostFile(ssh, pending, { file: certificate, kind: "original" })
  await publishHostFile(ssh, pending, { file: config, kind: "original" })
  await certificateCommand(ssh, "sshd -t")
  await transaction.readEffective({})
  await transaction.reloadOnly()
  const complete = await transitionHostPending(ssh, pending, "complete-old")
  await cleanupHostPending(ssh, complete)
}

/**
 * Candidate publication, reload, atomic completion, then independent repeatable cleanup.
 * @param transaction - Fenced sshd transaction with pure reload controls.
 * @param current - Validated Pending candidate to publish and complete.
 * @returns After activation and repeatable cleanup succeed.
 */
export async function commitHostPending(
  transaction: SshdConfigTransaction,
  current: PendingState
): Promise<void> {
  let complete: PendingState
  try {
    await activatePendingCandidate(transaction, current)
    complete = await transitionHostPending(transaction.connection, current, "complete-new")
  } catch (error) {
    return handleCommitFailure(transaction, current, error)
  }
  // Cleanup failures retain a completed manifest and can never trigger rollback.
  await cleanupHostPending(transaction.connection, complete)
}

async function activatePendingCandidate(
  transaction: SshdConfigTransaction,
  pending: PendingState
): Promise<void> {
  const ssh = transaction.connection
  await verifyHostPending(ssh, pending)
  await transaction.requireReloadOnly()
  const certificate = parseHostCertificate(
    await ssh.readFile(pendingSidecar(pending.manifest, "certificate", "candidate"))
  )
  if (
    !certificateSatisfies(certificate, {
      now: controllerSeconds(),
      policy: pending.manifest.policy,
      publicKey: pending.manifest.publicKey,
    })
  )
    throw new HostCertificateError("Pending candidate is no longer valid for this host policy")
  await validateHostCandidate(ssh, {
    certificate,
    certificatePath: pendingSidecar(pending.manifest, "certificate", "candidate"),
    content: await ssh.readFile(pendingSidecar(pending.manifest, "config", "candidate")),
    directory: pendingDirectory(pending.manifest),
    policy: pending.manifest.policy,
  })
  for (const file of pending.manifest.files) {
    // eslint-disable-next-line no-await-in-loop -- certificate precedes the configuration that references it
    await publishHostFile(ssh, pending, { file, kind: "candidate" })
  }
  await assertLiveConfiguration(transaction, pending)
  if (pending.manifest.files.some((file) => file.original?.hash !== file.candidate?.hash))
    await transaction.reloadOnly()
}

async function handleCommitFailure(
  transaction: SshdConfigTransaction,
  current: PendingState,
  error: unknown
): Promise<never> {
  // Re-read the durable phase: completion may have succeeded before a transport error.
  const recorded = await readHostPending(transaction.connection)
  if (recorded?.manifest.phase.startsWith("complete-") === true)
    throw new HostCertificateError(
      "Host certificate commit completed; cleanup must resume on the next run"
    )
  try {
    await restoreHostPending(transaction, recorded ?? current)
  } catch {
    throw new HostCertificateError(
      "Host certificate commit failed and automatic rollback is incomplete; Pending evidence retained for the next run"
    )
  }
  throw new HostCertificateError(
    error instanceof HostCertificateError
      ? `${error.message}; previous state restored and reloaded`
      : "Host certificate commit failed; previous state restored and reloaded"
  )
}

export async function recoverHostPending(
  transaction: SshdConfigTransaction,
  policy: HostCertificatePolicy
): Promise<"cleaned" | "none" | "restored" | "resumed"> {
  const ssh = transaction.connection
  const current = await readHostPending(ssh)
  if (current === null) return "none"
  await verifyHostPending(ssh, current)
  if (current.manifest.phase.startsWith("complete-")) {
    await cleanupHostPending(ssh, current)
    return "cleaned"
  }
  const samePolicy = JSON.stringify(current.manifest.policy) === JSON.stringify(policy)
  const candidate = parseHostCertificate(
    await ssh.readFile(pendingSidecar(current.manifest, "certificate", "candidate"))
  )
  if (
    current.manifest.phase === "rollback" ||
    !samePolicy ||
    !certificateSatisfies(candidate, {
      now: controllerSeconds(),
      policy,
      publicKey: current.manifest.publicKey,
    })
  ) {
    await restoreHostPending(transaction, current)
    return "restored"
  }
  await commitHostPending(transaction, current)
  return "resumed"
}
