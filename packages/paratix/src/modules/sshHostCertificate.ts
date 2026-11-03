import type { HostCertificateOptions } from "./sshHostCertificateTypes.js"

import { failed } from "../moduleFailure.js"
import { type Module, NEEDS_APPLY, type SshConnection } from "../types.js"
import { applyHostCertificate } from "./sshHostCertificateApply.js"
import { hostPendingExists } from "./sshHostCertificatePending.js"
import { hostCertificatePolicy, type HostCertificatePolicy } from "./sshHostCertificatePolicy.js"
import { controllerSeconds } from "./sshHostCertificateRecovery.js"
import { convergedHostTarget, inspectHostTarget } from "./sshHostCertificateTarget.js"
import { HostCertificateError } from "./sshSignerProcess.js"

async function checkHost(ssh: SshConnection, policy: HostCertificatePolicy): Promise<boolean> {
  if (await hostPendingExists(ssh)) return false
  return convergedHostTarget(await inspectHostTarget(ssh, policy), policy, controllerSeconds())
}

/**
 * Issue or renew a certificate for an existing target host key.
 *
 * Public state inspection powers check and dry-run without invoking the signer or resolving
 * secrets. Apply signs on the controller only when required, then publishes a validated
 * certificate through the target's reload-only transaction and retains secret-free Pending state
 * if interrupted. A successful run does not schedule autonomous renewal.
 * @param options - Host identity, validity policy and controller signer.
 * @returns The module for inspection, dry-run and transactional application.
 */
export function hostCertificate(options: HostCertificateOptions): Module {
  const policy = hostCertificatePolicy(options)
  const signer = options.signer
  return {
    async _applyDryRun(ssh) {
      if (ssh === null) return failed("[ssh.hostCertificate] SSH connection is required")
      try {
        return { status: (await checkHost(ssh, policy)) ? "ok" : "changed" }
      } catch (error) {
        return failed(
          `[ssh.hostCertificate] ${error instanceof HostCertificateError ? error.message : "Public state inspection failed"}`
        )
      }
    },
    async apply(ssh) {
      if (ssh === null) return failed("[ssh.hostCertificate] SSH connection is required")
      try {
        return await applyHostCertificate(ssh, signer, policy)
      } catch (error) {
        return failed(
          `[ssh.hostCertificate] ${error instanceof HostCertificateError ? error.message : "Target certificate transaction failed; inspect retained Pending state before administrative changes"}`
        )
      }
    },
    async check(ssh) {
      if (ssh === null) return NEEDS_APPLY
      try {
        return (await checkHost(ssh, policy)) ? "ok" : NEEDS_APPLY
      } catch {
        return NEEDS_APPLY
      }
    },
    name: `ssh.hostCertificate: ${policy.keyType}`,
  }
}
