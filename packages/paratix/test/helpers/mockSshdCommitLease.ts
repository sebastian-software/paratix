import type { withSshdCommitLease } from "../../src/modules/sshdCommitLock.js"

import { withMutexLock } from "../../src/modules/mutexLock.js"

/**
 * Domain unit tests retain the original lease and exact command/write fault assertions.
 * The target-process kernel/fencing boundary is exercised by real Docker process proofs.
 * @param ssh - Domain-test connection retaining the original lease behavior.
 * @param options - Writer identity and transaction section under test.
 * @returns The section result or original lease-acquisition failure.
 */
export const mockSshdCommitLease: typeof withSshdCommitLease = async (ssh, options) => {
  const result = await withMutexLock(ssh, {
    failureMessage: `[${options.name}] failed to acquire sshd_config mutex`,
    lockName: "etc-ssh-sshd-config-mutex",
    propagateSectionThrows: true,
    section: async (handle) => options.section(ssh, handle),
  })
  return result.kind === "ok" ? result.value : result.failure
}
