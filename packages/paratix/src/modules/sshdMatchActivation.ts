import type { SshConnection } from "../types.js"
import type { SshdMatchSpec } from "./sshdMatchSpec.js"

import { shellQuote } from "../ssh.js"
import { certificateCommand, inspectCertificateFile } from "./sshCertificateFiles.js"
import { errorText, SshdMatchError } from "./sshdMatchChecks.js"

/**
 * Whether an earlier run changed the drop-in without a confirmed reload. Read-only,
 * and also safe before `/var/lib/paratix` exists.
 * @param ssh - Target connection.
 * @param spec - Normalized module specification.
 * @returns `true` while the state file exists.
 * @throws {Error} When the state file is a symlink, not a regular file, or unsafe.
 */
export async function readActivationPending(
  ssh: SshConnection,
  spec: SshdMatchSpec
): Promise<boolean> {
  const state = await inspectCertificateFile(ssh, spec.pendingPath, {
    label: "sshd.match pending-activation file",
    preserve: true,
  })
  return state !== null
}

/**
 * Record, before the drop-in changes, that sshd has not confirmed the change yet.
 * @param ssh - Lease-fenced connection; its commands prepare the state directory.
 * @param spec - Normalized module specification.
 * @throws {SshdMatchError} When the state file cannot be written; nothing changed yet.
 */
export async function recordActivationPending(
  ssh: SshConnection,
  spec: SshdMatchSpec
): Promise<void> {
  try {
    await ssh.writeFile(spec.pendingPath, `pending sshd activation of ${spec.path}\n`, {
      mode: "0600",
    })
  } catch (error) {
    throw new SshdMatchError(
      `cannot record the pending activation in ${spec.pendingPath}, drop-in left unchanged: ${errorText(error)}`,
      { cause: error }
    )
  }
}

/**
 * Remove the state file. Returns the failure instead of throwing, because the
 * callers have already changed the host and must report that as well.
 * @param ssh - Lease-fenced connection.
 * @param spec - Normalized module specification.
 * @returns The failure text, or `undefined` once the file is gone.
 */
export async function clearActivationPending(
  ssh: SshConnection,
  spec: SshdMatchSpec
): Promise<string | undefined> {
  try {
    await certificateCommand(ssh, `rm -f -- ${shellQuote(spec.pendingPath)}`)
    return undefined
  } catch (error) {
    return errorText(error)
  }
}
