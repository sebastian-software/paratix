import { open } from "node:fs/promises"

import { HostCertificateError } from "./sshSignerProcess.js"

const MILLISECONDS_PER_SECOND = 1000
const ISO_DATE_TIME_LENGTH = 19
const MAX_CERTIFICATE_BYTES = 65_536

export function openSshUtc(seconds: number): string {
  return `${new Date(seconds * MILLISECONDS_PER_SECOND)
    .toISOString()
    .slice(0, ISO_DATE_TIME_LENGTH)
    .replaceAll(/[\-:T]/gv, "")}Z`
}

/**
 * Bound file reads independently of the subprocess output limit.
 * @param path - Fixed certificate path in the protected signer directory.
 * @returns The bounded UTF-8 certificate contents.
 */
export async function readSignerCertificate(path: string): Promise<string> {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed file in the private signer directory
    const file = await open(path, "r")
    try {
      const buffer = Buffer.alloc(MAX_CERTIFICATE_BYTES + 1)
      const { bytesRead } = await file.read(buffer, 0, buffer.length, 0)
      if (bytesRead > MAX_CERTIFICATE_BYTES) throw new Error("oversized")
      const metadata = await file.stat()
      if (metadata.size > MAX_CERTIFICATE_BYTES) throw new Error("oversized")
      return buffer.subarray(0, bytesRead).toString("utf8")
    } finally {
      await file.close()
    }
  } catch {
    throw new HostCertificateError("Controller signer did not produce one readable certificate")
  }
}
