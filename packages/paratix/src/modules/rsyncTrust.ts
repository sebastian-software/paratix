import { randomUUID } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import type { HostVerificationEvidence } from "../hostCertificates.js"

const DEFAULT_SSH_PORT = 22

function formatKnownHostsLabel(host: string, port: number): string {
  return port === DEFAULT_SSH_PORT ? host : `[${host}]:${port}`
}

export function createVerifiedKnownHostsFile(
  evidence: HostVerificationEvidence,
  revocations: string[]
): string {
  const filePath = join(tmpdir(), `paratix-rsync-known-hosts-${randomUUID()}`)
  const host = formatKnownHostsLabel(evidence.host, evidence.port)
  const anchor =
    evidence.kind === "certificate" && !evidence.explicitPins
      ? `@cert-authority ${host} ${evidence.authorityPublicKey}`
      : `${host} ${evidence.publicKey}`
  const lines = [anchor, ...revocations.map((key) => `@revoked ${host} ${key}`)]
  const content = `${lines.join("\n")}\n`
  // R-0000247: open with `wx` (O_WRONLY | O_CREAT | O_EXCL) so the create
  // step refuses to follow a pre-existing symlink in /tmp on shared hosts
  // without sticky bit. Combined with the random UUID in the filename,
  // this makes a symlink-replacement attack effectively impossible.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(filePath, content, { flag: "wx", mode: 0o600 })
  return filePath
}

export function hostAlgorithmFlags(evidence: HostVerificationEvidence): string {
  if (evidence.kind !== "certificate" || !evidence.explicitPins) return ""
  const algorithm = evidence.publicKey.split(" ")[0]
  return ` -o HostKeyAlgorithms=${algorithm === "ssh-rsa" ? "rsa-sha2-512,rsa-sha2-256" : algorithm}`
}

export function cleanupVerifiedKnownHostsFile(path: null | string): void {
  if (path == null) return
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    unlinkSync(path)
  } catch {
    // local cleanup is best-effort
  }
}
