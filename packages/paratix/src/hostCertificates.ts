import type { HostKeyInfo } from "@paratix/ssh-native"

import { createHash } from "node:crypto"

import { matchesHostPattern } from "./knownHostPatterns.js"

/** Trust established by one successful authenticated handshake. */
export type HostVerificationEvidence = (
  { authorityPublicKey: string; kind: "certificate" } | { kind: "key" }
) & {
  explicitPins: boolean
  host: string
  port: number
  publicKey: string
  revocations: string[]
}

const SSH_STRING_LENGTH_BYTES = 4

/**
 * Extract the public leaf from a revoked certificate, independent of renewal.
 *
 * @param key - The raw key or certificate blob from a revocation entry.
 * @returns The certified raw leaf, or the original blob when parsing fails.
 */
export function normalizeRevokedKey(key: Buffer): Buffer {
  let offset = 0
  const readString = (): Buffer => {
    if (offset + SSH_STRING_LENGTH_BYTES > key.length) throw new Error("Invalid revoked key")
    const length = key.readUInt32BE(offset)
    offset += SSH_STRING_LENGTH_BYTES
    if (length > key.length - offset) throw new Error("Invalid revoked key")
    const value = key.subarray(offset, offset + length)
    offset += length
    return value
  }
  try {
    const algorithm = readString().toString("ascii")
    if (!algorithm.endsWith("-cert-v01@openssh.com")) return key
    const rawAlgorithm = algorithm.replace("-cert-v01@openssh.com", "")
    readString() // Certificate nonce precedes the certified public key fields.
    const fieldCount = rawAlgorithm === "ssh-ed25519" ? 1 : 2
    if (!/^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))$/v.test(rawAlgorithm)) {
      return key
    }
    const fields: Buffer[] = [Buffer.from(rawAlgorithm)]
    for (let index = 0; index < fieldCount; index += 1) fields.push(readString())
    return Buffer.concat(
      fields.map((value) => {
        const length = Buffer.alloc(SSH_STRING_LENGTH_BYTES)
        length.writeUInt32BE(value.length)
        return Buffer.concat([length, value])
      })
    )
  } catch {
    return key
  }
}

/**
 * Compute the OpenSSH SHA-256 fingerprint of a public key blob.
 *
 * @param value - The public key blob.
 * @returns The OpenSSH fingerprint without padding.
 */
function fingerprint(value: Buffer): string {
  return `SHA256:${createHash("sha256").update(value).digest("base64").replaceAll("=", "")}`
}

/**
 * Native validation owns signatures and integer time; JS authorizes identity.
 *
 * @param info - The native certificate metadata and validation verdict.
 * @param key - The certified raw leaf blob.
 * @param host - The requested host without a port.
 * @returns Whether the metadata consistently identifies a valid certificate for the host.
 */
export function certificateMetadataValid(info: HostKeyInfo, key: Buffer, host: string): boolean {
  return (
    nativeCertificateValid(info) &&
    info.algorithm === `${info.keyAlgorithm}-cert-v01@openssh.com` &&
    info.keyBase64 === key.toString("base64") &&
    info.fingerprintSha256 === fingerprint(key) &&
    typeof info.caKeyBase64 === "string" &&
    typeof info.caAlgorithm === "string" &&
    info.caFingerprintSha256 === fingerprint(Buffer.from(info.caKeyBase64, "base64")) &&
    Array.isArray(info.principals) &&
    info.principals.length > 0 &&
    info.principals.some((principal) => matchesHostPattern(principal, host))
  )
}

function nativeCertificateValid(info: HostKeyInfo): boolean {
  return (
    info.kind === "certificate" &&
    info.certificateValidation?.valid === true &&
    info.caSignatureValid === true &&
    info.certType === "host"
  )
}
