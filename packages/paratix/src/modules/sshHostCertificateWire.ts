import { createPublicKey, type KeyObject, verify } from "node:crypto"

import { HostCertificateError } from "./sshSignerProcess.js"

const SSH_UINT32_BYTES = 4
const SSH_UINT64_BYTES = 8
const MAX_PUBLIC_KEY_TEXT_BYTES = 131_072
const MAX_PUBLIC_KEY_BLOB_BYTES = 65_536
const UNCOMPRESSED_EC_POINT = 4
const ED25519_PUBLIC_KEY_BYTES = 32
const MIN_RSA_MODULUS_BYTES = 256

/** Bounded SSH wire reader; all untrusted lengths are checked before slicing. */
export class SshWireReader {
  public offset = 0
  public constructor(public readonly data: Buffer) {}
  public bytes(length: number): Buffer {
    if (length < 0 || this.offset + length > this.data.length)
      throw new HostCertificateError("Malformed SSH certificate")
    const result = this.data.subarray(this.offset, this.offset + length)
    this.offset += length
    return result
  }
  public end(): void {
    if (this.offset !== this.data.length)
      throw new HostCertificateError("Trailing SSH certificate data")
  }
  public string(): Buffer {
    return this.bytes(this.uint32())
  }
  public text(): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.string())
  }
  public uint32(): number {
    return this.bytes(SSH_UINT32_BYTES).readUInt32BE()
  }
  public uint64(): number {
    const value = this.bytes(SSH_UINT64_BYTES).readBigUInt64BE()
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new HostCertificateError("Unsupported SSH certificate time or serial")
    return Number(value)
  }
}

export function sshString(value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value) : value
  const length = Buffer.alloc(SSH_UINT32_BYTES)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

export function publicKeyIdentity(key: string): string {
  if (key.length > MAX_PUBLIC_KEY_TEXT_BYTES)
    throw new HostCertificateError("SSH public key exceeds size limit")
  const lines = key.trim().split(/\r?\n/v)
  if (lines.length !== 1) throw new HostCertificateError("Exactly one public SSH key is required")
  const [algorithm, encoded] = lines[0].split(/\s+/v)
  if (typeof encoded !== "string" || !/^[A-Za-z0-9+\/]+={0,2}$/v.test(encoded))
    throw new HostCertificateError("Malformed SSH public key")
  const bytes = Buffer.from(encoded, "base64")
  if (
    bytes.length > MAX_PUBLIC_KEY_BLOB_BYTES ||
    bytes.toString("base64").replace(/={1,2}$/v, "") !== encoded.replace(/={1,2}$/v, "")
  )
    throw new HostCertificateError("Malformed SSH key encoding")
  const reader = new SshWireReader(bytes)
  if (reader.text() !== algorithm) throw new HostCertificateError("SSH key algorithm mismatch")
  return `${algorithm} ${bytes.toString("base64")}`
}

function unsigned(value: Buffer): Buffer {
  return value[0] === 0 ? value.subarray(1) : value
}

const CURVES: Record<string, { bytes: number; hash: string; jwk: string } | undefined> = {
  nistp256: { bytes: 32, hash: "sha256", jwk: "P-256" },
  nistp384: { bytes: 48, hash: "sha384", jwk: "P-384" },
  nistp521: { bytes: 66, hash: "sha512", jwk: "P-521" },
}

function ecdsaPublic(reader: SshWireReader): KeyObject {
  const curve = CURVES[reader.text()]
  const point = reader.string()
  if (
    curve === undefined ||
    point.length !== 1 + 2 * curve.bytes ||
    point[0] !== UNCOMPRESSED_EC_POINT
  )
    throw new HostCertificateError("Invalid SSH CA curve")
  return createPublicKey({
    format: "jwk",
    key: {
      crv: curve.jwk,
      kty: "EC",
      x: point.subarray(1, 1 + curve.bytes).toString("base64url"),
      y: point.subarray(1 + curve.bytes).toString("base64url"),
    },
  })
}

function caPublic(blob: Buffer): { algorithm: string; key: KeyObject } {
  const reader = new SshWireReader(blob)
  const algorithm = reader.text()
  let key: KeyObject
  if (algorithm === "ssh-ed25519") {
    const x = reader.string()
    if (x.length !== ED25519_PUBLIC_KEY_BYTES)
      throw new HostCertificateError("Invalid Ed25519 SSH CA")
    key = createPublicKey({
      format: "jwk",
      key: { crv: "Ed25519", kty: "OKP", x: x.toString("base64url") },
    })
  } else if (algorithm === "ssh-rsa") {
    const e = unsigned(reader.string())
    const n = unsigned(reader.string())
    if (n.length < MIN_RSA_MODULUS_BYTES)
      throw new HostCertificateError("SSH CA RSA keys require at least 2048 bits")
    key = createPublicKey({
      format: "jwk",
      key: { e: e.toString("base64url"), kty: "RSA", n: n.toString("base64url") },
    })
  } else if (algorithm.startsWith("ecdsa-sha2-")) key = ecdsaPublic(reader)
  else throw new HostCertificateError("Unsupported SSH CA algorithm")
  reader.end()
  return { algorithm, key }
}

function ecdsaSignature(encoded: Buffer, bytes: number): Buffer {
  const reader = new SshWireReader(encoded)
  const values = [unsigned(reader.string()), unsigned(reader.string())]
  reader.end()
  return Buffer.concat(
    values.map((value) => {
      if (value.length > bytes)
        throw new HostCertificateError("Invalid ECDSA certificate signature")
      return Buffer.concat([Buffer.alloc(bytes - value.length), value])
    })
  )
}

export function verifyCertificateSignature(ca: Buffer, signature: Buffer, data: Buffer): void {
  const { algorithm, key } = caPublic(ca)
  const reader = new SshWireReader(signature)
  const signatureAlgorithm = reader.text()
  const encoded = reader.string()
  reader.end()
  let valid = false
  if (algorithm === "ssh-ed25519" && signatureAlgorithm === algorithm)
    valid = verify(null, data, key, encoded)
  else if (
    algorithm === "ssh-rsa" &&
    ["rsa-sha2-256", "rsa-sha2-512"].includes(signatureAlgorithm)
  ) {
    valid = verify(signatureAlgorithm === "rsa-sha2-256" ? "sha256" : "sha512", data, key, encoded)
  } else if (signatureAlgorithm === algorithm) {
    const curve = CURVES[algorithm.slice("ecdsa-sha2-".length)]
    if (curve !== undefined)
      valid = verify(
        curve.hash,
        data,
        { dsaEncoding: "ieee-p1363", key },
        ecdsaSignature(encoded, curve.bytes)
      )
  }
  if (!valid) throw new HostCertificateError("Invalid or disallowed SSH certificate signature")
}

/**
 * Validate the independent trust anchor before any process or provider access.
 * @param value - Independently configured OpenSSH CA public key.
 * @returns The normalized, algorithm-validated public CA identity.
 */
export function hostCaIdentity(value: string): string {
  const identity = publicKeyIdentity(value)
  caPublic(Buffer.from(identity.split(" ")[1], "base64"))
  return identity
}
