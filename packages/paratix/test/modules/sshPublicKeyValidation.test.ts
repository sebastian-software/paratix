import { generateKeyPairSync } from "node:crypto"
import { describe, expect, it } from "vitest"

import { assertAuthorizedKeyValue } from "../../src/modules/sshPublicKeyValidation.js"

// ---------------------------------------------------------------------------
// Helpers: build real OpenSSH public-key wire blobs so the happy path
// exercises the full length-prefixed parser instead of a hand-waved fixture.
// ---------------------------------------------------------------------------

function sshString(payload: Buffer): Buffer {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(payload.length, 0)
  return Buffer.concat([length, payload])
}

// Convert a raw big-endian integer into an SSH mpint (leading 0x00 if MSB set).
function mpint(raw: Buffer): Buffer {
  if (raw.length > 0 && (raw[0] & 0x80) !== 0) return Buffer.concat([Buffer.from([0x00]), raw])
  return raw
}

function encodeOpenSshKey(algorithm: string, fields: Buffer[]): string {
  const blob = Buffer.concat([sshString(Buffer.from(algorithm, "ascii")), ...fields])
  return `${algorithm} ${blob.toString("base64")}`
}

function jwkField(value: unknown): Buffer {
  if (typeof value !== "string") throw new Error("expected a base64url JWK field")
  return Buffer.from(value, "base64url")
}

function ed25519PublicKey(): string {
  const { publicKey } = generateKeyPairSync("ed25519")
  const jwk = publicKey.export({ format: "jwk" })
  return encodeOpenSshKey("ssh-ed25519", [sshString(jwkField(jwk.x))])
}

function ecdsaNistp256PublicKey(): string {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  const jwk = publicKey.export({ format: "jwk" })
  const point = Buffer.concat([Buffer.from([0x04]), jwkField(jwk.x), jwkField(jwk.y)])
  return encodeOpenSshKey("ecdsa-sha2-nistp256", [
    sshString(Buffer.from("nistp256", "ascii")),
    sshString(point),
  ])
}

function rsaPublicKey(): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const jwk = publicKey.export({ format: "jwk" })
  return encodeOpenSshKey("ssh-rsa", [
    sshString(mpint(jwkField(jwk.e))),
    sshString(mpint(jwkField(jwk.n))),
  ])
}

describe("assertAuthorizedKeyValue", () => {
  it("accepts a valid ssh-ed25519 public key", () => {
    expect(() => {
      assertAuthorizedKeyValue(ed25519PublicKey())
    }).not.toThrow()
  })

  it("accepts a valid ecdsa-sha2-nistp256 public key", () => {
    expect(() => {
      assertAuthorizedKeyValue(ecdsaNistp256PublicKey())
    }).not.toThrow()
  })

  it("accepts a valid ssh-rsa public key", () => {
    expect(() => {
      assertAuthorizedKeyValue(rsaPublicKey())
    }).not.toThrow()
  })

  it("tolerates surrounding whitespace and an optional comment", () => {
    expect(() => {
      assertAuthorizedKeyValue(`  ${ed25519PublicKey()} user@host  `)
    }).not.toThrow()
  })

  it("rejects an empty key", () => {
    expect(() => {
      assertAuthorizedKeyValue("")
    }).toThrow("key must not be empty")
  })

  it("rejects keys containing newlines", () => {
    expect(() => {
      assertAuthorizedKeyValue(`${ed25519PublicKey()}\nssh-ed25519 AAAA`)
    }).toThrow("must not contain newlines")
  })

  it("rejects a value without a base64 field", () => {
    expect(() => {
      assertAuthorizedKeyValue("ssh-ed25519")
    }).toThrow("requires a full public key")
  })

  it("rejects an unsupported algorithm", () => {
    expect(() => {
      assertAuthorizedKeyValue("ssh-dss AAAAB3NzaC1kc3M=")
    }).toThrow("unsupported public key algorithm: ssh-dss")
  })

  it("rejects a non-strict-base64 key field", () => {
    expect(() => {
      assertAuthorizedKeyValue("ssh-ed25519 not*base64")
    }).toThrow("key field must be strict base64")
  })

  it("rejects a base64 field that is not a valid OpenSSH blob", () => {
    expect(() => {
      assertAuthorizedKeyValue("ssh-ed25519 AAAA")
    }).toThrow("not a valid OpenSSH public key")
  })

  it("rejects a key whose encoded algorithm does not match the label", () => {
    const [, base64Key] = ed25519PublicKey().split(" ")
    expect(() => {
      assertAuthorizedKeyValue(`ssh-rsa ${base64Key}`)
    }).toThrow("not a valid OpenSSH public key")
  })

  it("rejects an ed25519 blob whose payload is the wrong length", () => {
    const shortPayload = encodeOpenSshKey("ssh-ed25519", [sshString(Buffer.alloc(16))])
    expect(() => {
      assertAuthorizedKeyValue(shortPayload)
    }).toThrow("not a valid OpenSSH public key")
  })
})
