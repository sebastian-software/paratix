import type { HostKeyInfo } from "@paratix/ssh-native"

import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"

import { readHostFingerprint as readRawHostFingerprint } from "../src/hostFingerprintBootstrap.js"
import {
  buildEcdsaHostKeyBuffer,
  buildEcdsaPointFromGeneratedKey,
  buildEd25519HostKeyBuffer,
  createWireString,
  type EcdsaHostKeyFixtureSpec,
} from "./helpers.js"

const ED25519_PUBLIC_KEY_BYTE_LENGTH = 32
const NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH = 65
const NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH = 97
const NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH = 133
const UNCOMPRESSED_EC_POINT_PREFIX = 0x04

const ECDSA_FIXTURE_SPECS: readonly EcdsaHostKeyFixtureSpec[] = [
  {
    algorithm: "ecdsa-sha2-nistp256",
    curveName: "nistp256",
    jwkCurveName: "P-256",
    pointByteLength: NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH,
  },
  {
    algorithm: "ecdsa-sha2-nistp384",
    curveName: "nistp384",
    jwkCurveName: "P-384",
    pointByteLength: NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH,
  },
  {
    algorithm: "ecdsa-sha2-nistp521",
    curveName: "nistp521",
    jwkCurveName: "P-521",
    pointByteLength: NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH,
  },
]

function computeExpectedFingerprint(buffer: Buffer): string {
  const hash = createHash("sha256").update(buffer).digest("base64")
  return `SHA256:${hash.replaceAll("=", "")}`
}

function hostKeyInfo(buffer: Buffer): HostKeyInfo {
  return {
    algorithm: "ssh-ed25519",
    fingerprintSha256: computeExpectedFingerprint(buffer),
    keyBase64: buffer.toString("base64"),
    kind: "key",
  }
}

async function readHostFingerprint(
  host: string,
  options: Parameters<typeof readRawHostFingerprint>[1] = {}
): ReturnType<typeof readRawHostFingerprint> {
  return readRawHostFingerprint(host, { allowHostKeyScan: true, ...options })
}

describe("readHostFingerprint", () => {
  it("fails closed unless the caller explicitly opts into a live host-key scan", async () => {
    const scanner = vi.fn().mockRejectedValue(new Error("scan should not start"))

    await expect(
      readRawHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/without explicit opt-in/v)
    expect(scanner).not.toHaveBeenCalled()
  })

  it("derives the OpenSSH fingerprint from the native scan key blob", async () => {
    const hostKey = buildEd25519HostKeyBuffer()
    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).resolves.toStrictEqual({
      algorithm: "ssh-ed25519",
      fingerprint: computeExpectedFingerprint(hostKey),
    })

    expect(scanner).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "example.com",
        port: 22,
        timeoutMs: 10_000,
      })
    )
  })

  it.each(ECDSA_FIXTURE_SPECS)(
    "accepts $algorithm host keys when the wire blob is structurally valid",
    async (spec) => {
      const hostKey = buildEcdsaHostKeyBuffer(spec)
      const scanner = vi
        .fn()
        .mockResolvedValue({ ...hostKeyInfo(hostKey), algorithm: spec.algorithm })
      await expect(readHostFingerprint("example.com", { scanner })).resolves.toStrictEqual({
        algorithm: spec.algorithm,
        fingerprint: computeExpectedFingerprint(hostKey),
      })
    }
  )

  it("fails clearly when native scan cannot obtain a host key", async () => {
    const scanner = vi.fn().mockRejectedValue(new Error("connect ECONNREFUSED"))
    await expect(readHostFingerprint("example.com", { scanner })).rejects.toThrow(
      "Failed to read the host key from example.com:22: connect ECONNREFUSED"
    )
  })

  it("rejects with a MITM warning when the presented key uses an unknown algorithm", async () => {
    // Wire-format buffer with algorithm "ssh-bogus" (length-prefixed ASCII).
    const hostKey = Buffer.concat([createWireString("ssh-bogus"), Buffer.from("payload")])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-bogus"/v)
  })

  // R-0000232: the algorithm label must be validated as printable ASCII
  // (0x20-0x7E). `Buffer.toString("ascii")` strips the high bit, so without
  // an explicit byte-range guard a buffer whose algorithm field contains
  // bytes 0x80-0xFF would decode to printable ASCII (e.g. "ssh-ed25519")
  // and bypass the allowlist while the raw wire bytes are something else.
  it("rejects host keys whose algorithm field contains non-printable bytes", async () => {
    // Encode "ssh-ed25519" but with the high bit set on every byte. Without
    // the byte-range guard this would still decode to "ssh-ed25519" via
    // `toString("ascii")` (which masks 0x7F).
    const tamperedAlgorithm = Buffer.from("ssh-ed25519", "ascii").map((byte) => byte | 0x80)
    const hostKey = Buffer.concat([
      createWireString(Buffer.from(tamperedAlgorithm)),
      createWireString(Buffer.alloc(32, 0)),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/algorithm field contains non-printable bytes/v)
  })

  // R-0000128: ssh-rsa is intentionally absent from the host-key allowlist
  // because we cannot enforce a 2048-bit modulus floor on the wire blob in a
  // host-key scan while keeping the validation logic
  // minimal. Any ssh-rsa scan must be rejected with the unsupported-algorithm
  // error so operators are forced to pin a verified value out of band.
  it("rejects ssh-rsa host keys as unsupported", async () => {
    const hostKey = Buffer.concat([
      createWireString("ssh-rsa"),
      createWireString(Buffer.from([0x01, 0x00, 0x01])),
      createWireString(Buffer.alloc(256, 1)),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-rsa"/v)
  })

  it("rejects with a MITM warning when the presented key buffer is too short", async () => {
    const truncatedKey = Buffer.from([0, 0])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(truncatedKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/Invalid SSH host key buffer/v)
  })

  // R-0000128: structural validation of the wire blob.
  it("rejects ed25519 host keys whose public-key field is shorter than 32 bytes", async () => {
    const hostKey = buildEd25519HostKeyBuffer(Buffer.alloc(ED25519_PUBLIC_KEY_BYTE_LENGTH - 1, 2))

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/malformed "ssh-ed25519" host key blob/v)
  })

  it("rejects ed25519 host keys whose public-key field is longer than 32 bytes", async () => {
    const hostKey = buildEd25519HostKeyBuffer(Buffer.alloc(ED25519_PUBLIC_KEY_BYTE_LENGTH + 1, 3))

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/malformed "ssh-ed25519" host key blob/v)
  })

  it("rejects ed25519 host keys with trailing data after the public key", async () => {
    const hostKey = Buffer.concat([buildEd25519HostKeyBuffer(), Buffer.from([0x00])])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/trailing data after public key/v)
  })

  it("rejects ed25519 host keys whose buffer ends after the algorithm label", async () => {
    const hostKey = createWireString("ssh-ed25519")

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/missing or truncated public-key field/v)
  })

  it("rejects ECDSA host keys whose curve identifier does not match the algorithm", async () => {
    const point = buildEcdsaPointFromGeneratedKey("P-256")
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp384"),
      createWireString(point),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/curve identifier "nistp384" does not match "nistp256"/v)
  })

  it("rejects ECDSA host keys whose curve identifier contains non-printable bytes", async () => {
    const point = buildEcdsaPointFromGeneratedKey("P-256")
    const tamperedCurveName = Buffer.from(
      [...Buffer.from("nistp256", "ascii")].map((byte) => byte | 0x80)
    )
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString(tamperedCurveName),
      createWireString(point),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/curve identifier contains non-printable bytes/v)
  })

  it("rejects ECDSA host keys whose EC point is the wrong length", async () => {
    const wrongLengthPoint = Buffer.concat([
      Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
      Buffer.alloc(NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH - 2, 0xaa),
    ])
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp256"),
      createWireString(wrongLengthPoint),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/EC point/v)
  })

  it("rejects ECDSA host keys whose EC point is not in uncompressed form", async () => {
    const compressedPoint = Buffer.concat([
      Buffer.from([0x02]),
      Buffer.alloc(NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH - 1, 0xaa),
    ])
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp256"),
      createWireString(compressedPoint),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/EC point is not in uncompressed form/v)
  })

  it("rejects ECDSA host keys whose EC point is not on the expected curve", async () => {
    const offCurvePoint = Buffer.concat([
      Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
      Buffer.alloc(NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH - 1, 0),
    ])
    const hostKey = Buffer.concat([
      createWireString("ecdsa-sha2-nistp256"),
      createWireString("nistp256"),
      createWireString(offCurvePoint),
    ])

    const scanner = vi.fn().mockResolvedValue(hostKeyInfo(hostKey))

    await expect(
      readHostFingerprint("example.com", {
        scanner,
      })
    ).rejects.toThrow(/EC point is not on the expected curve/v)
  })

  it("rejects a fingerprint that differs from the locally computed key fingerprint", async () => {
    const info = hostKeyInfo(buildEd25519HostKeyBuffer())
    const scanner = vi.fn().mockResolvedValue({ ...info, fingerprintSha256: "SHA256:wrong" })
    await expect(readHostFingerprint("example.com", { scanner })).rejects.toThrow(
      "fingerprint does not match"
    )
  })

  it("rejects an algorithm that differs from the key blob", async () => {
    const info = hostKeyInfo(buildEd25519HostKeyBuffer())
    const scanner = vi.fn().mockResolvedValue({ ...info, algorithm: "ecdsa-sha2-nistp256" })
    await expect(readHostFingerprint("example.com", { scanner })).rejects.toThrow(
      "algorithm does not match"
    )
  })

  it("rejects host certificates even when their plain key is allowed", async () => {
    const info = hostKeyInfo(buildEd25519HostKeyBuffer())
    const scanner = vi.fn().mockResolvedValue({ ...info, kind: "certificate" })
    await expect(readHostFingerprint("example.com", { scanner })).rejects.toThrow(
      "host certificates are unsupported"
    )
  })

  it.each(["R-0000127", "R-0000188"])(
    "%s: passes the overall timeout to native scan and preserves its timeout error",
    async () => {
      const timeoutError = Object.assign(new Error("native scan deadline exceeded"), {
        code: "TIMEOUT",
      })
      const scanner = vi.fn().mockRejectedValue(timeoutError)
      await expect(
        readHostFingerprint("example.com", { port: 2222, scanner, timeoutMs: 3000 })
      ).rejects.toMatchObject({
        cause: timeoutError,
        message: "Failed to read the host key from example.com:2222: native scan deadline exceeded",
      })
      expect(scanner).toHaveBeenCalledExactlyOnceWith({
        host: "example.com",
        port: 2222,
        signal: undefined,
        timeoutMs: 3000,
      })
    }
  )

  it("passes cancellation to native scan and preserves the abort error", async () => {
    const controller = new AbortController()
    const abortError = Object.assign(new Error("scan aborted"), { code: "ABORTED" })
    const scanner = vi.fn().mockRejectedValue(abortError)
    controller.abort()
    await expect(
      readHostFingerprint("example.com", { scanner, signal: controller.signal })
    ).rejects.toMatchObject({ cause: abortError })
    expect(scanner).toHaveBeenCalledWith(expect.objectContaining({ signal: controller.signal }))
  })
})
