import { describe, expect, it } from "vitest"

import { normalizeRevokedKey } from "../src/hostCertificates.js"
import { renewedHostCertificates } from "./fixtures/hostCertificates.js"

function keyBlob(publicKey: string): Buffer {
  return Buffer.from(publicKey.split(" ")[1] ?? "", "base64")
}

const truncatedCertificateCases = renewedHostCertificates.map(({ certificates, publicKey }) => ({
  certificate: certificates[0] ?? "",
  publicKey,
}))

describe("revoked host certificate normalization", () => {
  for (const { certificates, publicKey } of renewedHostCertificates) {
    const algorithm = publicKey.split(" ")[0]
    it(`preserves ${algorithm} revocation across real OpenSSH certificate renewal`, () => {
      const leaf = keyBlob(publicKey)
      expect(certificates[0]).not.toBe(certificates[1])
      for (const certificate of certificates) {
        expect(normalizeRevokedKey(keyBlob(certificate))).toStrictEqual(leaf)
      }
      expect(normalizeRevokedKey(leaf)).toStrictEqual(leaf)
    })
  }

  it.each(truncatedCertificateCases)(
    "keeps a truncated certificate distinct from the certified leaf %#",
    ({ certificate: encoded, publicKey }) => {
      const leaf = keyBlob(publicKey)
      const certificate = keyBlob(encoded)
      const algorithmEnd = 4 + certificate.readUInt32BE(0)
      const nonceEnd = algorithmEnd + 4 + certificate.readUInt32BE(algorithmEnd)
      // Truncate inside the first leaf field, before normalization can succeed.
      const truncated = certificate.subarray(0, nonceEnd + 5)
      expect(normalizeRevokedKey(truncated)).toBe(truncated)
      expect(normalizeRevokedKey(truncated)).not.toStrictEqual(leaf)
    }
  )
})
