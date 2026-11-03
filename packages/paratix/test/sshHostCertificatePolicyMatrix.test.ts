/* oxlint-disable vitest/no-conditional-in-test -- Table-driven cases explicitly select fixture inputs and expected outcomes; every case runs its assertions. */
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

import type {
  HostCertificateRequest,
  HostCertificateSigner,
} from "../src/modules/sshHostCertificateTypes.js"
import type { FixtureKey } from "./helpers/hostCertificateFixtures.js"

import { ssh } from "../src/modules/ssh.js"
import {
  assertSignerCertificate,
  certificateSatisfies,
  durationSeconds,
  hostCertificatePolicy,
  parseHostCertificate,
} from "../src/modules/sshHostCertificatePolicy.js"
import {
  DAY,
  fixtureCertificate,
  fixtureKey,
  fixtureRequest,
  CERTIFICATE_NOW as NOW,
  resignFixture,
  wireString,
} from "./helpers/hostCertificateFixtures.js"

let directory: string
let ca: FixtureKey
let foreignCa: FixtureKey
let host: FixtureKey
let otherHost: FixtureKey
let signer: HostCertificateSigner

function policy(validity: number | string = "14d", renewBefore: number | string = "7d") {
  return hostCertificatePolicy({
    principals: ["host.test", "192.0.2.1"],
    renewBefore,
    signer,
    validity,
  })
}
function request(overrides: Partial<HostCertificateRequest> = {}) {
  return fixtureRequest(host.publicKey, overrides)
}
async function issue(overrides: Partial<HostCertificateRequest> = {}) {
  return fixtureCertificate(directory, ca, request(overrides))
}

describe("sshHostCertificatePolicyMatrix test context", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-certificate-policy-matrix-"))
    ca = await fixtureKey(directory, "ca", "rsa", "2048")
    foreignCa = await fixtureKey(directory, "foreign-ca", "ed25519")
    host = await fixtureKey(directory, "host", "ed25519")
    otherHost = await fixtureKey(directory, "other-host", "ed25519")
    signer = ssh.signer.local({ caKey: ca.path, caPublicKey: ca.publicKey })
  })
  afterAll(async () => rm(directory, { force: true, recursive: true }))

  describe("total signed lifetime and renewal policy", () => {
    it("immediately renews 30d original/10d remaining when the maximum becomes 14d, without consulting wish history", async () => {
      const parsed = parseHostCertificate(
        await issue({ validAfter: NOW - 20 * DAY, validBefore: NOW + 10 * DAY })
      )
      expect(parsed.validBefore - NOW).toBe(10 * DAY)
      expect(
        certificateSatisfies(parsed, { now: NOW, policy: policy("30d"), publicKey: host.publicKey })
      ).toBe(true)
      expect(
        certificateSatisfies(parsed, { now: NOW, policy: policy("14d"), publicKey: host.publicKey })
      ).toBe(false)
      expect(
        certificateSatisfies(structuredClone(parsed), {
          now: NOW,
          policy: policy("14d"),
          publicKey: host.publicKey,
        })
      ).toBe(false)
    })

    it("preserves an acceptable existing certificate when only desired validity is extended", async () => {
      const parsed = parseHostCertificate(await issue())
      for (const validity of [14 * DAY, 30 * DAY, 365 * DAY]) {
        expect(
          certificateSatisfies(parsed, {
            now: NOW,
            policy: policy(validity),
            publicKey: host.publicKey,
          })
        ).toBe(true)
      }
    })

    it.each([
      [-1, false],
      [0, false],
      [1, true],
    ])(
      "uses a strict remaining lifetime boundary at renewBefore %+is",
      async (offset, accepted) => {
        const parsed = parseHostCertificate(await issue({ validBefore: NOW + 7 * DAY + offset }))
        expect(
          certificateSatisfies(parsed, { now: NOW, policy: policy(), publicKey: host.publicKey })
        ).toBe(accepted)
      }
    )

    it.each([
      [14 * DAY, true],
      [14 * DAY + 1, false],
    ])(
      "compares the entire %is duration to the maximum, including the exact maximum",
      async (duration, accepted) => {
        const parsed = parseHostCertificate(await issue({ validBefore: NOW + duration }))
        expect(
          certificateSatisfies(parsed, { now: NOW, policy: policy(), publicKey: host.publicKey })
        ).toBe(accepted)
      }
    )

    it.each([
      [NOW + 1, NOW + 14 * DAY, "not yet valid"],
      [NOW - 14 * DAY, NOW, "expired"],
    ])("rejects existing certificates with bounds %i/%i (%s)", async (validAfter, validBefore) => {
      const parsed = parseHostCertificate(await issue({ validAfter, validBefore }))
      expect(
        certificateSatisfies(parsed, { now: NOW, policy: policy(), publicKey: host.publicKey })
      ).toBe(false)
    })

    it("accepts a CA-shortened duration only while it remains strictly above the renewal threshold", async () => {
      const value = await issue({ validBefore: NOW + 10 * DAY })
      expect(
        assertSignerCertificate(value, {
          now: NOW,
          policy: policy(),
          publicKey: host.publicKey,
          request: request(),
        }).validBefore
      ).toBe(NOW + 10 * DAY)
      for (const remaining of [7 * DAY, 7 * DAY - 1]) {
        // eslint-disable-next-line no-await-in-loop -- Fixture signatures share one public output file and must be generated sequentially.
        const shortened = await issue({ validBefore: NOW + remaining })
        expect(() =>
          assertSignerCertificate(shortened, {
            now: NOW,
            policy: policy(),
            publicKey: host.publicKey,
            request: request(),
          })
        ).toThrow("bounds")
      }
    })

    it("counts all CA backdating and enforces both requested absolute bounds", async () => {
      const backdated = await issue({ validAfter: NOW - 1 })
      expect(
        certificateSatisfies(parseHostCertificate(backdated), {
          now: NOW,
          policy: policy(),
          publicKey: host.publicKey,
        })
      ).toBe(false)
      const withinTotalButBackdated = await issue({
        validAfter: NOW - 1,
        validBefore: NOW + 10 * DAY,
      })
      expect(
        certificateSatisfies(parseHostCertificate(withinTotalButBackdated), {
          now: NOW,
          policy: policy(),
          publicKey: host.publicKey,
        })
      ).toBe(true)
      expect(() =>
        assertSignerCertificate(withinTotalButBackdated, {
          now: NOW,
          policy: policy(),
          publicKey: host.publicKey,
          request: request(),
        })
      ).toThrow("bounds")
      const afterUpperBound = await issue({ validBefore: NOW + 14 * DAY + 1 })
      expect(() =>
        assertSignerCertificate(afterUpperBound, {
          now: NOW,
          policy: policy("30d"),
          publicKey: host.publicKey,
          request: request(),
        })
      ).toThrow("bounds")
    })

    it.each([
      [7 * DAY - 1, true],
      [7 * DAY, false],
      [7 * DAY + 1, false],
    ])("rechecks the current clock after signing with %is elapsed", async (elapsed, accepted) => {
      const value = await issue()
      const check = () =>
        assertSignerCertificate(value, {
          now: NOW + elapsed,
          policy: policy(),
          publicKey: host.publicKey,
          request: request(),
        })
      const result = (() => {
        try {
          return check().validAfter
        } catch (error) {
          return error
        }
      })()
      const rejected = expect.objectContaining({ message: expect.stringContaining("bounds") })
      expect(result).toStrictEqual(accepted ? NOW : rejected)
    })

    it("normalizes principal order/deduplication and ignores public-key and certificate comments", async () => {
      const value = await issue({ principals: ["host.test", "192.0.2.1"] })
      const desired = hostCertificatePolicy({
        principals: ["192.0.2.1", "host.test", "host.test"],
        renewBefore: "7d",
        signer: {
          ...signer,
          caPublicKey: `${ca.publicKey.trim().split(/\s+/v).slice(0, 2).join(" ")} changed-ca-comment`,
        },
        validity: "14d",
      })
      const commented = `${value.trim().split(/\s+/v).slice(0, 2).join(" ")} changed-certificate-comment`
      const hostComment = `${host.publicKey.trim().split(/\s+/v).slice(0, 2).join(" ")} changed-host-comment`
      expect(
        certificateSatisfies(parseHostCertificate(commented), {
          now: NOW,
          policy: desired,
          publicKey: hostComment,
        })
      ).toBe(true)
      expect(desired.principals).toStrictEqual(["192.0.2.1", "host.test"])
    })
  })

  describe("cryptographically checked untrusted signer outputs", () => {
    it.each([
      "wrong public key",
      "wrong CA",
      "extra principal",
      "missing principal",
      "duplicate principal",
    ])("rejects a valid signature with %s", async (variant) => {
      const value = await fixtureCertificate(
        directory,
        variant === "wrong CA" ? foreignCa : ca,
        request({
          ...(variant === "wrong public key" ? { publicKey: otherHost.publicKey } : {}),
          ...(variant === "extra principal"
            ? { principals: ["host.test", "192.0.2.1", "other.test"] }
            : {}),
          ...(variant === "missing principal" ? { principals: ["host.test"] } : {}),
          ...(variant === "duplicate principal"
            ? { principals: ["host.test", "192.0.2.1", "host.test"] }
            : {}),
        })
      )
      expect(parseHostCertificate(value).validAfter).toBe(NOW)
      expect(() =>
        assertSignerCertificate(value, {
          now: NOW,
          policy: policy(),
          publicKey: host.publicKey,
          request: request(),
        })
      ).toThrow("bounds")
    })

    it.each([
      ["user type", { type: Buffer.from([0, 0, 0, 1]) }],
      [
        "critical options",
        {
          critical: wireString(
            Buffer.concat([wireString("force-command"), wireString(wireString("false"))])
          ),
        },
      ],
      ["reserved data", { reserved: wireString("unexpected") }],
    ])("rejects correctly re-signed %s", async (_variant, changes) => {
      const value = await resignFixture(await issue(), ca, changes)
      expect(() => parseHostCertificate(value)).toThrow("Invalid")
    })

    it("accepts valid re-signing and full unsigned serials but rejects a genuine RSA/SHA1 signature", async () => {
      const original = await issue()
      const valid = await resignFixture(original, ca, { serial: Buffer.alloc(8, 255) })
      expect(parseHostCertificate(valid).publicKey).toBe(parseHostCertificate(original).publicKey)
      const legacy = await resignFixture(original, ca, {}, "ssh-rsa")
      expect(() => parseHostCertificate(legacy)).toThrow("Invalid")
      const mislabeled = await resignFixture(original, ca, {}, "ssh-ed25519")
      expect(() => parseHostCertificate(mislabeled)).toThrow("Invalid")
    })

    it("rejects multiple, malformed, oversized, mismatched-algorithm and tampered outputs", async () => {
      const value = await issue()
      const [algorithm, encoded] = value.trim().split(/\s+/v)
      const tampered = Buffer.from(encoded, "base64")
      tampered[tampered.length - 1] ^= 1
      for (const malformed of [
        `${value.trim()}\n${value.trim()}`,
        "",
        host.publicKey,
        `${algorithm} !not-base64!`,
        `${algorithm} ${Buffer.from([255, 255, 255, 255]).toString("base64")}`,
        `ssh-rsa-cert-v01@openssh.com ${encoded}`,
        `${algorithm} ${tampered.toString("base64")}`,
        `${algorithm} ${Buffer.concat([Buffer.from(encoded, "base64"), Buffer.from([0])]).toString("base64")}`,
        "x".repeat(128 * 1024 + 1),
      ])
        expect(() => parseHostCertificate(malformed)).toThrow("Invalid")
    })

    it.each(["ed25519", "rsa", "ecdsa"])(
      "independently verifies a real local signer with a %s host key",
      async (algorithm) => {
        const key = await fixtureKey(
          directory,
          `local-host-${algorithm}`,
          algorithm,
          algorithm === "rsa" ? "2048" : undefined
        )
        const input = fixtureRequest(key.publicKey)
        const value = await signer.sign(input)
        const desired = hostCertificatePolicy({
          principals: input.principals,
          renewBefore: "7d",
          signer,
          validity: "14d",
        })
        expect(
          assertSignerCertificate(value, {
            now: NOW,
            policy: desired,
            publicKey: key.publicKey,
            request: input,
          }).publicKey
        ).toBe(key.publicKey.trim().split(/\s+/v).slice(0, 2).join(" "))
      }
    )

    it.each([
      ["ed25519", undefined],
      ["rsa", "2048"],
      ["ecdsa", "256"],
      ["ecdsa", "384"],
      ["ecdsa", "521"],
    ])("verifies real %s CA signatures with curve/bits %s", async (algorithm, bits) => {
      const authority = await fixtureKey(
        directory,
        `signature-ca-${algorithm}-${bits ?? "default"}`,
        algorithm,
        bits
      )
      const value = await fixtureCertificate(directory, authority, request())
      expect(parseHostCertificate(value).caPublicKey).toBe(
        authority.publicKey.trim().split(/\s+/v).slice(0, 2).join(" ")
      )
    })
  })

  describe("public constructor validation before side effects", () => {
    it.each([
      "",
      "*",
      "*.test",
      "host.*",
      "host test",
      "host\nname",
      "-host.test",
      "host-.test",
      "host..test",
      "host/test",
      ".",
      `${"a".repeat(64)}.test`,
    ])("rejects invalid principal %j", (principal) => {
      expect(() => ssh.hostCertificate({ principals: [principal], signer })).toThrow("principals")
    })
    it("requires a nonempty principal set and supports explicit IPv4/IPv6 and absolute DNS names", () => {
      expect(() => ssh.hostCertificate({ principals: [], signer })).toThrow("principals")
      expect(
        hostCertificatePolicy({ principals: ["host.test.", "192.0.2.1", "2001:db8::1"], signer })
          .principals
      ).toStrictEqual(["192.0.2.1", "2001:db8::1", "host.test."])
    })
    it.each([
      "relative/key",
      "/etc/ssh/../key",
      "/etc//ssh/key",
      "/etc/ssh/key/",
      "/etc/ssh/key\nother",
      "/etc/ssh/key;touch",
      "/etc/ssh/sshd_config",
      "/var/lib/paratix/private",
    ])("rejects unsafe or protected path %j", (path) => {
      expect(() =>
        ssh.hostCertificate({ hostKeyPath: path, principals: ["host.test"], signer })
      ).toThrow(/paths|overlap|durations/v)
      expect(() =>
        ssh.hostCertificate({ certificatePath: path, principals: ["host.test"], signer })
      ).toThrow(/paths|overlap|durations/v)
    })
    it.each([
      "1.5d",
      "1ms",
      "-1s",
      "1D",
      " 1d",
      "1d ",
      "1d1h",
      "NaN",
      "Infinityd",
      -1,
      0.5,
      Infinity,
      Number.NaN,
      Number.MAX_SAFE_INTEGER + 1,
    ])("rejects invalid duration %j", (value) => {
      expect(() => durationSeconds(value)).toThrow(/paths|overlap|durations/v)
    })
    it("converts every supported unit, allows zero renewal and refuses zero validity or threshold at/above validity", () => {
      expect(["1s", "1m", "1h", "1d", "1w"].map((value) => durationSeconds(value))).toStrictEqual([
        1,
        60,
        3600,
        DAY,
        7 * DAY,
      ])
      expect(policy(1, 0).renewBefore).toBe(0)
      for (const [validity, renewBefore] of [
        [0, 0],
        [10, 10],
        [10, 11],
      ])
        expect(() => policy(validity, renewBefore)).toThrow("renewBefore")
    })
  })
})
