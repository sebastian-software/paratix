import { execFile } from "node:child_process"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { inspect } from "node:util"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

import type { HostCertificateRequest } from "../src/modules/sshHostCertificateTypes.js"

import { assertSecretHandle } from "../src/modules/deferredSecret.js"
import { secret } from "../src/modules/secret.js"
import { ssh } from "../src/modules/ssh.js"
import {
  assertSignerCertificate,
  certificateSatisfies,
  durationSeconds,
  hostCertificatePolicy,
  parseHostCertificate,
} from "../src/modules/sshHostCertificatePolicy.js"

const execute = async (command: string, args: string[]): Promise<void> =>
  new Promise((resolveExit, reject) => {
    execFile(command, args, (error) => {
      if (error === null) resolveExit()
      else reject(new Error("Test key generation failed", { cause: error }))
    })
  })
let directory: string
let caKey: string
let caPublicKey: string
let publicKey: string

function request(): HostCertificateRequest {
  const now = Math.floor(Date.now() / 1000)
  return {
    principals: ["host.test", "192.0.2.1"],
    publicKey,
    requestId: "unit-request",
    signal: new AbortController().signal,
    validAfter: now,
    validBefore: now + 86_400,
    version: 1,
  }
}

describe("controller host certificate contract", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "paratix-host-certificate-test-"))
    caKey = join(directory, "ca")
    const key = join(directory, "host")
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", caKey])
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", key])
    caPublicKey = await readFile(`${caKey}.pub`, "utf8")
    publicKey = await readFile(`${key}.pub`, "utf8")
  })
  afterAll(async () => {
    await rm(directory, { force: true, recursive: true })
  })

  it("constructs opaque nominal provider-bound handles without provider access", () => {
    const reference = "op://test-vault/test-item/secret-field"
    const handle = secret.provider("1password").deferred(reference)
    expect(Object.isFrozen(handle)).toBe(true)
    expect(inspect(handle)).toBe("SecretHandle [redacted]")
    expect(inspect(handle, { customInspect: false, showHidden: true })).not.toContain(reference)
    expect(() => JSON.stringify(handle)).toThrow("cannot be serialized")
    expect(() => {
      assertSecretHandle({ ...handle })
    }).toThrow("provider-bound")
    expect(() => {
      assertSecretHandle({})
    }).toThrow("provider-bound")
    expect(() => {
      assertSecretHandle(handle)
    }).not.toThrow()
  })

  it("performs real noninteractive local signing and independently verifies host fields", async () => {
    const signer = ssh.signer.local({ caKey, caPublicKey })
    const input = request()
    const certificate = await signer.sign(input)
    const parsed = parseHostCertificate(certificate)
    const policy = hostCertificatePolicy({
      principals: input.principals,
      renewBefore: "1h",
      signer,
      validity: "1d",
    })
    expect(
      assertSignerCertificate(certificate, {
        now: input.validAfter + 120,
        policy,
        publicKey,
        request: input,
      })
    ).toStrictEqual(parsed)
    expect(parsed.validBefore - parsed.validAfter).toBe(86_400)
    expect(parsed.principals).toStrictEqual(["192.0.2.1", "host.test"])
    const parts = certificate.split(" ")
    const bytes = Buffer.from(parts[1], "base64")
    bytes[bytes.length - 1] ^= 1
    parts[1] = bytes.toString("base64")
    expect(() => parseHostCertificate(parts.join(" "))).toThrow("Invalid")
  })

  it("distinguishes total signed duration, CA caps and exact remaining threshold", async () => {
    const signer = ssh.signer.local({ caKey, caPublicKey })
    const input = request()
    const certificate = await signer.sign(input)
    const parsed = parseHostCertificate(certificate)
    const policy = hostCertificatePolicy({
      principals: input.principals,
      renewBefore: "1h",
      signer,
      validity: "2d",
    })
    expect(certificateSatisfies(parsed, { now: input.validAfter + 100, policy, publicKey })).toBe(
      true
    )
    expect(certificateSatisfies(parsed, { now: input.validBefore - 3601, policy, publicKey })).toBe(
      true
    )
    expect(certificateSatisfies(parsed, { now: input.validBefore - 3600, policy, publicKey })).toBe(
      false
    )
    expect(certificateSatisfies(parsed, { now: input.validBefore - 3599, policy, publicKey })).toBe(
      false
    )
    expect(
      certificateSatisfies(parsed, {
        now: input.validAfter,
        policy: { ...policy, validity: 86_399 },
        publicKey,
      })
    ).toBe(false)
    expect(
      certificateSatisfies(parsed, {
        now: input.validAfter,
        policy: { ...policy, validity: 86_400 },
        publicKey,
      })
    ).toBe(true)
    expect(() =>
      assertSignerCertificate(certificate, {
        now: input.validAfter,
        policy,
        publicKey,
        request: { ...input, validAfter: input.validAfter + 1 },
      })
    ).toThrow("bounds")
  })

  it("rejects invalid policies before processes and validates duration arithmetic", () => {
    for (const value of ["1.5d", "1ms", "Infinityd", -1, 0.5, Infinity])
      expect(() => durationSeconds(value)).toThrow(
        "Certificate durations must be finite whole seconds or s/m/h/d/w durations"
      )
    expect(durationSeconds("2w")).toBe(1_209_600)
    const signer = ssh.signer.local({ caKey, caPublicKey })
    expect(() => ssh.hostCertificate({ principals: ["*"], signer })).toThrow("principals")
    expect(() =>
      ssh.hostCertificate({ principals: ["host.test"], renewBefore: "1d", signer, validity: "1d" })
    ).toThrow("renewBefore")
    expect(() =>
      ssh.hostCertificate({
        certificatePath: "/etc/ssh/sshd_config",
        principals: ["host.test"],
        signer,
      })
    ).toThrow("overlap")
  })
})
