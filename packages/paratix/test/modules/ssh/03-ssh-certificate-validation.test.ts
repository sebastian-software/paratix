import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import { certificateFileMatches } from "../../../src/modules/sshCertificateFiles.js"
import {
  assertCertificatePath,
  assertDistinctCertificatePaths,
  certificateState,
  normalizeCaKeys,
  normalizePrincipals,
  principalsTemplate,
} from "../../../src/modules/sshCertificateValidation.js"

function sshString(value: string | Uint8Array): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value) : Buffer.from(value)
  const length = Buffer.alloc(4)
  length.writeUInt32BE(bytes.length)
  return Buffer.concat([length, bytes])
}

function ed25519Key(seed: number): string {
  const blob = Buffer.concat([sshString("ssh-ed25519"), sshString(new Uint8Array(32).fill(seed))])
  return `ssh-ed25519 ${blob.toString("base64")}`
}

describe("SSH user certificate module contracts", () => {
  it("normalizes duplicate CA keys and principals deterministically", () => {
    const key = ed25519Key(7)
    expect(normalizeCaKeys(`\n${key}\r\n${key}  comment\n`)).toBe(`${key}\n`)
    expect(normalizePrincipals("alice", ["zeta", "alpha", "zeta"])).toBe("alpha\nzeta\n")
    expect(normalizePrincipals("alice", [])).toBe("")
  })

  it("accepts only complete CA public keys and rejects options, certificates, private keys, and empty input", () => {
    const key = ed25519Key(1)
    expect(() => normalizeCaKeys(key)).not.toThrow()
    expect(() => normalizeCaKeys("")).toThrow(/requires at least one public CA key/v)
    expect(() => normalizeCaKeys("# comment only")).toThrow(/public key|algorithm/v)
    expect(() =>
      normalizeCaKeys(key.replace("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"))
    ).toThrow(/algorithm/v)
    expect(() => normalizeCaKeys(key.replace("ssh-ed25519", "ssh-rsa"))).toThrow(
      /valid OpenSSH public key/v
    )
    expect(() => normalizeCaKeys(`from=10.0.0.0/8 ${key}`)).toThrow(/public key/v)
    expect(() => normalizeCaKeys("ssh-ed25519 AAAA")).toThrow(/valid OpenSSH public key/v)
    expect(() => normalizeCaKeys("-----BEGIN OPENSSH PRIVATE KEY-----")).toThrow(
      /public key|algorithm/v
    )
  })

  it("rejects principal injection and invalid Unix users", () => {
    for (const value of ["", "alpha beta", "alpha,beta", "#admin", "admin#team", "line\nfeed"]) {
      expect(() => normalizePrincipals("alice", [value])).toThrow(/invalid principal/v)
    }
    expect(() => normalizePrincipals("alice;id", ["admin"])).toThrow(/user|invalid/v)
  })

  it("validates discriminated states, safe paths, templates, and collisions", () => {
    expect(certificateState(undefined)).toBe("present")
    expect(certificateState("absent")).toBe("absent")
    expect(() => certificateState("remove")).toThrow(/present|absent/v)
    expect(principalsTemplate()).toBe("/etc/ssh/auth_principals/%u")
    expect(principalsTemplate("/etc/ssh/custom/%u")).toBe("/etc/ssh/custom/%u")
    for (const path of ["/tmp/ca", "/etc/ssh/../ca", "/etc/ssh/ca file", "/etc/ssh/ca/"]) {
      expect(() => {
        assertCertificatePath(path)
      }).toThrow(/safe path/v)
    }
    expect(() => principalsTemplate("/etc/ssh/%u/extra")).toThrow(/exactly one %u/v)
    expect(() => principalsTemplate("/etc/ssh/custom/%u/%u")).toThrow(/exactly one %u/v)
    expect(() => {
      assertDistinctCertificatePaths(["/etc/ssh/auth/%u", "/etc/ssh/auth/alice"])
    }).toThrow(/collision/v)
  })

  it("exposes present and absent public module names and reports missing SSH", async () => {
    const key = ed25519Key(3)
    const present = ssh.trustedUserCa({ publicKey: key })
    const absent = ssh.trustedUserCa({ state: "absent" })
    const principals = ssh.authorizedPrincipals("alice", ["admin"])
    expect(present.name).toBe("ssh.trustedUserCa (present)")
    expect(absent.name).toBe("ssh.trustedUserCa (absent)")
    expect(principals.name).toBe("ssh.authorizedPrincipals: alice (present)")
    const noConnection = null
    await expect(present.apply(noConnection, {})).resolves.toMatchObject({ status: "failed" })
    await expect(principals.apply(noConnection, {})).resolves.toMatchObject({ status: "failed" })
  })

  it("detects content and metadata drift while preserving existing revocation metadata", () => {
    const content = "revoked-key\n"
    expect(
      certificateFileMatches({
        content,
        original: { hash: "wrong", metadata: "644 0 0" },
        path: "/etc/ssh/revoked_keys",
      })
    ).toBe(false)
    expect(
      certificateFileMatches({
        content,
        original: { hash: "wrong", metadata: "600 0 0" },
        path: "/etc/ssh/revoked_keys",
        preserve: true,
      })
    ).toBe(true)
    expect(
      certificateFileMatches({
        content,
        original: { hash: "wrong", metadata: "644 0 0" },
        path: "/etc/ssh/revoked_keys",
        preserve: true,
      })
    ).toBe(true)
  })
})
