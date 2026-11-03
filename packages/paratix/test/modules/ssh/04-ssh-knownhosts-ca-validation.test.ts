import { describe, expect, it } from "vitest"

import { ssh } from "../../../src/modules/ssh.js"
import {
  canonicalKnownHostsCaKey,
  knownHostsCaParameters,
  reconcileKnownHostsCa,
} from "../../../src/modules/sshKnownHostsCaValidation.js"
import { publicKey as makePublicKey, paddedPublicKey } from "./knownHostsCaTestHelpers.js"

const key = makePublicKey()
const sparseHosts: string[] = []
sparseHosts.length = 1
const options = { hosts: ["*.example.com"], publicKey: key }

function parameters(state: "absent" | "present" = "present") {
  return knownHostsCaParameters("alice", { ...options, state })
}

describe("ssh.knownHostsCertAuthority validation", () => {
  it("accepts a complete pub file with surrounding whitespace and ignores its comment", () => {
    expect(
      knownHostsCaParameters("alice", { ...options, publicKey: ` \t${key} operator comment\r\n` })
    ).toStrictEqual({ key, patterns: ["*.example.com"], state: "present", user: "alice" })
    expect(ssh.knownHostsCertAuthority("alice", options).name).toBe(
      "ssh.knownHostsCertAuthority: alice (present)"
    )
  })

  it.each([null, undefined, 7, "", "-alice", "alice;id", "alice user", "alice\nroot"])(
    "rejects unsafe users: %j",
    (user) => {
      expect(() => ssh.knownHostsCertAuthority(user as never, options)).toThrow(
        /user|key|host|state|pattern|publicKey/v
      )
    }
  )

  it.each(["remove", "", false, 0, null])("rejects invalid states: %j", (state) => {
    expect(() =>
      ssh.knownHostsCertAuthority("alice", { ...options, state: state as never })
    ).toThrow(/user|key|host|state|pattern|publicKey/v)
  })

  it.each([
    null,
    undefined,
    7,
    {},
    "",
    "# comment",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "ssh-ed25519 AAAA",
    `from=10.0.0.0/8 ${key}`,
    key.replace("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"),
    key.replace("ssh-ed25519", "ssh-rsa"),
    `${key}\n${key}`,
    `${key}\rcomment`,
  ])(
    "rejects incomplete, private, certificate, option-bearing or multiline keys: %j",
    (publicKey) => {
      expect(() =>
        ssh.knownHostsCertAuthority("alice", { ...options, publicKey: publicKey as never })
      ).toThrow(/user|key|host|state|pattern|publicKey/v)
      expect(() =>
        ssh.knownHostsCertAuthority("alice", { publicKey: publicKey as never, state: "absent" })
      ).toThrow(/user|key|host|state|pattern|publicKey/v)
    }
  )

  it("rejects extra and missing padding and nonzero pad bits for otherwise valid decoded blobs", () => {
    const padded = paddedPublicKey()
    expect(padded.endsWith("=")).toBe(true)
    const altered = padded.replace(/A==$/v, "B==")
    expect(altered).not.toBe(padded)
    expect(Buffer.from(altered.split(" ")[1], "base64")).toStrictEqual(
      Buffer.from(padded.split(" ")[1], "base64")
    )
    for (const publicKey of [`${key}=`, `${padded}=`, padded.slice(0, -2), altered]) {
      expect(() => ssh.knownHostsCertAuthority("alice", { ...options, publicKey })).toThrow(
        /canonical base64/v
      )
    }
  })

  it("rejects a wire algorithm that only matches after masking its high bit", () => {
    const malformed =
      "ssh-ed25519 AAAAC/NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
    expect(Buffer.from(malformed.split(" ")[1], "base64").toString("base64")).toBe(
      malformed.split(" ")[1]
    )
    expect(() => canonicalKnownHostsCaKey(malformed, false)).toThrow(
      /algorithm must match its encoded bytes exactly/v
    )
    expect(() =>
      ssh.knownHostsCertAuthority("alice", { ...options, publicKey: malformed })
    ).toThrow(/algorithm must match its encoded bytes exactly/v)
    expect(() =>
      ssh.knownHostsCertAuthority("alice", { publicKey: malformed, state: "absent" })
    ).toThrow(/algorithm must match its encoded bytes exactly/v)
    const foreign = `@cert-authority *.foreign.example ${malformed}\n`
    expect(reconcileKnownHostsCa(foreign, parameters("absent"))).toBe(foreign)
  })

  it("requires hosts for present and validates supplied absent hosts", () => {
    expect(() => ssh.knownHostsCertAuthority("alice", { publicKey: key } as never)).toThrow(
      /user|key|host|state|pattern|publicKey/v
    )
    expect(() => ssh.knownHostsCertAuthority("alice", { ...options, hosts: [] })).toThrow(
      /user|key|host|state|pattern|publicKey/v
    )
    expect(() =>
      ssh.knownHostsCertAuthority("alice", { publicKey: key, state: "absent" })
    ).not.toThrow(/user|key|host|state|pattern|publicKey/v)
    expect(() =>
      ssh.knownHostsCertAuthority("alice", { hosts: ["!bad"], publicKey: key, state: "absent" })
    ).toThrow(/user|key|host|state|pattern|publicKey/v)
  })

  it.each(["*.example.com", null, 7, {}])(
    "rejects a supplied hosts value that is not a list: %j",
    (hosts) => {
      expect(() =>
        ssh.knownHostsCertAuthority("alice", { ...options, hosts: hosts as never })
      ).toThrow(/user|key|host|state|pattern|publicKey/v)
      expect(() =>
        ssh.knownHostsCertAuthority("alice", {
          hosts: hosts as never,
          publicKey: key,
          state: "absent",
        })
      ).toThrow(/user|key|host|state|pattern|publicKey/v)
    }
  )

  it.each([
    { hosts: [null] },
    { hosts: [undefined] },
    { hosts: [7] },
    { hosts: [{}] },
    { hosts: sparseHosts },
  ])("rejects non-string hosts elements and sparse lists: %j", ({ hosts }) => {
    expect(() =>
      ssh.knownHostsCertAuthority("alice", { ...options, hosts: hosts as never })
    ).toThrow(/user|key|host|state|pattern|publicKey/v)
    expect(() =>
      ssh.knownHostsCertAuthority("alice", {
        hosts: hosts as never,
        publicKey: key,
        state: "absent",
      })
    ).toThrow(/user|key|host|state|pattern|publicKey/v)
  })

  it("sorts and deduplicates positive wildcards, IPv6 and valid port-qualified patterns", () => {
    const hosts = [
      "z.example.com",
      "*.example.com",
      "?.example.com",
      "::1",
      "[2001:db8::1]:65535",
      "[*.example.com]:1",
      "z.example.com",
    ]
    expect(knownHostsCaParameters("alice", { ...options, hosts }).patterns).toStrictEqual([
      "*.example.com",
      "::1",
      "?.example.com",
      "[*.example.com]:1",
      "[2001:db8::1]:65535",
      "z.example.com",
    ])
  })

  it.each([
    "",
    "!host",
    "a,b",
    "a b",
    "a\nb",
    "a\tb",
    "a\u0000b",
    "a\u200bb",
    "a\u2028b",
    "a\u2029b",
    "a\ud800b",
    "a\udfffb",
    "@cert-authority",
    "#host",
    "|1|hash|value",
    "-host",
    "a\\b",
    "[host]",
    "host]",
    "[host:22",
    "[]:22",
    "[host]:0",
    "[host]:65536",
    "[host]:-1",
    "[host]:22.5",
    "[host]:22junk",
    "host:22",
    "[invalid:ipv6]:22",
  ])("rejects unsafe or ambiguous host patterns: %j", (host) => {
    expect(() => ssh.knownHostsCertAuthority("alice", { ...options, hosts: [host] })).toThrow(
      /user|key|host|state|pattern|publicKey/v
    )
  })
})

describe("host CA reconciliation", () => {
  it("creates one canonical line, replaces patterns, merges duplicates and ignores comments and encoding aliases", () => {
    const current = `@cert-authority old ${key} original\n@cert-authority other ${key}= alias\n`
    const expected = `@cert-authority *.example.com ${key}\n`
    expect(canonicalKnownHostsCaKey(`${key}= alias`, false)).toBe(key)
    expect(reconcileKnownHostsCa(current, parameters())).toBe(expected)
    expect(reconcileKnownHostsCa(expected, parameters())).toBe(expected)
    const reordered = knownHostsCaParameters("alice", {
      hosts: ["z", "a", "z"],
      publicKey: `${key} new-comment`,
    })
    expect(reconcileKnownHostsCa(expected, reordered)).toBe(`@cert-authority a,z ${key}\n`)
  })

  it("preserves foreign, malformed, raw, hashed, revoked and different CA lines byte-for-byte", () => {
    const foreign = [
      "# retained",
      "",
      `host ${key}`,
      `|1|salt|hash ${key}`,
      `@revoked host ${key}`,
      `@cert-authority host ${makePublicKey(2)}`,
      "@cert-authority host ssh-ed25519 AAAA",
      "@cert-authority incomplete",
      "garbage",
    ].join("\n")
    expect(reconcileKnownHostsCa(foreign, parameters())).toBe(
      `${foreign}\n@cert-authority *.example.com ${key}\n`
    )
    expect(reconcileKnownHostsCa(foreign, parameters("absent"))).toBe(foreign)
  })

  it("removes all own CA identities without a historical hosts filter and keeps foreign ordering", () => {
    const foreignBefore = `# before\nhost ${key}\n`
    const foreignAfter = `@revoked host ${key}\n# after`
    const current = `${foreignBefore}@cert-authority old ${key} comment\n@cert-authority second ${key}=\n${foreignAfter}`
    const absent = knownHostsCaParameters("alice", {
      publicKey: `${key} changed-comment`,
      state: "absent",
    })
    const expected = `${foreignBefore}${foreignAfter}`
    expect(reconcileKnownHostsCa(current, absent)).toBe(expected)
    expect(reconcileKnownHostsCa(expected, absent)).toBe(expected)
    expect(reconcileKnownHostsCa("", absent)).toBe("")
  })
})
