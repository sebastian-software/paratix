import { createHash, createHmac } from "node:crypto"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  appendHostKey,
  buildHostVerifier,
  clearHostKeyCache,
  computeFingerprint,
  extractAlgoFromKey,
  lookupHostKey,
  parseKnownHosts,
  validateExpectedHostPublicKey,
  waitForKnownHostsWrites,
} from "../src/knownHosts.js"

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// R-0000845: `loadKnownHostEntries` now reads asynchronously via
// `node:fs/promises.readFile` (with a size cap enforced through `stat`).
// The legacy `node:fs.readFileSync` mock stays available as the source of
// truth for the "what content does the file have" assertion; the async
// surface routes through `readFile` so tests can keep setting up
// `readFileSyncMock.mockReturnValue(...)` without rewriting every case.
const synchronousReadFileMock = vi.fn<(...args: unknown[]) => string>(() => "")

vi.mock("node:fs", () => ({
  readFileSync: synchronousReadFileMock,
}))

vi.mock("node:fs/promises", () => ({
  appendFile: vi.fn().mockResolvedValue(null),
  mkdir: vi.fn().mockResolvedValue(null),
  // R-0000845: forward the async `readFile` through the existing sync mock
  // so a single `readFileSyncMock.mockReturnValue(...)` keeps configuring
  // both `loadKnownHostEntries` (async) and any legacy call sites.
  // eslint-disable-next-line @typescript-eslint/promise-function-async -- mock returns Promise directly; an async wrapper would add an extra microtask tick that breaks microtask-counting tests
  readFile: vi.fn((...args: unknown[]) => Promise.resolve(synchronousReadFileMock(...args))),
  // R-0000845: report the simulated file size so the in-source size cap
  // never trips during tests. Real production callers receive a `Stats`
  // instance; the size-only shape is sufficient for the cap check.
  // eslint-disable-next-line @typescript-eslint/promise-function-async -- mock returns Promise directly; an async wrapper would add an extra microtask tick that breaks microtask-counting tests
  stat: vi.fn(() => Promise.resolve({ size: 0 })),
}))

vi.mock("node:os", () => ({
  homedir: vi.fn().mockReturnValue("/home/testuser"),
}))

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal SSH wire-format key buffer:
 *   uint32 algo_length | algo_bytes | keyData
 *
 * @param algo - The algorithm name string (e.g. "ssh-ed25519").
 * @param keyData - Optional raw key material bytes.
 * @returns A Buffer in SSH wire format.
 */
function makeKeyBuffer(algo: string, keyData: Buffer = Buffer.from("fake-key-data")): Buffer {
  const algoBytes = Buffer.from(algo)
  const lengthBuf = Buffer.alloc(4)
  lengthBuf.writeUInt32BE(algoBytes.length)
  return Buffer.concat([lengthBuf, algoBytes, keyData])
}

function makeHashedHostPattern(
  host: string,
  port = 22,
  salt = Buffer.from("known-hosts-salt")
): string {
  const hostLabel = port === 22 ? host : `[${host}]:${port}`
  const hostHash = createHmac("sha1", salt).update(hostLabel).digest("base64")
  return `|1|${salt.toString("base64")}|${hostHash}`
}

// ---------------------------------------------------------------------------
// parseKnownHosts
// ---------------------------------------------------------------------------

describe("parseKnownHosts", () => {
  it("parses a simple hostname algo base64key entry", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `example.com ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({ algo: "ssh-ed25519", host: "example.com" })
    expect(entries[0]?.key).toStrictEqual(key)
  })

  it("parses a bracketed [host]:port entry", () => {
    const key = makeKeyBuffer("ssh-rsa")
    const base64Key = key.toString("base64")
    const content = `[example.com]:2222 ssh-rsa ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({ algo: "ssh-rsa", host: "[example.com]:2222" })
  })

  it("skips comment lines starting with #", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `# this is a comment\nexample.com ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]?.host).toBe("example.com")
  })

  it("skips blank lines", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `\n\nexample.com ssh-ed25519 ${base64Key}\n\n`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
  })

  it("parses hashed hostnames starting with |1|", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `${makeHashedHostPattern("example.com")} ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]?.host).toMatch(/^\|1\|/v)
  })

  it("parses @revoked entries instead of skipping them", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `@revoked example.com ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({
      algo: "ssh-ed25519",
      host: "example.com",
      marker: "@revoked",
    })
  })

  it("parses @cert-authority entries without treating the marker as a host", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `@cert-authority example.com ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({
      algo: "ssh-ed25519",
      host: "example.com",
      marker: "@cert-authority",
    })
  })

  it("splits comma-separated hosts into separate entries", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `host1.com,host2.com,192.168.1.1 ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(3)
    expect(entries[0]?.host).toBe("host1.com")
    expect(entries[1]?.host).toBe("host2.com")
    expect(entries[2]?.host).toBe("192.168.1.1")
    // All entries share the same key and algo
    for (const entry of entries) {
      expect(entry.algo).toBe("ssh-ed25519")
      expect(entry.key).toStrictEqual(key)
    }
  })

  it("returns an empty array for empty input", () => {
    expect(parseKnownHosts("")).toHaveLength(0)
  })

  it("returns an empty array for whitespace-only input", () => {
    expect(parseKnownHosts("   \n   \n")).toHaveLength(0)
  })

  it("skips lines with fewer than three fields", () => {
    const content = "example.com ssh-ed25519"
    const entries = parseKnownHosts(content)
    expect(entries).toHaveLength(0)
  })

  it("skips entries whose base64 key contains characters outside the strict alphabet", () => {
    // Whitespace, control characters, and any character outside [A-Za-z0-9+/=]
    // would be silently dropped by Buffer.from(value, "base64"), producing a
    // truncated buffer. Verify such lines are rejected entirely.
    const validKey = makeKeyBuffer("ssh-ed25519").toString("base64")
    const corruptKey = `${validKey.slice(0, 8)}!@#${validKey.slice(8)}`
    const content = `example.com ssh-ed25519 ${corruptKey}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(0)
  })

  it("skips entries whose base64 key has invalid padding placement", () => {
    // Padding characters in the middle of the key are not valid strict base64
    // and must be rejected before Buffer.from silently ignores them.
    const content = "example.com ssh-ed25519 AAAA==BBBB"

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(0)
  })

  it("skips realistic mixed content that contains a corrupt base64 entry", () => {
    const validKey = makeKeyBuffer("ssh-ed25519").toString("base64")
    const corruptLine = "corrupt.example ssh-ed25519 not_base64$$$"
    const content = [corruptLine, `valid.example ssh-ed25519 ${validKey}`].join("\n")

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]?.host).toBe("valid.example")
  })

  it("parses multiple valid entries from multi-line content", () => {
    const keyA = makeKeyBuffer("ssh-ed25519", Buffer.from("key-a"))
    const keyB = makeKeyBuffer("ssh-rsa", Buffer.from("key-b"))
    const content = [
      `hostA.com ssh-ed25519 ${keyA.toString("base64")}`,
      `hostB.com ssh-rsa ${keyB.toString("base64")}`,
    ].join("\n")

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(2)
    expect(entries[0]?.host).toBe("hostA.com")
    expect(entries[1]?.host).toBe("hostB.com")
  })

  it("handles a realistic known_hosts file with mixed lines", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = [
      "# Known hosts file",
      "",
      `${makeHashedHostPattern("hashed.example")} ssh-ed25519 ${base64Key}`,
      `github.com ssh-ed25519 ${base64Key}`,
      `@revoked revoked.example ssh-ed25519 ${base64Key}`,
      "",
    ].join("\n")

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(3)
    expect(entries[1]?.host).toBe("github.com")
    expect(entries[2]?.marker).toBe("@revoked")
  })
})

// ---------------------------------------------------------------------------
// lookupHostKey
// ---------------------------------------------------------------------------

describe("lookupHostKey", () => {
  const edKey = makeKeyBuffer("ssh-ed25519", Buffer.from("ed-key-data"))
  const rsaKey = makeKeyBuffer("ssh-rsa", Buffer.from("rsa-key-data"))

  const entries = [
    { algo: "ssh-ed25519", host: "example.com", key: edKey },
    { algo: "ssh-rsa", host: "[example.com]:2222", key: rsaKey },
  ]

  it("finds key for exact host match on port 22", () => {
    const result = lookupHostKey(entries, "example.com", 22)
    expect(result).toStrictEqual(edKey)
  })

  it("matches plain hostname entries case-insensitively", () => {
    const mixedCaseEntries = [{ algo: "ssh-ed25519", host: "Example.COM", key: edKey }]

    expect(lookupHostKey(mixedCaseEntries, "example.com", 22)).toStrictEqual(edKey)
    expect(lookupHostKey(mixedCaseEntries, "EXAMPLE.COM", 22)).toStrictEqual(edKey)
  })

  it("finds key for [host]:port format on non-standard port", () => {
    const result = lookupHostKey(entries, "example.com", 2222)
    expect(result).toStrictEqual(rsaKey)
  })

  it("matches bracketed non-standard port entries case-insensitively", () => {
    const mixedCaseEntries = [{ algo: "ssh-ed25519", host: "[Example.COM]:2222", key: rsaKey }]

    expect(lookupHostKey(mixedCaseEntries, "example.com", 2222)).toStrictEqual(rsaKey)
    expect(lookupHostKey(mixedCaseEntries, "EXAMPLE.COM", 2222)).toStrictEqual(rsaKey)
  })

  it("finds key for a hashed host entry", () => {
    const hashedEntries = [
      { algo: "ssh-ed25519", host: makeHashedHostPattern("example.com"), key: edKey },
    ]
    const result = lookupHostKey(hashedEntries, "example.com", 22)
    expect(result).toStrictEqual(edKey)
  })

  it("keeps hashed host entries matched against the original host spelling", () => {
    const hashedEntries = [
      { algo: "ssh-ed25519", host: makeHashedHostPattern("example.com"), key: edKey },
    ]

    expect(lookupHostKey(hashedEntries, "EXAMPLE.COM", 22)).toBeNull()
  })

  it("finds key for a wildcard host pattern", () => {
    const wildcardEntries = [{ algo: "ssh-ed25519", host: "*.example.com", key: edKey }]
    expect(lookupHostKey(wildcardEntries, "app.example.com", 22)).toStrictEqual(edKey)
    expect(lookupHostKey(wildcardEntries, "example.com", 22)).toBeNull()
  })

  it("matches wildcard host patterns case-insensitively", () => {
    const wildcardEntries = [{ algo: "ssh-ed25519", host: "*.Example.COM", key: edKey }]

    expect(lookupHostKey(wildcardEntries, "APP.example.com", 22)).toStrictEqual(edKey)
  })

  it("honors negated patterns in a comma-separated host list", () => {
    const patternEntries = parseKnownHosts(
      `*.example.com,!blocked.example.com ssh-ed25519 ${edKey.toString("base64")}`
    )

    expect(lookupHostKey(patternEntries, "app.example.com", 22)).toStrictEqual(edKey)
    expect(lookupHostKey(patternEntries, "blocked.example.com", 22)).toBeNull()
  })

  it("honors negated patterns case-insensitively", () => {
    const patternEntries = parseKnownHosts(
      `*.example.com,!Blocked.Example.COM ssh-ed25519 ${edKey.toString("base64")}`
    )

    expect(lookupHostKey(patternEntries, "APP.example.com", 22)).toStrictEqual(edKey)
    expect(lookupHostKey(patternEntries, "blocked.example.com", 22)).toBeNull()
    expect(lookupHostKey(patternEntries, "BLOCKED.EXAMPLE.COM", 22)).toBeNull()
  })

  it("matches wildcard patterns for bracketed non-standard ports", () => {
    const wildcardEntries = [{ algo: "ssh-ed25519", host: "[*.example.com]:2222", key: rsaKey }]

    expect(lookupHostKey(wildcardEntries, "app.example.com", 2222)).toStrictEqual(rsaKey)
    expect(lookupHostKey(wildcardEntries, "app.example.com", 22)).toBeNull()
  })

  it("matches bracketed wildcard patterns case-insensitively", () => {
    const wildcardEntries = [{ algo: "ssh-ed25519", host: "[*.Example.COM]:2222", key: rsaKey }]

    expect(lookupHostKey(wildcardEntries, "APP.example.com", 2222)).toStrictEqual(rsaKey)
  })

  it("returns null when host is not found", () => {
    const result = lookupHostKey(entries, "unknown.com", 22)
    expect(result).toBeNull()
  })

  it("returns null for an empty entries array", () => {
    const result = lookupHostKey([], "example.com", 22)
    expect(result).toBeNull()
  })

  it("uses plain hostname (no brackets) for port 22", () => {
    const specialEntries = [{ algo: "ssh-ed25519", host: "myhost.com", key: edKey }]
    expect(lookupHostKey(specialEntries, "myhost.com", 22)).toStrictEqual(edKey)
    expect(lookupHostKey(specialEntries, "myhost.com", 23)).toBeNull()
  })

  it("does not match plain hostname entry when looking up non-standard port", () => {
    // entry stored as "example.com" (port 22 format) should not match port 2222 lookup
    const plainEntries = [{ algo: "ssh-ed25519", host: "example.com", key: edKey }]
    expect(lookupHostKey(plainEntries, "example.com", 2222)).toBeNull()
  })

  it("does not return @cert-authority entries as raw host keys", () => {
    const certAuthorityEntries = parseKnownHosts(
      `@cert-authority example.com ssh-ed25519 ${edKey.toString("base64")}`
    )

    expect(lookupHostKey(certAuthorityEntries, "example.com", 22)).toBeNull()
  })

  it("does not return unknown marker entries as raw host keys", () => {
    const markerEntries = parseKnownHosts(
      `@unknown example.com ssh-ed25519 ${edKey.toString("base64")}`
    )

    expect(lookupHostKey(markerEntries, "example.com", 22)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// extractAlgoFromKey
// ---------------------------------------------------------------------------

describe("extractAlgoFromKey", () => {
  it("extracts 'ssh-rsa' from an RSA key buffer", () => {
    const keyBuf = makeKeyBuffer("ssh-rsa")
    expect(extractAlgoFromKey(keyBuf)).toBe("ssh-rsa")
  })

  it("extracts 'ssh-ed25519' from an Ed25519 key buffer", () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    expect(extractAlgoFromKey(keyBuf)).toBe("ssh-ed25519")
  })

  it("extracts 'ecdsa-sha2-nistp256' from an ECDSA key buffer", () => {
    const keyBuf = makeKeyBuffer("ecdsa-sha2-nistp256")
    expect(extractAlgoFromKey(keyBuf)).toBe("ecdsa-sha2-nistp256")
  })

  it("round-trips: key created with makeKeyBuffer yields the same algo", () => {
    const algo = "ssh-ed25519"
    const keyBuf = makeKeyBuffer(algo, Buffer.from("some-key-material"))
    expect(extractAlgoFromKey(keyBuf)).toBe(algo)
  })
})

// ---------------------------------------------------------------------------
// computeFingerprint
// ---------------------------------------------------------------------------

describe("computeFingerprint", () => {
  it("returns SHA256:<base64> format", () => {
    const key = makeKeyBuffer("ssh-ed25519", Buffer.from("some-key-material"))
    const expectedHash = createHash("sha256").update(key).digest("base64").replaceAll("=", "")
    const fingerprint = computeFingerprint(key)
    expect(fingerprint).toBe(`SHA256:${expectedHash}`)
  })

  it("does not include trailing padding characters", () => {
    const key = makeKeyBuffer("ssh-ed25519", Buffer.from("another-key-material"))
    const fingerprint = computeFingerprint(key)
    expect(fingerprint).not.toMatch(/=$/v)
  })

  it("matches ssh-keygen fingerprint for a real RSA public key", () => {
    // Key and expected fingerprint verified with: ssh-keygen -lf test-key.pub
    // 4096 SHA256:+RNNX58XMUIvS6ccvCfIuIPuOcPgorJ9P+2CtmrRbxM test-key (RSA)
    const realKeyBase64 =
      "AAAAB3NzaC1yc2EAAAADAQABAAACAQCcKn9oaPBEX5MPGQ23ucwsy4ii6f5zzktrIaHz" +
      "MknBTempDzTuT2dVfiLz1f/eToE0ezwQ+OuqVZlXrAi/dOv4mZnupsY1xKvG6INzbD5z" +
      "K4VN4asMKvAwpPYHwY5x0NCJDwNJrm2fzP3lQyj7lTbvZQwPezGxVFfwp/c+yM3CnSX" +
      "hyMBkBawQo4VnB9HT7mhiCsy46WqDuG/zGb5f1YxoS1wnbHsHKKi/ZdH1ttdQwI6lPo" +
      "FLZNWYhPVm4Heyy8p6EAku0t1EKmZRZh4qKkUlIKZwBYLGm0irNlH7Z2SWnuFEDjWSN" +
      "jUl5y5jLqZTJ8hpSh0YJfPcHEVp63+MshFCzlq6snHEgFxidoFbxQ03j70aT8yWbLzf" +
      "qjYt+kSLwzdSOAdqsOXxC2H7WchUI7nyjKpUyEsibLbJ9okBcLRmU3xAnQtYz7U9XHa" +
      "aHqlX7Ll2Uz8mxUsG/BZUnOMLtOnu4ZU5l3oJBXOB6N4QVW5Sj1GWfAlL4I8fZpyZXiM" +
      "kbJNOb0YqNLr4NYqEXKB1YXSoYBsw5tZBpPa66blrh4BnBOqbqrzgfW9ais+CIg2MeD" +
      "qwMe39toei1oZKKKySHwvCMNmTI8mdQdMR/8VaM9qh8/O/19CHwRzXUEnuoygii1mLwR" +
      "F/DhNI6dWaZjp/XPNXn6VSr0kIL/ZTcDgprPFxPw=="
    const key = Buffer.from(realKeyBase64, "base64")
    expect(computeFingerprint(key)).toBe("SHA256:+RNNX58XMUIvS6ccvCfIuIPuOcPgorJ9P+2CtmrRbxM")
  })

  it("returns different fingerprints for different keys", () => {
    const keyA = makeKeyBuffer("ssh-ed25519", Buffer.from("key-material-alpha"))
    const keyB = makeKeyBuffer("ssh-ed25519", Buffer.from("key-material-beta"))
    const fingerprintA = computeFingerprint(keyA)
    const fingerprintB = computeFingerprint(keyB)
    expect(fingerprintA).not.toBe(fingerprintB)
  })
})

// ---------------------------------------------------------------------------
// appendHostKey
// ---------------------------------------------------------------------------

describe("appendHostKey", () => {
  let appendFileMock: ReturnType<typeof vi.fn>
  let mkdirMock: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    const fsp = await import("node:fs/promises")
    appendFileMock = vi.mocked(fsp.appendFile)
    mkdirMock = vi.mocked(fsp.mkdir)
    appendFileMock.mockResolvedValue(null)
    mkdirMock.mockResolvedValue(null)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it("appends the key in correct format for port 22 (plain hostname)", async () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    await appendHostKey("example.com", 22, keyBuf)

    const expectedLine = `example.com ssh-ed25519 ${keyBuf.toString("base64")}\n`
    expect(appendFileMock).toHaveBeenCalledOnce()
    const [filePath, content] = appendFileMock.mock.calls[0] as [string, string, unknown]
    expect(filePath).toContain("known_hosts")
    expect(content).toBe(expectedLine)
  })

  it("appends the key in [host]:port format for non-standard port", async () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    await appendHostKey("example.com", 2222, keyBuf)

    const expectedLine = `[example.com]:2222 ssh-ed25519 ${keyBuf.toString("base64")}\n`
    expect(appendFileMock).toHaveBeenCalledOnce()
    const [, content] = appendFileMock.mock.calls[0] as [string, string, unknown]
    expect(content).toBe(expectedLine)
  })

  it("creates the ~/.ssh directory with mode 0o700", async () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    await appendHostKey("example.com", 22, keyBuf)

    expect(mkdirMock).toHaveBeenCalledOnce()
    const [dirPath, options] = mkdirMock.mock.calls[0] as [
      string,
      { mode: number; recursive: boolean },
    ]
    expect(dirPath).toContain(".ssh")
    expect(options.mode).toBe(0o700)
    expect(options.recursive).toBe(true)
  })

  it("writes to the known_hosts file path under homedir", async () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    await appendHostKey("example.com", 22, keyBuf)

    const [filePath] = appendFileMock.mock.calls[0] as [string, string, unknown]
    expect(filePath).toBe("/home/testuser/.ssh/known_hosts")
  })

  // R-0000793: known_hosts must be created with 0600 so other local users
  // cannot read which hosts the operator pinned. Aligns with the 0700
  // permissions on `~/.ssh/` and the broader trust-store hygiene contract.
  it("writes the file with mode 0o600 (R-0000793)", async () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    await appendHostKey("example.com", 22, keyBuf)

    const thirdArg = (appendFileMock.mock.calls[0] as [string, string, { mode: number }])[2]
    expect(thirdArg.mode).toBe(0o600)
  })
})

// ---------------------------------------------------------------------------
// buildHostVerifier
// ---------------------------------------------------------------------------

/**
 * Build a known_hosts file content line for testing.
 *
 * @param host - The hostname.
 * @param port - The SSH port (22 = plain hostname, else [host]:port).
 * @param keyBuf - The key buffer to encode as base64.
 * @returns A single known_hosts line string.
 */
function makeKnownHostsContent(host: string, port: number, keyBuf: Buffer): string {
  const hostLabel = port === 22 ? host : `[${host}]:${port}`
  return `${hostLabel} ssh-ed25519 ${keyBuf.toString("base64")}\n`
}

describe("buildHostVerifier", () => {
  let readFileSyncMock: ReturnType<typeof vi.fn>
  let appendFileMock: ReturnType<typeof vi.fn>
  let mkdirMock: ReturnType<typeof vi.fn>

  const ed25519Key = makeKeyBuffer("ssh-ed25519", Buffer.from("real-key-material-here"))
  const rsaKey = makeKeyBuffer("ssh-rsa", Buffer.from("real-rsa-key-material"))

  beforeEach(async () => {
    clearHostKeyCache()
    const fs = await import("node:fs")
    const fsp = await import("node:fs/promises")
    readFileSyncMock = vi.mocked(fs.readFileSync)
    appendFileMock = vi.mocked(fsp.appendFile)
    mkdirMock = vi.mocked(fsp.mkdir)
    appendFileMock.mockResolvedValue(null)
    mkdirMock.mockResolvedValue(null)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it("returns an empty object (no hostVerifier) for mode 'no' without pinned trust anchors", async () => {
    const result = await buildHostVerifier("no", { host: "example.com", port: 22 })
    expect(result).toStrictEqual({})
    expect(result.hostVerifier).toBeUndefined()
  })

  it("mode 'yes' with unknown host and matching expected fingerprint: hostVerifier returns true", async () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = await buildHostVerifier(
      "yes",
      { host: "newhost.com", port: 22 },
      {
        expectedHostFingerprint: computeFingerprint(ed25519Key),
      }
    )

    expect(hostVerifier).toBeDefined()
    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'yes' with unknown host and matching expected public key: hostVerifier returns true", async () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = await buildHostVerifier(
      "yes",
      { host: "newhost.com", port: 22 },
      {
        expectedHostPublicKey: `ssh-ed25519 ${ed25519Key.toString("base64")} comment`,
      }
    )

    expect(hostVerifier).toBeDefined()
    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'yes' with unknown host and mismatching expected fingerprint: hostVerifier throws verification error", async () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = await buildHostVerifier(
      "yes",
      { host: "newhost.com", port: 22 },
      {
        expectedHostFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      }
    )

    expect(hostVerifier).toBeDefined()
    expect(() => hostVerifier!(ed25519Key)).toThrow(/configured trust anchor/v)
  })

  it("mode 'accept-new' with unknown host: hostVerifier returns true and commits appendHostKey later", async () => {
    // No known hosts
    readFileSyncMock.mockReturnValue("")

    const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
      host: "newhost.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()

    await commitAcceptedHostKey?.()

    expect(appendFileMock).toHaveBeenCalled()
  })

  it("mode 'accept-new' treats missing known_hosts as an empty trust store", async () => {
    const missingFileError = Object.assign(new Error("missing"), { code: "ENOENT" })
    readFileSyncMock.mockImplementation(() => {
      throw missingFileError
    })

    const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
      host: "newhost.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()

    await commitAcceptedHostKey?.()

    expect(appendFileMock).toHaveBeenCalled()
  })

  it("mode 'accept-new' fails closed when known_hosts cannot be read", async () => {
    const accessError = Object.assign(new Error("Permission denied"), { code: "EACCES" })
    readFileSyncMock.mockImplementation(() => {
      throw accessError
    })

    await expect(
      buildHostVerifier("accept-new", { host: "newhost.com", port: 22 })
    ).rejects.toThrow(/Could not read known_hosts/v)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'accept-new' with unknown host: writes fingerprint warning to stderr", async () => {
    readFileSyncMock.mockReturnValue("")

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    try {
      const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
        host: "newhost.com",
        port: 22,
      })
      expect(hostVerifier).toBeDefined()

      hostVerifier!(ed25519Key)
      expect(stderrSpy).not.toHaveBeenCalled()

      await commitAcceptedHostKey?.()

      expect(stderrSpy).toHaveBeenCalledTimes(1)
      const warning = (stderrSpy.mock.calls[0] as [string])[0]
      expect(warning).toContain("SHA256:")
      expect(warning).toContain("ssh-ed25519")

      await Promise.resolve()
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it("mode 'accept-new' with known host and correct key: hostVerifier returns true", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)
  })

  it("mode 'accept-new' with hashed known host and correct key: returns true without appending", async () => {
    readFileSyncMock.mockReturnValue(
      `${makeHashedHostPattern("example.com")} ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'accept-new' with wildcard known host and correct key: returns true without appending", async () => {
    readFileSyncMock.mockReturnValue(`*.example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`)

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "app.example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'accept-new' matches a known host case-insensitively without appending", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "EXAMPLE.COM",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'accept-new' with known host and wrong key: hostVerifier throws Error", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("different-key-material"))
    expect(() => hostVerifier!(differentKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
    expect(() => hostVerifier!(differentKey)).toThrow("example.com")
  })

  it("mode 'accept-new' with hashed known host and changed key: throws verification error", async () => {
    readFileSyncMock.mockReturnValue(
      `${makeHashedHostPattern("example.com")} ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("different-key-material"))
    expect(() => hostVerifier!(differentKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
  })

  it("mode 'yes' with known host and correct key: hostVerifier returns true", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)
  })

  it("mode 'yes' matches a known host case-insensitively", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("yes", { host: "EXAMPLE.COM", port: 22 })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
  })

  it("regression — mode 'yes' accepts a matching key when known_hosts contains multiple algorithms for the same host", async () => {
    readFileSyncMock.mockReturnValue(
      `example.com ssh-rsa ${rsaKey.toString("base64")}\nexample.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
  })

  it("regression — mode 'accept-new' does not reject a matching key when a different algorithm entry appears first", async () => {
    readFileSyncMock.mockReturnValue(
      `example.com ssh-rsa ${rsaKey.toString("base64")}\nexample.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'yes' with unknown host: hostVerifier throws Error", async () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = await buildHostVerifier("yes", { host: "unknownhost.com", port: 22 })
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/not found in known_hosts/v)
    expect(() => hostVerifier!(ed25519Key)).toThrow("unknownhost.com")
  })

  it("mode 'yes' with @cert-authority entry rejects with a clear error (R-0000204)", async () => {
    readFileSyncMock.mockReturnValue(
      `@cert-authority example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/@cert-authority/v)
    expect(() => hostVerifier!(ed25519Key)).toThrow(/does not validate certificate-authority/v)
  })

  it("mode 'accept-new' with @cert-authority entry refuses to persist a raw host key (R-0000204)", async () => {
    readFileSyncMock.mockReturnValue(
      `@cert-authority ca-only.example ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "ca-only.example",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/@cert-authority/v)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'yes' with known host and wrong key: hostVerifier throws Error", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })
    expect(hostVerifier).toBeDefined()

    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("wrong-key-material"))
    expect(() => hostVerifier!(differentKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
  })

  it("mode 'yes' with @revoked host key: throws revoked error", async () => {
    readFileSyncMock.mockReturnValue(
      `@revoked example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/revoked/v)
  })

  it("mode 'accept-new' with @revoked host key: throws revoked error instead of accepting", async () => {
    readFileSyncMock.mockReturnValue(
      `@revoked example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/revoked/v)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'accept-new' with @revoked wildcard host key: rejects matching hosts", async () => {
    readFileSyncMock.mockReturnValue(
      `@revoked *.example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "app.example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/revoked/v)
    expect(appendFileMock).not.toHaveBeenCalled()
  })

  it("mode 'accept-new' with @revoked negated wildcard host key: accepts excluded hosts as new", async () => {
    readFileSyncMock.mockReturnValue(
      `@revoked *.example.com,!safe.example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`
    )

    const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
      host: "safe.example.com",
      port: 22,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
    await commitAcceptedHostKey?.()

    expect(appendFileMock).toHaveBeenCalled()
  })

  it("mode 'accept-new': writes WARNING to stderr when appendHostKey fails", async () => {
    // No known hosts so the key is treated as new
    readFileSyncMock.mockReturnValue("")
    const accessError = Object.assign(new Error("Permission denied"), { code: "EACCES" })
    appendFileMock.mockRejectedValue(accessError)

    // Install the spy BEFORE calling hostVerifier so it captures the async .catch() write
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    try {
      const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
        host: "newhost.com",
        port: 22,
      })
      expect(hostVerifier).toBeDefined()

      // hostVerifier itself returns true; persistence is committed separately.
      const result = hostVerifier!(ed25519Key)
      expect(result).toBe(true)
      expect(stderrSpy).not.toHaveBeenCalled()

      await commitAcceptedHostKey?.()
      expect(stderrSpy).toHaveBeenCalledTimes(2)
      const addedWarning = (stderrSpy.mock.calls[0] as [string])[0]
      expect(addedWarning).toContain("WARNING")
      expect(addedWarning).toContain("Permanently added")
      expect(addedWarning).toContain("newhost.com")

      const persistWarning = (stderrSpy.mock.calls[1] as [string])[0]
      expect(persistWarning).toContain("WARNING")
      expect(persistWarning).toContain("cached in memory")
      expect(persistWarning).toContain("newhost.com")
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it("mode 'accept-new' with unknown host on non-standard port: appends [host]:port entry", async () => {
    readFileSyncMock.mockReturnValue("")

    const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 2222,
    })
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)

    await commitAcceptedHostKey?.()

    expect(appendFileMock).toHaveBeenCalled()
    const [, content] = appendFileMock.mock.calls[0] as [string, string, unknown]
    expect(content).toContain("[example.com]:2222")
  })

  it("mode 'accept-new' with known host on non-standard port and correct key: returns true", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 2222, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 2222,
    })
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
  })

  it("error message for key mismatch mentions man-in-the-middle attack", async () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = await buildHostVerifier("accept-new", {
      host: "example.com",
      port: 22,
    })
    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("attacker-key"))

    expect(() => hostVerifier!(differentKey)).toThrow(/man-in-the-middle/v)
  })

  it("error message for 'yes' with missing host suggests explicit TOFU or pinned trust anchors", async () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = await buildHostVerifier("yes", { host: "newhost.com", port: 22 })

    expect(() => hostVerifier!(ed25519Key)).toThrow(/accept-new/v)
    expect(() => hostVerifier!(ed25519Key)).toThrow(/expectedHostFingerprint/v)
  })

  it("mode 'accept-new': caches key in memory after accepting unknown host", async () => {
    // Arrange: empty known_hosts, appendFile succeeds
    readFileSyncMock.mockReturnValue("")

    const { commitAcceptedHostKey, hostVerifier: firstVerifier } = await buildHostVerifier(
      "accept-new",
      {
        host: "newhost.com",
        port: 22,
      }
    )
    expect(firstVerifier).toBeDefined()

    // Act: accept the key — it gets cached in memory
    const firstResult = firstVerifier!(ed25519Key)
    expect(firstResult).toBe(true)

    await commitAcceptedHostKey?.()

    // Arrange: second verifier with empty known_hosts but in-memory cache still populated
    // (clearHostKeyCache NOT called)
    readFileSyncMock.mockReturnValue("")
    const { hostVerifier: secondVerifier } = await buildHostVerifier("accept-new", {
      host: "newhost.com",
      port: 22,
    })
    expect(secondVerifier).toBeDefined()

    // Act: second verifier should recognize the cached key
    const secondResult = secondVerifier!(ed25519Key)

    // Assert: returns true and appendFile was called only once (for the first verifier)
    expect(secondResult).toBe(true)
    expect(appendFileMock).toHaveBeenCalledTimes(1)
  })

  it("mode 'accept-new': cached key mismatch throws verification error", async () => {
    // Arrange: empty known_hosts, accept key A
    readFileSyncMock.mockReturnValue("")

    const { commitAcceptedHostKey, hostVerifier: firstVerifier } = await buildHostVerifier(
      "accept-new",
      {
        host: "newhost.com",
        port: 22,
      }
    )
    expect(firstVerifier).toBeDefined()
    firstVerifier!(ed25519Key)

    await commitAcceptedHostKey?.()

    // Arrange: second verifier with empty known_hosts but cached key A still in memory
    readFileSyncMock.mockReturnValue("")
    const { hostVerifier: secondVerifier } = await buildHostVerifier("accept-new", {
      host: "newhost.com",
      port: 22,
    })
    expect(secondVerifier).toBeDefined()

    // Act & Assert: presenting a different key B should throw
    const keyB = makeKeyBuffer("ssh-ed25519", Buffer.from("different-key-material-B"))
    expect(() => secondVerifier!(keyB)).toThrow(/HOST KEY VERIFICATION FAILED/v)
  })

  it("mode 'accept-new': persist failure warning includes ssh-keyscan hint", async () => {
    // Arrange: empty known_hosts, appendFile rejects
    readFileSyncMock.mockReturnValue("")
    const accessError = Object.assign(new Error("Permission denied"), { code: "EACCES" })
    appendFileMock.mockRejectedValue(accessError)

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    try {
      const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
        host: "newhost.com",
        port: 22,
      })
      expect(hostVerifier).toBeDefined()

      hostVerifier!(ed25519Key)
      await commitAcceptedHostKey?.()

      // Wait for the async .catch() to fire
      await vi.waitFor(() => {
        expect(stderrSpy).toHaveBeenCalledTimes(2)
      })

      const persistWarning = (stderrSpy.mock.calls[1] as [string])[0]
      expect(persistWarning).toContain("ssh-keyscan")
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it("mode 'accept-new': persist failure warning includes port flag for non-standard port", async () => {
    // Arrange: empty known_hosts, appendFile rejects, non-standard port
    readFileSyncMock.mockReturnValue("")
    const accessError = Object.assign(new Error("Permission denied"), { code: "EACCES" })
    appendFileMock.mockRejectedValue(accessError)

    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

    try {
      const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
        host: "newhost.com",
        port: 2222,
      })
      expect(hostVerifier).toBeDefined()

      hostVerifier!(ed25519Key)
      await commitAcceptedHostKey?.()

      // Wait for the async .catch() to fire
      await vi.waitFor(() => {
        expect(stderrSpy).toHaveBeenCalledTimes(2)
      })

      const persistWarning = (stderrSpy.mock.calls[1] as [string])[0]
      expect(persistWarning).toContain("-p 2222")
    } finally {
      stderrSpy.mockRestore()
    }
  })

  it.each([
    [22, "ssh-keyscan 'evil'\\''host; rm -rf /' >> ~/.ssh/known_hosts."],
    [2222, "ssh-keyscan -p 2222 'evil'\\''host; rm -rf /' >> ~/.ssh/known_hosts."],
  ] satisfies ReadonlyArray<readonly [number, string]>)(
    "mode 'accept-new': persist failure ssh-keyscan hint shell-quotes hostname with special chars on port %i",
    async (port, expectedKeyscanHint) => {
      // Regression test: the ssh-keyscan command suggestion in the persist failure warning
      // must shell-quote the hostname to prevent shell injection when the user copies it.
      // e.g. "evil'host; rm -rf /" must appear as 'evil'\''host; rm -rf /' in the hint.
      const maliciousHost = "evil'host; rm -rf /"
      readFileSyncMock.mockReturnValue("")
      const accessError = Object.assign(new Error("Permission denied"), { code: "EACCES" })
      appendFileMock.mockRejectedValue(accessError)

      const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)

      try {
        const { commitAcceptedHostKey, hostVerifier } = await buildHostVerifier("accept-new", {
          host: maliciousHost,
          port,
        })
        expect(hostVerifier).toBeDefined()

        hostVerifier!(ed25519Key)
        await commitAcceptedHostKey?.()

        // Wait for the async .catch() to fire and write the second warning
        await vi.waitFor(() => {
          expect(stderrSpy).toHaveBeenCalledTimes(2)
        })

        const persistWarning = (stderrSpy.mock.calls[1] as [string])[0]

        expect(persistWarning).toContain(expectedKeyscanHint)
        // The raw unquoted form must NOT appear as a standalone shell-injectable sequence
        expect(persistWarning).not.toContain("ssh-keyscan evil'host; rm -rf /")
      } finally {
        stderrSpy.mockRestore()
      }
    }
  )

  it("clearHostKeyCache removes cached keys", async () => {
    // Arrange: accept a key so it gets cached
    readFileSyncMock.mockReturnValue("")

    const { commitAcceptedHostKey, hostVerifier: firstVerifier } = await buildHostVerifier(
      "accept-new",
      {
        host: "newhost.com",
        port: 22,
      }
    )
    expect(firstVerifier).toBeDefined()
    firstVerifier!(ed25519Key)

    await commitAcceptedHostKey?.()

    // Act: clear the cache
    clearHostKeyCache()

    // Arrange: new verifier with empty known_hosts and empty cache
    readFileSyncMock.mockReturnValue("")
    appendFileMock.mockClear()
    const { commitAcceptedHostKey: secondCommitAcceptedHostKey, hostVerifier: secondVerifier } =
      await buildHostVerifier("accept-new", {
        host: "newhost.com",
        port: 22,
      })
    expect(secondVerifier).toBeDefined()

    // Act: second verifier should treat the key as unknown again
    const result = secondVerifier!(ed25519Key)
    expect(result).toBe(true)

    // Assert: appendFile called again (key was unknown, not from cache)
    await secondCommitAcceptedHostKey?.()
    expect(appendFileMock).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// R-0000210: corrupt buffers from untrusted callers must surface as
// HostKeyVerificationError, not as a raw RangeError.
// ---------------------------------------------------------------------------

describe("buildHostVerifier handling of corrupt buffers (R-0000210)", () => {
  let readFileSyncMock: ReturnType<typeof vi.fn>
  let appendFileMock: ReturnType<typeof vi.fn>
  let mkdirMock: ReturnType<typeof vi.fn>

  const ed25519Key = makeKeyBuffer("ssh-ed25519", Buffer.from("legit-key-material"))

  beforeEach(async () => {
    clearHostKeyCache()
    const fs = await import("node:fs")
    const fsp = await import("node:fs/promises")
    readFileSyncMock = vi.mocked(fs.readFileSync)
    appendFileMock = vi.mocked(fsp.appendFile)
    mkdirMock = vi.mocked(fsp.mkdir)
    appendFileMock.mockResolvedValue(null)
    mkdirMock.mockResolvedValue(null)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it("surfaces HostKeyVerificationError instead of RangeError for a malformed presented key on mismatch", async () => {
    // known_hosts has a normal entry; the remote presents a buffer that is
    // shorter than the SSH wire-format minimum. The mismatch path used to
    // call extractAlgoFromKey on the corrupt buffer and throw a RangeError.
    readFileSyncMock.mockReturnValue(`example.com ssh-ed25519 ${ed25519Key.toString("base64")}\n`)

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })
    const corruptKey = Buffer.from([0x00, 0x00])

    expect(() => hostVerifier!(corruptKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
  })

  it("surfaces HostKeyVerificationError when the @revoked entry on disk is malformed", async () => {
    // Build a wire-format key whose advertised algoLength exceeds the
    // buffer length, so extractAlgoFromKey would throw a RangeError if
    // called directly.
    const corruptWire = Buffer.alloc(8)
    corruptWire.writeUInt32BE(0xff_ff_ff_ff, 0)
    const base64Corrupt = corruptWire.toString("base64")
    // The remote presents the same bytes so findRevokedEntry matches.
    readFileSyncMock.mockReturnValue(`@revoked example.com ssh-ed25519 ${base64Corrupt}\n`)

    const { hostVerifier } = await buildHostVerifier("yes", { host: "example.com", port: 22 })

    expect(() => hostVerifier!(corruptWire)).toThrow(/HOST KEY VERIFICATION FAILED/v)
    expect(() => hostVerifier!(corruptWire)).toThrow(/<unknown>/v)
  })

  it("rejects a malformed presented key under a pinned trust anchor without leaking RangeError", async () => {
    readFileSyncMock.mockReturnValue("")
    const corruptKey = Buffer.from([0x00, 0x00])

    const { hostVerifier } = await buildHostVerifier(
      "yes",
      { host: "newhost.com", port: 22 },
      { expectedHostPublicKey: `ssh-ed25519 ${ed25519Key.toString("base64")}` }
    )

    expect(() => hostVerifier!(corruptKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
  })
})

// ---------------------------------------------------------------------------
// R-0000205: validateExpectedHostPublicKey rejects bad algorithm/base64
// ---------------------------------------------------------------------------

describe("validateExpectedHostPublicKey (R-0000205)", () => {
  it("accepts a well-formed ssh-ed25519 pinned public key", () => {
    const ed25519Key = makeKeyBuffer("ssh-ed25519", Buffer.from("real-key-material"))
    expect(
      validateExpectedHostPublicKey(`ssh-ed25519 ${ed25519Key.toString("base64")} comment`)
    ).toBeNull()
  })

  it("accepts ecdsa-sha2-nistp256 pinned keys", () => {
    const ecdsaKey = makeKeyBuffer("ecdsa-sha2-nistp256", Buffer.from("ecdsa-material"))
    expect(
      validateExpectedHostPublicKey(`ecdsa-sha2-nistp256 ${ecdsaKey.toString("base64")}`)
    ).toBeNull()
  })

  it("rejects an algorithm typo like 'ed25519' instead of 'ssh-ed25519'", () => {
    const ed25519Key = makeKeyBuffer("ssh-ed25519")
    const message = validateExpectedHostPublicKey(`ed25519 ${ed25519Key.toString("base64")}`)
    expect(message).not.toBeNull()
    expect(message).toMatch(/unsupported algorithm/v)
    expect(message).toMatch(/ssh-ed25519/v)
  })

  it("rejects unknown algorithms", () => {
    expect(validateExpectedHostPublicKey("ssh-dss AAAA")).toMatch(/unsupported algorithm/v)
  })

  it("rejects a key field that is not strict base64", () => {
    expect(validateExpectedHostPublicKey("ssh-ed25519 not_base64$$$")).toMatch(/invalid base64/v)
  })

  it("rejects keys missing the algorithm/base64 separator", () => {
    expect(validateExpectedHostPublicKey("ssh-ed25519")).toMatch(/<algorithm> <base64>/v)
  })
})

// ---------------------------------------------------------------------------
// R-0000151: known_hosts read/append serialization
// ---------------------------------------------------------------------------

describe("appendHostKey serialization (R-0000151)", () => {
  let appendFileMock: ReturnType<typeof vi.fn<(...arguments_: unknown[]) => null | Promise<null>>>
  let mkdirMock: ReturnType<typeof vi.fn<(...arguments_: unknown[]) => null | Promise<null>>>

  beforeEach(async () => {
    const fsp = await import("node:fs/promises")
    appendFileMock = vi.mocked(fsp.appendFile) as unknown as typeof appendFileMock
    mkdirMock = vi.mocked(fsp.mkdir) as unknown as typeof mkdirMock
    appendFileMock.mockReset()
    mkdirMock.mockReset()
    mkdirMock.mockResolvedValue(null)
    // Drain any leftover lock state from previous tests so each case starts
    // from a known baseline.
    await waitForKnownHostsWrites()
  })

  afterEach(async () => {
    vi.clearAllMocks()
    await waitForKnownHostsWrites()
  })

  it("serializes parallel appendHostKey calls so writes never interleave", async () => {
    // Capture the call order: each appendFile call begins, asserts no other
    // call is in flight, waits a tick, then completes.
    let inFlight = 0
    let maxInFlight = 0
    const serializedAppend = async (): Promise<null> => {
      inFlight++
      maxInFlight = Math.max(maxInFlight, inFlight)
      // Wait for a microtask so a parallel call has the chance to interleave
      // if the lock were missing.
      await Promise.resolve()
      await Promise.resolve()
      inFlight--
      return null
    }
    appendFileMock.mockImplementation(serializedAppend)

    const key = makeKeyBuffer("ssh-ed25519", Buffer.from("test-key-1"))

    await Promise.all([
      appendHostKey("first.example.com", 22, key),
      appendHostKey("second.example.com", 22, key),
      appendHostKey("third.example.com", 22, key),
    ])

    expect(appendFileMock).toHaveBeenCalledTimes(3)
    // The lock guarantees at most one appendFile is in flight at any time.
    expect(maxInFlight).toBe(1)
  })

  it("waitForKnownHostsWrites resolves once the queued append has completed", async () => {
    let resolveAppend: (() => void) | undefined
    const deferredAppend = async (): Promise<null> => {
      await new Promise<void>((res) => {
        resolveAppend = () => {
          res()
        }
      })
      return null
    }
    appendFileMock.mockImplementationOnce(deferredAppend)

    const key = makeKeyBuffer("ssh-ed25519", Buffer.from("test-key-2"))
    const appendPromise = appendHostKey("delayed.example.com", 22, key)

    let drained = false
    const drainPromise = waitForKnownHostsWrites().then(() => {
      drained = true
    })

    // Allow several microtasks for `appendHostKey` to start the queued
    // `mkdir`/`appendFile` calls so the mock implementation has been entered.
    // R-0000838/R-0000845: appendHostKey now performs additional async
    // steps inside the lock (stat + readFile for duplicate detection)
    // before calling appendFile, so more microtask ticks are required for
    // the mock implementation to be entered.
    for (let index = 0; index < 15; index++) {
      // eslint-disable-next-line no-await-in-loop
      await Promise.resolve()
    }
    expect(drained).toBe(false)

    expect(resolveAppend).toBeDefined()
    resolveAppend!()

    await appendPromise
    await drainPromise
    expect(drained).toBe(true)
  })

  it("a rejected append does not poison subsequent appends", async () => {
    appendFileMock.mockRejectedValueOnce(new Error("disk full"))
    appendFileMock.mockResolvedValueOnce(null)

    const key = makeKeyBuffer("ssh-ed25519", Buffer.from("test-key-3"))

    await expect(appendHostKey("fail.example.com", 22, key)).rejects.toThrow("disk full")
    // Subsequent appends still proceed.
    await expect(appendHostKey("ok.example.com", 22, key)).resolves.toBeUndefined()
    expect(appendFileMock).toHaveBeenCalledTimes(2)
  })
})

// ---------------------------------------------------------------------------
// R-0000194: known_hosts read path is serialized through the same lock as
// the append path, so a verifier built right after a queued append sees the
// freshly persisted line.
// ---------------------------------------------------------------------------

describe("buildHostVerifier read serialization (R-0000194)", () => {
  let appendFileMock: ReturnType<typeof vi.fn<(...arguments_: unknown[]) => null | Promise<null>>>
  let mkdirMock: ReturnType<typeof vi.fn<(...arguments_: unknown[]) => null | Promise<null>>>
  let readFileSyncMock: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    clearHostKeyCache()
    const fs = await import("node:fs")
    const fsp = await import("node:fs/promises")
    appendFileMock = vi.mocked(fsp.appendFile) as unknown as typeof appendFileMock
    mkdirMock = vi.mocked(fsp.mkdir) as unknown as typeof mkdirMock
    readFileSyncMock = vi.mocked(fs.readFileSync)
    appendFileMock.mockReset()
    mkdirMock.mockReset()
    readFileSyncMock.mockReset()
    mkdirMock.mockResolvedValue(null)
    appendFileMock.mockResolvedValue(null)
    readFileSyncMock.mockReturnValue("")
    await waitForKnownHostsWrites()
  })

  afterEach(async () => {
    vi.clearAllMocks()
    await waitForKnownHostsWrites()
  })

  it("does not invoke readFileSync until a concurrent appendHostKey has finished", async () => {
    const key = makeKeyBuffer("ssh-ed25519", Buffer.from("serialized-read-key"))
    let resolveAppend: (() => void) | undefined
    let appendStarted = false
    let appendEnded = false
    appendFileMock.mockImplementationOnce(async () => {
      appendStarted = true
      await new Promise<void>((resolve) => {
        resolveAppend = (): void => {
          appendEnded = true
          resolve()
        }
      })
      return null
    })

    // Schedule the append first so it acquires the lock.
    const appendPromise = appendHostKey("queued.example.com", 22, key)
    // Then schedule the verifier — its read must wait until the append
    // releases the lock before invoking readFileSync.
    const verifierPromise = buildHostVerifier("accept-new", {
      host: "queued.example.com",
      port: 22,
    })

    // Allow microtasks to start the append's mock implementation.
    // R-0000838/R-0000845: appendHostKey now performs additional async
    // steps inside the lock (stat + readFile for duplicate detection)
    // before calling appendFile, so more microtask ticks are required for
    // the mock implementation to be entered.
    for (let index = 0; index < 15; index++) {
      // eslint-disable-next-line no-await-in-loop
      await Promise.resolve()
    }

    // The append is in flight and the lock is held; the verifier's read
    // must not have been invoked yet. After R-0000838 the append itself
    // reads the file once to detect duplicates before writing, so the read
    // counter starts at 1 instead of 0; the assertion below verifies the
    // verifier has not added a second read while the lock is still held.
    expect(appendStarted).toBe(true)
    expect(appendEnded).toBe(false)
    expect(readFileSyncMock).toHaveBeenCalledOnce()

    // Release the append; the verifier read should now proceed.
    resolveAppend?.()
    await appendPromise
    await verifierPromise

    expect(appendEnded).toBe(true)
    // One read inside the append (duplicate detection) plus one read by
    // the verifier after the lock has been released.
    expect(readFileSyncMock).toHaveBeenCalledTimes(2)
  })
})
