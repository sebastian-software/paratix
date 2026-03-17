import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  appendHostKey,
  buildHostVerifier,
  extractAlgoFromKey,
  lookupHostKey,
  parseKnownHosts,
} from "../src/knownHosts.js"

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("node:fs", () => ({
  readFileSync: vi.fn().mockReturnValue(""),
}))

vi.mock("node:fs/promises", () => ({
  appendFile: vi.fn().mockResolvedValue(null),
  mkdir: vi.fn().mockResolvedValue(null),
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

  it("skips hashed hostnames starting with |1|", () => {
    const key = makeKeyBuffer("ssh-ed25519")
    const base64Key = key.toString("base64")
    const content = `|1|abc123|def456xyz ssh-ed25519 ${base64Key}`

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(0)
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
      `|1|abc123|def456 ssh-ed25519 AAAA`,
      `github.com ssh-ed25519 ${base64Key}`,
      "",
    ].join("\n")

    const entries = parseKnownHosts(content)

    expect(entries).toHaveLength(1)
    expect(entries[0]?.host).toBe("github.com")
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

  it("finds key for [host]:port format on non-standard port", () => {
    const result = lookupHostKey(entries, "example.com", 2222)
    expect(result).toStrictEqual(rsaKey)
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

  it("writes the file with mode 0o644", async () => {
    const keyBuf = makeKeyBuffer("ssh-ed25519")
    await appendHostKey("example.com", 22, keyBuf)

    const thirdArg = (appendFileMock.mock.calls[0] as [string, string, { mode: number }])[2]
    expect(thirdArg.mode).toBe(0o644)
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

  beforeEach(async () => {
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

  it("returns an empty object (no hostVerifier) for mode 'no'", () => {
    const result = buildHostVerifier("no", "example.com", 22)
    expect(result).toStrictEqual({})
    expect(result.hostVerifier).toBeUndefined()
  })

  it("mode 'accept-new' with unknown host: hostVerifier returns true and calls appendHostKey", async () => {
    // No known hosts
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = buildHostVerifier("accept-new", "newhost.com", 22)
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)

    // appendHostKey is fire-and-forget, give microtasks a chance to run
    await Promise.resolve()

    expect(appendFileMock).toHaveBeenCalled()
  })

  it("mode 'accept-new' with known host and correct key: hostVerifier returns true", () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = buildHostVerifier("accept-new", "example.com", 22)
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)
  })

  it("mode 'accept-new' with known host and wrong key: hostVerifier throws Error", () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = buildHostVerifier("accept-new", "example.com", 22)
    expect(hostVerifier).toBeDefined()

    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("different-key-material"))
    expect(() => hostVerifier!(differentKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
    expect(() => hostVerifier!(differentKey)).toThrow("example.com")
  })

  it("mode 'yes' with known host and correct key: hostVerifier returns true", () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = buildHostVerifier("yes", "example.com", 22)
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)
  })

  it("mode 'yes' with unknown host: hostVerifier throws Error", () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = buildHostVerifier("yes", "unknownhost.com", 22)
    expect(hostVerifier).toBeDefined()

    expect(() => hostVerifier!(ed25519Key)).toThrow(/not found in known_hosts/v)
    expect(() => hostVerifier!(ed25519Key)).toThrow("unknownhost.com")
  })

  it("mode 'yes' with known host and wrong key: hostVerifier throws Error", () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = buildHostVerifier("yes", "example.com", 22)
    expect(hostVerifier).toBeDefined()

    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("wrong-key-material"))
    expect(() => hostVerifier!(differentKey)).toThrow(/HOST KEY VERIFICATION FAILED/v)
  })

  it("mode 'accept-new' with unknown host on non-standard port: appends [host]:port entry", async () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = buildHostVerifier("accept-new", "example.com", 2222)
    expect(hostVerifier).toBeDefined()

    const result = hostVerifier!(ed25519Key)
    expect(result).toBe(true)

    await Promise.resolve()

    expect(appendFileMock).toHaveBeenCalled()
    const [, content] = appendFileMock.mock.calls[0] as [string, string, unknown]
    expect(content).toContain("[example.com]:2222")
  })

  it("mode 'accept-new' with known host on non-standard port and correct key: returns true", () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 2222, ed25519Key))

    const { hostVerifier } = buildHostVerifier("accept-new", "example.com", 2222)
    expect(hostVerifier).toBeDefined()

    expect(hostVerifier!(ed25519Key)).toBe(true)
  })

  it("error message for key mismatch mentions man-in-the-middle attack", () => {
    readFileSyncMock.mockReturnValue(makeKnownHostsContent("example.com", 22, ed25519Key))

    const { hostVerifier } = buildHostVerifier("accept-new", "example.com", 22)
    const differentKey = makeKeyBuffer("ssh-ed25519", Buffer.from("attacker-key"))

    expect(() => hostVerifier!(differentKey)).toThrow(/man-in-the-middle/v)
  })

  it("error message for 'yes' with missing host suggests 'accept-new'", () => {
    readFileSyncMock.mockReturnValue("")

    const { hostVerifier } = buildHostVerifier("yes", "newhost.com", 22)

    expect(() => hostVerifier!(ed25519Key)).toThrow(/accept-new/v)
  })
})
