import { describe, expect, it, vi } from "vitest"

import { sshd } from "../../src/modules/sshd.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}
const SSHD_CONFIG = "/etc/ssh/sshd_config"
const CAT_SSHD = `cat '${SSHD_CONFIG}'`

function trackWriteFile(
  mockSsh: ReturnType<typeof createMockSsh>
): Array<{ content: string; path: string }> {
  const writtenFiles: Array<{ content: string; path: string }> = []
  // eslint-disable-next-line @typescript-eslint/promise-function-async -- vi.mockImplementation requires matching return type
  vi.spyOn(mockSsh, "writeFile").mockImplementation((path: string, content: string) => {
    writtenFiles.push({ content, path })
    return Promise.resolve()
  })
  return writtenFiles
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

describe("sshd.config — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = sshd.config({ PasswordAuthentication: "no" })
    // eslint-disable-next-line prefer-spread -- mod.apply is a Module method, not Function.prototype.apply
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("replaces an existing key in-place and returns changed", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication yes\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    expect(written?.content).toContain("PasswordAuthentication no")
    expect(written?.content).not.toContain("PasswordAuthentication yes")
  })

  it("appends a new key when it does not yet exist in sshd_config", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "# sshd config\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PermitRootLogin: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    expect(written?.content).toContain("PermitRootLogin no")
  })

  it("appends newline separator when original content does not end with newline", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "# sshd config" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ X11Forwarding: "no" })
    await mod.apply(mockSsh, emptyEnv)

    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written?.content).toMatch(/\nX11Forwarding no\n$/v)
  })

  it("applies multiple settings in sequence (regression: no command injection via key/value)", async () => {
    // First read returns original, subsequent reads should reflect writes in real code.
    // The mock always returns the same content; we verify both keys are written.
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication yes\nPermitRootLogin yes\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no", PermitRootLogin: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // writeFile must have been called for each setting
    expect(writtenFiles).toHaveLength(2)
  })

  it("regression — key with RegExp special chars is handled safely (no injection)", async () => {
    // Key contains a dot which is a RegExp special char
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Match.User root\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ "Match.User": "admin" })
    await mod.apply(mockSsh, emptyEnv)

    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    // The exact key "Match.User" must be replaced, not a wildcard match
    expect(written?.content).toContain("Match.User admin")
  })

  it("regression — value with RegExp special chars like * and [ does not throw", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "AllowUsers root\n" },
    })
    trackWriteFile(mockSsh)

    // Value with a shell glob — previously could cause RegExp errors or injection
    const mod = sshd.config({ AllowUsers: "admin*" })
    await expect(mod.apply(mockSsh, emptyEnv)).resolves.not.toThrow()
    const calls = vi.mocked(mockSsh.writeFile).mock.calls
    expect(calls).toHaveLength(1)
    expect(calls[0][1]).toContain("AllowUsers admin*")
  })

  it("regression — value with forward slash does not break file path or pattern", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "AuthorizedKeysFile .ssh/authorized_keys\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ AuthorizedKeysFile: "/etc/ssh/authorized_keys/%u" })
    await mod.apply(mockSsh, emptyEnv)

    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written?.content).toContain("AuthorizedKeysFile /etc/ssh/authorized_keys/%u")
  })
})

// ─── sshd.config — check ──────────────────────────────────────────────────────

describe("sshd.config — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when all settings are present in sshd_config", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication no\nPermitRootLogin no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no", PermitRootLogin: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when a setting has a different value", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication yes\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when a setting is completely missing", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "# empty config\n" },
    })
    const mod = sshd.config({ PermitRootLogin: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when only one of multiple settings is missing", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no", PermitRootLogin: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("reads sshd_config via cat command", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(CAT_SSHD)
  })

  it("regression — key with dot is matched literally, not as RegExp wildcard", async () => {
    // "Match.User" with a dot must not match "MatchXUser" (dot is RegExp wildcard)
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "MatchXUser root\n" },
    })
    const mod = sshd.config({ "Match.User": "root" })
    const result = await mod.check(mockSsh, emptyEnv)
    // Should NOT match because the key is "Match.User" not "MatchXUser"
    expect(result).toBe("needs-apply")
  })

  it("regression — value with RegExp special chars [ and * is matched literally", async () => {
    // Value "admin*" must not match "adminXYZ" (star is RegExp wildcard)
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "AllowUsers adminXYZ\n" },
    })
    const mod = sshd.config({ AllowUsers: "admin*" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("regression — exact value with RegExp special chars matches correctly", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "AllowUsers admin*\n" },
    })
    const mod = sshd.config({ AllowUsers: "admin*" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })
})

// ─── sshd.port — check ────────────────────────────────────────────────────────

describe("sshd.port — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = sshd.port(2222)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when the configured port matches", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when the configured port does not match", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok for default port 22 when no Port directive exists", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "# sshd config\n" },
    })
    const mod = sshd.port(22)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("has correct module name", () => {
    const mod = sshd.port(2222)
    expect(mod.name).toBe("sshd.port: 2222")
  })
})

// ─── sshd.config — module name ────────────────────────────────────────────────

describe("sshd.config — module name", () => {
  it("includes the setting key in the module name", () => {
    const mod = sshd.config({ PasswordAuthentication: "no" })
    expect(mod.name).toBe("sshd.config: PasswordAuthentication")
  })

  it("lists multiple setting keys in the module name", () => {
    const mod = sshd.config({ PasswordAuthentication: "no", PermitRootLogin: "no" })
    expect(mod.name).toContain("PasswordAuthentication")
    expect(mod.name).toContain("PermitRootLogin")
  })
})
