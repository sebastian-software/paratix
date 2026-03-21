import { describe, expect, it, vi } from "vitest"

import { isSshdPortMetaEntry } from "../../src/meta.js"
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

function mockSshdDryRunExecSuccess(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    return { code: 0, stderr: "", stdout: "" }
  })
}

function mockSshdDryRunExecValidationFailure(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementationOnce(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    return { code: 1, stderr: "Bad configuration option", stdout: "" }
  })
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
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    expect(written?.content).toContain("PasswordAuthentication no")
    expect(written?.content).not.toContain("PasswordAuthentication yes")
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl reload sshd")
  })

  it("does not duplicate a directive when the desired value is already set", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication no\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    // No write needed when content is already correct
    expect(writtenFiles).toHaveLength(0)
    expect(result.status).toBe("ok")
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
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
    // All settings are applied in one write (single readFile + single guardedWriteFile)
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.content).toContain("PasswordAuthentication no")
    expect(writtenFiles[0]?.content).toContain("PermitRootLogin no")
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

  it("bug — replaces ALL occurrences of a duplicate directive, not only the first", async () => {
    // sshd_config with the same directive appearing twice (e.g. after a manual edit or
    // a partial previous run).  Both lines must be replaced, not just the first one.
    const mockSsh = createMockSsh({
      [CAT_SSHD]: {
        stdout: "PasswordAuthentication yes\nPasswordAuthentication yes\n",
      },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    await mod.apply(mockSsh, emptyEnv)

    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    // After apply the old value must be gone entirely — both duplicates replaced.
    expect(written?.content).not.toContain("PasswordAuthentication yes")
    expect(written?.content).toContain("PasswordAuthentication no")
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

// ─── sshd.config — dry-run ───────────────────────────────────────────────────

describe("sshd.config — dry-run", () => {
  it("validates the prospective config via sshd -t without reloading sshd", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication yes\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = mockSshdDryRunExecSuccess(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod._applyDryRun?.(mockSsh, emptyEnv)

    expect(result).toStrictEqual({
      _dryRunDetail: "(dry-run, sshd -t ok; reload not executed)",
      status: "changed",
    })
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.path).toMatch(/^\/tmp\/paratix-sshd-dry-run-.+\.conf$/v)
    expect(writtenFiles[0]?.content).toContain("PasswordAuthentication no")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands.some((command) => command.startsWith("sshd -t -f "))).toBe(true)
    expect(execCommands.some((command) => command.startsWith("rm -f "))).toBe(true)
    expect(execCommands).not.toContain("systemctl reload sshd")
  })

  it("returns failed when sshd -t rejects the prospective config in dry-run", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "# empty config\n" },
    })
    mockSshdDryRunExecValidationFailure(mockSsh)

    const mod = sshd.config({ PermitRootLogin: "maybe" })
    const result = await mod._applyDryRun?.(mockSsh, emptyEnv)

    expect(result?.status).toBe("failed")
    expect(result?.error).toBeInstanceOf(Error)
    expect(String(result?.error)).toContain("sshd -t failed for prospective config")
  })
})

// ─── sshd.port — check ────────────────────────────────────────────────────────

describe("sshd.port — check", () => {
  it("throws when the port is greater than 65535", () => {
    expect(() => sshd.port(65_536)).toThrow(
      "sshd.port requires an integer port between 1 and 65535, got 65536"
    )
  })

  it("throws when the port is less than 1", () => {
    expect(() => sshd.port(0)).toThrow(
      "sshd.port requires an integer port between 1 and 65535, got 0"
    )
  })

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

// ─── sshd.config — apply: validateSshdConfig rollback ────────────────────────

describe("sshd.config — apply: validation and rollback", () => {
  it("rolls back to original config and throws when sshd -t fails", async () => {
    // readFile internally calls output() which trims whitespace — use a value without trailing newline
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    // sshd -t is the only exec call during sshd.config.apply
    vi.spyOn(mockSsh, "exec").mockResolvedValueOnce({
      code: 1,
      stderr: "sshd: bad config",
      stdout: "",
    })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("sshd config validation failed")

    // After failed validation the last write must restore the original config
    const lastWrite = writtenFiles.at(-1)
    expect(lastWrite?.path).toBe(SSHD_CONFIG)
    expect(lastWrite?.content).toBe(originalConfig)
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  it("writes new config and reloads sshd without rollback when validation succeeds", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // Only one write: the new config — no rollback write
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.content).toContain("PasswordAuthentication no")
    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      "sshd -t",
      "systemctl reload sshd",
    ])
  })

  it("returns failed when sshd reload fails after successful validation", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "reload failed", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      "sshd -t",
      "systemctl reload sshd",
    ])
  })
})

// ─── sshd.port — apply ────────────────────────────────────────────────────────

describe("sshd.port — apply: validation and rollback", () => {
  it("rolls back config and does NOT restart sshd when sshd -t fails", async () => {
    // readFile internally calls output() which trims whitespace — use a value without trailing newline
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    // First exec call is sshd -t — return failure so apply throws before systemctl restart
    execSpy.mockResolvedValueOnce({ code: 1, stderr: "sshd: invalid port", stdout: "" })

    const mod = sshd.port(2222)
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("sshd config validation failed")

    // Last write must restore the original config
    const lastWrite = writtenFiles.at(-1)
    expect(lastWrite?.path).toBe(SSHD_CONFIG)
    expect(lastWrite?.content).toBe(originalConfig)

    // systemctl restart must NOT have been called
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
  })

  it("writes new port config and restarts sshd when sshd -t succeeds", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    // All exec calls succeed: sshd -t passes, systemctl restart runs
    execSpy.mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.meta?.find(isSshdPortMetaEntry)?.port).toBe(2222)
    // Only one write: the new port config — no rollback
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.content).toContain("Port 2222")

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
    expect(addPortSpy).toHaveBeenCalledWith(2222)
  })

  it("returns ok and does not write when the desired port is already configured", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    // No write, no restart, no addPort — early return when config is already correct
    expect(writtenFiles).toHaveLength(0)
    expect(result.status).toBe("ok")
    expect(result).not.toHaveProperty("meta")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(addPortSpy).not.toHaveBeenCalled()
  })

  it("regression — addPort is called before systemctl restart sshd", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    execSpy.mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const addPortOrder = addPortSpy.mock.invocationCallOrder[0]
    const restartCallIndex = execSpy.mock.calls.findIndex(
      (args) => args[0] === "systemctl restart sshd"
    )
    const restartOrder = execSpy.mock.invocationCallOrder[restartCallIndex]

    expect(addPortOrder).toBeDefined()
    expect(restartOrder).toBeDefined()
    expect(addPortOrder).toBeLessThan(restartOrder)
  })

  it("regression — removes added port again when systemctl restart sshd fails with a real error", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    // sshd -t succeeds, then systemctl restart sshd fails
    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockRejectedValueOnce(new Error("systemctl restart sshd failed")) // systemctl restart

    const mod = sshd.port(2222)
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("systemctl restart sshd failed")

    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
  })

  it("regression — keeps added port when restart aborts the SSH session", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockRejectedValueOnce(new Error("SSH connection closed unexpectedly"))

    const mod = sshd.port(2222)
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("SSH connection closed unexpectedly")

    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).not.toHaveBeenCalled()
  })
})

// ─── sshd.port — dry-run ─────────────────────────────────────────────────────

describe("sshd.port — dry-run", () => {
  it("validates the prospective port config without restart, reconnect, or meta", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = mockSshdDryRunExecSuccess(mockSsh)
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod._applyDryRun?.(mockSsh, emptyEnv)

    expect(result).toStrictEqual({
      _dryRunDetail:
        "(dry-run, sshd -t ok; restart, port switch, firewall and reconnect not verified)",
      status: "changed",
    })
    expect(result).not.toHaveProperty("meta")
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.content).toContain("Port 2222")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands.some((command) => command.startsWith("sshd -t -f "))).toBe(true)
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(addPortSpy).not.toHaveBeenCalled()
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
