/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { isSshdPortMetaEntry } from "../../../src/meta.js"
import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^\/tmp\/paratix-sshd-dry-run-/v },
      ...(options?.allowWrites ?? []),
    ],
    responseStubs: [
      { command: "mkdir -p '/run/sshd'", result: { code: 0 } },
      { command: "sshd -t", result: { code: 0 } },
      { command: SYSTEMCTL_CAT_SSHD, result: { code: 0 } },
      { command: SYSTEMCTL_CAT_SSH, result: { code: 1 } },
      { command: "systemctl is-enabled --quiet sshd.service", result: { code: 0 } },
      { command: "systemctl is-enabled --quiet ssh.service", result: { code: 0 } },
      { command: "systemctl reload sshd", result: { code: 0 } },
      { command: "systemctl reload ssh", result: { code: 0 } },
      { command: "systemctl cat ssh.socket >/dev/null 2>&1", result: { code: 1 } },
      { command: "systemctl is-enabled ssh.socket >/dev/null 2>&1", result: { code: 1 } },
      { command: "systemctl is-active ssh.socket >/dev/null 2>&1", result: { code: 1 } },
      { command: "systemctl disable --now ssh.socket", result: { code: 0 } },
      { command: "systemctl enable --now ssh.socket", result: { code: 0 } },
      { command: "systemctl restart sshd", result: { code: 0 } },
      { command: /^rm -f '\/tmp\/paratix-sshd-dry-run-.+\.conf'$/v, result: { code: 0 } },
      ...(options?.responseStubs ?? []),
    ],
  })

const emptyEnv = {}
const SSHD_CONFIG = "/etc/ssh/sshd_config"
const CAT_SSHD = `cat '${SSHD_CONFIG}'`
const SYSTEMCTL_CAT_SSH = "systemctl cat ssh.service >/dev/null 2>&1"
const SYSTEMCTL_CAT_SSHD = "systemctl cat sshd.service >/dev/null 2>&1"

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
  return vi
    .spyOn(mockSsh, "exec")
    .mockImplementationOnce(async (command) => {
      mockSsh.calls.push(command)
      await Promise.resolve()
      return { code: 0, stderr: "", stdout: "" }
    })
    .mockImplementationOnce(async (command) => {
      mockSsh.calls.push(command)
      await Promise.resolve()
      return { code: 1, stderr: "Bad configuration option", stdout: "" }
    })
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

describe("sshd.port — apply: validation and rollback", () => {
  it("rolls back config and does NOT restart sshd when sshd -t fails", async () => {
    // readFile internally calls output() which trims whitespace — use a value without trailing newline
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    // mkdir -p /run/sshd succeeds, then sshd -t fails before restart
    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "sshd: invalid port", stdout: "" })

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config validation failed")

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
    expect(execCommands).toContain("mkdir -p '/run/sshd'")
    expect(execCommands).toContain("systemctl cat ssh.socket >/dev/null 2>&1")
    expect(execCommands).toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl restart sshd")
    expect(addPortSpy).toHaveBeenCalledWith(2222)
  })

  it("disables ssh.socket before restarting sshd on socket-activated hosts", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy.mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const socketDisableIndex = execSpy.mock.calls.findIndex(
      (args) => args[0] === "systemctl disable --now ssh.socket"
    )
    const restartIndex = execSpy.mock.calls.findIndex(
      (args) => args[0] === "systemctl restart sshd"
    )

    expect(socketDisableIndex).toBeGreaterThanOrEqual(0)
    expect(restartIndex).toBeGreaterThan(socketDisableIndex)
  })

  it("enables the SSH service for boot when disabling an enabled ssh.socket", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // ssh.socket exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // ssh.socket enabled
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // ssh.socket active
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // disable --now ssh.socket
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // sshd.service disabled
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // enable sshd.service
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // restart sshd

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl enable sshd.service")
  })

  it("keeps the previous restart path when ssh.socket does not exist", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // restart sshd

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl cat ssh.socket >/dev/null 2>&1")
    expect(execCommands).not.toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl restart sshd")
  })

  it("creates /run/sshd before sshd -t during first port bootstrap validation", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy.mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    await mod.apply(mockSsh, emptyEnv)

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands.slice(0, 2)).toStrictEqual(["mkdir -p '/run/sshd'", "sshd -t"])
  })

  it("returns ok and does not write when the desired port is already configured", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
      "ss -H -ltnp 'sport = :2222'": {
        code: 0,
        stdout: 'LISTEN 0 128 0.0.0.0:2222 users:(("sshd",pid=123,fd=3))\n',
      },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    // No write, no restart, no addPort — early return when config and live listener are correct
    expect(writtenFiles).toHaveLength(0)
    expect(result.status).toBe("ok")
    expect(result).not.toHaveProperty("meta")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(addPortSpy).not.toHaveBeenCalled()
  })

  it("restarts and emits reconnect meta when config matches but target port is not live", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
      "ss -H -ltnp 'sport = :2222'": { code: 1, stdout: "" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(writtenFiles).toHaveLength(0)
    expect(result.status).toBe("changed")
    expect(result.meta?.find(isSshdPortMetaEntry)?.port).toBe(2222)
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl restart sshd")
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
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    // sshd -t succeeds, then systemctl restart sshd fails
    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("systemctl restart sshd failed")) // systemctl restart

    const mod = sshd.port(2222)
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("systemctl restart sshd failed")

    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
    expect(writtenFiles.at(-1)?.content).toBe("Port 22")
    expect(writtenFiles.at(-1)?.path).toBe(SSHD_CONFIG)
  })

  it("restores config and ssh.socket when restart fails after disabling socket activation", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // ssh.socket exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // ssh.socket enabled
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // ssh.socket active
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // disable --now ssh.socket
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("systemctl restart sshd failed")) // systemctl restart
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // enable --now ssh.socket

    const mod = sshd.port(2222)
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("systemctl restart sshd failed")

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl enable --now ssh.socket")
    expect(execCommands.filter((command) => command === "systemctl restart sshd")).toHaveLength(2)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
    expect(writtenFiles.at(-1)?.content).toBe("Port 22")
    expect(writtenFiles.at(-1)?.path).toBe(SSHD_CONFIG)
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
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("SSH connection closed unexpectedly"))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result).toMatchObject({
      meta: [{ kind: "sshd.port", port: 2222 }],
      status: "changed",
    })
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).not.toHaveBeenCalled()
  })

  it("returns reconnect meta when restart resets the SSH session", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("ECONNRESET"))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result).toMatchObject({
      meta: [{ kind: "sshd.port", port: 2222 }],
      status: "changed",
    })
  })

  it("falls back to ssh.service for restart on Ubuntu-style systems", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(execSpy.mock.calls.map((args) => args[0])).toContain("systemctl restart ssh")
  })
})

// ─── sshd.port — dry-run ─────────────────────────────────────────────────────
