/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { isSshdPortMetaEntry } from "../../../src/meta.js"
import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const ssh = createBaseMockSsh(responses, {
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
      // R-0000283: default the post-restart live verify to "listener present"
      // so existing fixtures keep passing. Tests that exercise the missing
      // listener path stub `ss` explicitly with a non-zero exit.
      {
        command: /^ss -H -ltnp 'sport = :\d+'$/v,
        result: { code: 0, stdout: 'LISTEN 0 128 0.0.0.0:2222 users:(("sshd",pid=1,fd=3))\n' },
      },
      ...(options?.responseStubs ?? []),
    ],
  })
  vi.spyOn(ssh, "getConnectionInfo").mockReturnValue({
    ...ssh.getConnectionInfo(),
    configuredPorts: [22, 2222],
  })
  return ssh
}

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

// R-0000283: post-restart live verify probes `ss -H -ltnp 'sport = :<port>'`.
// Tests that bulk-mock exec to `code: 0, stdout: ""` need a stand-in stdout for
// these probes so `liveSshdPortMatches` returns true and the verify loop exits
// instead of polling until timeout.
const SS_PROBE_PATTERN = /^ss -H -ltnp 'sport = :\d+'$/v
const SS_PROBE_LISTENING_STDOUT = 'LISTEN 0 128 0.0.0.0:0 users:(("sshd",pid=1,fd=3))\n'

type ExecSpy = {
  mockImplementation: (impl: ReturnType<typeof createMockSsh>["exec"]) => unknown
} & ReturnType<typeof createMockSsh>["exec"]

function mockExecResolvedValue(
  execSpy: ExecSpy,
  result: { code: number; stderr?: string; stdout?: string }
) {
  execSpy.mockImplementation(async (command) => {
    await Promise.resolve()
    if (SS_PROBE_PATTERN.test(command) && result.code === 0) {
      return { code: 0, stderr: "", stdout: SS_PROBE_LISTENING_STDOUT }
    }
    return { code: result.code, stderr: result.stderr ?? "", stdout: result.stdout ?? "" }
  })
}

function buildExecWithSsOverride(
  originalExec: ReturnType<typeof createMockSsh>["exec"],
  ssResponse: { code: number; stderr?: string; stdout?: string }
): ReturnType<typeof createMockSsh>["exec"] {
  return async (command, options) => {
    if (!SS_PROBE_PATTERN.test(command)) return originalExec(command, options)
    await Promise.resolve()
    return {
      code: ssResponse.code,
      stderr: ssResponse.stderr ?? "",
      stdout: ssResponse.stdout ?? "",
    }
  }
}

function buildSequencedSsProbeExec(
  originalExec: ReturnType<typeof createMockSsh>["exec"],
  responses: ReadonlyArray<{ code: number; stderr?: string; stdout?: string }>
): ReturnType<typeof createMockSsh>["exec"] {
  let callIndex = 0
  return async (command, options) => {
    if (!SS_PROBE_PATTERN.test(command)) {
      return originalExec(command, options)
    }
    const response = responses[Math.min(callIndex, responses.length - 1)] ?? { code: 0 }
    callIndex += 1
    await Promise.resolve()
    return { code: response.code, stderr: response.stderr ?? "", stdout: response.stdout ?? "" }
  }
}

function mockSshdDryRunExecSuccess(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    if (SS_PROBE_PATTERN.test(command)) {
      return { code: 0, stderr: "", stdout: SS_PROBE_LISTENING_STDOUT }
    }
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
  it("fails before validation or restart when target port is not statically configured", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      ...mockSsh.getConnectionInfo(),
      configuredPorts: [22],
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("static ssh.ports")
    expect(writtenFiles).toHaveLength(0)
    expect(execSpy).not.toHaveBeenCalled()
  })

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

  it("rolls back and returns failed when the initial port write reports failure after remote replacement", async () => {
    const originalConfig = "Port 22"
    const newConfig = "Port 2222"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig)
      .mockResolvedValueOnce(originalConfig)
      .mockResolvedValueOnce(newConfig)
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockRejectedValueOnce(new Error("SFTP write failed"))
      .mockResolvedValueOnce(undefined)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
    expect(result.error?.message).toContain("SFTP write failed")
    expect(writeFileSpy.mock.calls).toStrictEqual([
      [SSHD_CONFIG, newConfig, { mode: "0644" }],
      [SSHD_CONFIG, originalConfig, { mode: "0644" }],
    ])
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("sshd -t")
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl restart sshd")
    expect(addPortSpy).not.toHaveBeenCalled()
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
    mockExecResolvedValue(execSpy, { code: 0 })

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

    mockExecResolvedValue(execSpy, { code: 0 })

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

    mockExecResolvedValue(execSpy, { code: 0 })

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
    // R-0000283: live-verify probes `ss -H -ltnp` twice — once before the
    // restart (where the listener is not yet present) and once after (where
    // the post-restart verify confirms the listener is up). Use the sequenced
    // helper so the pre/post progression is explicit.
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    const execSpy = vi
      .spyOn(mockSsh, "exec")
      .mockImplementation(
        buildSequencedSsProbeExec(originalExec, [
          { code: 1 },
          { code: 0, stdout: SS_PROBE_LISTENING_STDOUT },
        ])
      )
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

    mockExecResolvedValue(execSpy, { code: 0 })

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
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    expect(result.error?.message).toContain("systemctl restart sshd failed")
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
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    expect(result.error?.message).toContain("systemctl restart sshd failed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl disable --now ssh.socket")
    expect(execCommands).toContain("systemctl enable --now ssh.socket")
    expect(execCommands.filter((command) => command === "systemctl restart sshd")).toHaveLength(2)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
    expect(writtenFiles.at(-1)?.content).toBe("Port 22")
    expect(writtenFiles.at(-1)?.path).toBe(SSHD_CONFIG)
  })

  it("regression — removes added port even when rollback writeFile fails after restart error", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")
    // The initial writeFile (new config with new port) must succeed so the
    // restart path is reached; only the rollback writeFile (restoring the
    // original config after the failed restart) should fail in this scenario.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("SFTP rollback failed"))

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("systemctl restart sshd failed"))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd restart failed")
    expect(result.error?.message).toContain("systemctl restart sshd failed")
    // Even though the rollback writeFile threw, removePort must still have been called
    // so the runner reverts to the previous port instead of staying on the new one.
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
  })

  it("reconnects and live-verifies the target port when restart aborts the SSH session", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const addPortSpy = vi.spyOn(mockSsh, "addPort")
    const reconnectSpy = vi.spyOn(mockSsh, "reconnect")
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("SSH connection closed unexpectedly"))
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: SS_PROBE_LISTENING_STDOUT })

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result).toMatchObject({
      meta: [{ kind: "sshd.port", port: 2222 }],
      status: "changed",
    })
    expect(addPortSpy).toHaveBeenCalledWith(2222)
    expect(reconnectSpy).toHaveBeenCalledOnce()
    expect(removePortSpy).not.toHaveBeenCalled()
  })

  it("returns failed and removes the target port when reconnect after restart disconnect fails", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")
    const reconnectError = new Error("reconnect refused")
    vi.spyOn(mockSsh, "reconnect").mockRejectedValue(reconnectError)
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" }) // ssh.socket missing
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service exists
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd.service enabled
      .mockRejectedValueOnce(new Error("ECONNRESET"))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("before the target port could be verified")
    expect(result.error?.message).toContain("reconnect refused")
    expect(removePortSpy).toHaveBeenCalledWith(2222)
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

  // R-0000283: a successful restart that leaves no listener on the target port
  // must not be reported as `changed`. The runner would reconnect into the
  // void; instead surface a structured failure and roll back.
  it("R-0000283: returns failed when restart succeeds but no listener appears on the target port", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(buildExecWithSsOverride(originalExec, { code: 0 }))
    const removePortSpy = vi.spyOn(mockSsh, "removePort")

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("no listener on port 2222")
    expect(result.error?.message).toContain("rolled back")
    // Last write must restore the original config.
    expect(writtenFiles.at(-1)?.content).toBe(originalConfig)
    expect(removePortSpy).toHaveBeenCalledWith(2222)
  }, 10_000)

  it("R-0000283: combines verify failure with rollback writeFile failure in the error message", async () => {
    const originalConfig = "Port 22"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // First write (new config) succeeds, rollback write fails.
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("SFTP rollback failed"))
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(buildExecWithSsOverride(originalExec, { code: 0 }))

    const mod = sshd.port(2222)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("no listener on port 2222")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
    expect(writeFileSpy).toHaveBeenCalled()
  }, 10_000)
})

// ─── sshd.port — dry-run ─────────────────────────────────────────────────────
