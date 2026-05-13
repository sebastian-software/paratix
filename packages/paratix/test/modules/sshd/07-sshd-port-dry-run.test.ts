/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

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
      ...(options?.responseStubs ?? []),
      { command: "ufw status", result: { stdout: "Status: inactive" } },
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

describe("sshd.port — dry-run", () => {
  it("fails before validation when target port is not statically configured", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
    })
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      ...mockSsh.getConnectionInfo(),
      configuredPorts: [22],
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.port(2222)
    const result = await mod._applyDryRun?.(mockSsh, emptyEnv)

    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("static ssh.ports")
    expect(writtenFiles).toHaveLength(0)
    expect(execSpy).not.toHaveBeenCalled()
  })

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
