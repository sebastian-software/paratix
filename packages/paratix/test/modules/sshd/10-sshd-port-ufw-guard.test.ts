import { describe, expect, it, vi } from "vitest"

import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const SSHD_CONFIG = "/etc/ssh/sshd_config"
const CAT_SSHD = `cat '${SSHD_CONFIG}'`
const SYSTEMCTL_CAT_SSH = "systemctl cat ssh.service >/dev/null 2>&1"
const SYSTEMCTL_CAT_SSHD = "systemctl cat sshd.service >/dev/null 2>&1"
const UFW_STATUS_ACTIVE_PORT_22_ONLY = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_ALLOWED = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "2222                       ALLOW       Anywhere",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_IPV4_ONLY = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "22 (v6)                    ALLOW       Anywhere (v6)",
  "2222                       ALLOW       Anywhere",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_BOTH_FAMILIES = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "22 (v6)                    ALLOW       Anywhere (v6)",
  "2222                       ALLOW       Anywhere",
  "2222 (v6)                  ALLOW       Anywhere (v6)",
].join("\n")

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
      { command: "systemctl cat ssh.socket >/dev/null 2>&1", result: { code: 1 } },
      { command: "systemctl restart sshd", result: { code: 0 } },
      { command: /^rm -f '\/tmp\/paratix-sshd-dry-run-.+\.conf'$/v, result: { code: 0 } },
      ...(options?.responseStubs ?? []),
    ],
  })

const emptyEnv = {}

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

describe("sshd.port — apply: ufw lockout guard", () => {
  it("fails-closed when ufw is active and the target port has no allow rule", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_22_ONLY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")
    const addPortSpy = vi.spyOn(ssh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw is active")
    expect(result.error?.message).toContain("2222")
    // No mutation must have happened
    expect(writtenFiles).toHaveLength(0)
    expect(addPortSpy).not.toHaveBeenCalled()
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(execCommands).not.toContain("sshd -t")
  })

  it("fails-closed when ufw is active, IPv6 rules are reported, but only IPv4 allows the target port", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_IPV4_ONLY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writtenFiles).toHaveLength(0)
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
  })

  it("proceeds when ufw is active and the target port is allowed for IPv4 only (no IPv6 rules reported)", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_ALLOWED },
    })
    trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec").mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
  })

  it("proceeds when ufw is active and the target port is allowed for both IPv4 and IPv6", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_BOTH_FAMILIES },
    })
    trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec").mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
  })

  it("proceeds when ufw is inactive (Status: inactive)", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: "Status: inactive" },
    })
    trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec").mockResolvedValue({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
  })
})

describe("sshd.port — dry-run: ufw lockout guard", () => {
  it("fails-closed during dry-run when ufw is active and the target port has no allow rule", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_22_ONLY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")

    const mod = sshd.port(2222)
    const result = await mod._applyDryRun?.(ssh, emptyEnv)

    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("ufw is active")
    expect(writtenFiles).toHaveLength(0)
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands.every((command) => !command.startsWith("sshd -t -f "))).toBe(true)
  })
})
