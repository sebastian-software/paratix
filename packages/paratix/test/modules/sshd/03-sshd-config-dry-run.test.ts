/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"
import { spyOnFailClosedSshdDryRunExec } from "../../helpers/runnerMocks.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      // R-0000587: dry-run tempfiles carry restrictive 0600 permissions.
      { options: { mode: "0600" }, remotePath: /^\/tmp\/paratix-sshd-dry-run\./v },
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
      { command: /^rm -f '\/tmp\/paratix-sshd-dry-run\..+'$/v, result: { code: 0 } },
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
  return spyOnFailClosedSshdDryRunExec(mockSsh)
}

function mockSshdDryRunExecValidationFailure(mockSsh: ReturnType<typeof createMockSsh>) {
  return spyOnFailClosedSshdDryRunExec(mockSsh, {
    validationResult: { code: 1, stderr: "Bad configuration option", stdout: "" },
  })
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

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
    expect(writtenFiles[0]?.path).toMatch(/paratix-sshd-dry-run\..+$/v)
    expect(writtenFiles[0]?.content).toContain("PasswordAuthentication no")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands.some((command) => command.startsWith("sshd -t -f "))).toBe(true)
    expect(execCommands.some((command) => command.startsWith("rm -f "))).toBe(true)
    expect(execCommands).not.toContain("systemctl reload sshd")
  })

  it("fails closed when dry-run tries an unexpected mutating command", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication yes\n" },
    })
    const execSpy = mockSshdDryRunExecSuccess(mockSsh)

    await expect(mockSsh.exec("systemctl reload sshd")).rejects.toThrow(
      "Unexpected sshd dry-run exec command: systemctl reload sshd"
    )
    expect(execSpy).toHaveBeenCalledWith("systemctl reload sshd")
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

  it("rejects security-sensitive Match-block overrides before dry-run validation", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: {
        stdout: [
          "PasswordAuthentication yes",
          "",
          "Match User admin",
          "    PasswordAuthentication yes",
        ].join("\n"),
      },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod._applyDryRun?.(mockSsh, emptyEnv)

    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("conflicting security-relevant Match-block override")
    expect(writtenFiles).toHaveLength(0)
    expect(
      execSpy.mock.calls.map((args) => args[0]).some((command) => command.includes("sshd -t"))
    ).toBe(false)
  })
})

// ─── sshd.port — check ────────────────────────────────────────────────────────
