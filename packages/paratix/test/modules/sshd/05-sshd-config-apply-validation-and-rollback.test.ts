/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

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
      // R-0000496: sshd.config probes for ExecReload before reloading.
      {
        command: "systemctl cat 'sshd' | grep -E '^ExecReload='",
        result: { code: 0, stdout: "ExecReload=/bin/kill -HUP $MAINPID\n" },
      },
      {
        command: "systemctl cat 'ssh' | grep -E '^ExecReload='",
        result: { code: 0, stdout: "ExecReload=/bin/kill -HUP $MAINPID\n" },
      },
      { command: "systemctl reload sshd", result: { code: 0 } },
      { command: "systemctl reload ssh", result: { code: 0 } },
      { command: "systemctl reload-or-restart sshd", result: { code: 0 } },
      { command: "systemctl reload-or-restart ssh", result: { code: 0 } },
      // R-0000492: socket-state probes no longer use shell redirects.
      { command: "systemctl cat ssh.socket", result: { code: 1 } },
      { command: "systemctl is-enabled --quiet ssh.socket", result: { code: 1 } },
      { command: "systemctl is-active --quiet ssh.socket", result: { code: 1 } },
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
const SSHD_T = "sshd -T"
// R-0000492: shell redirects removed from resolveSshServiceUnit.
const SYSTEMCTL_CAT_SSH = "systemctl cat ssh.service"
const SYSTEMCTL_CAT_SSHD = "systemctl cat sshd.service"

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

describe("sshd.config — apply: validation and rollback", () => {
  it("rolls back to original config and returns failed when sshd -t fails", async () => {
    // readFile internally calls output() which trims whitespace — use a value without trailing newline
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    // service preflight and mkdir -p /run/sshd succeed, then sshd -t fails
    vi.spyOn(mockSsh, "exec")
      .mockResolvedValueOnce({
        code: 0,
        stderr: "",
        stdout: "",
      })
      .mockResolvedValueOnce({
        code: 0,
        stderr: "",
        stdout: "",
      })
      .mockResolvedValueOnce({
        code: 1,
        stderr: "sshd: bad config",
        stdout: "",
      })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config validation failed")

    // After failed validation the last write must restore the original config
    const lastWrite = writtenFiles.at(-1)
    expect(lastWrite?.path).toBe(SSHD_CONFIG)
    expect(lastWrite?.content).toBe(originalConfig)
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  it("returns failed with rollback note when both validation and rollback write fail", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // The initial writeFile (new config) must succeed so that validation runs;
    // only the rollback writeFile (restoring originalConfig after sshd -t fails)
    // is the one we want to fail in this scenario.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("SFTP rollback failed"))

    vi.spyOn(mockSsh, "exec")
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "sshd: bad config", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
  })

  it("rolls back and returns failed when the initial config write reports failure after remote replacement", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const newConfig = "PasswordAuthentication no"
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

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
    expect(result.error?.message).toContain("SFTP write failed")
    expect(writeFileSpy.mock.calls).toStrictEqual([
      [SSHD_CONFIG, newConfig, { mode: "0644" }],
      [SSHD_CONFIG, originalConfig, { mode: "0644" }],
    ])
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("sshd -t")
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
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "passwordauthentication no\n" })
      // R-0000496: probe for ExecReload directive before reload.
      .mockResolvedValueOnce({
        code: 0,
        stderr: "",
        stdout: "ExecReload=/bin/kill -HUP $MAINPID\n",
      })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // Only one write: the new config — no rollback write
    expect(writtenFiles).toHaveLength(1)
    expect(writtenFiles[0]?.content).toContain("PasswordAuthentication no")
    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      SYSTEMCTL_CAT_SSHD,
      "mkdir -p '/run/sshd'",
      "sshd -t",
      "mkdir -p '/run/sshd'",
      SSHD_T,
      // R-0000496: ExecReload probe runs before the reload action.
      "systemctl cat 'sshd' | grep -E '^ExecReload='",
      "systemctl reload sshd",
    ])
  })

  it("rolls back and returns failed when sshd -T reports an included override after validation", async () => {
    const originalConfig = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "passwordauthentication yes\n" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("effective sshd configuration does not match")
    expect(writtenFiles.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      SYSTEMCTL_CAT_SSHD,
      "mkdir -p '/run/sshd'",
      "sshd -t",
      "mkdir -p '/run/sshd'",
      SSHD_T,
    ])
  })

  it("returns failed when sshd reload fails after successful validation", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "passwordauthentication no\n" })
      // R-0000496: probe for ExecReload before reload.
      .mockResolvedValueOnce({
        code: 0,
        stderr: "",
        stdout: "ExecReload=/bin/kill -HUP $MAINPID\n",
      })
      .mockResolvedValueOnce({ code: 1, stderr: "reload failed", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      SYSTEMCTL_CAT_SSHD,
      "mkdir -p '/run/sshd'",
      "sshd -t",
      "mkdir -p '/run/sshd'",
      SSHD_T,
      // R-0000496: ExecReload probe runs before the reload action.
      "systemctl cat 'sshd' | grep -E '^ExecReload='",
      "systemctl reload sshd",
    ])
    expect(writtenFiles.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
  })

  it("falls back to ssh.service for reload on Ubuntu-style systems", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "passwordauthentication no\n" })
      // R-0000496: ExecReload probe — empty stdout means "no ExecReload",
      // so the fallback path uses `reload-or-restart`.
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      SYSTEMCTL_CAT_SSHD,
      SYSTEMCTL_CAT_SSH,
      "mkdir -p '/run/sshd'",
      "sshd -t",
      "mkdir -p '/run/sshd'",
      SSHD_T,
      // R-0000496: ExecReload probe runs; with no ExecReload directive the
      // module falls back to `reload-or-restart`.
      "systemctl cat 'ssh' | grep -E '^ExecReload='",
      "systemctl reload-or-restart ssh",
    ])
    expect(result.status).toBe("changed")
  })

  it("returns failed without writing config when neither sshd.service nor ssh.service exists", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    execSpy
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "", stdout: "" })

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("could not find a systemd SSH service unit")
    expect(writtenFiles).toHaveLength(0)
    expect(execSpy.mock.calls.map((args) => args[0])).toStrictEqual([
      SYSTEMCTL_CAT_SSHD,
      SYSTEMCTL_CAT_SSH,
    ])
  })

  // R-0000284: a reload failure followed by a failing rollback writeFile
  // (e.g. SFTP error) must surface a combined error that names both causes.
  // Without the try/catch the rollback exception bubbled up and masked the
  // original reload diagnostic.
  it("R-0000284: combines reload failure with rollback writeFile failure in the error message", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // First write (new config) succeeds, rollback write fails.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("SFTP rollback failed"))
    const execSpy = vi.spyOn(mockSsh, "exec")
    execSpy
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // systemctl cat sshd.service
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // sshd -t
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" }) // mkdir -p /run/sshd for sshd -T
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "passwordauthentication no\n" }) // sshd -T
      // R-0000496: ExecReload probe — stdout indicates ExecReload exists.
      .mockResolvedValueOnce({
        code: 0,
        stderr: "",
        stdout: "ExecReload=/bin/kill -HUP $MAINPID\n",
      })
      .mockResolvedValueOnce({ code: 1, stderr: "reload failed", stdout: "" }) // systemctl reload sshd

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd reload failed")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
  })
})

// ─── sshd.port — apply ────────────────────────────────────────────────────────
