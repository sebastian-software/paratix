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
      // R-0000539: validateProspectiveSshdConfig writes a temp file and validates
      // it with `sshd -t -f <UUID>.conf` before overwriting the live config.
      { command: /^sshd -t -f '\/tmp\/paratix-sshd-dry-run-[^']+\.conf'$/v, result: { code: 0 } },
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

// R-0000539: helper for the failing-dry-run interceptor — kept outside the test
// body so the conditional branching satisfies vitest's no-conditional-in-test.
function createDryRunFailingExec(
  mockSsh: ReturnType<typeof createMockSsh>,
  originalExec: typeof mockSsh.exec,
  dryRunFailPattern: RegExp
): typeof mockSsh.exec {
  return async (command, options) => {
    if (dryRunFailPattern.test(command)) {
      mockSsh.calls.push(command)
      return { code: 1, stderr: "sshd: bad config", stdout: "" }
    }
    return originalExec(command, options)
  }
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

describe("sshd.config — apply: validation and rollback", () => {
  // R-0000539: validate prospective sshd_config in a tempfile BEFORE overwriting
  // the live config. When `sshd -t -f <tmp>` fails, the live /etc/ssh/sshd_config
  // is never touched and no rollback is needed.
  it("rolls back to original config and returns failed when sshd -t fails", async () => {
    // readFile internally calls output() which trims whitespace — use a value without trailing newline
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: place the failing dry-run stub in responses (exact string key would not work
    // for dynamic UUID paths), so use a custom exec interceptor that fails only for the
    // prospective-validation command and forwards everything else to the stub-based handler.
    const dryRunFailPattern = /^sshd -t -f '\/tmp\/paratix-sshd-dry-run-/v
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    // Capture the original stub-based exec before overriding.
    const originalExec = mockSsh.exec.bind(mockSsh)
    const execSpy = vi
      .spyOn(mockSsh, "exec")
      .mockImplementation(createDryRunFailingExec(mockSsh, originalExec, dryRunFailPattern))

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config validation failed")

    // The live config must NEVER have been touched — no rollback write needed.
    expect(writtenFiles.filter((f) => f.path === SSHD_CONFIG)).toHaveLength(0)
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  // R-0000539: "rollback also failed" now occurs when the live-config write
  // fails AND the subsequent rollback write also fails (not when sshd -t fails,
  // since the new flow validates in a tempfile before the live write).
  it("returns failed with rollback note when both validation and rollback write fail", async () => {
    const originalConfig = "PasswordAuthentication yes"
    const newConfig = "PasswordAuthentication no"
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    // R-0000539: readFile sequence — initial read, guard read (guardedWriteFile),
    // and rollback check read. The rollback check must see the newContent so the
    // rollback write path is entered (simulates a partial SFTP write that committed
    // the new content before the connection dropped).
    vi.spyOn(mockSsh, "readFile")
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdConfig
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
      .mockResolvedValueOnce(newConfig) // rollback check: current == newConfig → rollback
    // writeFile sequence: tmpfile (dry-run), live SSHD_CONFIG (fails), rollback (fails).
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write
      .mockRejectedValueOnce(new Error("SFTP write failed")) // live config write fails
      .mockRejectedValueOnce(new Error("SFTP rollback failed")) // rollback write fails

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
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
      .mockResolvedValueOnce(originalConfig) // initial read in applySshdConfig
      .mockResolvedValueOnce(originalConfig) // guard read in guardedWriteFile
      .mockResolvedValueOnce(newConfig) // rollback check: current == newConfig → rollback
    // R-0000539: first writeFile is the temp file for prospective validation (succeeds),
    // second is the live SSHD_CONFIG write (fails), third is the rollback write (succeeds).
    const writeFileSpy = vi
      .spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write succeeds
      .mockRejectedValueOnce(new Error("SFTP write failed")) // live config write fails
      .mockResolvedValueOnce(undefined) // rollback write succeeds
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd config write failed")
    expect(result.error?.message).toContain("SFTP write failed")
    // The live config writes: first fails, second is the rollback.
    // Filter out the tmpfile write (dynamic UUID path) to check only live config writes.
    const liveConfigWrites = writeFileSpy.mock.calls.filter(([path]) => path === SSHD_CONFIG)
    expect(liveConfigWrites).toStrictEqual([
      [SSHD_CONFIG, newConfig, { mode: "0644" }],
      [SSHD_CONFIG, originalConfig, { mode: "0644" }],
    ])
    // R-0000539: plain `sshd -t` is never called; validation uses `sshd -t -f <tmpfile>`.
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("sshd -t")
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  it("writes new config and reloads sshd without rollback when validation succeeds", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: createMockSsh responseStubs handle all exec calls including the
    // dry-run `sshd -t -f <tmpfile>` and cleanup `rm -f <tmpfile>` with dynamic UUIDs.
    const mockSsh = createMockSsh(
      { [CAT_SSHD]: { stdout: originalConfig } },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    // R-0000539: validateProspectiveSshdConfig writes a tmpfile before the live config.
    // Filter to SSHD_CONFIG writes only: expect exactly one (the new config, no rollback).
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites).toHaveLength(1)
    expect(liveConfigWrites[0]?.content).toContain("PasswordAuthentication no")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    // Core operations must still be executed in the correct order.
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SSHD_T)
    // R-0000496: ExecReload probe and reload action must follow.
    expect(execCommands).toContain("systemctl cat 'sshd' | grep -E '^ExecReload='")
    expect(execCommands).toContain("systemctl reload sshd")
    // Dry-run temp file must have been cleaned up.
    expect(execCommands.some((cmd) => cmd.startsWith("rm -f '/tmp/paratix-sshd-dry-run-"))).toBe(
      true
    )
  })

  it("rolls back and returns failed when sshd -T reports an included override after validation", async () => {
    const originalConfig = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes"
    // R-0000539: responseStubs handle exec calls including the dry-run tempfile validation.
    // sshd -T returns the overriding value ("yes") to trigger the effective-config mismatch.
    const mockSsh = createMockSsh(
      { [CAT_SSHD]: { stdout: originalConfig } },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication yes\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("effective sshd configuration does not match")
    // Last write must be the rollback to the original config.
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SSHD_T)
    // No reload because effective config check failed.
    expect(execCommands).not.toContain("systemctl reload sshd")
  })

  it("returns failed when sshd reload fails after successful validation", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: responseStubs handle exec calls including dry-run tempfile validation.
    // Override reload to fail via responses (highest priority over responseStubs defaults).
    const mockSsh = createMockSsh(
      {
        [CAT_SSHD]: { stdout: originalConfig },
        // Responses take priority; override reload to fail.
        "systemctl reload sshd": { code: 1, stderr: "reload failed" },
      },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SSHD_T)
    // R-0000496: ExecReload probe must run before the reload action.
    expect(execCommands).toContain("systemctl cat 'sshd' | grep -E '^ExecReload='")
    expect(execCommands).toContain("systemctl reload sshd")
    // Last write: rollback to original config after reload failure.
    const liveConfigWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(liveConfigWrites.at(-1)).toStrictEqual({ content: originalConfig, path: SSHD_CONFIG })
  })

  it("falls back to ssh.service for reload on Ubuntu-style systems", async () => {
    const originalConfig = "PasswordAuthentication yes"
    // R-0000539: responseStubs handle all exec calls including the dry-run tempfile validation.
    // SYSTEMCTL_CAT_SSHD is set via responses (highest priority) to fail (code 1),
    // forcing fallback to ssh.service. ExecReload probe for ssh returns empty stdout
    // so the module uses `reload-or-restart` instead of `reload`.
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
      // sshd -T returns match so that effective config check passes.
      "sshd -T": { code: 0, stdout: "passwordauthentication no\n" },
      // Responses take priority over responseStubs; override service unit probes:
      // sshd.service fails → forces fallback to ssh.service which succeeds.
      [SYSTEMCTL_CAT_SSH]: { code: 0 },
      [SYSTEMCTL_CAT_SSHD]: { code: 1 },
      // R-0000496: override ExecReload probe for ssh to return empty stdout
      // → sshdUnitDefinesExecReload returns false → action becomes reload-or-restart.
      "systemctl cat 'ssh' | grep -E '^ExecReload='": { code: 0, stdout: "" },
    })
    trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSHD)
    expect(execCommands).toContain(SYSTEMCTL_CAT_SSH)
    // R-0000539: prospective validation uses `sshd -t -f <tmpfile>`, never plain `sshd -t`.
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands).toContain(SSHD_T)
    // R-0000496: ExecReload probe runs; with no ExecReload directive the
    // module falls back to `reload-or-restart`.
    expect(execCommands).toContain("systemctl cat 'ssh' | grep -E '^ExecReload='")
    expect(execCommands).toContain("systemctl reload-or-restart ssh")
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
    // R-0000539: responseStubs handle exec calls including dry-run tempfile validation.
    // Override reload to fail via responses (highest priority over responseStubs defaults).
    const mockSsh = createMockSsh(
      {
        [CAT_SSHD]: { stdout: originalConfig },
        // Responses take priority; override reload to fail.
        "systemctl reload sshd": { code: 1, stderr: "reload failed" },
      },
      {
        responseStubs: [
          {
            command: "sshd -T",
            result: { code: 0, stdout: "passwordauthentication no\n" },
          },
        ],
      }
    )
    // R-0000539: tmpfile write (call 1) and new config write (call 2) succeed;
    // rollback write (call 3) fails.
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce(undefined) // tmpfile dry-run write
      .mockResolvedValueOnce(undefined) // live config write succeeds
      .mockRejectedValueOnce(new Error("SFTP rollback failed")) // rollback write fails

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("sshd reload failed")
    expect(result.error?.message).toContain("rollback also failed")
    expect(result.error?.message).toContain("SFTP rollback failed")
  })
})

// ─── sshd.port — apply ────────────────────────────────────────────────────────
