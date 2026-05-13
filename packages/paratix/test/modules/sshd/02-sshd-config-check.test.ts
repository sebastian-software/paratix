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
const SSHD_T = "sshd -T"
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

describe("sshd.config — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when all settings are present in sshd_config", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "PasswordAuthentication no\nPermitRootLogin no\n" },
      [SSHD_T]: { stdout: "passwordauthentication no\npermitrootlogin no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no", PermitRootLogin: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when sshd -T reports an included override with a different value", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n" },
      [SSHD_T]: { stdout: "passwordauthentication yes\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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
      [SSHD_T]: { stdout: "passwordauthentication no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(CAT_SSHD)
  })

  // R-0000114: directive names with non-alphanumeric characters are rejected
  // up-front, so the check path can rely on the parsed directive being a
  // bare identifier and never has to defend against regex injection.
  it("regression — rejects directive names with non-alphanumeric characters during check setup", () => {
    expect(() => sshd.config({ "Match.User": "root" })).toThrow(
      /invalid directive name "Match\.User"/v
    )
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
      [SSHD_T]: { stdout: "allowusers admin*\n" },
    })
    const mod = sshd.config({ AllowUsers: "admin*" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when a security-sensitive Match-block override contradicts the desired value", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: {
        stdout: [
          "PasswordAuthentication no",
          "PermitRootLogin no",
          "",
          "Match User admin",
          "    PasswordAuthentication yes",
        ].join("\n"),
      },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("keeps ignoring non-security Match-block overrides when the top-level value matches", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: {
        stdout: [
          "AuthorizedKeysFile .ssh/authorized_keys",
          "",
          "Match User admin",
          "    AuthorizedKeysFile /etc/ssh/admin_authorized_keys",
        ].join("\n"),
      },
      [SSHD_T]: { stdout: "authorizedkeysfile .ssh/authorized_keys\n" },
    })
    const mod = sshd.config({ AuthorizedKeysFile: ".ssh/authorized_keys" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000045: a Match-block override that agrees with the desired value
  // must keep the check at "ok".
  it("returns ok when both top-level and Match-block values agree with the desired value", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: {
        stdout: [
          "PasswordAuthentication no",
          "",
          "Match User backup",
          "    PasswordAuthentication no",
        ].join("\n"),
      },
      [SSHD_T]: { stdout: "passwordauthentication no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000045: commented-out lines do not count as active occurrences.
  it("ignores commented-out directives when scanning for drift", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: {
        stdout: [
          "# PasswordAuthentication yes",
          "PasswordAuthentication no",
          "  # PasswordAuthentication yes",
        ].join("\n"),
      },
      [SSHD_T]: { stdout: "passwordauthentication no\n" },
    })
    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })
})

// ─── sshd.config — dry-run ───────────────────────────────────────────────────
