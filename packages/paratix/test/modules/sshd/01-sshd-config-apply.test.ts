/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [
      // R-0000587: dry-run tempfiles carry restrictive 0600 permissions.
      { options: { mode: "0600" }, remotePath: /^\/tmp\/paratix-sshd-dry-run-/v },
      ...(options?.allowWrites ?? []),
    ],
    responseStubs: [
      { command: "mkdir -p '/run/sshd'", result: { code: 0 } },
      { command: "sshd -t", result: { code: 0 } },
      // R-0000: validateProspectiveSshdConfig writes a temp file and validates
      // it with `sshd -t -f <UUID>.conf` before overwriting the live config.
      { command: /^sshd -t -f '\/tmp\/paratix-sshd-dry-run-[^']+\.conf'$/v, result: { code: 0 } },
      {
        command: "sshd -T",
        result: {
          code: 0,
          stdout: [
            "passwordauthentication no",
            "permitrootlogin no",
            "x11forwarding no",
            "allowusers admin*",
            "authorizedkeysfile /etc/ssh/authorized_keys/%u",
          ].join("\n"),
        },
      },
      { command: SYSTEMCTL_CAT_SSHD, result: { code: 0 } },
      { command: SYSTEMCTL_CAT_SSH, result: { code: 1 } },
      { command: "systemctl is-enabled --quiet sshd.service", result: { code: 0 } },
      { command: "systemctl is-enabled --quiet ssh.service", result: { code: 0 } },
      // R-0000496: sshd.config probes for an ExecReload directive before
      // deciding between `reload` and `reload-or-restart`.
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
      // R-0000492: shell redirects removed from socket-state probes; the
      // source now relies on `silent: true` to swallow stdout/stderr.
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
// R-0000492: shell redirects removed from resolveSshServiceUnit; the source
// now relies on `silent: true` for output suppression.
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
    // All settings are applied in one write (single readFile + single guardedWriteFile).
    // validateProspectiveSshdConfig writes a temp file first; filter it out.
    const configWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(configWrites).toHaveLength(1)
    expect(configWrites[0]?.content).toContain("PasswordAuthentication no")
    expect(configWrites[0]?.content).toContain("PermitRootLogin no")
  })

  // R-0000114: directive names are validated up-front, so no caller can
  // smuggle a regex/shell metacharacter into the rewriter to begin with.
  it("regression — rejects directive names with non-alphanumeric characters synchronously", () => {
    expect(() => sshd.config({ "Match.User": "admin" })).toThrow(
      /invalid directive name "Match\.User"/v
    )
  })

  it("regression — value with RegExp special chars like * and [ does not throw", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "AllowUsers root\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    // Value with a shell glob — previously could cause RegExp errors or injection
    const mod = sshd.config({ AllowUsers: "admin*" })
    await expect(mod.apply(mockSsh, emptyEnv)).resolves.not.toThrow()
    // validateProspectiveSshdConfig writes a temp file; filter to config writes only.
    const configWrites = writtenFiles.filter((f) => f.path === SSHD_CONFIG)
    expect(configWrites).toHaveLength(1)
    expect(configWrites[0]?.content).toContain("AllowUsers admin*")
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

  // R-0000058: apply must be case-insensitive (just like check) so a lowercase
  // directive like `passwordauthentication yes` is overwritten in place rather
  // than appended at the end of the file. After apply the directive is also
  // normalized to its canonical casing and a follow-up check returns `ok`.
  it("regression — overwrites a lowercase directive in place and normalizes the casing", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "passwordauthentication yes\n" },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    // Replacement happened in place; the file must not contain a second,
    // appended occurrence of the directive at the end.
    expect(written?.content.match(/PasswordAuthentication/giv)).toHaveLength(1)
    // Canonical casing is used in the rewritten line; the original lowercase
    // `yes` value must be entirely gone (replaced in place, not appended).
    expect(written?.content).toContain("PasswordAuthentication no")
    expect(written?.content).not.toMatch(/passwordauthentication\s+yes/iv)

    // Follow-up check against the rewritten content reports `ok`.
    const followUpSsh = createMockSsh({
      [CAT_SSHD]: { stdout: written!.content },
    })
    const followUp = await mod.check(followUpSsh, emptyEnv)
    expect(followUp).toBe("ok")
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

  // R-0000113 regression: apply must rewrite the top-level directive but
  // leave any non-security Match-block override of the same directive untouched.
  it("regression — preserves non-security Match-block overrides when rewriting a top-level directive", async () => {
    const originalConfig = [
      "X11Forwarding yes",
      "PermitRootLogin no",
      "",
      "Match User admin",
      "    X11Forwarding yes",
      "",
    ].join("\n")
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ X11Forwarding: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    // Top-level directive was rewritten…
    expect(written?.content).toMatch(/^X11Forwarding no$/mv)
    // …but the Match-block override stayed intact.
    expect(written?.content).toMatch(/Match User admin\n {4}X11Forwarding yes/v)
  })

  it("rejects security-sensitive Match-block overrides that would keep check drifting", async () => {
    const originalConfig = [
      "PasswordAuthentication yes",
      "",
      "Match User admin",
      "    PasswordAuthentication yes",
      "",
    ].join("\n")
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)
    const execSpy = vi.spyOn(mockSsh, "exec")

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("conflicting security-relevant Match-block override")
    expect(writtenFiles).toHaveLength(0)
    expect(execSpy.mock.calls.map((args) => args[0])).not.toContain("systemctl reload sshd")
  })

  it("returns ok on follow-up check when security-sensitive Match-block overrides agree", async () => {
    const originalConfig = [
      "PasswordAuthentication yes",
      "",
      "Match User admin",
      "    PasswordAuthentication no",
      "",
    ].join("\n")
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()

    const followUpSsh = createMockSsh({
      [CAT_SSHD]: { stdout: written!.content },
    })
    await expect(mod.check(followUpSsh, emptyEnv)).resolves.toBe("ok")
  })

  // R-0000113: when no top-level occurrence exists yet, the new directive
  // must be inserted before the first Match block — not after it, where it
  // would silently fall under the Match scope.
  it("regression — appends a new top-level directive before the first Match block", async () => {
    const originalConfig = ["# header", "Match User admin", "    PermitRootLogin yes", ""].join(
      "\n"
    )
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: originalConfig },
    })
    const writtenFiles = trackWriteFile(mockSsh)

    const mod = sshd.config({ PasswordAuthentication: "no" })
    await mod.apply(mockSsh, emptyEnv)

    const written = writtenFiles.find((f) => f.path === SSHD_CONFIG)
    expect(written).toBeDefined()
    const passwordIndex = written!.content.indexOf("PasswordAuthentication no")
    const matchIndex = written!.content.indexOf("Match User admin")
    expect(passwordIndex).toBeGreaterThanOrEqual(0)
    expect(matchIndex).toBeGreaterThan(passwordIndex)
  })
})

// ─── sshd.config — check ──────────────────────────────────────────────────────
