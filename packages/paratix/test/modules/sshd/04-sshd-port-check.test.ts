/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { sshd } from "../../../src/modules/sshd.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

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
      // R-0000608: `captureSshSocketState` now probes both `ssh.socket`
      // (Debian/Ubuntu) and `sshd.socket` (Fedora/RHEL); both default-miss
      // here so the default Debian/Ubuntu service-restart path stays selected.
      { command: "systemctl cat ssh.socket", result: { code: 1 } },
      { command: "systemctl cat sshd.socket", result: { code: 1 } },
      { command: "systemctl is-enabled --quiet ssh.socket", result: { code: 1 } },
      { command: "systemctl is-active --quiet ssh.socket", result: { code: 1 } },
      { command: "systemctl is-enabled --quiet sshd.socket", result: { code: 1 } },
      { command: "systemctl is-active --quiet sshd.socket", result: { code: 1 } },
      { command: "systemctl disable --now ssh.socket", result: { code: 0 } },
      { command: "systemctl disable --now sshd.socket", result: { code: 0 } },
      { command: "systemctl enable --now ssh.socket", result: { code: 0 } },
      { command: "systemctl enable --now sshd.socket", result: { code: 0 } },
      { command: "systemctl restart sshd", result: { code: 0 } },
      {
        command: /^ss -H -ltnp 'sport = :\d+'$/v,
        result: { code: 0, stdout: 'LISTEN 0 128 *:2222 users:(("sshd",pid=123,fd=3))\n' },
      },
      { command: /^rm -f '\/tmp\/paratix-sshd-dry-run\..+'$/v, result: { code: 0 } },
      ...(options?.responseStubs ?? []),
    ],
  })

const emptyEnv = {}
const SSHD_CONFIG = "/etc/ssh/sshd_config"
const CAT_SSHD = `cat '${SSHD_CONFIG}'`
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

// R-0000766: route the dry-run mktemp call to a fixed stub path so the
// validateProspectiveSshdConfig pipeline can proceed without the helper
// having to anticipate the exact call order.
const SSHD_DRY_RUN_MKTEMP = "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'"
const SSHD_DRY_RUN_TEMP_PATH = "/tmp/paratix-sshd-dry-run.ABCDEF"

function mockSshdDryRunExecSuccess(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    if (command === SSHD_DRY_RUN_MKTEMP) {
      return { code: 0, stderr: "", stdout: SSHD_DRY_RUN_TEMP_PATH }
    }
    return { code: 0, stderr: "", stdout: "" }
  })
}

function mockSshdDryRunExecValidationFailure(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    mockSsh.calls.push(command)
    await Promise.resolve()
    if (command === SSHD_DRY_RUN_MKTEMP) {
      return { code: 0, stderr: "", stdout: SSHD_DRY_RUN_TEMP_PATH }
    }
    if (command.startsWith("sshd -t -f ")) {
      return { code: 1, stderr: "Bad configuration option", stdout: "" }
    }
    return { code: 0, stderr: "", stdout: "" }
  })
}

// ─── sshd.config — apply ──────────────────────────────────────────────────────

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

  it("returns needs-apply when the configured port matches but no live listener exists", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
      "ss -H -ltnp 'sport = :2222'": { code: 0, stdout: "" },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the configured port does not match", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when mixed active top-level ports include the target port", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\nPort 2222\n" },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok for default port 22 when no Port directive exists", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "# sshd config\n" },
      "ss -H -ltnp 'sport = :22'": {
        code: 0,
        stdout: 'LISTEN 0 128 *:22 users:(("sshd",pid=123,fd=3))\n',
      },
    })
    const mod = sshd.port(22)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when a non-SSH process listens on the target port", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
      "ss -H -ltnp 'sport = :2222'": {
        code: 0,
        stdout: 'LISTEN 0 128 *:2222 users:(("nginx",pid=123,fd=3))\n',
      },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ssh.socket is enabled but the SSH service is disabled", async () => {
    const mockSsh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 2222\n" },
      // R-0000492: socket-state probes no longer use shell redirects.
      "systemctl cat ssh.socket": { code: 0 },
      "systemctl is-active --quiet ssh.socket": { code: 0 },
      "systemctl is-enabled --quiet ssh.socket": { code: 0 },
      "systemctl is-enabled --quiet sshd.service": { code: 1 },
    })
    const mod = sshd.port(2222)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("has correct module name", () => {
    const mod = sshd.port(2222)
    expect(mod.name).toBe("sshd.port: 2222")
  })
})

// ─── sshd.config — apply: validateSshdConfig rollback ────────────────────────
