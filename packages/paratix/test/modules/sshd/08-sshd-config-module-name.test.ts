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

// R-0000766: route the dry-run mktemp call to a fixed stub path.
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

describe("sshd.config — module name", () => {
  it("includes the setting key in the module name", () => {
    const mod = sshd.config({ PasswordAuthentication: "no" })
    expect(mod.name).toBe("sshd.config: PasswordAuthentication")
  })

  it("lists multiple setting keys in the module name", () => {
    const mod = sshd.config({ PasswordAuthentication: "no", PermitRootLogin: "no" })
    expect(mod.name).toContain("PasswordAuthentication")
    expect(mod.name).toContain("PermitRootLogin")
  })
})

// ─── sshd.config — input validation ───────────────────────────────────────────

// R-0000114: synchronous validation in the module constructor protects the
// rewriter (regex inputs) and the resulting sshd_config (line-based parser)
// from caller-supplied keys/values that would otherwise inject extra
// directives or regex metacharacters.
