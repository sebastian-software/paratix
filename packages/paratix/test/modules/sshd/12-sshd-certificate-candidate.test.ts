import { describe, expect, it, vi } from "vitest"

import { trustedUserCa } from "../../../src/modules/sshCertificateModules.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

const CANDIDATE_PATH = "/tmp/paratix-sshd-dry-run.ABCDEF"
const EFFECTIVE_CONFIG = "trustedusercakeys none\nauthorizedprincipalsfile none\n"

function createConvergedSsh() {
  return createMockSsh(
    {
      "[ -e '/etc/ssh/trusted_user_ca_keys' ]": { code: 1 },
      "cat '/etc/ssh/sshd_config'": { stdout: "Port 22\n" },
      hostname: { stdout: "" },
      "mkdir -p '/run/sshd'": { code: 0 },
      "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'": { stdout: CANDIDATE_PATH },
      "sha256sum '/etc/ssh/sshd_config'": { stdout: "original-config-hash" },
      "sshd -T": { stdout: EFFECTIVE_CONFIG },
      "stat -c '%a %u %g' -- '/etc/ssh/sshd_config'": { stdout: "644 0 0" },
      "test -d '/run/sshd'": { code: 0 },
    },
    {
      allowFlagLockInternalDefaults: true,
      allowWrites: [{ options: { mode: "0600" }, remotePath: CANDIDATE_PATH }],
      responseStubs: [
        { command: /^\[ -L /v, result: { code: 1 } },
        { command: /^\[ -[edf] /v, result: { code: 0 } },
        { command: /^stat -c '%a %u %g' -- /v, result: { stdout: "755 0 0" } },
        {
          command: /^printf '%s@%s %s\\n' "\$\$" '' "\$\(date \+%s\)" > \S+\/holder$/v,
          result: { code: 0 },
        },
        { command: /^sshd -t -f /v, result: { code: 0 } },
        { command: /^sshd -T -f /v, result: { stdout: EFFECTIVE_CONFIG } },
        { command: /^rm -f /v, result: { code: 0 } },
      ],
    }
  )
}

function failFirstCandidateCleanup(ssh: ReturnType<typeof createConvergedSsh>): void {
  const exec = ssh.exec
  let cleanupAttempts = 0
  vi.spyOn(ssh, "exec").mockImplementation(async (command, options) => {
    const execResult = await exec(command, options)
    if (command.startsWith("rm -f ")) {
      cleanupAttempts += 1
      if (cleanupAttempts === 1)
        return { ...execResult, code: 1, stderr: "candidate removal denied" }
    }
    return execResult
  })
}

describe("sshd certificate candidate cleanup", () => {
  it.each(["apply", "_applyDryRun"] as const)(
    "fails when the first candidate cleanup fails (%s)",
    async (method) => {
      const ssh = createConvergedSsh()
      failFirstCandidateCleanup(ssh)

      const module = trustedUserCa({ state: "absent" })
      const result = await module[method]?.(ssh, {})

      expect(result?.status).toBe("failed")
      expect(result?.error?.message).toMatch(/cleanup.*candidate removal denied/sv)
      expect(ssh.writeFileCalls).toStrictEqual([
        { content: "Port 22\n", options: { mode: "0600" }, remotePath: CANDIDATE_PATH },
      ])
      expect(ssh.calls.some((command) => command.startsWith("systemctl "))).toBe(false)
    }
  )

  it("keeps repeated apply and dry-run converged when candidate cleanup succeeds", async () => {
    const ssh = createConvergedSsh()
    const module = trustedUserCa({ state: "absent" })

    expect(await module.apply(ssh, {})).toMatchObject({ status: "ok" })
    expect(await module.apply(ssh, {})).toMatchObject({ status: "ok" })
    expect(await module._applyDryRun?.(ssh, {})).toMatchObject({ status: "ok" })
    expect(ssh.writeFileCalls).toHaveLength(3)
    expect(ssh.calls.filter((command) => command.startsWith("rm -f "))).toHaveLength(3)
    expect(ssh.calls.some((command) => command.startsWith("systemctl "))).toBe(false)
  })
})
