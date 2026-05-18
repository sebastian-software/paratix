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
const UFW_STATUS_ACTIVE_PORT_2222_ALLOW_AND_DENY = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "2222                       ALLOW       Anywhere",
  "2222                       DENY        Anywhere",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_TCP_ALLOWED = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "2222/tcp                   ALLOW       Anywhere",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_TCP_ALLOW_AND_DENY = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "2222                       ALLOW       Anywhere",
  "2222/tcp                   ALLOW       Anywhere",
  "2222/tcp                   DENY        Anywhere",
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
const UFW_STATUS_ACTIVE_PORT_2222_TCP_BOTH_FAMILIES = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "22 (v6)                    ALLOW       Anywhere (v6)",
  "2222/tcp                   ALLOW       Anywhere",
  "2222/tcp (v6)              ALLOW       Anywhere (v6)",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_ALLOW_AND_IPV6_DENY = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "22 (v6)                    ALLOW       Anywhere (v6)",
  "2222                       ALLOW       Anywhere",
  "2222 (v6)                  ALLOW       Anywhere (v6)",
  "2222 (v6)                  DENY        Anywhere (v6)",
].join("\n")
const UFW_STATUS_ACTIVE_PORT_2222_ALLOW_AND_IPV6_TCP_DENY = [
  "Status: active",
  "",
  "To                         Action      From",
  "--                         ------      ----",
  "22                         ALLOW       Anywhere",
  "22 (v6)                    ALLOW       Anywhere (v6)",
  "2222                       ALLOW       Anywhere",
  "2222 (v6)                  ALLOW       Anywhere (v6)",
  "2222/tcp (v6)              DENY        Anywhere (v6)",
].join("\n")

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const ssh = createBaseMockSsh(responses, {
    ...options,
    // R-0000670: acquireFlagLock now fails fast when the holder marker
    // write/readback is empty, so the sshd-port mutex tests need the
    // shared flag-lock internal defaults that supply a deterministic
    // holder token via `ssh.output`.
    allowFlagLockInternalDefaults: true,
    allowWrites: [
      // R-0000587: dry-run tempfiles carry restrictive 0600 permissions.
      { options: { mode: "0600" }, remotePath: /^\/tmp\/paratix-sshd-dry-run\./v },
      ...(options?.allowWrites ?? []),
    ],
    responseStubs: [
      { command: "mkdir -p '/run/sshd'", result: { code: 0 } },
      { command: "sshd -t", result: { code: 0 } },
      // R-0000766: allocateProspectiveSshdConfigPath allocates the dry-run
      // path via `mktemp -p /tmp -- paratix-sshd-dry-run.XXXXXX`.
      {
        command: "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'",
        result: { code: 0, stdout: "/tmp/paratix-sshd-dry-run.ABCDEF" },
      },
      { command: SYSTEMCTL_CAT_SSHD, result: { code: 0 } },
      { command: SYSTEMCTL_CAT_SSH, result: { code: 1 } },
      { command: "systemctl is-enabled --quiet sshd.service", result: { code: 0 } },
      { command: "systemctl cat ssh.socket >/dev/null 2>&1", result: { code: 1 } },
      { command: "systemctl restart sshd", result: { code: 0 } },
      { command: /^rm -f '\/tmp\/paratix-sshd-dry-run\..+'$/v, result: { code: 0 } },
      // R-0000283: post-restart live verify defaults to "listener present" so
      // the existing fixtures keep proceeding past the new verify step.
      {
        command: /^ss -H -ltnp 'sport = :\d+'$/v,
        result: { code: 0, stdout: 'LISTEN 0 128 0.0.0.0:0 users:(("sshd",pid=1,fd=3))\n' },
      },
      ...(options?.responseStubs ?? []),
    ],
  })
  vi.spyOn(ssh, "getConnectionInfo").mockReturnValue({
    ...ssh.getConnectionInfo(),
    configuredPorts: [22, 2222],
  })
  return ssh
}

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

// R-0000283: post-restart verify probe pattern; tests that bulk-mock exec to
// `code: 0, stdout: ""` need a stand-in stdout for these probes so
// `liveSshdPortMatches` returns true.
const SS_PROBE_PATTERN = /^ss -H -ltnp 'sport = :\d+'$/v
const SS_PROBE_LISTENING_STDOUT = 'LISTEN 0 128 0.0.0.0:0 users:(("sshd",pid=1,fd=3))\n'

// R-0000766: route the dry-run mktemp call to a fixed stub path.
const SSHD_DRY_RUN_MKTEMP_10 = "mktemp -p /tmp -- 'paratix-sshd-dry-run.XXXXXX'"
const SSHD_DRY_RUN_TEMP_PATH_10 = "/tmp/paratix-sshd-dry-run.ABCDEF"

function spyExecSuccessAcceptingSsProbe(mockSsh: ReturnType<typeof createMockSsh>) {
  return vi.spyOn(mockSsh, "exec").mockImplementation(async (command) => {
    await Promise.resolve()
    if (command === SSHD_DRY_RUN_MKTEMP_10) {
      return { code: 0, stderr: "", stdout: SSHD_DRY_RUN_TEMP_PATH_10 }
    }
    if (SS_PROBE_PATTERN.test(command)) {
      return { code: 0, stderr: "", stdout: SS_PROBE_LISTENING_STDOUT }
    }
    return { code: 0, stderr: "", stdout: "" }
  })
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

  it("fails-closed when ufw status cannot be read", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { code: 1, stderr: "ERROR: problem running ufw" },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")
    const addPortSpy = vi.spyOn(ssh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("could not determine ufw status")
    expect(writtenFiles).toHaveLength(0)
    expect(addPortSpy).not.toHaveBeenCalled()
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands.every((command) => !command.startsWith("sshd -t -f "))).toBe(true)
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

  it("fails-closed when ufw has allow and deny rules for the target port", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_ALLOW_AND_DENY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw is active")
    expect(writtenFiles).toHaveLength(0)
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
  })

  it("fails-closed when ufw has TCP allow and TCP deny rules for the target port", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_TCP_ALLOW_AND_DENY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw is active")
    expect(writtenFiles).toHaveLength(0)
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
  })

  it("fails-closed when ufw has an IPv6 deny rule alongside target port allows", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_ALLOW_AND_IPV6_DENY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw is active")
    expect(writtenFiles).toHaveLength(0)
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
  })

  it("fails-closed when ufw has an IPv6 TCP deny rule alongside target port allows", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_ALLOW_AND_IPV6_TCP_DENY },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("ufw is active")
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
    const execSpy = spyExecSuccessAcceptingSsProbe(ssh)

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
  })

  it("proceeds when ufw is active and the target port is allowed for TCP", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_TCP_ALLOWED },
    })
    trackWriteFile(ssh)
    const execSpy = spyExecSuccessAcceptingSsProbe(ssh)

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
    const execSpy = spyExecSuccessAcceptingSsProbe(ssh)

    const mod = sshd.port(2222)
    const result = await mod.apply(ssh, emptyEnv)

    expect(result.status).toBe("changed")
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).toContain("systemctl restart sshd")
  })

  it("proceeds when ufw is active and the target port is allowed for TCP on both address families", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { stdout: UFW_STATUS_ACTIVE_PORT_2222_TCP_BOTH_FAMILIES },
    })
    trackWriteFile(ssh)
    const execSpy = spyExecSuccessAcceptingSsProbe(ssh)

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
    const execSpy = spyExecSuccessAcceptingSsProbe(ssh)

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

  it("fails-closed during dry-run when ufw status cannot be read", async () => {
    const ssh = createMockSsh({
      [CAT_SSHD]: { stdout: "Port 22\n" },
      "ufw status": { code: 1, stderr: "ERROR: problem running ufw" },
    })
    const writtenFiles = trackWriteFile(ssh)
    const execSpy = vi.spyOn(ssh, "exec")
    const addPortSpy = vi.spyOn(ssh, "addPort")

    const mod = sshd.port(2222)
    const result = await mod._applyDryRun?.(ssh, emptyEnv)

    expect(result?.status).toBe("failed")
    expect(result?.error?.message).toContain("could not determine ufw status")
    expect(writtenFiles).toHaveLength(0)
    expect(addPortSpy).not.toHaveBeenCalled()
    const execCommands = execSpy.mock.calls.map((args) => args[0])
    expect(execCommands).not.toContain("systemctl restart sshd")
    expect(execCommands).not.toContain("sshd -t")
    expect(execCommands.every((command) => !command.startsWith("sshd -t -f "))).toBe(true)
  })
})
