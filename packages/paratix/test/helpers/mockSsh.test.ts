import { describe, expect, it, vi } from "vitest"

import { createMockSsh, createStrictMockSsh } from "./mockSsh.js"

describe("createMockSsh", () => {
  it("fails closed for unstubbed commands by default", async () => {
    const ssh = createMockSsh()

    await expect(ssh.exec("echo ok")).rejects.toThrow("createMockSsh: unstubbed exec call: echo ok")
    await expect(ssh.output("cat /tmp/file")).rejects.toThrow(
      "createMockSsh: unstubbed output call: cat /tmp/file"
    )
    await expect(ssh.test("test -f /tmp/file")).rejects.toThrow(
      "createMockSsh: unstubbed test call: test -f /tmp/file"
    )
    expect(() => {
      ssh.disconnect()
    }).toThrow("createMockSsh: unstubbed disconnect call: disconnect()")
    await expect(ssh.reconnect()).rejects.toThrow(
      "createMockSsh: unstubbed reconnect call: reconnect()"
    )
    await expect(ssh.downloadFile("/remote/file", "/local/file")).rejects.toThrow(
      "createMockSsh: unstubbed downloadFile call: /remote/file -> /local/file"
    )
    await expect(ssh.uploadFile("/local/file", "/remote/file")).rejects.toThrow(
      "createMockSsh: unstubbed uploadFile call: /local/file -> /remote/file"
    )
    await expect(ssh.writeFile("/remote/file", "secret content", { mode: "0600" })).rejects.toThrow(
      "createMockSsh: unstubbed writeFile call: /remote/file (content redacted, 14 bytes)"
    )
    await expect(ssh.probeSudo()).rejects.toThrow(
      "createMockSsh: unstubbed probeSudo call: probeSudo()"
    )
    expect(() => {
      ssh.addPort(2022)
    }).toThrow("createMockSsh: unstubbed addPort call: addPort(2022)")
    expect(() => {
      ssh.removePort(2022)
    }).toThrow("createMockSsh: unstubbed removePort call: removePort(2022)")
    expect(() => {
      ssh.updateHost("10.0.0.1")
    }).toThrow("createMockSsh: unstubbed updateHost call: updateHost(10.0.0.1)")
  })

  it("supports explicit permissive legacy behavior", async () => {
    const ssh = createMockSsh({}, { strict: false })

    expect(ssh.addPort(2022)).toBe(true)
    expect(() => {
      ssh.removePort(2022)
    }).not.toThrow()
    expect(() => {
      ssh.updateHost("10.0.0.1")
    }).not.toThrow()
    await expect(ssh.exec("echo ok")).resolves.toMatchObject({ code: 0, stderr: "", stdout: "" })
    await expect(ssh.output("cat /tmp/file")).resolves.toBe("")
    await expect(ssh.test("test -f /tmp/file")).resolves.toBe(true)
    expect(() => {
      ssh.disconnect()
    }).not.toThrow()
    await expect(ssh.reconnect()).resolves.toBeUndefined()
    await expect(ssh.downloadFile("/remote/file", "/local/file")).resolves.toBeUndefined()
    await expect(ssh.uploadFile("/local/file", "/remote/file")).resolves.toBeUndefined()
    await expect(
      ssh.writeFile("/remote/file", "secret content", { mode: "0600" })
    ).resolves.toBeUndefined()
    await expect(ssh.probeSudo()).resolves.toBeUndefined()
  })

  it("records explicitly allowed addPort, removePort and updateHost invocations", () => {
    const ssh = createMockSsh(
      {},
      {
        allowAddPorts: [2022, 8080],
        allowRemovePorts: [2022],
        allowUpdateHosts: ["10.0.0.1", "10.0.0.2"],
      }
    )

    expect(ssh.addPort(2022)).toBe(true)
    expect(ssh.addPort(8080)).toBe(true)
    ssh.removePort(2022)
    ssh.updateHost("10.0.0.1")
    ssh.updateHost("10.0.0.2")

    expect(ssh.addPortCalls).toStrictEqual([2022, 8080])
    expect(ssh.removePortCalls).toStrictEqual([2022])
    expect(ssh.updateHostCalls).toStrictEqual(["10.0.0.1", "10.0.0.2"])
  })

  it("rejects non-allowlisted addPort, removePort and updateHost values", () => {
    const ssh = createMockSsh(
      {},
      { allowAddPorts: [2022], allowRemovePorts: [2022], allowUpdateHosts: ["10.0.0.1"] }
    )

    expect(() => {
      ssh.addPort(8080)
    }).toThrow("createMockSsh: unstubbed addPort call: addPort(8080)")
    expect(() => {
      ssh.removePort(8080)
    }).toThrow("createMockSsh: unstubbed removePort call: removePort(8080)")
    expect(() => {
      ssh.updateHost("10.0.0.2")
    }).toThrow("createMockSsh: unstubbed updateHost call: updateHost(10.0.0.2)")

    expect(ssh.addPortCalls).toStrictEqual([8080])
    expect(ssh.removePortCalls).toStrictEqual([8080])
    expect(ssh.updateHostCalls).toStrictEqual(["10.0.0.2"])
  })

  it("records side-effect invocations", async () => {
    const ssh = createMockSsh(
      {},
      {
        allowDisconnect: true,
        allowDownloads: [{ localPath: "/local/file", remotePath: "/remote/file" }],
        allowProbeSudo: true,
        allowReconnect: true,
        allowUploads: [
          { localPath: "/local/input", options: { mode: "0644" }, remotePath: "/remote/input" },
        ],
        allowWrites: [{ options: { mode: "0600" }, remotePath: "/remote/output" }],
      }
    )

    ssh.disconnect()
    await ssh.downloadFile("/remote/file", "/local/file")
    await ssh.uploadFile("/local/input", "/remote/input", { mode: "0644" })
    await ssh.writeFile("/remote/output", "secret content", { mode: "0600" })
    await ssh.probeSudo()
    await ssh.reconnect()

    expect(ssh.disconnectCalls).toHaveLength(1)
    expect(ssh.downloadFileCalls).toStrictEqual([
      { localPath: "/local/file", remotePath: "/remote/file" },
    ])
    expect(ssh.uploadFileCalls).toStrictEqual([
      { localPath: "/local/input", options: { mode: "0644" }, remotePath: "/remote/input" },
    ])
    expect(ssh.writeFileCalls).toStrictEqual([
      { content: "secret content", options: { mode: "0600" }, remotePath: "/remote/output" },
    ])
    expect(ssh.probeSudoCalls).toHaveLength(1)
    expect(ssh.reconnectCalls).toHaveLength(1)
  })

  it("rejects traversal paths for write, upload and download allowlists", async () => {
    const ssh = createMockSsh(
      {},
      {
        allowDownloads: [{ localPath: "/local/file", remotePath: /^\/remote\/file$/v }],
        allowUploads: [
          { localPath: "/local/input", options: { mode: "0644" }, remotePath: "/remote/input" },
        ],
        allowWrites: [{ options: { mode: "0600" }, remotePath: "/remote/output" }],
      }
    )

    await expect(
      ssh.writeFile("/remote/safe/../output", "secret content", { mode: "0600" })
    ).rejects.toThrow(
      "createMockSsh: unstubbed writeFile call: /remote/safe/../output (content redacted, 14 bytes)"
    )
    await expect(
      ssh.uploadFile("/local/safe/../input", "/remote/input", { mode: "0644" })
    ).rejects.toThrow(
      "createMockSsh: unstubbed uploadFile call: /local/safe/../input -> /remote/input"
    )
    await expect(ssh.downloadFile("/remote/safe/../file", "/local/file")).rejects.toThrow(
      "createMockSsh: unstubbed downloadFile call: /remote/safe/../file -> /local/file"
    )
  })

  it("does not include writeFile content in strict error messages", async () => {
    const ssh = createMockSsh()
    const secret = "super-secret-token-value"

    await expect(ssh.writeFile("/remote/secret", secret, { mode: "0600" })).rejects.not.toThrow(
      secret
    )
  })

  it("rejects unstubbed test calls when only defaultTestResult is configured", async () => {
    const ssh = createMockSsh({}, { defaultTestResult: false })

    await expect(ssh.test("test -f /tmp/missing")).rejects.toThrow(
      "createMockSsh: unstubbed test call: test -f /tmp/missing"
    )
  })

  it("returns the configured defaultTestResult for unstubbed test calls with explicit opt-in", async () => {
    const ssh = createMockSsh({}, { allowUnstubbedDefaults: true, defaultTestResult: false })

    await expect(ssh.test("test -f /tmp/missing")).resolves.toBe(false)
  })

  it("still honors stubbed responses when defaultTestResult is false", async () => {
    const ssh = createMockSsh({ "test -f /tmp/exists": { code: 0 } }, { defaultTestResult: false })

    await expect(ssh.test("test -f /tmp/exists")).resolves.toBe(true)
    await expect(ssh.test("test -f /tmp/missing")).rejects.toThrow(
      "createMockSsh: unstubbed test call: test -f /tmp/missing"
    )
  })

  it("warns about unstubbed test calls when warnOnUnstubbedTest is enabled", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {
      // Silence the warning so it does not pollute test output; the assertion
      // below verifies that the warning was invoked.
    })
    try {
      const ssh = createMockSsh({}, { strict: false, warnOnUnstubbedTest: true })
      await ssh.test("test -f /tmp/audit")
      expect(warnSpy).toHaveBeenCalledWith("createMockSsh: unstubbed test call: test -f /tmp/audit")
    } finally {
      warnSpy.mockRestore()
    }
  })

  it("rejects unstubbed exec calls when only defaultExecResult is configured", async () => {
    const ssh = createMockSsh(
      {},
      { defaultExecResult: { code: 1, stderr: "command not found", stdout: "" } }
    )

    await expect(ssh.exec("rename-me")).rejects.toThrow(
      "createMockSsh: unstubbed exec call: rename-me"
    )
  })

  it("rejects the configured defaultExecResult when opt-in allows it and it has a non-zero exit code", async () => {
    const ssh = createMockSsh(
      {},
      {
        allowUnstubbedDefaults: true,
        defaultExecResult: { code: 1, stderr: "command not found", stdout: "" },
      }
    )

    await expect(ssh.exec("rename-me")).rejects.toThrow(
      "Command failed with exit code 1: rename-me"
    )
  })

  it("returns non-zero exec results when ignoreExitCode is true", async () => {
    const ssh = createMockSsh({
      "cat /tmp/file": { code: 1, stderr: "permission denied", stdout: "partial\n" },
    })

    await expect(
      ssh.exec("cat /tmp/file", { ignoreExitCode: true, silent: true })
    ).resolves.toMatchObject({
      code: 1,
      stderr: "permission denied",
      stdout: "partial\n",
    })
  })

  it("supports explicit permissive non-zero exec behavior", async () => {
    const ssh = createMockSsh(
      {},
      {
        allowUnstubbedDefaults: true,
        defaultExecResult: { code: 1, stderr: "command not found", stdout: "" },
        rejectNonZeroExit: false,
      }
    )

    await expect(ssh.exec("rename-me")).resolves.toMatchObject({
      code: 1,
      stderr: "command not found",
      stdout: "",
    })
  })

  it("rejects unstubbed exec calls when defaultExecResult is 'throw'", async () => {
    const ssh = createMockSsh({}, { defaultExecResult: "throw" })

    await expect(ssh.exec("rename-me")).rejects.toThrow(
      "createMockSsh: unstubbed exec call: rename-me"
    )
  })

  it("still honors stubbed responses when defaultExecResult is set", async () => {
    const ssh = createMockSsh(
      { "echo ok": { code: 0, stdout: "ok" } },
      { defaultExecResult: "throw" }
    )

    await expect(ssh.exec("echo ok")).resolves.toMatchObject({ code: 0, stdout: "ok" })
    await expect(ssh.exec("rename-me")).rejects.toThrow(
      "createMockSsh: unstubbed exec call: rename-me"
    )
  })

  it("rejects unstubbed flag-lock internal exec calls by default", async () => {
    const ssh = createMockSsh()

    await expect(ssh.exec("mkdir -p /var/lib/paratix/flags")).rejects.toThrow(
      "createMockSsh: unstubbed exec call: mkdir -p /var/lib/paratix/flags"
    )
    await expect(ssh.exec("mkdir /var/lib/paratix/flags/'etc-hosts-mutex'")).rejects.toThrow(
      "createMockSsh: unstubbed exec call: mkdir /var/lib/paratix/flags/'etc-hosts-mutex'"
    )
  })

  it("supports explicit flag-lock internal defaults", async () => {
    const reclaimProbe =
      "if [ -d /var/lib/paratix/flags/'etc-hosts-mutex' ]; then " +
      "if [ -f /var/lib/paratix/flags/'etc-hosts-mutex'/holder ]; then " +
      "STALE_TOKEN=\"$(awk 'NR==1{print $1}' -- '/var/lib/paratix/flags/etc-hosts-mutex/holder' 2>/dev/null)\"; " +
      "if find /var/lib/paratix/flags/'etc-hosts-mutex'/holder -maxdepth 0 -mmin +0 -print -quit | grep -q .; then " +
      "[ \"$(awk 'NR==1{print $1}' -- '/var/lib/paratix/flags/etc-hosts-mutex/holder' 2>/dev/null)\" = \"$STALE_TOKEN\" ] && " +
      "rm -f -- /var/lib/paratix/flags/'etc-hosts-mutex'/holder && rmdir -- /var/lib/paratix/flags/'etc-hosts-mutex'; " +
      "else exit 1; fi; else " +
      "if find /var/lib/paratix/flags/'etc-hosts-mutex' -maxdepth 0 -mmin +0 -print -quit | grep -q .; then " +
      "find /var/lib/paratix/flags/'etc-hosts-mutex' -maxdepth 0 -mmin +0 -print -quit | grep -q . && " +
      "rm -f -- /var/lib/paratix/flags/'etc-hosts-mutex'/holder && rmdir -- /var/lib/paratix/flags/'etc-hosts-mutex'; " +
      "else exit 1; fi; fi; else exit 1; fi"
    const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })

    await expect(ssh.exec("mkdir -p /var/lib/paratix/flags")).resolves.toMatchObject({ code: 0 })
    await expect(ssh.exec("mkdir /var/lib/paratix/flags/'etc-hosts-mutex'")).resolves.toMatchObject(
      { code: 0 }
    )
    await expect(
      ssh.exec(reclaimProbe, { ignoreExitCode: true, silent: true })
    ).resolves.toMatchObject({ code: 1 })
  })

  it("rejects flag-lock reclaim probes without the token recheck", async () => {
    const reclaimProbe =
      "if [ -d /var/lib/paratix/flags/'etc-hosts-mutex' ]; then " +
      "if [ -f /var/lib/paratix/flags/'etc-hosts-mutex'/holder ]; then " +
      "STALE_TOKEN=\"$(awk 'NR==1{print $1}' -- '/var/lib/paratix/flags/etc-hosts-mutex/holder' 2>/dev/null)\"; " +
      "if find /var/lib/paratix/flags/'etc-hosts-mutex'/holder -maxdepth 0 -mmin +0 -print -quit | grep -q .; then " +
      "rm -f -- /var/lib/paratix/flags/'etc-hosts-mutex'/holder && rmdir -- /var/lib/paratix/flags/'etc-hosts-mutex'; " +
      "else exit 1; fi; else exit 1; fi; else exit 1; fi"
    const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })

    await expect(ssh.exec(reclaimProbe, { ignoreExitCode: true, silent: true })).rejects.toThrow(
      "createMockSsh: unstubbed exec call"
    )
  })

  it("rejects flag-lock reclaim probes without the marker removal sequence", async () => {
    const reclaimProbe =
      "if [ -d /var/lib/paratix/flags/'etc-hosts-mutex' ]; then " +
      "if [ -f /var/lib/paratix/flags/'etc-hosts-mutex'/holder ]; then " +
      "STALE_TOKEN=\"$(awk 'NR==1{print $1}' -- '/var/lib/paratix/flags/etc-hosts-mutex/holder' 2>/dev/null)\"; " +
      "if find /var/lib/paratix/flags/'etc-hosts-mutex'/holder -maxdepth 0 -mmin +0 -print -quit | grep -q .; then " +
      "[ \"$(awk 'NR==1{print $1}' -- '/var/lib/paratix/flags/etc-hosts-mutex/holder' 2>/dev/null)\" = \"$STALE_TOKEN\" ]; " +
      "else exit 1; fi; else exit 1; fi; else exit 1; fi"
    const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })

    await expect(ssh.exec(reclaimProbe, { ignoreExitCode: true, silent: true })).rejects.toThrow(
      "createMockSsh: unstubbed exec call"
    )
  })

  it("rejects unstubbed output calls when only defaultOutputResult is configured", async () => {
    const ssh = createMockSsh({}, { defaultOutputResult: "legacy output" })

    await expect(ssh.output("stat /tmp/file")).rejects.toThrow(
      "createMockSsh: unstubbed output call: stat /tmp/file"
    )
  })

  it("returns the configured defaultOutputResult for unstubbed output calls with explicit opt-in", async () => {
    const ssh = createMockSsh(
      {},
      { allowUnstubbedDefaults: true, defaultOutputResult: "legacy output" }
    )

    await expect(ssh.output("stat /tmp/file")).resolves.toBe("legacy output")
  })

  it("still honors stubbed responses when defaultOutputResult is set", async () => {
    const ssh = createMockSsh(
      { "cat /tmp/file": { stdout: "stubbed\n" } },
      { defaultOutputResult: "legacy output" }
    )

    await expect(ssh.output("cat /tmp/file")).resolves.toBe("stubbed")
    await expect(ssh.output("stat /tmp/file")).rejects.toThrow(
      "createMockSsh: unstubbed output call: stat /tmp/file"
    )
  })

  it("rejects output calls with non-zero exit codes by default", async () => {
    const ssh = createMockSsh({
      "cat /tmp/file": { code: 1, stderr: "permission denied", stdout: "partial\n" },
    })

    await expect(ssh.output("cat /tmp/file")).rejects.toThrow(
      "Command failed with exit code 1: cat /tmp/file"
    )
  })

  it("rejects lines calls when output returns a non-zero exit code by default", async () => {
    const ssh = createMockSsh({
      "cat /tmp/list": { code: 1, stderr: "permission denied", stdout: "a\nb\n" },
    })

    await expect(ssh.lines("cat /tmp/list")).rejects.toThrow(
      "Command failed with exit code 1: cat /tmp/list"
    )
  })

  it("rejects sha256 calls when sha256sum returns a non-zero exit code by default", async () => {
    const ssh = createMockSsh({
      "[ -f '/tmp/file' ]": { code: 0 },
      "sha256sum '/tmp/file'": { code: 1, stderr: "read error", stdout: "" },
    })

    await expect(ssh.sha256("/tmp/file")).rejects.toThrow(
      "Command failed with exit code 1: sha256sum '/tmp/file'"
    )
  })

  it("supports precise response stubs without permitting unrelated commands", async () => {
    const ssh = createMockSsh(
      {},
      {
        responseStubs: [
          { command: /^stat -c '%a %U %G' '\/etc\//v, result: { stdout: "644 root root" } },
        ],
      }
    )

    await expect(ssh.output("stat -c '%a %U %G' '/etc/config'")).resolves.toBe("644 root root")
    await expect(ssh.output("cat /etc/config")).rejects.toThrow(
      "createMockSsh: unstubbed output call: cat /etc/config"
    )
  })
})

describe("createStrictMockSsh", () => {
  it("throws on unstubbed exec calls", async () => {
    const ssh = createStrictMockSsh()

    await expect(ssh.exec("echo ok")).rejects.toThrow("createMockSsh: unstubbed exec call: echo ok")
  })

  it("throws on unstubbed output calls", async () => {
    const ssh = createStrictMockSsh()

    await expect(ssh.output("cat /tmp/file")).rejects.toThrow(
      "createMockSsh: unstubbed output call: cat /tmp/file"
    )
  })

  it("throws on unstubbed test calls", async () => {
    const ssh = createStrictMockSsh()

    await expect(ssh.test("test -f /tmp/file")).rejects.toThrow(
      "createMockSsh: unstubbed test call: test -f /tmp/file"
    )
  })

  it("supports explicit allowlists for irrelevant commands", async () => {
    const ssh = createStrictMockSsh(
      {},
      {
        allowAddPorts: [2022],
        allowDisconnect: true,
        allowDownloads: [{ localPath: "/local/file", remotePath: "/remote/file" }],
        allowProbeSudo: true,
        allowReconnect: true,
        allowRemovePorts: [2022],
        allowUnstubbedExec: ["echo ok"],
        allowUnstubbedOutput: ["cat /tmp/file"],
        allowUnstubbedTest: ["test -f /tmp/file"],
        allowUpdateHosts: ["10.0.0.1"],
        allowUploads: [
          { localPath: "/local/file", options: undefined, remotePath: "/remote/file" },
        ],
        allowWrites: [{ options: { mode: "0600" }, remotePath: "/remote/file" }],
      }
    )

    await expect(ssh.exec("echo ok")).resolves.toMatchObject({ code: 0, stderr: "", stdout: "" })
    expect(ssh.addPort(2022)).toBe(true)
    expect(() => {
      ssh.removePort(2022)
    }).not.toThrow()
    expect(() => {
      ssh.updateHost("10.0.0.1")
    }).not.toThrow()
    await expect(ssh.output("cat /tmp/file")).resolves.toBe("")
    await expect(ssh.test("test -f /tmp/file")).resolves.toBe(true)
    expect(() => {
      ssh.disconnect()
    }).not.toThrow()
    await expect(ssh.downloadFile("/remote/file", "/local/file")).resolves.toBeUndefined()
    await expect(ssh.uploadFile("/local/file", "/remote/file")).resolves.toBeUndefined()
    await expect(
      ssh.writeFile("/remote/file", "content", { mode: "0600" })
    ).resolves.toBeUndefined()
    await expect(ssh.probeSudo()).resolves.toBeUndefined()
    await expect(ssh.reconnect()).resolves.toBeUndefined()
  })
})
