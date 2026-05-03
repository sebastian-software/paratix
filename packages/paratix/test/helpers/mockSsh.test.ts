import { describe, expect, it, vi } from "vitest"

import { createMockSsh, createStrictMockSsh } from "./mockSsh.js"

// cspell:ignore unstubbed

describe("createMockSsh", () => {
  it("keeps permissive defaults for the legacy helper", async () => {
    const ssh = createMockSsh()

    await expect(ssh.exec("echo ok")).resolves.toMatchObject({ code: 0, stderr: "", stdout: "" })
    await expect(ssh.output("cat /tmp/file")).resolves.toBe("")
    await expect(ssh.test("test -f /tmp/file")).resolves.toBe(true)
  })

  it("records addPort, removePort and updateHost invocations", () => {
    const ssh = createMockSsh()

    ssh.addPort(2022)
    ssh.addPort(8080)
    ssh.removePort(2022)
    ssh.updateHost("10.0.0.1")
    ssh.updateHost("10.0.0.2")

    expect(ssh.addPortCalls).toStrictEqual([2022, 8080])
    expect(ssh.removePortCalls).toStrictEqual([2022])
    expect(ssh.updateHostCalls).toStrictEqual(["10.0.0.1", "10.0.0.2"])
  })

  it("returns the configured defaultTestResult for unstubbed test calls", async () => {
    const ssh = createMockSsh({}, { defaultTestResult: false })

    await expect(ssh.test("test -f /tmp/missing")).resolves.toBe(false)
  })

  it("still honors stubbed responses when defaultTestResult is false", async () => {
    const ssh = createMockSsh({ "test -f /tmp/exists": { code: 0 } }, { defaultTestResult: false })

    await expect(ssh.test("test -f /tmp/exists")).resolves.toBe(true)
    await expect(ssh.test("test -f /tmp/missing")).resolves.toBe(false)
  })

  it("warns about unstubbed test calls when warnOnUnstubbedTest is enabled", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {
      // Silence the warning so it does not pollute test output; the assertion
      // below verifies that the warning was invoked.
    })
    try {
      const ssh = createMockSsh({}, { warnOnUnstubbedTest: true })
      await ssh.test("test -f /tmp/audit")
      expect(warnSpy).toHaveBeenCalledWith("createMockSsh: unstubbed test call: test -f /tmp/audit")
    } finally {
      warnSpy.mockRestore()
    }
  })

  it("returns the configured defaultExecResult for unstubbed exec calls", async () => {
    const ssh = createMockSsh(
      {},
      { defaultExecResult: { code: 1, stderr: "command not found", stdout: "" } }
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
        allowUnstubbedExec: ["echo ok"],
        allowUnstubbedOutput: ["cat /tmp/file"],
        allowUnstubbedTest: ["test -f /tmp/file"],
      }
    )

    await expect(ssh.exec("echo ok")).resolves.toMatchObject({ code: 0, stderr: "", stdout: "" })
    await expect(ssh.output("cat /tmp/file")).resolves.toBe("")
    await expect(ssh.test("test -f /tmp/file")).resolves.toBe(true)
  })
})
