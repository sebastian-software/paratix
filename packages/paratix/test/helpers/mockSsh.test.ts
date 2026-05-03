import { describe, expect, it } from "vitest"

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
