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
