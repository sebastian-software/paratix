import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ServerDefinition } from "../src/types.js"

import { installRunnerTestHooks, makeMockSshClass } from "./helpers/runnerMocks.js"

installRunnerTestHooks()
const originalStdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
const originalStderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY")

function definition(run: Module[]): ServerDefinition {
  return {
    host: "127.0.0.1",
    name: "podman-secrets",
    run,
    ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
  }
}
async function harness() {
  const chronology: string[] = []
  const prompt = vi.fn<() => Promise<string>>().mockImplementation(async () => {
    chronology.push("prompt")
    await Promise.resolve()
    return "synthetic-token"
  })
  const connect = vi.fn().mockImplementation(async () => {
    chronology.push("connect")
    await Promise.resolve()
    return null
  })
  const exec = vi.fn().mockResolvedValue({ code: 80, stderr: "", stdout: "" })
  vi.doMock("../src/terminal.js", () => ({ promptTerminal: prompt }))
  vi.doMock("../src/ssh.js", () => ({
    shellQuote: (value: string) => `'${value.replaceAll("'", "'\\''")}'`,
    SshConnectionImpl: makeMockSshClass([], { connect, exec, lifecycle: "permissive" }),
  }))
  const { runPlaybook } = await import("../src/runner.js")
  const { secret } = await import("../src/modules/secret.js")
  const { podman } = await import("../src/modules/podman.js")
  return { chronology, connect, exec, podman, prompt, runPlaybook, secret }
}

describe("runner podman secret lifecycle", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.spyOn(console, "log").mockImplementation(() => {
      /* Captured output. */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* Captured output. */
    })
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true })
  })
  afterEach(() => {
    vi.doUnmock("../src/terminal.js")
    vi.doUnmock("../src/ssh.js")
    vi.restoreAllMocks()
    if (originalStdinTty) Object.defineProperty(process.stdin, "isTTY", originalStdinTty)
    else Reflect.deleteProperty(process.stdin, "isTTY")
    if (originalStderrTty) Object.defineProperty(process.stderr, "isTTY", originalStderrTty)
    else Reflect.deleteProperty(process.stderr, "isTTY")
    process.exitCode = 0
  })
  it.each([false, true])(
    "prewarms before SSH with dryRun=%s and makes metadata available to podman",
    async (dryRun) => {
      const h = await harness()
      const resolver = h.secret.provider("manual").resolve({ TOKEN: "opaque" })
      const consumer = h.podman.login({
        passwordEnv: "TOKEN",
        registry: "localhost",
        username: "OK",
      })
      await h.runPlaybook(definition([resolver, consumer]), { dryRun })
      expect(h.chronology).toStrictEqual(["prompt", "connect"])
      expect(h.prompt).toHaveBeenCalledOnce()
      expect(h.exec).toHaveBeenCalledOnce()
      expect(h.exec.mock.calls[0][1]).toMatchObject({
        input: '{"version":1,"password":"synthetic-token","username":"OK"}\n',
      })
    }
  )
  it("reads fresh values in the next run while check and apply share the first read", async () => {
    const h = await harness()
    h.prompt.mockResolvedValueOnce("first-token").mockResolvedValueOnce("rotated-token")
    h.exec
      .mockResolvedValueOnce({ code: 81, stderr: "", stdout: "" })
      .mockResolvedValueOnce({ code: 82, stderr: "", stdout: "" })
    const run = definition([
      h.secret.provider("manual").resolve({ TOKEN: "opaque" }),
      h.podman.login({ passwordEnv: "TOKEN", registry: "localhost", username: "u" }),
    ])
    await h.runPlaybook(run)
    await h.runPlaybook(run)
    expect(h.prompt).toHaveBeenCalledTimes(2)
    expect(h.exec).toHaveBeenCalledTimes(3)
    expect(h.exec.mock.calls[0][1]).toMatchObject({
      input: '{"version":1,"password":"first-token","username":"u"}\n',
    })
    expect(h.exec.mock.calls[1][1]).toMatchObject({
      input: '{"version":1,"password":"first-token","username":"u"}\n',
    })
    expect(h.exec.mock.calls[2][1]).toMatchObject({
      input: '{"version":1,"password":"rotated-token","username":"u"}\n',
    })
  })
  it("does not mutate when a filter removes its resolver", async () => {
    const h = await harness()
    const consumer = h.podman.login({ passwordEnv: "TOKEN", registry: "localhost", username: "u" })
    await h.runPlaybook(definition([consumer]))
    expect(h.prompt).not.toHaveBeenCalled()
    expect(h.exec).not.toHaveBeenCalled()
  })
  it.each(["no TTY", "aborted prompt"])("fails before connection for %s", async (failure) => {
    const h = await harness()
    // eslint-disable-next-line vitest/no-conditional-in-test -- The fixture sets up two distinct provider failure modes.
    if (failure === "no TTY")
      Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: false })
    else h.prompt.mockRejectedValue(new Error("synthetic prompt aborted"))
    const run = definition([
      h.secret.provider("manual").resolve({ TOKEN: "opaque" }),
      h.podman.login({ passwordEnv: "TOKEN", registry: "localhost", username: "u" }),
    ])
    await expect(h.runPlaybook(run)).rejects.toThrow(/secret|manual|prompt/iv)
    expect(h.connect).not.toHaveBeenCalled()
    expect(h.exec).not.toHaveBeenCalled()
  })
})
