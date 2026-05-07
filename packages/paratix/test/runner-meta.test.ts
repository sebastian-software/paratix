import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { resolveEnvironment } from "../src/environment.js"
import { meta } from "../src/meta.js"
import { installRunnerTestHooks, makeMockSshClass } from "./helpers/runnerMocks.js"

installRunnerTestHooks()

describe("runPlaybook meta validation", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    vi.resetModules()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  it("fails the run when a module returns malformed meta entries", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const malformedMetaModule: Module = {
      apply: vi
        .fn()
        .mockResolvedValue({ meta: [{ kind: "sshd.port", port: "2222" }], status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "malformed-meta",
    }

    const subsequentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [malformedMetaModule, subsequentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
    expect(subsequentModule.check).not.toHaveBeenCalled()
  })

  it("prints exactly one final failed status when a module returns malformed meta", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")

    const malformedMetaModule: Module = {
      apply: vi
        .fn()
        .mockResolvedValue({ meta: [{ kind: "sshd.port", port: "2222" }], status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "malformed-meta",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [malformedMetaModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const statusLines = consoleLogs.filter((line) => line.includes("malformed-meta"))
    expect(statusLines).toHaveLength(1)
    expect(statusLines[0]).toContain("failed")
    expect(statusLines[0]).not.toContain("changed")
  })
})

describe("runPlaybook failed result control-plane meta", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    vi.resetModules()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  it("does not apply sshd.port meta from a failed module result", async () => {
    const capturedConfigs: unknown[] = []
    const addPort = vi.fn().mockReturnValue(true)
    const reconnect = vi.fn().mockResolvedValue(null)
    const removePort = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { addPort, reconnect, removePort }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const failedModule: Module = {
      apply: vi.fn().mockResolvedValue({
        meta: [meta.sshdPort(2222)],
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failed-port-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [failedModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
    expect(addPort).not.toHaveBeenCalled()
    expect(reconnect).not.toHaveBeenCalled()
    expect(removePort).not.toHaveBeenCalled()
  })

  it("does not apply reboot or host meta from a failed module result", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)
    const updateHost = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { reconnect, updateHost }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const failedModule: Module = {
      apply: vi.fn().mockResolvedValue({
        meta: [meta.systemHost("10.0.0.42"), meta.systemReboot()],
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failed-reboot-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [failedModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
    expect(updateHost).not.toHaveBeenCalled()
    expect(reconnect).not.toHaveBeenCalled()
  })
})

describe("runPlaybook signal meta propagation", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    vi.resetModules()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  it("propagates env meta from one signal to the next signal", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }
    const firstSignal: Module = {
      apply: vi
        .fn()
        .mockResolvedValue({ meta: [meta.env("SIGNAL_TOKEN", "abc123")], status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "first-signal",
    }
    const secondSignal: Module = {
      apply: vi.fn().mockImplementation(async (_ssh, env) => {
        await expect(resolveEnvironment(env, "SIGNAL_TOKEN")).resolves.toBe("abc123")
        return { status: "changed" } satisfies ModuleResult
      }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "second-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [firstSignal, secondSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(secondSignal.apply).toHaveBeenCalledOnce()
  })

  it("processes sshd.port meta from a signal before the next signal starts", async () => {
    const capturedConfigs: unknown[] = []
    const addPort = vi.fn()
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { addPort, reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }
    const firstSignal: Module = {
      apply: vi.fn().mockResolvedValue({
        meta: [meta.sshdPort(2222)],
        status: "changed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "port-signal",
    }
    const secondSignal: Module = {
      apply: vi.fn().mockImplementation(() => {
        expect(addPort).toHaveBeenCalledWith(2222)
        expect(reconnect).toHaveBeenCalledTimes(1)
        return { status: "changed" } satisfies ModuleResult
      }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "after-port-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [firstSignal, secondSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(secondSignal.apply).toHaveBeenCalledOnce()
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  it("processes system.reboot meta from a signal before the next signal starts", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)
    const updateHost = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { reconnect, updateHost }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }
    const firstSignal: Module = {
      apply: vi.fn().mockResolvedValue({
        meta: [meta.systemHost("10.0.0.42"), meta.systemReboot()],
        status: "changed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "reboot-signal",
    }
    const secondSignal: Module = {
      apply: vi.fn().mockImplementation(() => {
        expect(updateHost).toHaveBeenCalledWith("10.0.0.42")
        expect(reconnect).toHaveBeenCalledTimes(1)
        return { status: "changed" } satisfies ModuleResult
      }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "after-reboot-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [firstSignal, secondSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

    expect(secondSignal.apply).toHaveBeenCalledOnce()
    expect(updateHost).toHaveBeenCalledWith("10.0.0.42")
    expect(reconnect).toHaveBeenCalledTimes(1)
  })
})

// Bug regression: local: true in dry-run recipe child modules must receive null instead of ssh
