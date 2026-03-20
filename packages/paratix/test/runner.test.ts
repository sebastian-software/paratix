import { EventEmitter } from "node:events"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type {
  Environment,
  Module,
  ModuleMetaEntry,
  ModuleResult,
  ServerDefinition,
} from "../src/types.js"

import { resolveEnvironment } from "../src/environment.js"
import { meta } from "../src/meta.js"
import { recipe as createRecipe } from "../src/recipe.js"

function makeMockSshClass(
  capturedConfigs: unknown[],
  overrides?: {
    addPort?: ReturnType<typeof vi.fn>
    disconnect?: ReturnType<typeof vi.fn>
    reconnect?: ReturnType<typeof vi.fn>
    updateHost?: ReturnType<typeof vi.fn>
  }
) {
  return class MockSshConnectionImpl {
    public addPort = overrides?.addPort ?? vi.fn()
    public connect = vi.fn().mockResolvedValue(null)
    public disconnect = overrides?.disconnect ?? vi.fn()
    public downloadFile = vi.fn().mockResolvedValue(null)
    public exec = vi.fn().mockResolvedValue({ code: 0, stderr: "", stdout: "" })
    public exists = vi.fn().mockResolvedValue(true)
    public getConnectionInfo = vi
      .fn()
      .mockReturnValue({ host: "1.2.3.4", port: 22, privateKeyPath: "~/.ssh/id", user: "root" })
    public lines = vi.fn().mockResolvedValue([])
    public output = vi.fn().mockResolvedValue("")
    public probeSudo = vi.fn().mockResolvedValue(null)
    public readFile = vi.fn().mockResolvedValue("")
    public reconnect = overrides?.reconnect ?? vi.fn().mockResolvedValue(null)
    public sha256 = vi.fn().mockResolvedValue(null)
    public test = vi.fn().mockResolvedValue(true)
    public updateHost = overrides?.updateHost ?? vi.fn()
    public uploadFile = vi.fn().mockResolvedValue(null)
    public writeFile = vi.fn().mockResolvedValue(null)

    public constructor(_host: string, config: unknown) {
      capturedConfigs.push(config)
    }
  }
}

function makeModuleWithMeta(metaEntries: ModuleMetaEntry[]): Module {
  return {
    apply: vi
      .fn()
      .mockResolvedValue({ meta: metaEntries, status: "changed" } satisfies ModuleResult),
    check: vi.fn().mockResolvedValue("needs-apply"),
    name: "test-module",
  }
}

type MockChildProcess = {
  stderr?: EventEmitter
  stdin?: { end: ReturnType<typeof vi.fn> }
  stdout?: EventEmitter
} & EventEmitter

function createMockSpawnChild(stdout: string, exitCode = 0): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess
  child.stdout = new EventEmitter()
  child.stderr = new EventEmitter()
  child.stdin = { end: vi.fn() }

  queueMicrotask(() => {
    child.stdout?.emit("data", Buffer.from(stdout))
    child.emit("close", exitCode)
  })

  return child
}

// Bug regression: failed reconnect after port change or reboot must propagate and abort playbook
describe("runPlaybook reconnect failure propagation", () => {
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
  })

  it("propagates reconnect failure after port change (meta sshd.port) and records status failed", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Connection timed out after port change")

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(2222)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortChange],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
    process.exitCode = 0
  })

  it("propagates reconnect failure after reboot (meta system.reboot) and records status failed", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Host unreachable after reboot")

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
    process.exitCode = 0
  })

  it("stops processing subsequent modules when reconnect fails after port change", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Connection refused")

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(2222)])
    const subsequentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortChange, subsequentModule],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(subsequentModule.check).not.toHaveBeenCalled()
    process.exitCode = 0
  })

  it("stops processing subsequent modules when reconnect fails after reboot", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Host unreachable")

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])
    const subsequentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot, subsequentModule],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(subsequentModule.check).not.toHaveBeenCalled()
    process.exitCode = 0
  })
})

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
    process.exitCode = 0
  })
})

// Bug regression: when sshd.port and system.reboot are both set, reconnect must only be called once
describe("runPlaybook handlePortChange + handleReboot interaction", () => {
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
  })

  it("calls addPort but skips port-change reconnect when system.reboot is also set, resulting in exactly one reconnect", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortAndReboot = makeModuleWithMeta([meta.sshdPort(2222), meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortAndReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // reconnect is called exactly once (by the reboot handler, not the port-change handler)
    expect(reconnect).toHaveBeenCalledTimes(1)
    process.exitCode = 0
  })

  it("calls reconnect exactly once when only sshd.port is set (no reboot)", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortOnly = makeModuleWithMeta([meta.sshdPort(2222)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortOnly],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // reconnect is called exactly once by the port-change handler
    expect(reconnect).toHaveBeenCalledTimes(1)
    process.exitCode = 0
  })
})

describe("runPlaybook recipe child control-plane processing", () => {
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

  it("processes recipe child sshd.port meta before the next child starts", async () => {
    const capturedConfigs: unknown[] = []
    const addPort = vi.fn()
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { addPort, reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const portChangingChild: Module = {
      apply: vi.fn().mockResolvedValue({
        meta: [meta.sshdPort(2222)],
        status: "changed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "port-change-child",
    }
    const secondChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(() => {
        expect(addPort).toHaveBeenCalledWith(2222)
        expect(reconnect).toHaveBeenCalledTimes(1)
        return "ok"
      }),
      name: "second-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [createRecipe("test-recipe", [portChangingChild, secondChild])],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(secondChild.check).toHaveBeenCalledOnce()
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  it("processes recipe child reboot meta before the next child starts", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)
    const updateHost = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { reconnect, updateHost }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const rebootingChild: Module = {
      apply: vi.fn().mockResolvedValue({
        meta: [meta.systemHost("10.0.0.42"), meta.systemReboot()],
        status: "changed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "reboot-child",
    }
    const secondChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(() => {
        expect(updateHost).toHaveBeenCalledWith("10.0.0.42")
        expect(reconnect).toHaveBeenCalledTimes(1)
        return "ok"
      }),
      name: "post-reboot-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [createRecipe("test-recipe", [rebootingChild, secondChild])],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(secondChild.check).toHaveBeenCalledOnce()
    expect(updateHost).toHaveBeenCalledWith("10.0.0.42")
    expect(reconnect).toHaveBeenCalledTimes(1)
  })
})

// Bug regression: exceptions thrown by recipeModule.apply() must not crash the playbook run
describe("runPlaybook recipe exception handling", () => {
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
  })

  it("does not crash when recipe apply() throws, records status as failed and sets exitCode to 1", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const throwingRecipe = {
      _isRecipe: true as const,
      _modules: [],
      apply: vi.fn().mockRejectedValue(new Error("recipe internal failure")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "throwing-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [throwingRecipe],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(process.exitCode).toBe(1)
    process.exitCode = 0
  })

  it("calls printCommandError (outputs to console.log) when recipe apply() throws with a non-empty error message", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const consoleLogs: unknown[][] = []
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args)
    })

    const { runPlaybook } = await import("../src/runner.js")

    const recipeError = new Error("recipe internal failure")
    const throwingRecipe = {
      _isRecipe: true as const,
      _modules: [],
      apply: vi.fn().mockRejectedValue(recipeError),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "throwing-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [throwingRecipe],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    // printCommandError uses console.log to output the error message
    const allLogOutput = consoleLogs.flat().join(" ")
    expect(allLogOutput).toContain("recipe internal failure")
    process.exitCode = 0
  })

  it("stops processing subsequent modules when recipe apply() throws", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const throwingRecipe = {
      _isRecipe: true as const,
      _modules: [],
      apply: vi.fn().mockRejectedValue(new Error("recipe boom")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "throwing-recipe",
    }

    const subsequentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [throwingRecipe, subsequentModule],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(subsequentModule.check).not.toHaveBeenCalled()
    process.exitCode = 0
  })
})

// Signal handling: graceful shutdown on SIGINT / SIGTERM
describe("runPlaybook signal handling", () => {
  let capturedConfigs: unknown[]
  let disconnectFn: ReturnType<typeof vi.fn>

  beforeEach(() => {
    capturedConfigs = []
    disconnectFn = vi.fn()
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

  it("registers SIGINT and SIGTERM listeners during runPlaybook and removes them after completion", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const interruptListenersBefore = process.listenerCount("SIGINT")
    const terminateListenersBefore = process.listenerCount("SIGTERM")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.listenerCount("SIGINT")).toBe(interruptListenersBefore)
    expect(process.listenerCount("SIGTERM")).toBe(terminateListenersBefore)
  })

  it("calls ssh.disconnect() and sets exitCode to 130 when SIGINT is received during runPlaybook", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const slowModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi
        .fn()
        .mockImplementationOnce(async () => {
          await Promise.resolve()
          process.emit("SIGINT", "SIGINT")
          return "needs-apply" as const
        })
        .mockResolvedValue("needs-apply"),
      name: "slow-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [slowModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(130)
    // disconnect is called by the signal handler and again in the finally block
    expect(disconnectFn).toHaveBeenCalled()
  })

  it("sets exitCode to 143 when SIGTERM is received during runPlaybook", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const slowModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi
        .fn()
        .mockImplementationOnce(async () => {
          await Promise.resolve()
          process.emit("SIGTERM", "SIGTERM")
          return "needs-apply" as const
        })
        .mockResolvedValue("needs-apply"),
      name: "slow-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [slowModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(143)
  })

  it("does not run signals when a shutdown signal was received before signal execution", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const changingModule: Module = {
      apply: vi
        .fn()
        .mockImplementationOnce(async () => {
          await Promise.resolve()
          process.emit("SIGINT", "SIGINT")
          return { status: "changed" } satisfies ModuleResult
        })
        .mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }

    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(signalModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(130)
  })

  it("does not count an interrupt during a running module as a regular failure in stats or summary", async () => {
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")

    const interruptedModule: Module = {
      apply: vi.fn().mockImplementationOnce(async () => {
        await Promise.resolve()
        process.emit("SIGINT", "SIGINT")
        throw new Error("socket closed during shutdown")
      }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "interrupted-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [interruptedModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const output = consoleLogs.join("\n")
    expect(output).toContain("0 failed")
    expect(output).not.toContain("interrupted-module")
    expect(process.exitCode).toBe(130)
  })

  it("does not count an interrupt during a running recipe as a regular failure in stats or summary", async () => {
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")

    const interruptedRecipe = {
      _isRecipe: true as const,
      _modules: [],
      apply: vi.fn().mockImplementationOnce(async () => {
        await Promise.resolve()
        process.emit("SIGTERM", "SIGTERM")
        throw new Error("recipe transport closed during shutdown")
      }),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "interrupted-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [interruptedRecipe],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const output = consoleLogs.join("\n")
    expect(output).toContain("0 failed")
    expect(output).not.toContain("interrupted-recipe")
    expect(process.exitCode).toBe(143)
  })

  it("does not run top-level signals when the module loop ended with both changed and failed results", async () => {
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

    const failingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "failed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-module",
    }

    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule, failingModule],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(changingModule.apply).toHaveBeenCalledOnce()
    expect(failingModule.apply).toHaveBeenCalledOnce()
    expect(signalModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })

  it.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "does not start further signal modules when %s is received during signal execution",
    async (signalName, expectedExitCode) => {
      vi.doMock("../src/ssh.js", () => ({
        shellQuote: (s: string) => `'${s}'`,
        SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
      }))

      const { runPlaybook } = await import("../src/runner.js")

      const changingModule: Module = {
        apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
        check: vi.fn().mockResolvedValue("needs-apply"),
        name: "changing-module",
      }

      const firstSignal: Module = {
        apply: vi.fn().mockImplementationOnce(async () => {
          await Promise.resolve()
          process.emit(signalName, signalName)
          return { status: "changed" } satisfies ModuleResult
        }),
        check: vi.fn().mockResolvedValue("needs-apply"),
        name: "first-signal",
      }

      const secondSignal: Module = {
        apply: vi.fn(),
        check: vi.fn(),
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

      expect(firstSignal.apply).toHaveBeenCalledOnce()
      expect(secondSignal.apply).not.toHaveBeenCalled()
      expect(process.exitCode).toBe(expectedExitCode)
      expect(disconnectFn).toHaveBeenCalled()
    }
  )

  it("does not set signal exitCode when runPlaybook completes normally without any signal", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // no signal received — exitCode should not be set to a signal exit code
    expect(process.exitCode).toBe(0)
  })

  it("aborts the module loop and sets exitCode to 130 when SIGINT is received during reconnect", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        reconnect: vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          process.emit("SIGINT", "SIGINT")
          throw new Error("Reconnect interrupted by signal")
        }),
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(2222)])
    const subsequentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortChange, subsequentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // Signal exit code 130 takes precedence over module failure exit code 1
    expect(process.exitCode).toBe(130)
    expect(moduleWithPortChange.apply).toHaveBeenCalledOnce()
    expect(subsequentModule.check).not.toHaveBeenCalled()
    expect(disconnectFn).toHaveBeenCalled()
  })

  // Unlike "does not run signals" above which tests the shutdownSignal() guard
  // before runSignals (runner.ts L393), this tests the guard at the TOP of the
  // module for-loop (runner.ts L292) — ensuring the next run[] module is never started.
  it("skips remaining modules when shutdown signal was received during a successful module", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect: disconnectFn }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const module1: Module = {
      apply: vi.fn().mockImplementationOnce(async () => {
        await Promise.resolve()
        process.emit("SIGINT", "SIGINT")
        return { status: "changed" } satisfies ModuleResult
      }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "successful-module",
    }

    const module2: Module = {
      apply: vi.fn(),
      check: vi.fn(),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [module1, module2],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // Module 1 ran to completion (apply returned successfully)
    expect(module1.apply).toHaveBeenCalledOnce()
    // Module 2 was never started — shutdownSignal() check at loop start prevented it
    expect(module2.check).not.toHaveBeenCalled()
    expect(module2.apply).not.toHaveBeenCalled()
    // Signal exit code is set
    expect(process.exitCode).toBe(130)
    // SSH connection was disconnected
    expect(disconnectFn).toHaveBeenCalled()
  })
})

describe("runPlaybook failed result diagnostics", () => {
  beforeEach(() => {
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

  it("prints centralized diagnostics for a module that returns failed with an error payload", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const [{ runPlaybook }, { CommandError }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/sshHelpers.js"),
    ])

    const failingModule: Module = {
      apply: vi.fn().mockResolvedValue({
        error: new CommandError("module failed summary", "full stdout", "full stderr"),
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [failingModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(consoleLogs.join("\n")).toContain("module failed summary")
    expect(process.exitCode).toBe(1)
  })

  it("prints centralized diagnostics for failed signals and shows verbose output when requested", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const [{ runPlaybook }, { CommandError }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/sshHelpers.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-module",
    }
    const failingSignal: Module = {
      apply: vi.fn().mockResolvedValue({
        error: new CommandError("signal failed summary", "signal stdout", "signal stderr"),
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changedModule],
      signals: [failingSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { verbose: true })

    const output = consoleLogs.join("\n")
    expect(output).toContain("signal failed summary")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("signal stderr")
    expect(output).toContain("Full stdout:")
    expect(output).toContain("signal stdout")
    expect(process.exitCode).toBe(1)
  })

  it("prints verbose diagnostics for failed recipe signals with the same output path as top-level signals", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const [{ runPlaybook }, { recipe }, { CommandError }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/recipe.js"),
      import("../src/sshHelpers.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-module",
    }
    const failingSignal: Module = {
      apply: vi.fn().mockResolvedValue({
        error: new CommandError(
          "recipe signal failed summary",
          "recipe signal stdout",
          "recipe signal stderr"
        ),
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-recipe-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("test-recipe", [changedModule], { signals: [failingSignal] })],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { verbose: true })

    const output = consoleLogs.join("\n")
    expect(output).toContain("recipe signal failed summary")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("recipe signal stderr")
    expect(output).toContain("Full stdout:")
    expect(output).toContain("recipe signal stdout")
    expect(process.exitCode).toBe(1)
  })

  it("counts recipe signals in the summary with the same semantics as top-level signals", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const [{ runPlaybook }, { recipe }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/recipe.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-module",
    }
    const changedSignal: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-recipe-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("test-recipe", [changedModule], { signals: [changedSignal] })],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(consoleLogs.join("\n")).toContain("1 signals triggered")
  })
})

// Bug #12 regression: runPlaybook must pass reconnectTimeout from RunOptions into SshConfig
describe("runPlaybook reconnectTimeout", () => {
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
  })

  it("passes reconnectTimeout from RunOptions into SshConfig when provided", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition, { reconnectTimeout: 42_000 })

    expect(capturedConfigs).toHaveLength(1)
    expect(capturedConfigs[0]).toMatchObject({ reconnectTimeout: 42_000 })
  })

  it("uses definition.ssh as-is when reconnectTimeout is not provided in RunOptions", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const sshConfig = {
      ports: [22],
      privateKey: "~/.ssh/id",
      user: "root",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: sshConfig,
    }

    await runPlaybook(definition)

    expect(capturedConfigs).toHaveLength(1)
    // When no reconnectTimeout in options, the original sshConfig object is passed unchanged
    expect(capturedConfigs[0]).toBe(sshConfig)
  })
})

// Bug regression: SIGINT/SIGTERM handlers must be cleaned up even when createSshConnection() throws
describe("runPlaybook shutdown handler leak on SSH connection failure", () => {
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

  it("does not leak SIGINT/SIGTERM listeners when createSshConnection throws (connect fails)", async () => {
    // createSshConnection() is called BEFORE the try block in runPlaybook().
    // When ssh.connect() throws, the finally block (which removes the listeners)
    // is never reached. This test documents the handler leak bug.
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockFailingConnection {
        public connect = vi.fn().mockRejectedValue(new Error("Connection refused"))
        public disconnect = vi.fn()
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const sigintBefore = process.listenerCount("SIGINT")
    const sigtermBefore = process.listenerCount("SIGTERM")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    // runPlaybook throws because createSshConnection throws
    await expect(runPlaybook(definition)).rejects.toThrow("Connection refused")

    // The SIGINT/SIGTERM listeners registered by setupShutdownHandlers() must be
    // removed even when createSshConnection() fails. Currently this does NOT happen
    // because createSshConnection() is outside the try block, so the finally block
    // with process.removeListener() is never reached.
    expect(process.listenerCount("SIGINT")).toBe(sigintBefore)
    expect(process.listenerCount("SIGTERM")).toBe(sigtermBefore)
  })

  it("does not leak SIGINT/SIGTERM listeners when probeSudo throws after connect succeeds", async () => {
    // Same bug: probeSudo() is also called inside createSshConnection(), still
    // before the try block. A failure there equally bypasses the finally cleanup.
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockProbeSudoFailing {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = vi.fn()
        public probeSudo = vi.fn().mockRejectedValue(new Error("sudo probe failed"))
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const sigintBefore = process.listenerCount("SIGINT")
    const sigtermBefore = process.listenerCount("SIGTERM")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).rejects.toThrow("sudo probe failed")

    expect(process.listenerCount("SIGINT")).toBe(sigintBefore)
    expect(process.listenerCount("SIGTERM")).toBe(sigtermBefore)
  })

  it("disconnects and sets signal exitCode when SIGINT arrives during connect", async () => {
    const disconnect = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockConnectInterrupted {
        public connect = vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          process.emit("SIGINT", "SIGINT")
          throw new Error("connect interrupted")
        })
        public disconnect = disconnect
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(disconnect).toHaveBeenCalled()
    expect(process.exitCode).toBe(130)
  })

  it("disconnects and sets signal exitCode when SIGTERM arrives during probeSudo", async () => {
    const disconnect = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockProbeInterrupted {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = disconnect
        public probeSudo = vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          process.emit("SIGTERM", "SIGTERM")
          throw new Error("probe interrupted")
        })
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(disconnect).toHaveBeenCalled()
    expect(process.exitCode).toBe(143)
  })
})

// Bug regression: recipes must NOT apply() child modules in dry-run mode, only check()
describe("runPlaybook dry-run recipe behaviour", () => {
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

  it("does not call apply() on any child module when a recipe runs in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const childModule1: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "child-module-1",
    }
    const childModule2: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "child-module-2",
    }

    const recipeModule = {
      _isRecipe: true as const,
      _modules: [childModule1, childModule2],
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "test-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipeModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(childModule1.apply).not.toHaveBeenCalled()
    expect(childModule2.apply).not.toHaveBeenCalled()
  })

  it("calls check() on every child module when a recipe runs in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const childModule1: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "child-module-1",
    }
    const childModule2: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "child-module-2",
    }

    const recipeModule = {
      _isRecipe: true as const,
      _modules: [childModule1, childModule2],
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "test-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipeModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(childModule1.check).toHaveBeenCalledOnce()
    expect(childModule2.check).toHaveBeenCalledOnce()
  })

  it("outputs (dry-run) suffix in console log when a child module needs-apply in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const consoleLogs: unknown[][] = []
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args)
    })

    const { runPlaybook } = await import("../src/runner.js")

    const childModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "pending-child-module",
    }

    const recipeModule = {
      _isRecipe: true as const,
      _modules: [childModule],
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "test-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipeModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    const allLogOutput = consoleLogs.flat().join(" ")
    expect(allLogOutput).toContain("(dry-run)")
  })

  it("treats top-level fail() as a blocker in dry-run mode and stops the remaining run modules", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { fail }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const laterModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [fail("stop here"), laterModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(laterModule.check).not.toHaveBeenCalled()
    expect(laterModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })

  it("treats recipe child assert() as a blocker in dry-run mode and stops later recipe children", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { assert }, { recipe }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
      import("../src/recipe.js"),
    ])

    const laterChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("test-recipe", [assert(() => false, "must pass"), laterChild])],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(laterChild.check).not.toHaveBeenCalled()
    expect(laterChild.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })
})

// Bug: modules with local: true receive an SSH connection instead of null
describe("runPlaybook local module behaviour", () => {
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

  it("calls check() with null as ssh parameter when module has local: true", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    let capturedSshInCheck: unknown = "NOT_SET"
    const localModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (ssh: unknown) => {
        await Promise.resolve()
        capturedSshInCheck = ssh
        return "ok" as const
      }),
      local: true,
      name: "local-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [localModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // A local module must receive null instead of an SSH connection
    expect(capturedSshInCheck).toBeNull()
  })

  it("calls apply() with null as ssh parameter when module has local: true", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    let capturedSshInApply: unknown = "NOT_SET"
    const localModule: Module = {
      apply: vi.fn().mockImplementation(async (ssh: unknown) => {
        await Promise.resolve()
        capturedSshInApply = ssh
        return { status: "changed" } satisfies ModuleResult
      }),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      local: true,
      name: "local-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [localModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // A local module must receive null instead of an SSH connection
    expect(capturedSshInApply).toBeNull()
  })
})

// Bug regression: local: true in signal modules must receive null instead of ssh
describe("runPlaybook local signal module behaviour", () => {
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

  it("calls signal apply() with null as ssh parameter when signal module has local: true", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    let capturedSshInSignalApply: unknown = "NOT_SET"
    const localSignal: Module = {
      apply: vi.fn().mockImplementation(async (ssh: unknown) => {
        await Promise.resolve()
        capturedSshInSignalApply = ssh
        return { status: "ok" } satisfies ModuleResult
      }),
      check: vi.fn().mockResolvedValue("ok" as const),
      local: true,
      name: "local-signal",
    }

    // A module that produces a change triggers signals execution
    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "changing-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [localSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // A local signal module must receive null instead of an SSH connection
    expect(capturedSshInSignalApply).toBeNull()
  })
})

describe("runPlaybook op.resolve integration", () => {
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

  it("executes op.resolve and propagates its meta values to following modules", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => createMockSpawnChild(JSON.stringify({ SECRET: "resolved-secret" }))),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
    ])

    let receivedEnvInCheck: Environment | undefined
    const dependentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (_ssh, env: Environment) => {
        await Promise.resolve()
        receivedEnvInCheck = env
        return "ok" as const
      }),
      name: "dependent-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [op.resolve({ SECRET: "op://vault/item/password" }), dependentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(receivedEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(receivedEnvInCheck!, "SECRET")).resolves.toBe("resolved-secret")
    expect(dependentModule.apply).not.toHaveBeenCalled()
  })
})

describe("runPlaybook rsync check error handling", () => {
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

  it("marks the run as failed when rsync check throws instead of masking it as needs-apply", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLog = vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })

    vi.doMock("node:child_process", () => ({
      execFile: vi.fn(
        (
          _file: string,
          _args: readonly string[],
          callback: (error: Error, stdout: string, stderr: string) => void
        ) => {
          const error = Object.assign(new Error("rsync failed"), {
            code: 23,
            stderr: "Permission denied (publickey).",
            stdout: "",
          })
          callback(error, "", "Permission denied (publickey).")
        }
      ),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { rsync }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/rsync.js"),
    ])

    const subsequentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok" as const),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [rsync.sync({ dest: "/remote/dest", src: "/local/src" }), subsequentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(subsequentModule.check).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
    expect(consoleLog).toHaveBeenCalledWith(
      expect.stringContaining(
        "[rsync.sync] check failed for /local/src -> /remote/dest (exit code 23)"
      )
    )
    expect(consoleLog).toHaveBeenCalledWith(
      expect.stringContaining("Permission denied (publickey).")
    )
  })
})

// Bug regression: stats.incrementSignals() must be called even when signal apply() throws,
// so that failed signals are counted in the summary (not only successful ones)
describe("runPlaybook runSignals stats.incrementSignals on failure", () => {
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

  it("increments stats.signals even when signal apply() throws an exception", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const consoleLogs: unknown[][] = []
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args)
    })

    const { runPlaybook } = await import("../src/runner.js")

    const failingSignal: Module = {
      apply: vi.fn().mockRejectedValue(new Error("signal apply failure")),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "failing-signal",
    }

    // A module that produces a change so that signals are executed
    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "changing-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [failingSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // printSummary outputs "N signals triggered" — verify the count is 1, not 0
    const allLogOutput = consoleLogs.flat().join(" ")
    expect(allLogOutput).toContain("1 signals triggered")
  })
})

// Bug regression: local: true in dry-run recipe child modules must receive null instead of ssh
describe("runPlaybook local module in dry-run recipe behaviour", () => {
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

  it("calls check() with null as ssh parameter when a dry-run recipe child module has local: true", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    let capturedSshInCheck: unknown = "NOT_SET"
    const localChildModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (ssh: unknown) => {
        await Promise.resolve()
        capturedSshInCheck = ssh
        return "needs-apply" as const
      }),
      local: true,
      name: "local-child-module",
    }

    const recipeModule = {
      _isRecipe: true as const,
      _modules: [localChildModule],
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "test-recipe",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipeModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    // A local child module in a dry-run recipe must receive null instead of an SSH connection
    expect(capturedSshInCheck).toBeNull()
  })
})

// Bug regression: runSignals() must update stats.failed on exception and { status: "failed" } returns
describe("runSignals stats tracking", () => {
  let capturedConfigs: unknown[]

  beforeEach(() => {
    capturedConfigs = []
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

  it("increments stats.failed and sets exitCode to 1 when a signal module throws an exception", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    // A run[] module that returns "changed" is required to trigger runSignals()
    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }

    const throwingSignal: Module = {
      apply: vi.fn().mockRejectedValue(new Error("signal module crashed")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "throwing-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [throwingSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
  })

  it("increments stats.failed and sets exitCode to 1 when a signal module returns { status: 'failed' }", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    // A run[] module that returns "changed" is required to trigger runSignals()
    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }

    const failingSignal: Module = {
      apply: vi.fn().mockResolvedValue({ status: "failed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [failingSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
  })

  it("increments stats.changed and does not set exitCode to 1 when a signal module returns { status: 'changed' }", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    // A run[] module that returns "changed" is required to trigger runSignals()
    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changing-module",
    }

    const successSignal: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "success-signal",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [successSignal],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // No failure — exitCode must not be set to 1
    expect(process.exitCode).toBe(0)
    // The signal module result "changed" must be reflected in the summary stats
    expect(successSignal.apply).toHaveBeenCalledOnce()
  })
})

// Bug regression: CLI --env overrides (options.envOverrides) must take priority over definition.env
describe("runPlaybook environment merge priority", () => {
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

  it("envOverrides (CLI --env) wins over definition.env when both set the same key", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    let capturedEnv: Record<string, unknown> = {}
    const probeModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation((_ssh: unknown, env: Record<string, unknown>) => {
        capturedEnv = env
      }),
      name: "env-probe",
    }

    const definition: ServerDefinition = {
      env: { APP_ENV: "from-definition" },
      host: "1.2.3.4",
      name: "test-server",
      run: [probeModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { envOverrides: { APP_ENV: "from-cli-override" } })

    expect(capturedEnv.APP_ENV).toBe("from-cli-override")
  })
})

describe("runPlaybook happy-path lifecycle (check → apply → signals)", () => {
  let capturedConfigs: unknown[]

  beforeEach(() => {
    capturedConfigs = []
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

  it("calls check on every module, applies only needs-apply modules, triggers signals, and exits cleanly", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const alreadyOkModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "already-ok",
    }

    const needsApplyModule1: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "needs-apply-1",
    }

    const needsApplyModule2: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "needs-apply-2",
    }

    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "restart-service",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [alreadyOkModule, needsApplyModule1, needsApplyModule2],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // check() called on every run[] module
    expect(alreadyOkModule.check).toHaveBeenCalledOnce()
    expect(needsApplyModule1.check).toHaveBeenCalledOnce()
    expect(needsApplyModule2.check).toHaveBeenCalledOnce()

    // apply() skipped for "ok" module, called for "needs-apply" modules
    expect(alreadyOkModule.apply).not.toHaveBeenCalled()
    expect(needsApplyModule1.apply).toHaveBeenCalledOnce()
    expect(needsApplyModule2.apply).toHaveBeenCalledOnce()

    // signals triggered because stats.changed > 0
    expect(signalModule.apply).toHaveBeenCalledOnce()

    // exitCode stays 0 — no failures
    expect(process.exitCode).toBe(0)
  })

  it("does not trigger signals when all modules return ok from check", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const okModule1: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "ok-1",
    }

    const okModule2: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "ok-2",
    }

    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "should-not-run",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [okModule1, okModule2],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // No apply calls since everything is ok
    expect(okModule1.apply).not.toHaveBeenCalled()
    expect(okModule2.apply).not.toHaveBeenCalled()

    // Signals NOT triggered because stats.changed === 0
    expect(signalModule.apply).not.toHaveBeenCalled()

    expect(process.exitCode).toBe(0)
  })
})
