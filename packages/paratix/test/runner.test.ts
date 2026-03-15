import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ModuleResult, ServerDefinition } from "../src/types.js"

function makeMockSshClass(capturedConfigs: unknown[]) {
  return class MockSshConnectionImpl {
    public addPort = vi.fn()
    public connect = vi.fn().mockResolvedValue(null)
    public disconnect = vi.fn()
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
    public reconnect = vi.fn().mockResolvedValue(null)
    public sha256 = vi.fn().mockResolvedValue(null)
    public test = vi.fn().mockResolvedValue(true)
    public updateHost = vi.fn()
    public uploadFile = vi.fn().mockResolvedValue(null)
    public writeFile = vi.fn().mockResolvedValue(null)

    public constructor(_host: string, config: unknown) {
      capturedConfigs.push(config)
    }
  }
}

function makeMockSshClassWithReconnectFailure(capturedConfigs: unknown[], reconnectError: Error) {
  return class MockSshConnectionWithFailureImpl {
    public addPort = vi.fn()
    public connect = vi.fn().mockResolvedValue(null)
    public disconnect = vi.fn()
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
    public reconnect = vi.fn().mockRejectedValue(reconnectError)
    public sha256 = vi.fn().mockResolvedValue(null)
    public test = vi.fn().mockResolvedValue(true)
    public updateHost = vi.fn()
    public uploadFile = vi.fn().mockResolvedValue(null)
    public writeFile = vi.fn().mockResolvedValue(null)

    public constructor(_host: string, config: unknown) {
      capturedConfigs.push(config)
    }
  }
}

function makeModuleWithMeta(meta: Record<string, string>): Module {
  return {
    apply: vi.fn().mockResolvedValue({ meta, status: "changed" } satisfies ModuleResult),
    check: vi.fn().mockResolvedValue("needs-apply"),
    name: "test-module",
  }
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
      SshConnectionImpl: makeMockSshClassWithReconnectFailure(capturedConfigs, reconnectError),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta({ "sshd.port": "2222" })

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
      SshConnectionImpl: makeMockSshClassWithReconnectFailure(capturedConfigs, reconnectError),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithReboot = makeModuleWithMeta({ "system.reboot": "true" })

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
      SshConnectionImpl: makeMockSshClassWithReconnectFailure(capturedConfigs, reconnectError),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta({ "sshd.port": "2222" })
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
      SshConnectionImpl: makeMockSshClassWithReconnectFailure(capturedConfigs, reconnectError),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithReboot = makeModuleWithMeta({ "system.reboot": "true" })
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

  it("calls printError (outputs to console.log) when recipe apply() throws with a non-empty error message", async () => {
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

    // printError uses console.log to output the error message
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

  function makeMockSshClassWithDisconnectCapture(
    configs: unknown[],
    disconnectMock: ReturnType<typeof vi.fn>
  ) {
    return class MockSshConnectionWithDisconnectCapture {
      public addPort = vi.fn()
      public connect = vi.fn().mockResolvedValue(null)
      public disconnect = disconnectMock
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
      public reconnect = vi.fn().mockResolvedValue(null)
      public sha256 = vi.fn().mockResolvedValue(null)
      public test = vi.fn().mockResolvedValue(true)
      public updateHost = vi.fn()
      public uploadFile = vi.fn().mockResolvedValue(null)
      public writeFile = vi.fn().mockResolvedValue(null)

      public constructor(_host: string, config: unknown) {
        configs.push(config)
      }
    }
  }

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
      SshConnectionImpl: makeMockSshClassWithDisconnectCapture(capturedConfigs, disconnectFn),
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
      SshConnectionImpl: makeMockSshClassWithDisconnectCapture(capturedConfigs, disconnectFn),
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
      SshConnectionImpl: makeMockSshClassWithDisconnectCapture(capturedConfigs, disconnectFn),
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
      SshConnectionImpl: makeMockSshClassWithDisconnectCapture(capturedConfigs, disconnectFn),
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

  it("does not set signal exitCode when runPlaybook completes normally without any signal", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClassWithDisconnectCapture(capturedConfigs, disconnectFn),
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
