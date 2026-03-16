import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ModuleResult, ServerDefinition } from "../src/types.js"

function makeMockSshClass(
  capturedConfigs: unknown[],
  overrides?: { disconnect?: ReturnType<typeof vi.fn>; reconnect?: ReturnType<typeof vi.fn> }
) {
  return class MockSshConnectionImpl {
    public addPort = vi.fn()
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
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
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // Signal exit code 130 takes precedence over module failure exit code 1
    expect(process.exitCode).toBe(130)
    expect(moduleWithPortChange.apply).toHaveBeenCalledOnce()
    expect(subsequentModule.check).not.toHaveBeenCalled()
    expect(disconnectFn).toHaveBeenCalled()
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
