import { EventEmitter } from "node:events"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type {
  Environment,
  Module,
  ModuleMetaEntry,
  ModuleResult,
  ServerDefinition,
  SshConnection,
} from "../src/types.js"

import { resolveEnvironment } from "../src/environment.js"
import { meta } from "../src/meta.js"
import { recipe as createRecipe } from "../src/recipe.js"

function makeMockSshClass(
  capturedConfigs: unknown[],
  overrides?: {
    addPort?: ReturnType<typeof vi.fn>
    disconnect?: ReturnType<typeof vi.fn>
    exec?: ReturnType<typeof vi.fn>
    output?: ReturnType<typeof vi.fn>
    readFile?: ReturnType<typeof vi.fn>
    reconnect?: ReturnType<typeof vi.fn>
    updateHost?: ReturnType<typeof vi.fn>
    writeFile?: ReturnType<typeof vi.fn>
  }
) {
  return class MockSshConnectionImpl {
    public addPort = overrides?.addPort ?? vi.fn()
    public connect = vi.fn().mockResolvedValue(null)
    public disconnect = overrides?.disconnect ?? vi.fn()
    public downloadFile = vi.fn().mockResolvedValue(null)
    public exec = overrides?.exec ?? vi.fn().mockResolvedValue({ code: 0, stderr: "", stdout: "" })
    public exists = vi.fn().mockResolvedValue(true)
    public getConnectionInfo = vi
      .fn()
      .mockReturnValue({ host: "1.2.3.4", port: 22, privateKeyPath: "~/.ssh/id", user: "root" })
    public lines = vi.fn().mockResolvedValue([])
    public output = overrides?.output ?? vi.fn().mockResolvedValue("")
    public probeSudo = vi.fn().mockResolvedValue(null)
    public readFile = overrides?.readFile ?? vi.fn().mockResolvedValue("")
    public reconnect = overrides?.reconnect ?? vi.fn().mockResolvedValue(null)
    public sha256 = vi.fn().mockResolvedValue(null)
    public test = vi.fn().mockResolvedValue(true)
    public updateHost = overrides?.updateHost ?? vi.fn()
    public uploadFile = vi.fn().mockResolvedValue(null)
    public writeFile = overrides?.writeFile ?? vi.fn().mockResolvedValue(null)

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

function createSuccessfulSshdDryRunExecMock() {
  return vi.fn().mockResolvedValue({ code: 0, stderr: "", stdout: "" })
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

  it("prints exactly one final failed status when reconnect after port change fails", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const reconnectError = new Error("Connection timed out after port change")

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        reconnect: vi.fn().mockRejectedValue(reconnectError),
      }),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(2222)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortChange],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const statusLines = consoleLogs.filter((line) => line.includes("test-module"))
    expect(statusLines).toHaveLength(1)
    expect(statusLines[0]).toContain("failed")
    expect(statusLines[0]).not.toContain("changed")
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

  it("starts a spinner for a top-level recipe before running its check", async () => {
    const capturedConfigs: unknown[] = []
    const outputModule = await import("../src/output.js")
    const startModuleSpinner = vi
      .spyOn(outputModule, "startModuleSpinner")
      .mockImplementation(() => {
        void 0
      })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (value: string) => `'${value}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const childModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" }),
      check: vi.fn().mockResolvedValue("ok"),
      name: "first-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [createRecipe("bootstrap", [childModule])],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(startModuleSpinner).toHaveBeenCalledWith("bootstrap")
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
    process.exitCode = 0
  })
})

describe("runPlaybook SSH config immutability", () => {
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

  it("does not mutate definition.ssh during runtime port and host updates", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const sshConfig = {
      expectedHostFingerprint: "SHA256:trusted-fingerprint",
      ports: [22],
      privateKey: "~/.ssh/id",
      reconnectTimeout: 30_000,
      strictHostKeyChecking: "yes" as const,
      user: "root",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        makeModuleWithMeta([meta.sshdPort(2222)]),
        makeModuleWithMeta([meta.systemHost("10.0.0.42"), meta.systemReboot()]),
      ],
      ssh: sshConfig,
    }

    await runPlaybook(definition)

    expect(definition.host).toBe("1.2.3.4")
    expect(definition.ssh).toStrictEqual({
      expectedHostFingerprint: "SHA256:trusted-fingerprint",
      ports: [22],
      privateKey: "~/.ssh/id",
      reconnectTimeout: 30_000,
      strictHostKeyChecking: "yes",
      user: "root",
    })
    expect(definition.ssh.ports).toStrictEqual([22])
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

  it("writes recipe apply() throw diagnostics to stderr when the error message is non-empty", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const consoleErrors: unknown[][] = []
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args)
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

    const allErrorOutput = consoleErrors.flat().join(" ")
    expect(allErrorOutput).toContain("recipe internal failure")
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

  it("logs the concrete recipe child module name when child check() throws during runPlaybook", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }, { recipe }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/recipe.js"),
    ])

    const throwingChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockRejectedValue(new Error("recipe child check exploded")),
      name: "throwing-child-check",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("test-recipe", [throwingChild])],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(consoleLogs.join("\n")).toContain("test-recipe")
    expect(consoleErrors.join("\n")).toContain("throwing-child-check")
    expect(consoleErrors.join("\n")).toContain("recipe child check exploded")
    expect(process.exitCode).toBe(1)
    process.exitCode = 0
  })

  it("logs the concrete recipe child module name when child apply() throws during runPlaybook", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }, { recipe }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/recipe.js"),
    ])

    const throwingChild: Module = {
      apply: vi.fn().mockRejectedValue(new Error("recipe child apply exploded")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "throwing-child-apply",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("test-recipe", [throwingChild])],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(consoleLogs.join("\n")).toContain("throwing-child-apply")
    expect(consoleErrors.join("\n")).toContain("recipe child apply exploded")
    expect(process.exitCode).toBe(1)
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
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
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

    expect(consoleErrors.join("\n")).toContain("module failed summary")
    expect(process.exitCode).toBe(1)
  })

  it("prints centralized diagnostics for a top-level module that now returns ModuleResult.error", async () => {
    const capturedConfigs: unknown[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec: vi.fn().mockResolvedValue({ code: 1, stderr: "permission denied", stdout: "" }),
      }),
    }))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }, { hostname }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/hostname.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [hostname.set("new-hostname")],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const output = consoleErrors.join("\n")
    expect(output).toContain("[hostname.set: new-hostname] hostnamectl set-hostname failed")
    expect(output).toContain("permission denied")
    expect(process.exitCode).toBe(1)
  })

  it("prints module name and a clear ssh.writeFile validation error for custom modules", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }] = await Promise.all([import("../src/runner.js")])

    const failingModule: Module = {
      apply: vi
        .fn()
        .mockRejectedValue(
          new Error(
            '[ssh.writeFile: /etc/custom.conf] missing options.mode; pass { mode: "0644" } or another explicit file mode'
          )
        ),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "custom-config-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [failingModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const output = [...consoleLogs, ...consoleErrors].join("\n")
    expect(output).toContain("custom-config-module")
    expect(output).toContain(
      '[ssh.writeFile: /etc/custom.conf] missing options.mode; pass { mode: "0644" } or another explicit file mode'
    )
    expect(output).not.toContain("Cannot read properties of undefined")
    expect(process.exitCode).toBe(1)
  })

  it("prints centralized diagnostics for a failed recipe child module with ModuleResult.error", async () => {
    const capturedConfigs: unknown[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec: vi.fn().mockResolvedValue({ code: 1, stderr: "permission denied", stdout: "" }),
      }),
    }))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }, { hostname }, { recipe }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/hostname.js"),
      import("../src/recipe.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("set-hostname", [hostname.set("recipe-hostname")])],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const output = consoleErrors.join("\n")
    expect(output).toContain("[hostname.set: recipe-hostname] hostnamectl set-hostname failed")
    expect(output).toContain("permission denied")
    expect(process.exitCode).toBe(1)
  })

  it("prints centralized diagnostics for failed signals and shows verbose output when requested", async () => {
    const capturedConfigs: unknown[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
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

    const output = consoleErrors.join("\n")
    expect(output).toContain("signal failed summary")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("signal stderr")
    expect(output).toContain("Full stdout:")
    expect(output).toContain("signal stdout")
    expect(process.exitCode).toBe(1)
  })

  it("prints full stack traces and causes for failed signals with plain Errors in verbose mode", async () => {
    const capturedConfigs: unknown[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }] = await Promise.all([import("../src/runner.js")])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-module",
    }
    const rootCause = new Error("root cause")
    rootCause.stack = "Error: root cause\n    at root.ts:3:3"
    const cause = new Error("inner cause", { cause: rootCause })
    cause.stack = "Error: inner cause\n    at inner.ts:2:2"
    const failingSignal: Module = {
      apply: vi.fn().mockResolvedValue({
        error: Object.assign(new Error("plain signal failure", { cause }), {
          stack: "Error: plain signal failure\n    at outer.ts:1:1",
        }),
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

    const output = consoleErrors.join("\n")
    expect(output).toContain("plain signal failure")
    expect(output).toContain("Full stack:")
    expect(output).toContain("at outer.ts:1:1")
    expect(output).toContain("Cause 1:")
    expect(output).toContain("inner cause")
    expect(output).toContain("Cause 2:")
    expect(output).toContain("root cause")
    expect(process.exitCode).toBe(1)
  })

  it("prints verbose diagnostics for failed recipe signals with the same output path as top-level signals", async () => {
    const capturedConfigs: unknown[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
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

    const output = consoleErrors.join("\n")
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

  it("passes a defensive copy of definition.ssh when reconnectTimeout is not provided in RunOptions", async () => {
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
    expect(capturedConfigs[0]).toStrictEqual(sshConfig)
    expect(capturedConfigs[0]).not.toBe(sshConfig)
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

  it("prints run context before connect failures", async () => {
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockFailingConnection {
        public connect = vi.fn().mockRejectedValue(new Error("Connection refused"))
        public disconnect = vi.fn()
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "10.0.0.5",
      name: "bootstrap-server",
      run: [],
      ssh: { ports: [22, 2222], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).rejects.toThrow("Connection refused")

    const output = consoleLogs.join("\n")
    expect(output).toContain("Run bootstrap-server")
    expect(output).toContain("host 10.0.0.5")
    expect(output).toContain("ports 22, 2222")
    expect(output).toContain("mode apply")
  })

  it("does not leak SIGINT/SIGTERM listeners when the first lazy sudo-required module step fails", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockLazySudoFailing {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = vi.fn()
        public exec = vi.fn().mockRejectedValue(new Error("sudo probe failed"))
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const sigintBefore = process.listenerCount("SIGINT")
    const sigtermBefore = process.listenerCount("SIGTERM")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        {
          apply: vi.fn(),
          check: vi.fn(async (ssh: null | SshConnection) => {
            await ssh?.exec("true")
            return "ok"
          }),
          name: "needs-sudo",
        },
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(process.listenerCount("SIGINT")).toBe(sigintBefore)
    expect(process.listenerCount("SIGTERM")).toBe(sigtermBefore)
    expect(process.exitCode).toBe(1)
  })

  it("prints run context before lazy sudo failures in the first module step", async () => {
    const consoleLogs: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockLazySudoFailing {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = vi.fn()
        public exec = vi.fn().mockRejectedValue(new Error("sudo probe failed"))
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "10.0.0.6",
      name: "sudo-server",
      run: [
        {
          apply: vi.fn(),
          check: vi.fn(async (ssh: null | SshConnection) => {
            await ssh?.exec("true")
            return "ok"
          }),
          name: "needs-sudo",
        },
      ],
      ssh: { ports: [2222], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    const output = consoleLogs.join("\n")
    expect(output).toContain("Run sudo-server")
    expect(output).toContain("host 10.0.0.6")
    expect(output).toContain("ports 2222")
    expect(output).toContain("mode apply")
    expect(output).toContain("needs-sudo")
    expect(process.exitCode).toBe(1)
  })

  it("prints dry-run in the run context before bootstrap begins", async () => {
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

    const definition: ServerDefinition = {
      host: "10.0.0.7",
      name: "dry-run-server",
      run: [],
      ssh: { ports: [2022], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    const output = consoleLogs.join("\n")
    expect(output).toContain("Run dry-run-server")
    expect(output).toContain("host 10.0.0.7")
    expect(output).toContain("ports 2022")
    expect(output).toContain("mode dry-run")
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

  it("disconnects and sets signal exitCode when SIGTERM arrives during the first lazy sudo-required module step", async () => {
    const disconnect = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockLazySudoInterrupted {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = disconnect
        public exec = vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          process.emit("SIGTERM", "SIGTERM")
          throw new Error("probe interrupted")
        })
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        {
          apply: vi.fn(),
          check: vi.fn(async (ssh: null | SshConnection) => {
            await ssh?.exec("true")
            return "ok"
          }),
          name: "needs-sudo",
        },
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(disconnect).toHaveBeenCalled()
    expect(process.exitCode).toBe(143)
  })

  it("does not call probeSudo when SIGINT arrives after connect resolves", async () => {
    const disconnect = vi.fn()
    const probeSudo = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockConnectResolvedThenInterrupted {
        public connect = vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          process.emit("SIGINT", "SIGINT")
        })
        public disconnect = disconnect
        public probeSudo = probeSudo
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

    expect(probeSudo).not.toHaveBeenCalled()
    expect(disconnect).toHaveBeenCalled()
    expect(process.exitCode).toBe(130)
  })

  it("does not eagerly probe sudo during bootstrap for dry-run without sudo-needing modules", async () => {
    const probeSudo = vi.fn().mockImplementation(() => {
      throw new Error("probeSudo should not have been called")
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockDryRunNoSudoNeed {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = vi.fn()
        public probeSudo = probeSudo
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "deploy" },
    }

    await expect(runPlaybook(definition, { dryRun: true })).resolves.toBeUndefined()

    expect(probeSudo).not.toHaveBeenCalled()
  })

  it("does not eagerly probe sudo during non-interactive bootstrap when no module runs", async () => {
    const probeSudo = vi.fn().mockImplementation(() => {
      throw new Error("probeSudo should not have been called")
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockNonInteractiveNoSudoNeed {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = vi.fn()
        public probeSudo = probeSudo
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "deploy" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(probeSudo).not.toHaveBeenCalled()
  })

  it("does not start prompt-capable bootstrap work when SIGTERM arrives after connect resolves", async () => {
    const disconnect = vi.fn()
    const probeSudo = vi.fn().mockImplementation(() => {
      throw new Error("probeSudo should not have been called")
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockPromptBootstrapInterrupted {
        public connect = vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          process.emit("SIGTERM", "SIGTERM")
        })
        public disconnect = disconnect
        public probeSudo = probeSudo
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

    expect(probeSudo).not.toHaveBeenCalled()
    expect(disconnect).toHaveBeenCalled()
    expect(process.exitCode).toBe(143)
  })

  it("aborts an active lazy sudo prompt on the first SIGINT instead of waiting for a second signal", async () => {
    const disconnect = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: class MockLazyPromptAbortable {
        public connect = vi.fn().mockResolvedValue(null)
        public disconnect = disconnect
        public exec = vi.fn().mockImplementation(
          async () =>
            new Promise((_, reject) => {
              queueMicrotask(() => {
                process.emit("SIGINT", "SIGINT")
                reject(new Error("prompt interrupted"))
              })
            })
        )
        public probeSudo = vi.fn().mockResolvedValue(null)
      },
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        {
          apply: vi.fn(),
          check: vi.fn(async (ssh: null | SshConnection) => {
            await ssh?.exec("true")
            return "ok"
          }),
          name: "needs-sudo",
        },
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(disconnect).toHaveBeenCalled()
    expect(process.exitCode).toBe(130)
  })

  it("does not start apply() for a regular module when SIGINT arrives after check()", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const interruptedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(() => {
        process.emit("SIGINT", "SIGINT")
        return "needs-apply"
      }),
      name: "interrupt-between-check-and-apply",
    }
    const laterModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [interruptedModule, laterModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(interruptedModule.apply).not.toHaveBeenCalled()
    expect(laterModule.check).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(130)
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

  it("prints validated dry-run detail for sshd.config", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const exec = createSuccessfulSshdDryRunExecMock()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec,
        readFile: vi.fn().mockResolvedValue("PasswordAuthentication yes\n"),
        writeFile: vi.fn().mockResolvedValue(null),
      }),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const [{ runPlaybook }, { sshd }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/sshd.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [sshd.config({ PasswordAuthentication: "no" })],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    const output = consoleLogs.join("\n")
    expect(output).toContain("(dry-run, sshd -t ok; reload not executed)")
  })

  it("prints verbose diagnostics for failed dry-run recipe children when --verbose is enabled", async () => {
    const capturedConfigs: unknown[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const [{ runPlaybook }, { recipe }, { CommandError }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/recipe.js"),
      import("../src/sshHelpers.js"),
    ])

    const failingChild: Module = {
      _dryRunBlocker: true,
      apply: vi.fn().mockResolvedValue({
        error: new CommandError("dry-run child failed", "dry-run stdout", "dry-run stderr"),
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [recipe("test-recipe", [failingChild])],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true, verbose: true })

    const output = consoleErrors.join("\n")
    expect(output).toContain("dry-run child failed")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("dry-run stderr")
    expect(output).toContain("Full stdout:")
    expect(output).toContain("dry-run stdout")
    expect(process.exitCode).toBe(1)
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

  it("stops the run successfully on firstRun.stop during dry-run and skips later modules", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { firstRun }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const laterModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-module",
    }

    const definition: ServerDefinition = {
      env: { PARATIX_FIRST_RUN: "true" },
      host: "1.2.3.4",
      name: "test-server",
      run: [firstRun.stop("bootstrap boundary"), laterModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(laterModule.check).not.toHaveBeenCalled()
    expect(laterModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(0)
  })

  it("stops the run successfully on firstRun.stop in apply mode, skips later modules, and still runs pending signals", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { firstRun }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-before-stop",
    }
    const laterModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-module",
    }
    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      env: { PARATIX_FIRST_RUN: "true" },
      host: "1.2.3.4",
      name: "test-server",
      run: [changedModule, firstRun.stop("bootstrap boundary"), laterModule],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(changedModule.apply).toHaveBeenCalledOnce()
    expect(laterModule.check).not.toHaveBeenCalled()
    expect(laterModule.apply).not.toHaveBeenCalled()
    expect(signalModule.apply).toHaveBeenCalledOnce()
    expect(process.exitCode).toBe(0)
  })

  it("flushes top-level pending signals immediately and does not rerun them at run end", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { signals }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-before-flush",
    }
    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changedModule, signals.flush("checkpoint")],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(signalModule.apply).toHaveBeenCalledOnce()
    expect(process.exitCode).toBe(0)
  })

  it("can flush top-level pending signals multiple times when new changes happen after a checkpoint", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { signals }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-module",
    }
    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changedModule, signals.flush("checkpoint"), changedModule],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(signalModule.apply).toHaveBeenCalledTimes(2)
    expect(process.exitCode).toBe(0)
  })

  it("does not execute top-level signals on signals.flush during dry-run", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { signals }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-before-flush",
    }
    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changedModule, signals.flush("checkpoint")],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(signalModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(0)
  })

  it("does not run top-level definition.signals in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const changedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "changed-module",
    }
    const signalModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changedModule],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(signalModule.apply).not.toHaveBeenCalled()
    expect(signalModule.check).not.toHaveBeenCalled()
  })

  it("prints limited verification detail for sshd.port dry-run without reconnect side effects", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const addPort = vi.fn()
    const exec = createSuccessfulSshdDryRunExecMock()
    const reconnect = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        exec,
        readFile: vi.fn().mockResolvedValue("Port 22\n"),
        reconnect,
        writeFile: vi.fn().mockResolvedValue(null),
      }),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const [{ runPlaybook }, { sshd }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/sshd.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [sshd.port(2222)],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    const output = consoleLogs.join("\n")
    expect(output).toContain(
      "(dry-run, sshd -t ok; restart, port switch, firewall and reconnect not verified)"
    )
    expect(addPort).not.toHaveBeenCalled()
    expect(reconnect).not.toHaveBeenCalled()
  })

  it("does not start dry-run blocker apply() when SIGTERM arrives after check()", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const dryRunBlocker: Module = {
      _dryRunBlocker: true,
      apply: vi.fn().mockResolvedValue({ status: "failed" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(() => {
        process.emit("SIGTERM", "SIGTERM")
        return "needs-apply"
      }),
      name: "dry-run-blocker",
    }
    const laterModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [dryRunBlocker, laterModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(dryRunBlocker.apply).not.toHaveBeenCalled()
    expect(laterModule.check).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(143)
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

  it("propagates op.resolve meta to following modules in dry-run mode", async () => {
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

    await runPlaybook(definition, { dryRun: true })

    expect(receivedEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(receivedEnvInCheck!, "SECRET")).resolves.toBe("resolved-secret")
    expect(dependentModule.apply).not.toHaveBeenCalled()
  })

  it("propagates system facts and uptime meta to following modules in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []
    const factOutputs: Record<string, string> = {
      "cat /etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n',
      "df -m /":
        "Filesystem 1M-blocks Used Available Use% Mounted on\n/dev/sda1 10240 2048 8192 20% /\n",
      "free -m": "Mem: 2048 1024 1024\n",
      hostname: "test-host\n",
      "ip -4 addr": "inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n",
      "ip -4 route get 1.1.1.1": "1.1.1.1 via 10.0.0.1 dev eth0 src 203.0.113.5 uid 0\n",
      nproc: "4\n",
      "uname -m": "x86_64\n",
      "uname -r": "6.8.0\n",
    }
    const uptimeOutputs: Record<string, string> = {
      "awk '{print int($1)}' /proc/uptime": "12345",
    }

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec: vi.fn().mockImplementation((command: keyof typeof factOutputs) => ({
          code: 0,
          stderr: "",
          stdout: factOutputs[command],
        })),
        output: vi
          .fn()
          .mockImplementation((command: keyof typeof uptimeOutputs) => uptimeOutputs[command]),
      }),
    }))

    const [{ runPlaybook }, { system }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/system.js"),
    ])

    let factsEnvInCheck: Environment | undefined
    let uptimeEnvInCheck: Environment | undefined
    const factsDependentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (_ssh, env: Environment) => {
        await Promise.resolve()
        factsEnvInCheck = env
        return "ok" as const
      }),
      name: "facts-dependent-module",
    }
    const uptimeDependentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (_ssh, env: Environment) => {
        await Promise.resolve()
        uptimeEnvInCheck = env
        return "ok" as const
      }),
      name: "uptime-dependent-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [system.facts(), factsDependentModule, system.uptime(), uptimeDependentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(factsEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(factsEnvInCheck!, "system.hostname")).resolves.toBe("test-host")
    await expect(resolveEnvironment(factsEnvInCheck!, "system.os")).resolves.toBe("ubuntu")
    expect(uptimeEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(uptimeEnvInCheck!, "system.uptime")).resolves.toBe("12345")
    expect(factsDependentModule.apply).not.toHaveBeenCalled()
    expect(uptimeDependentModule.apply).not.toHaveBeenCalled()
  })

  it("propagates service facts meta to following modules in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []
    const execOutputs: Record<string, string> = {
      "systemctl list-units --type=service --all --no-pager --no-legend":
        "  nginx.service  loaded  active  running  A high performance web server\n" +
        "  sshd.service   loaded  active  running  OpenBSD Secure Shell server\n",
    }

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec: vi
          .fn()
          .mockImplementation(
            (command: "systemctl list-units --type=service --all --no-pager --no-legend") => ({
              code: 0,
              stderr: "",
              stdout: execOutputs[command],
            })
          ),
      }),
    }))

    const [{ runPlaybook }, { service }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/service.js"),
    ])

    let receivedEnvInCheck: Environment | undefined
    const dependentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (_ssh, env: Environment) => {
        await Promise.resolve()
        receivedEnvInCheck = env
        return "ok" as const
      }),
      name: "service-facts-dependent-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [service.facts(), dependentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(receivedEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(receivedEnvInCheck!, "service.nginx")).resolves.toBe("active")
    await expect(resolveEnvironment(receivedEnvInCheck!, "service.sshd")).resolves.toBe("active")
    expect(dependentModule.apply).not.toHaveBeenCalled()
  })

  it("propagates apply-only recipe child meta to following recipe children in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => createMockSpawnChild(JSON.stringify({ TOKEN: "recipe-secret" }))),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { op }, { recipe }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
      import("../src/recipe.js"),
    ])

    let receivedEnvInCheck: Environment | undefined
    const dependentChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(async (_ssh, env: Environment) => {
        await Promise.resolve()
        receivedEnvInCheck = env
        return "ok" as const
      }),
      name: "dependent-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        recipe("dry-run-meta", [op.resolve({ TOKEN: "op://vault/item/password" }), dependentChild]),
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(receivedEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(receivedEnvInCheck!, "TOKEN")).resolves.toBe("recipe-secret")
    expect(dependentChild.apply).not.toHaveBeenCalled()
  })

  it("treats when(assert()) as a dry-run blocker and stops later modules", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { assert, when }] = await Promise.all([
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
      run: [
        when(
          () => true,
          assert(() => false, "must pass")
        ),
        laterModule,
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(laterModule.check).not.toHaveBeenCalled()
    expect(laterModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })

  it("treats when(fail()) as a dry-run blocker and stops later modules", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { fail, when }] = await Promise.all([
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
      run: [when(() => true, fail("stop here")), laterModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(laterModule.check).not.toHaveBeenCalled()
    expect(laterModule.apply).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })

  it("propagates when(op.resolve()) meta to following modules in dry-run mode", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => createMockSpawnChild(JSON.stringify({ SECRET: "wrapped-secret" }))),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs),
    }))

    const [{ runPlaybook }, { when }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
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
      run: [when(() => true, op.resolve({ SECRET: "op://vault/item/password" })), dependentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { dryRun: true })

    expect(receivedEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(receivedEnvInCheck!, "SECRET")).resolves.toBe("wrapped-secret")
    expect(dependentModule.apply).not.toHaveBeenCalled()
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
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {
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
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining(
        "[rsync.sync] check failed for /local/src -> /remote/dest (exit code 23)"
      )
    )
    expect(consoleError).toHaveBeenCalledWith(
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

    await runPlaybook(definition)

    expect(secondSignal.apply).toHaveBeenCalledOnce()
    expect(updateHost).toHaveBeenCalledWith("10.0.0.42")
    expect(reconnect).toHaveBeenCalledTimes(1)
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
  let tempDirectory: string

  beforeEach(() => {
    tempDirectory = mkdtempSync(join(tmpdir(), "paratix-runner-env-"))
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
    rmSync(tempDirectory, { force: true, recursive: true })
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

  it("merges env-file, server env, and CLI --env with CLI taking final precedence", async () => {
    const capturedConfigs: unknown[] = []
    const envFilePath = join(tempDirectory, ".env")
    writeFileSync(envFilePath, "APP_ENV=from-env-file\nFROM_FILE=file-value\n")

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
      env: {
        APP_ENV: "from-definition",
        FROM_DEFINITION: "definition-value",
      },
      host: "1.2.3.4",
      name: "test-server",
      run: [probeModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, {
      envFile: envFilePath,
      envOverrides: { APP_ENV: "from-cli-override", FROM_CLI: "cli-value" },
    })

    expect(capturedEnv.APP_ENV).toBe("from-cli-override")
    expect(capturedEnv.FROM_FILE).toBe("file-value")
    expect(capturedEnv.FROM_DEFINITION).toBe("definition-value")
    expect(capturedEnv.FROM_CLI).toBe("cli-value")
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
