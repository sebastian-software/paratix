import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { when } from "../src/builtins.js"
import { meta } from "../src/meta.js"
import { recipe as createRecipe } from "../src/recipe.js"
import {
  installRunnerTestHooks,
  makeMockSshClass,
  makeModuleWithMeta,
} from "./helpers/runnerMocks.js"

installRunnerTestHooks()

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
    process.exitCode = 0
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
  })

  it("rolls back addPort by calling removePort when reconnect after port change fails", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Connection refused")
    const addPort = vi.fn().mockReturnValue(true)
    const removePort = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        reconnect: vi.fn().mockRejectedValue(reconnectError),
        removePort,
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

    expect(addPort).toHaveBeenCalledWith(2222)
    expect(removePort).toHaveBeenCalledWith(2222)
  })

  it("does not remove an already registered port when reconnect after port change fails", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Connection refused")
    const addPort = vi.fn().mockReturnValue(false)
    const removePort = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        reconnect: vi.fn().mockRejectedValue(reconnectError),
        removePort,
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(22)])

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

    expect(addPort).toHaveBeenCalledWith(22)
    expect(removePort).not.toHaveBeenCalled()
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

  it("does not print a recipe header when a top-level recipe is already ok", async () => {
    const capturedConfigs: unknown[] = []
    const outputModule = await import("../src/output.js")
    const printRecipeHeader = vi.spyOn(outputModule, "printRecipeHeader")

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
      run: [createRecipe("base-setup", [childModule])],
      ssh: {
        ports: [22],
        privateKey: "~/.ssh/id",
        user: "root",
      },
    }

    await runPlaybook(definition)

    expect(printRecipeHeader).not.toHaveBeenCalledWith("base-setup")
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
    process.exitCode = 0
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
  })

  it("calls addPort for every sshd.port meta entry when a module emits multiple", async () => {
    const capturedConfigs: unknown[] = []
    const addPort = vi.fn()
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { addPort, reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithMultiplePorts = makeModuleWithMeta([meta.sshdPort(2222), meta.sshdPort(2223)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithMultiplePorts],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(addPort).toHaveBeenCalledTimes(2)
    expect(addPort).toHaveBeenNthCalledWith(1, 2222)
    expect(addPort).toHaveBeenNthCalledWith(2, 2223)
    // reconnect runs once after all ports have been registered
    expect(reconnect).toHaveBeenCalledTimes(1)
    const [reconnectOrder] = reconnect.mock.invocationCallOrder
    const [, secondAddPortOrder] = addPort.mock.invocationCallOrder
    expect(reconnectOrder).toBeGreaterThan(secondAddPortOrder)
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

describe("runPlaybook conditional child control-plane processing", () => {
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

  it("processes conditional child sshd.port meta before the next child starts", async () => {
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
      name: "conditional-port-change-child",
    }
    const secondChildCheck = vi.fn().mockImplementation(() => {
      expect(addPort).toHaveBeenCalledWith(2222)
      expect(reconnect).toHaveBeenCalledTimes(1)
      expect(addPort.mock.invocationCallOrder[0]).toBeLessThan(
        secondChildCheck.mock.invocationCallOrder[0]
      )
      expect(reconnect.mock.invocationCallOrder[0]).toBeLessThan(
        secondChildCheck.mock.invocationCallOrder[0]
      )
      return "ok"
    })
    const secondChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: secondChildCheck,
      name: "conditional-second-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [when(() => true, portChangingChild, secondChild)],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(secondChild.check).toHaveBeenCalledOnce()
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  it("keeps successful conditional child control-plane meta when a later child fails", async () => {
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
      name: "conditional-port-change-child",
    }
    const failingChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "failed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "conditional-failing-child",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [when(() => true, portChangingChild, failingChild)],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(process.exitCode).toBe(1)
    expect(addPort).toHaveBeenCalledWith(2222)
    expect(reconnect).toHaveBeenCalledTimes(1)
  })
})

// Bug regression: exceptions thrown by recipeModule.apply() must not crash the playbook run

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
