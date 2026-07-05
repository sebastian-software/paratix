import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ModuleResult, ServerDefinition, SshConnection } from "../src/types.js"

import { when } from "../src/builtins.js"
import { meta } from "../src/meta.js"
import { recipe as createRecipe } from "../src/recipe.js"
import {
  getSignalBus,
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
        lifecycle: "permissive",
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
        lifecycle: "permissive",
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
        lifecycle: "permissive",
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

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

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
        // R-0000207: simulate a true reconnect failure — no port held a
        // connection after the throw, so handlePortChange must roll back.
        getConnectionInfo: vi
          .fn()
          .mockReturnValue({ host: "1.2.3.4", port: 0, privateKeyPath: "~/.ssh/id", user: "root" }),
        lifecycle: "permissive",
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
        getConnectionInfo: vi
          .fn()
          .mockReturnValue({ host: "1.2.3.4", port: 0, privateKeyPath: "~/.ssh/id", user: "root" }),
        lifecycle: "permissive",
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

  // A fully failed reconnect must produce the failure-path diagnostic,
  // not the misleading "Reconnect succeeded but follow-up step failed"
  // message that R-0000207 introduced for partial-success cases. This
  // depends on disconnectTransport() resetting connectedPort to 0 so that
  // getConnectionInfo().port truly reflects the absence of a connection
  // after the reconnect attempts are exhausted.
  it("emits the failure-path diagnostic when reconnect fully fails (port resets to 0)", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Connection refused")
    const consoleErrors: string[] = []
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort: vi.fn().mockReturnValue(true),
        // After a fully failed reconnect, ssh.disconnectTransport() must
        // have reset connectedPort to 0 — this mock encodes that contract.
        getConnectionInfo: vi
          .fn()
          .mockReturnValue({ host: "1.2.3.4", port: 0, privateKeyPath: "~/.ssh/id", user: "root" }),
        lifecycle: "permissive",
        reconnect: vi.fn().mockRejectedValue(reconnectError),
        removePort: vi.fn(),
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(2222)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortChange],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const diagnosticLines = consoleErrors.filter((line) =>
      line.includes("Failed to reconnect on port(s)")
    )
    expect(diagnosticLines).toHaveLength(1)
    // The misleading partial-success message must NOT appear.
    expect(
      consoleErrors.some((line) => line.includes("succeeded but a follow-up step failed"))
    ).toBe(false)
  })

  // R-0000207: when the reconnect itself succeeded but a follow-up step
  // (e.g. commitAcceptedHostKey) threw, the runner must NOT remove the
  // newly added ports — the connection is alive on those ports.
  it("keeps added ports registered when reconnect succeeded but a follow-up step failed", async () => {
    const capturedConfigs: unknown[] = []
    const commitError = new Error("Disk full while persisting host key")
    const addPort = vi.fn().mockReturnValue(true)
    const removePort = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        // The connection is still attached to a port — reconnect itself
        // succeeded, only the post-connect work failed.
        getConnectionInfo: vi.fn().mockReturnValue({
          host: "1.2.3.4",
          port: 2222,
          privateKeyPath: "~/.ssh/id",
          user: "root",
        }),
        lifecycle: "permissive",
        reconnect: vi.fn().mockRejectedValue(commitError),
        removePort,
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortChange = makeModuleWithMeta([meta.sshdPort(2222)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortChange],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(addPort).toHaveBeenCalledWith(2222)
    // The port is still reachable — keep it registered.
    expect(removePort).not.toHaveBeenCalled()
  })

  it("stops processing subsequent modules when reconnect fails after port change", async () => {
    const capturedConfigs: unknown[] = []
    const reconnectError = new Error("Connection refused")

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        lifecycle: "permissive",
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
        lifecycle: "permissive",
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

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

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

  it("exposes the definition host through the runner SSH mock connection info", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const hostCheckingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn(async (ssh: null | SshConnection) => {
        await Promise.resolve()
        expect(ssh?.getConnectionInfo().host).toBe("203.0.113.10")
        return "ok" as const
      }),
      name: "host-check",
    }
    const definition: ServerDefinition = {
      host: "203.0.113.10",
      name: "test-server",
      run: [hostCheckingModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(hostCheckingModule.check).toHaveBeenCalledOnce()
  })

  it("exposes runtime host updates through the runner SSH mock connection info", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const updatingModule = makeModuleWithMeta([
      meta.systemHost("203.0.113.42"),
      meta.systemReboot(),
    ])
    const hostCheckingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn(async (ssh: null | SshConnection) => {
        await Promise.resolve()
        expect(ssh?.getConnectionInfo().host).toBe("203.0.113.42")
        return "ok" as const
      }),
      name: "updated-host-check",
    }
    const definition: ServerDefinition = {
      host: "203.0.113.10",
      name: "test-server",
      run: [updatingModule, hostCheckingModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

    expect(hostCheckingModule.check).toHaveBeenCalledOnce()
    expect(reconnect).toHaveBeenCalledOnce()
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithPortAndReboot = makeModuleWithMeta([meta.sshdPort(2222), meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithPortAndReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

    // reconnect is called exactly once (by the reboot handler, not the port-change handler)
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  it("calls reconnect exactly once when only sshd.port is set (no reboot)", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
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

  // Issue #73: only the reboot path extends the default window. Port changes
  // come back almost immediately and must keep the generic reconnect default,
  // so the handler must not pass a defaultTimeout override.
  it("does not extend the reconnect window for a port change (no defaultTimeout override)", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
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

    expect(reconnect).toHaveBeenCalledTimes(1)
    expect(reconnect).toHaveBeenCalledWith()
  })

  it("skips runner reconnect when sshd.port already reconnected to the reported target port", async () => {
    const capturedConfigs: unknown[] = []
    const addPort = vi.fn().mockReturnValue(true)
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        getConnectionInfo: vi.fn().mockReturnValue({
          host: "1.2.3.4",
          port: 2222,
          privateKeyPath: "~/.ssh/id",
          user: "root",
        }),
        lifecycle: "permissive",
        reconnect,
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const moduleWithVerifiedPortChange = makeModuleWithMeta([meta.sshdPort(2222)])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithVerifiedPortChange],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(addPort).toHaveBeenCalledWith(2222)
    expect(reconnect).not.toHaveBeenCalled()
  })

  it("calls addPort for every sshd.port meta entry when a module emits multiple", async () => {
    const capturedConfigs: unknown[] = []
    const addPort = vi.fn()
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        lifecycle: "permissive",
        reconnect,
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        lifecycle: "permissive",
        reconnect,
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        lifecycle: "permissive",
        reconnect,
        updateHost,
      }),
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

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

    expect(secondChild.check).toHaveBeenCalledOnce()
    expect(updateHost).toHaveBeenCalledWith("10.0.0.42")
    expect(reconnect).toHaveBeenCalledTimes(1)
  })
})

describe("runPlaybook handleReboot grace period (R-0000153)", () => {
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

  it("waits for the configured grace period before the first reconnect after a reboot", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    const start = Date.now()
    await runPlaybook(definition, { rebootGraceSeconds: 0.05 })
    const elapsed = Date.now() - start

    expect(reconnect).toHaveBeenCalledTimes(1)
    // Grace was 50ms; allow generous tolerance for slow CI but assert lower bound.
    expect(elapsed).toBeGreaterThanOrEqual(40)
  })

  it("keeps the reboot grace timer refed until reconnect can run", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)
    const realSetTimeout = globalThis.setTimeout
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout")
    const unrefSpies: Array<ReturnType<typeof vi.fn>> = []

    setTimeoutSpy.mockImplementation((handler, timeout, ...args) => {
      const timer = realSetTimeout(handler, timeout, ...args)
      const unref = vi.fn()
      timer.unref = unref
      unrefSpies.push(unref)
      return timer
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { rebootGraceSeconds: 0.01 })

    expect(reconnect).toHaveBeenCalledTimes(1)
    expect(unrefSpies).toHaveLength(1)
    expect(unrefSpies[0]).not.toHaveBeenCalled()
  })

  it("skips the grace wait entirely when rebootGraceSeconds is 0", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    const start = Date.now()
    await runPlaybook(definition, { rebootGraceSeconds: 0 })
    const elapsed = Date.now() - start

    expect(reconnect).toHaveBeenCalledTimes(1)
    expect(elapsed).toBeLessThan(500)
  })

  it("does not consume the reconnect attempt budget for the grace wait", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

    // The grace wait must not have caused additional reconnect calls.
    expect(reconnect).toHaveBeenCalledTimes(1)
  })

  // Issue #73: the reboot path must hand the SSH layer a longer default
  // reconnect window (300 s) so slow VPS reboots still reconnect.
  it("grants the reboot reconnect a longer default window via defaultTimeout", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { DEFAULT_REBOOT_RECONNECT_TIMEOUT, runPlaybook } = await import("../src/runner.js")
    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition, { rebootGraceSeconds: 0 })

    expect(DEFAULT_REBOOT_RECONNECT_TIMEOUT).toBe(300_000)
    expect(reconnect).toHaveBeenCalledTimes(1)
    expect(reconnect).toHaveBeenCalledWith({ defaultTimeout: DEFAULT_REBOOT_RECONNECT_TIMEOUT })
  })

  // R-0000203: a SIGINT/SIGTERM observed mid-sleep aborts the grace timer
  // immediately so the runner reaches its shutdown path without idling for
  // the full grace duration.
  it("ends the grace sleep immediately when SIGINT arrives mid-grace", async () => {
    const capturedConfigs: unknown[] = []
    const reconnect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive", reconnect }),
    }))

    const { runPlaybook } = await import("../src/runner.js")
    const moduleWithReboot = makeModuleWithMeta([meta.systemReboot()])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [moduleWithReboot],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    // Schedule a SIGINT shortly after the run starts, while the 5-second
    // grace sleep is still in flight. Without R-0000203, the run would have
    // to wait the full 5 seconds; with the AbortSignal hookup it returns
    // almost instantly.
    const signalTimer = setTimeout(() => {
      getSignalBus().emit("SIGINT")
    }, 50)

    const start = Date.now()
    await runPlaybook(definition, { rebootGraceSeconds: 5 })
    const elapsed = Date.now() - start

    clearTimeout(signalTimer)

    // Allow generous tolerance for slow CI but assert we did not idle for
    // anywhere near the full 5-second grace.
    expect(elapsed).toBeLessThan(2000)
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        lifecycle: "permissive",
        reconnect,
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        addPort,
        lifecycle: "permissive",
        reconnect,
      }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
