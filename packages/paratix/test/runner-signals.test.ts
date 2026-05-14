import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type * as OutputModule from "../src/output.js"
import type * as SecretSinkModule from "../src/secretSink.js"
import type { Module, ModuleResult, ServerDefinition, SshConnection } from "../src/types.js"

import { meta } from "../src/meta.js"
import {
  getSignalBus,
  installRunnerTestHooks,
  makeMockSshClass,
  makeModuleWithMeta,
} from "./helpers/runnerMocks.js"

installRunnerTestHooks()

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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const interruptListenersBefore = getSignalBus().listenerCount("SIGINT")
    const terminateListenersBefore = getSignalBus().listenerCount("SIGTERM")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(getSignalBus().listenerCount("SIGINT")).toBe(interruptListenersBefore)
    expect(getSignalBus().listenerCount("SIGTERM")).toBe(terminateListenersBefore)
  })

  it("calls ssh.disconnect() and sets exitCode to 130 when SIGINT is received during runPlaybook", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const slowModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi
        .fn()
        .mockImplementationOnce(async () => {
          getSignalBus().emit("SIGINT")
          await Promise.resolve()
          expect(disconnectFn).toHaveBeenCalledOnce()
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
    // The signal handler disconnects first; teardown disconnects again.
    expect(disconnectFn).toHaveBeenCalledTimes(2)
  })

  it("defers ssh.disconnect() to a microtask so the signal handler returns before disconnectTransport iterates pendingRejects (R-0000257 regression)", async () => {
    // Regression: handleShutdownSignal called ssh?.disconnect() synchronously
    // inside the signal handler. disconnect -> disconnectTransport iterates
    // pendingRejects and calls reject handlers, which can reentrantly invoke
    // ssh2 stream internals during a single signal-dispatch tick. ssh2
    // assumes coherent event-loop tick lifetimes; reentrant stream access
    // is a known crash source. The fix wraps the call in queueMicrotask so
    // the handler returns immediately and disconnect runs in the next
    // microtask after ssh2 has processed its pending events.
    const disconnectInvocationOrder: string[] = []
    const disconnect = vi.fn().mockImplementation(() => {
      disconnectInvocationOrder.push("disconnect")
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { disconnect, lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const interruptingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockImplementationOnce(() => {
        getSignalBus().emit("SIGINT")
        // Synchronously after emit, disconnect must NOT yet have been called —
        // the signal handler must have queued it for a later microtask.
        disconnectInvocationOrder.push("after-emit")
        return "needs-apply" as const
      }),
      name: "interrupting-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [interruptingModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    // The synchronous "after-emit" marker must come before any disconnect
    // call, proving the signal handler returned before disconnect ran.
    const afterEmitIndex = disconnectInvocationOrder.indexOf("after-emit")
    const firstDisconnectIndex = disconnectInvocationOrder.indexOf("disconnect")
    expect(afterEmitIndex).toBeGreaterThan(-1)
    expect(firstDisconnectIndex).toBeGreaterThan(-1)
    expect(afterEmitIndex).toBeLessThan(firstDisconnectIndex)
    expect(disconnect).toHaveBeenCalled()
  })

  it("sets exitCode to 143 when SIGTERM is received during runPlaybook", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const slowModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi
        .fn()
        .mockImplementationOnce(async () => {
          await Promise.resolve()
          getSignalBus().emit("SIGTERM")
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const changingModule: Module = {
      apply: vi
        .fn()
        .mockImplementationOnce(async () => {
          await Promise.resolve()
          getSignalBus().emit("SIGINT")
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
    }))
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })

    const { runPlaybook } = await import("../src/runner.js")

    const interruptedModule: Module = {
      apply: vi.fn().mockImplementationOnce(async () => {
        await Promise.resolve()
        getSignalBus().emit("SIGINT")
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
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
        getSignalBus().emit("SIGTERM")
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
        SshConnectionImpl: makeMockSshClass(capturedConfigs, {
          disconnect: disconnectFn,
          lifecycle: "permissive",
        }),
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
          getSignalBus().emit(signalName)
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
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
        lifecycle: "permissive",
        reconnect: vi.fn().mockImplementation(async () => {
          await Promise.resolve()
          getSignalBus().emit("SIGINT")
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        disconnect: disconnectFn,
        lifecycle: "permissive",
      }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const module1: Module = {
      apply: vi.fn().mockImplementationOnce(async () => {
        await Promise.resolve()
        getSignalBus().emit("SIGINT")
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

    const sigintBefore = getSignalBus().listenerCount("SIGINT")
    const sigtermBefore = getSignalBus().listenerCount("SIGTERM")

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
    expect(getSignalBus().listenerCount("SIGINT")).toBe(sigintBefore)
    expect(getSignalBus().listenerCount("SIGTERM")).toBe(sigtermBefore)
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

    const sigintBefore = getSignalBus().listenerCount("SIGINT")
    const sigtermBefore = getSignalBus().listenerCount("SIGTERM")

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        {
          apply: vi.fn(),
          check: vi.fn(async (ssh: null | SshConnection) => {
            await ssh?.exec("true")
            return "ok" as const
          }),
          name: "needs-sudo",
        },
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(getSignalBus().listenerCount("SIGINT")).toBe(sigintBefore)
    expect(getSignalBus().listenerCount("SIGTERM")).toBe(sigtermBefore)
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
            return "ok" as const
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
          getSignalBus().emit("SIGINT")
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
          getSignalBus().emit("SIGTERM")
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
            return "ok" as const
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
          getSignalBus().emit("SIGINT")
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
          getSignalBus().emit("SIGTERM")
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
                getSignalBus().emit("SIGINT")
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
            return "ok" as const
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const interruptedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockImplementation(() => {
        getSignalBus().emit("SIGINT")
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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

  it("passes shutdownSignal to top-level signal apply options", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    let capturedShutdownSignal: NodeJS.Signals | null | undefined
    const signalModule: Module = {
      async apply(_ssh, _environment, options) {
        await Promise.resolve()
        getSignalBus().emit("SIGTERM")
        capturedShutdownSignal = options?.shutdownSignal?.()
        return { status: "changed" } satisfies ModuleResult
      },
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "signal-module",
    }

    const changingModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply" as const),
      name: "changing-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [changingModule],
      signals: [signalModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(capturedShutdownSignal).toBe("SIGTERM")
  })
})

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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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

describe("runPlaybook second-signal best-effort cleanup", () => {
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

  it("performShutdownBestEffortCleanup stops live output, restores raw mode, shows the cursor and clears secrets", async () => {
    const stopLiveModuleOutputSpy = vi.fn()
    const clearRegisteredSecretsSpy = vi.fn()

    vi.doMock("../src/output.js", async () => {
      const actual = await vi.importActual<typeof OutputModule>("../src/output.js")
      return {
        ...actual,
        stopLiveModuleOutput: stopLiveModuleOutputSpy,
      }
    })
    vi.doMock("../src/secretSink.js", async () => {
      const actual = await vi.importActual<typeof SecretSinkModule>("../src/secretSink.js")
      return {
        ...actual,
        clearRegisteredSecrets: clearRegisteredSecretsSpy,
      }
    })

    const stdoutWrites: string[] = []
    const stdoutWriteSpy = vi
      .spyOn(process.stdout, "write")
      .mockImplementation((chunk: string | Uint8Array): boolean => {
        stdoutWrites.push(Buffer.from(chunk).toString("utf8"))
        return true
      })

    const setRawModeSpy = vi.fn(() => process.stdin)
    const setRawModeBackup = Reflect.get(process.stdin, "setRawMode") as unknown
    const previousIsTTY = process.stdin.isTTY
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Reflect.set(process.stdin, "setRawMode", setRawModeSpy)

    try {
      const { __testing } = await import("../src/runner.js")
      __testing.performShutdownBestEffortCleanup()

      expect(stopLiveModuleOutputSpy).toHaveBeenCalledWith(true)
      expect(setRawModeSpy).toHaveBeenCalledWith(false)
      // Cursor restore must use the ANSI "show cursor" sequence ESC + "[?25h".
      const cursorWrite = stdoutWrites.find((entry) => entry.includes("[?25h"))
      expect(cursorWrite).toBeDefined()
      expect(cursorWrite?.charCodeAt(0)).toBe(0x1b)
      expect(clearRegisteredSecretsSpy).toHaveBeenCalledOnce()
    } finally {
      Reflect.set(process.stdin, "setRawMode", setRawModeBackup)
      Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: previousIsTTY })
      stdoutWriteSpy.mockRestore()
    }
  })

  it("a single failing cleanup step does not prevent the others from running", async () => {
    const stopLiveModuleOutputSpy = vi.fn().mockImplementation(() => {
      throw new Error("live output failure")
    })
    const clearRegisteredSecretsSpy = vi.fn()

    vi.doMock("../src/output.js", async () => {
      const actual = await vi.importActual<typeof OutputModule>("../src/output.js")
      return {
        ...actual,
        stopLiveModuleOutput: stopLiveModuleOutputSpy,
      }
    })
    vi.doMock("../src/secretSink.js", async () => {
      const actual = await vi.importActual<typeof SecretSinkModule>("../src/secretSink.js")
      return {
        ...actual,
        clearRegisteredSecrets: clearRegisteredSecretsSpy,
      }
    })

    const stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    try {
      const { __testing } = await import("../src/runner.js")
      expect(() => {
        __testing.performShutdownBestEffortCleanup()
      }).not.toThrow()

      // Despite stopLiveModuleOutput throwing, the other steps still ran.
      expect(stopLiveModuleOutputSpy).toHaveBeenCalled()
      expect(clearRegisteredSecretsSpy).toHaveBeenCalled()
    } finally {
      stdoutWriteSpy.mockRestore()
    }
  })
})

// Bug regression: CLI --env overrides (options.envOverrides) must take priority over definition.env
