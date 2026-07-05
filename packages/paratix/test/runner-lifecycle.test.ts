import { EventEmitter } from "node:events"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { installRunnerTestHooks, makeMockSshClass, setEncodingNoop } from "./helpers/runnerMocks.js"

installRunnerTestHooks()

describe("runPlaybook runtime module validation", () => {
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

  it("rejects malformed run modules before constructing an SSH connection", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const definition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [{ name: "broken-module" }],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    } as unknown as ServerDefinition

    await expect(runPlaybook(definition)).rejects.toThrow(
      "ServerDefinition: run[0] must be a module with name, check, and apply"
    )
    expect(capturedConfigs).toStrictEqual([])
  })

  it("disconnects the SSH connection when initial connect rejects", async () => {
    const capturedConfigs: unknown[] = []
    const disconnect = vi.fn()

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        connect: vi.fn().mockRejectedValue(new Error("connect refused")),
        disconnect,
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

    await expect(runPlaybook(definition)).rejects.toThrow("connect refused")

    expect(disconnect).toHaveBeenCalledOnce()
  })
})

// Bug regression: when sshd.port and system.reboot are both set, reconnect must only be called once

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
    process.exitCode = 0
  })

  it("does not crash when recipe apply() throws, records status as failed and sets exitCode to 1", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const throwingRecipe = {
      _modules: [],
      apply: vi.fn().mockRejectedValue(new Error("recipe internal failure")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      kind: "recipe" as const,
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
  })

  it("writes recipe apply() throw diagnostics to stderr when the error message is non-empty", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const consoleErrors: unknown[][] = []
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args)
    })

    const { runPlaybook } = await import("../src/runner.js")

    const recipeError = new Error("recipe internal failure")
    const throwingRecipe = {
      _modules: [],
      apply: vi.fn().mockRejectedValue(recipeError),
      check: vi.fn().mockResolvedValue("needs-apply"),
      kind: "recipe" as const,
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
  })

  it("stops processing subsequent modules when recipe apply() throws", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const throwingRecipe = {
      _modules: [],
      apply: vi.fn().mockRejectedValue(new Error("recipe boom")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      kind: "recipe" as const,
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
  })

  it("logs the concrete recipe child module name when child check() throws during runPlaybook", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
  })

  it("logs the concrete recipe child module name when child apply() throws during runPlaybook", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
  })
})

// Signal handling: graceful shutdown on SIGINT / SIGTERM

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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
        lifecycle: "permissive",
        output: vi.fn().mockResolvedValue("old-hostname"),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
        lifecycle: "permissive",
        output: vi.fn().mockResolvedValue("old-hostname"),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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

  it("marks the run as failed when rsync apply fails after check returned needs-apply", async () => {
    // R-0000484: rsync.sync.check now swallows executeRsync failures and
    // reports needs-apply, so the runner proceeds to apply where the rsync
    // failure surfaces with the apply-error message instead.
    const capturedConfigs: unknown[] = []
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => {
        // Mirror the spawn-based runner contract introduced in R-0000040: a
        // failed rsync emits stderr lines and closes with a non-zero exit code.
        const child = new EventEmitter() as {
          stderr: { on: EventEmitter["on"]; setEncoding: () => void }
          stdout: { on: EventEmitter["on"]; setEncoding: () => void }
        } & EventEmitter
        const stdoutStream = new EventEmitter()
        const stderrStream = new EventEmitter()
        child.stdout = Object.assign(stdoutStream, { setEncoding: setEncodingNoop })
        child.stderr = Object.assign(stderrStream, { setEncoding: setEncodingNoop })
        queueMicrotask(() => {
          stderrStream.emit("data", "Permission denied (publickey).\n")
          child.emit("close", 23)
        })
        return child
      }),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
        "[rsync.sync] apply failed for /local/src -> /remote/dest (exit code 23)"
      )
    )
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining("Permission denied (publickey).")
    )
  })
})

// Bug regression: stats.incrementSignals() must be called even when signal apply() throws,
// so that failed signals are counted in the summary (not only successful ones)

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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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

  it("resets a previous failed run exitCode after a subsequent successful run", async () => {
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const failingModule: Module = {
      apply: vi.fn().mockResolvedValue({
        error: new Error("apply failed"),
        status: "failed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "failing-module",
    }
    const successfulModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "successful-module",
    }

    const failedDefinition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [failingModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }
    const successfulDefinition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [successfulModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(failedDefinition)
    expect(process.exitCode).toBe(1)

    await runPlaybook(successfulDefinition)
    expect(process.exitCode).toBe(0)
  })
})
