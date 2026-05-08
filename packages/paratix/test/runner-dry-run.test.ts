import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { resolveEnvironment } from "../src/environment.js"
import {
  createMockSpawnChild,
  createSuccessfulSshdDryRunExecMock,
  getSignalBus,
  installRunnerTestHooks,
  makeMockSshClass,
} from "./helpers/runnerMocks.js"

installRunnerTestHooks()

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

  it("prints normal module detail text for changed apply results", async () => {
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

    const detailModule: Module = {
      apply: vi.fn().mockResolvedValue({
        detail: "(sha256:new-traefik-id)",
        status: "changed",
      } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "quadlet.updateImage: traefik",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [detailModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const allLogOutput = consoleLogs.flat().join(" ")
    expect(allLogOutput).toContain("quadlet.updateImage: traefik")
    expect(allLogOutput).toContain("changed")
    expect(allLogOutput).toContain("(sha256:new-traefik-id)")
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
        getSignalBus().emit("SIGTERM")
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
      spawn: vi.fn(() => createMockSpawnChild("resolved-secret\n")),
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
      "awk '{print int($1)}' /proc/uptime": "12345",
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

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec: vi.fn().mockImplementation((command: keyof typeof factOutputs) => ({
          code: 0,
          stderr: "",
          stdout: factOutputs[command],
        })),
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
      "LC_ALL=C systemctl list-units --type=service --all --no-pager --no-legend":
        "  nginx.service  loaded  active  running  A high performance web server\n" +
        "  sshd.service   loaded  active  running  OpenBSD Secure Shell server\n",
    }

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, {
        exec: vi
          .fn()
          .mockImplementation(
            (
              command: "LC_ALL=C systemctl list-units --type=service --all --no-pager --no-legend"
            ) => ({
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
      spawn: vi.fn(() => createMockSpawnChild("recipe-secret\n")),
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
      spawn: vi.fn(() => createMockSpawnChild("wrapped-secret\n")),
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
