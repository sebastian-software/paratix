import { EventEmitter } from "node:events"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { resolveEnvironment } from "../src/environment.js"
import {
  createMockSpawnChild,
  installRunnerTestHooks,
  makeMockSshClass,
} from "./helpers/runnerMocks.js"

installRunnerTestHooks()

describe("runPlaybook secret sink cleanup", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    vi.resetModules()
  })

  afterEach(async () => {
    const { clearRegisteredSecrets } = await import("../src/secretSink.js")
    clearRegisteredSecrets()
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  // R-0000518: the runner no longer calls clearRegisteredSecrets() on teardown.
  // Secrets are managed by reference-counting via withRegisteredSecrets. Modules
  // that use withRegisteredSecrets drain the sink automatically on scope exit.
  it("clears registered secrets after a successful run", async () => {
    const capturedConfigs: unknown[] = []
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { getRegisteredSecrets, withRegisteredSecrets }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/secretSink.js"),
    ])
    const secret = "runner-success-secret"
    const module: Module = {
      apply: vi.fn(),
      check: vi.fn().mockImplementation(async () =>
        withRegisteredSecrets(
          [secret],
          // eslint-disable-next-line @typescript-eslint/require-await -- withRegisteredSecrets expects an async-shaped callback; the body is intentionally synchronous.
          async () => {
            expect(getRegisteredSecrets()).toContain(secret)
            return "ok" as const
          }
        )
      ),
      name: "secret-check",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [module],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  // R-0000518: same as above — withRegisteredSecrets drains the sink even when
  // the module returns a failed result.
  it("clears registered secrets after a failed run", async () => {
    const capturedConfigs: unknown[] = []
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { getRegisteredSecrets, withRegisteredSecrets }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/secretSink.js"),
    ])
    const secret = "runner-failure-secret"
    const module: Module = {
      apply: vi.fn().mockImplementation(async () =>
        withRegisteredSecrets(
          [secret],
          // eslint-disable-next-line @typescript-eslint/require-await -- withRegisteredSecrets expects an async-shaped callback; the body is intentionally synchronous.
          async () => {
            expect(getRegisteredSecrets()).toContain(secret)
            return { error: new Error("module failed"), status: "failed" } satisfies ModuleResult
          }
        )
      ),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "secret-apply",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [module],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).resolves.toBeUndefined()

    expect(process.exitCode).toBe(1)
    expect(getRegisteredSecrets()).toStrictEqual([])
  })
})

// Bug regression: recipes must NOT apply() child modules in dry-run mode, only check()

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
      spawn: vi.fn(() => createMockSpawnChild("resolved-secret\n")),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }, { getRegisteredSecrets }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
      import("../src/secretSink.js"),
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
    expect(getRegisteredSecrets()).not.toContain("resolved-secret")
  })
})

// R-0000743 acceptance: every `op read` in a run happens before `ssh.connect`,
// a failing prewarm phase never reaches `ssh.connect`, and the secret sink is
// empty once the run is over.
describe("runPlaybook secret prewarm phase", () => {
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    vi.resetModules()
  })

  afterEach(async () => {
    const { clearRegisteredSecrets } = await import("../src/secretSink.js")
    clearRegisteredSecrets()
    vi.restoreAllMocks()
    vi.resetModules()
    process.exitCode = 0
  })

  it("resolves every op read before ssh.connect, in a single shared call chronology", async () => {
    const capturedConfigs: unknown[] = []
    const chronology: string[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => {
        chronology.push("op-read")
        return createMockSpawnChild("resolved-secret\n")
      }),
    }))

    const connect = vi.fn().mockImplementation(async () => {
      chronology.push("ssh-connect")
      await Promise.resolve()
      return null
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { connect, lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
    ])

    const dependentModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "dependent-module",
    }

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [op.resolve({ SECRET: "op://vault/item/password" }), dependentModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(chronology).toStrictEqual(["op-read", "ssh-connect"])
  })

  it("resolves multiple op reads (across two op.resolve modules) before ssh.connect", async () => {
    const capturedConfigs: unknown[] = []
    const chronology: string[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => {
        chronology.push("op-read")
        return createMockSpawnChild("resolved-secret\n")
      }),
    }))

    const connect = vi.fn().mockImplementation(async () => {
      chronology.push("ssh-connect")
      await Promise.resolve()
      return null
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { connect, lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        op.resolve({ FIRST: "op://vault/item/first" }),
        op.resolve({ SECOND: "op://vault/item/second" }),
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(chronology).toStrictEqual(["op-read", "op-read", "ssh-connect"])
  })

  // R3 (review finding F4): the dedupe guarantee ("same reference → exactly
  // one op read") was previously only proven indirectly, via the
  // resolveCachedSecret unit test in secretPrewarm.test.ts. Prove it here too,
  // through two independent op.resolve modules naming the identical
  // reference, so a refactor that widened the cache key (e.g. by module name)
  // would still be caught at the runner level.
  it("dedupes two op.resolve modules that name the same reference into a single op read", async () => {
    const capturedConfigs: unknown[] = []
    const chronology: string[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => {
        chronology.push("op-read")
        return createMockSpawnChild("shared-secret\n")
      }),
    }))

    const connect = vi.fn().mockImplementation(async () => {
      chronology.push("ssh-connect")
      await Promise.resolve()
      return null
    })

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { connect, lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [
        op.resolve({ FIRST: "op://vault/item/shared" }),
        op.resolve({ SECOND: "op://vault/item/shared" }),
      ],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(chronology).toStrictEqual(["op-read", "ssh-connect"])
  })

  it("fails fast: ssh.connect is never reached when the prewarm phase fails", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => {
        const enoent = Object.assign(new Error("spawn op ENOENT"), { code: "ENOENT" })
        const child = new EventEmitter()
        Object.defineProperty(child, "stdout", { value: new EventEmitter() })
        Object.defineProperty(child, "stderr", { value: new EventEmitter() })
        Object.defineProperty(child, "stdin", {
          value: Object.assign(new EventEmitter(), { end: vi.fn(), once: vi.fn() }),
        })
        queueMicrotask(() => {
          child.emit("error", enoent)
        })
        return child
      }),
    }))

    const connect = vi.fn().mockResolvedValue(null)

    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { connect, lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [op.resolve({ SECRET: "op://vault/item/password" })],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await expect(runPlaybook(definition)).rejects.toThrow(/Failed to resolve 1Password references/v)

    expect(connect).not.toHaveBeenCalled()
  })

  it("leaves the secret sink empty after a successful run that resolved secrets up front", async () => {
    const capturedConfigs: unknown[] = []

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => createMockSpawnChild("up-front-secret\n")),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }, { getRegisteredSecrets }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
      import("../src/secretSink.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [op.resolve({ SECRET: "op://vault/item/password" })],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(getRegisteredSecrets()).toStrictEqual([])
  })

  it("prints exactly one status line without reference names or a counter when a reference resolves", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })

    vi.doMock("node:child_process", () => ({
      spawn: vi.fn(() => createMockSpawnChild("resolved-secret\n")),
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { op }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/modules/op.js"),
    ])

    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [op.resolve({ SECRET: "op://vault/item/password" })],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    const prewarmLines = consoleLogs.filter((line) => /resolving secrets/iv.test(line))
    expect(prewarmLines).toHaveLength(1)
    expect(prewarmLines[0]).not.toContain("op://")
    expect(prewarmLines[0]).not.toContain("vault")
    expect(prewarmLines[0]).not.toMatch(/\b1\/1\b|\b1 of 1\b/v)
  })

  it("emits no spawn call and no prewarm status line for a playbook without op.resolve", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })
    const spawnSpy = vi.fn()

    vi.doMock("node:child_process", () => ({
      spawn: spawnSpy,
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const { runPlaybook } = await import("../src/runner.js")

    const plainModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "plain-module",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [plainModule],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(spawnSpy).not.toHaveBeenCalled()
    expect(consoleLogs.some((line) => /resolving secrets/iv.test(line))).toBe(false)
  })

  // R1 (review finding F1): a when(...) block over a secret-free subtree must
  // not become a prewarm carrier itself. The existing "no op.resolve at all"
  // test above only exercises plain leaf modules; this covers the case F1
  // actually fixed — a guarded block whose children never call op.resolve.
  it("emits no spawn call and no prewarm status line for a when(...) block without op.resolve", async () => {
    const capturedConfigs: unknown[] = []
    const consoleLogs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })
    const spawnSpy = vi.fn()

    vi.doMock("node:child_process", () => ({
      spawn: spawnSpy,
    }))
    vi.doMock("../src/ssh.js", () => ({
      shellQuote: (s: string) => `'${s}'`,
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
    }))

    const [{ runPlaybook }, { when }] = await Promise.all([
      import("../src/runner.js"),
      import("../src/builtins.js"),
    ])

    const guardedModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" } satisfies ModuleResult),
      check: vi.fn().mockResolvedValue("ok"),
      name: "guarded-plain-module",
    }
    const definition: ServerDefinition = {
      host: "1.2.3.4",
      name: "test-server",
      run: [when(() => true, guardedModule)],
      ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
    }

    await runPlaybook(definition)

    expect(spawnSpy).not.toHaveBeenCalled()
    expect(consoleLogs.some((line) => /resolving secrets/iv.test(line))).toBe(false)
  })
})

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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
      SshConnectionImpl: makeMockSshClass(capturedConfigs, { lifecycle: "permissive" }),
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
