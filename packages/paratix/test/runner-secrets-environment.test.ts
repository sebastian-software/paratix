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
      check: vi.fn().mockImplementation(async () => {
        return withRegisteredSecrets([secret], async () => {
          expect(getRegisteredSecrets()).toContain(secret)
          return "ok" as const
        })
      }),
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
      apply: vi.fn().mockImplementation(async () => {
        return withRegisteredSecrets([secret], async () => {
          expect(getRegisteredSecrets()).toContain(secret)
          return { error: new Error("module failed"), status: "failed" } satisfies ModuleResult
        })
      }),
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
