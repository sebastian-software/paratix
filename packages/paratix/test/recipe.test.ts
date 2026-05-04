import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module } from "../src/types.js"

import { assert, fail, firstRun, signals } from "../src/builtins.js"
import { dryRunRecipeModule } from "../src/dryRunRecipe.js"
import { resolveEnvironment } from "../src/environment.js"
import { recipe } from "../src/recipe.js"
import { setRunnerAbortSignal } from "../src/runnerAbortSignal.js"
import { CommandError } from "../src/sshHelpers.js"
import { createMockSsh } from "./helpers/mockSsh.js"

const emptyEnv: Environment = {}

function makeModule(
  checkResult: "needs-apply" | "ok",
  applyResult: "changed" | "failed" | "ok",
  name = "test-module"
): Module {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply() {
      return { status: applyResult }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check() {
      return checkResult
    },
    name,
  }
}

describe("recipe", () => {
  // Suppress console output from recipe's printRecipeHeader / printModuleResult
  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("executes all modules sequentially", async () => {
    const order: string[] = []
    const mod1: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        order.push("apply-1")
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        order.push("check-1")
        return "needs-apply"
      },
      name: "first",
    }
    const mod2: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        order.push("apply-2")
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        order.push("check-2")
        return "needs-apply"
      },
      name: "second",
    }

    const r = recipe("test-recipe", [mod1, mod2])
    // eslint-disable-next-line prefer-spread
    await r.apply(null, emptyEnv)

    expect(order).toStrictEqual(["check-1", "apply-1", "check-2", "apply-2"])
  })

  it("aggregates status as ok when all modules are already ok", async () => {
    const mod1 = makeModule("ok", "ok", "mod-1")
    const mod2 = makeModule("ok", "ok", "mod-2")

    const r = recipe("test-recipe", [mod1, mod2])
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
  })

  it("hands the first child module a null-prototype environment", async () => {
    // R-0000079: executeModules used to initialize state.env via object
    // spread (`{ ...parameters.environment }`), which always creates a plain
    // object with Object.prototype, breaking the null-prototype hardening
    // from R-0000069 / R-0000070 / R-0000074 for the very first child
    // module. Verify that the first child observes a map without
    // Object.prototype on the prototype chain.
    let receivedEnv: Environment | undefined
    const captureModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply(_ssh, environment) {
        receivedEnv = environment
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "capture-module",
    }

    const nullProtoEnv: Environment = Object.create(null)
    nullProtoEnv.EXISTING = "value"

    const r = recipe("test-recipe", [captureModule])
    // eslint-disable-next-line prefer-spread
    await r.apply(null, nullProtoEnv)

    expect(receivedEnv).toBeDefined()
    expect(Object.getPrototypeOf(receivedEnv)).toBeNull()
    expect(receivedEnv?.EXISTING).toBe("value")
  })

  it("aggregates status as changed when at least one module changed", async () => {
    const mod1 = makeModule("ok", "ok", "mod-1")
    const mod2 = makeModule("needs-apply", "changed", "mod-2")

    const r = recipe("test-recipe", [mod1, mod2])
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("changed")
  })

  it("indents nested recipes and their child modules in CLI output", async () => {
    const consoleLogs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })

    const nestedChild = makeModule("needs-apply", "ok", "nested-child")
    const nestedRecipe = recipe("nested-recipe", [nestedChild])
    const outerRecipe = recipe("outer-recipe", [nestedRecipe])
    const applyRecipe = outerRecipe.apply

    await applyRecipe(null, emptyEnv)

    const output = consoleLogs.join("\n")

    expect(output).toContain("[outer-recipe]")
    expect(output).toContain("\n  · [nested-recipe]")
    expect(output).toContain("\n  · · ✓  nested-child")
    expect(output).toContain("\n  · ✓  nested-recipe")
  })

  it("prints child module detail text in recipe output", async () => {
    const consoleLogs: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })

    const childModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { detail: "(sha256:new-traefik-id)", status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "quadlet.updateImage: traefik",
    }

    const applyRecipe = recipe("image-update", [childModule]).apply
    await applyRecipe(null, emptyEnv)

    const output = consoleLogs.join("\n")
    expect(output).toContain("quadlet.updateImage: traefik")
    expect(output).toContain("(sha256:new-traefik-id)")
  })

  it("aggregates status as failed and stops when a module fails", async () => {
    const applyCount = { count: 0 }
    const mod1 = makeModule("needs-apply", "failed", "mod-1")
    const mod2: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        applyCount.count++
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "mod-2",
    }

    const r = recipe("test-recipe", [mod1, mod2])
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    // mod2 should not have been applied because mod1 failed
    expect(applyCount.count).toBe(0)
  })

  it("prints verbose diagnostics for failed child modules when recipe apply runs with verbose", async () => {
    const consoleErrors: string[] = []
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const failingModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return {
          error: new CommandError("child failed summary", "child stdout", "child stderr"),
          status: "failed",
        }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "child-module",
    }

    const r = recipe("test-recipe", [failingModule])
    const result = await r.apply(null, emptyEnv, { verbose: true })

    expect(result.status).toBe("failed")
    const output = consoleErrors.join("\n")
    expect(output).toContain("child failed summary")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("child stderr")
    expect(output).toContain("Full stdout:")
    expect(output).toContain("child stdout")
  })

  it("logs the concrete child module name when child check() throws", async () => {
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const throwingChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockRejectedValue(new Error("child check exploded")),
      name: "throwing-check-child",
    }

    const r = recipe("test-recipe", [throwingChild])
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(consoleLogs.join("\n")).toContain("throwing-check-child")
    expect(consoleErrors.join("\n")).toContain("child check exploded")
  })

  it("logs the concrete child module name when child apply() throws", async () => {
    const consoleLogs: string[] = []
    const consoleErrors: string[] = []
    vi.spyOn(console, "log").mockImplementation((...args) => {
      consoleLogs.push(args.join(" "))
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      consoleErrors.push(args.join(" "))
    })

    const throwingChild: Module = {
      apply: vi.fn().mockRejectedValue(new Error("child apply exploded")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "throwing-apply-child",
    }

    const r = recipe("test-recipe", [throwingChild])
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(consoleLogs.join("\n")).toContain("throwing-apply-child")
    expect(consoleErrors.join("\n")).toContain("child apply exploded")
  })

  it("does not trigger signals when status is ok", async () => {
    const signalApplied = { count: 0 }
    const signal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        signalApplied.count++
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "signal-module",
    }

    const mod = makeModule("ok", "ok")
    const r = recipe("test-recipe", [mod], { signals: [signal] })
    // eslint-disable-next-line prefer-spread
    await r.apply(null, emptyEnv)

    expect(signalApplied.count).toBe(0)
  })

  it("triggers signals when status is changed", async () => {
    const signalApplied = { count: 0 }
    const signal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        signalApplied.count++
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "signal-module",
    }

    const mod = makeModule("needs-apply", "changed")
    const r = recipe("test-recipe", [mod], { signals: [signal] })
    // eslint-disable-next-line prefer-spread
    await r.apply(null, emptyEnv)

    expect(signalApplied.count).toBe(1)
  })

  it("still triggers signals after firstRun.stop when an earlier child changed", async () => {
    const signalApplied = { count: 0 }
    const signal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        signalApplied.count++
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "signal-module",
    }

    const changedModule = makeModule("needs-apply", "changed")
    const r = recipe("test-recipe", [changedModule, firstRun.stop("bootstrap boundary")], {
      signals: [signal],
    })
    const applyRecipe = r.apply
    const result = await applyRecipe(null, { PARATIX_FIRST_RUN: "true" })

    expect(result.status).toBe("changed")
    expect(result._stopRun).toBe(true)
    expect(signalApplied.count).toBe(1)
  })

  it("flushes pending recipe signals immediately and does not rerun them at recipe end", async () => {
    const signalApplied = { count: 0 }
    const signal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        signalApplied.count++
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "signal-module",
    }

    const changedModule = makeModule("needs-apply", "changed")
    const applyRecipe = recipe(
      "test-recipe",
      [changedModule, signals.flush("after changed module")],
      { signals: [signal] }
    ).apply
    const result = await applyRecipe(null, emptyEnv)

    expect(result.status).toBe("changed")
    expect(signalApplied.count).toBe(1)
  })

  it("can flush recipe signals multiple times when new changes happen after a checkpoint", async () => {
    const signalApplied = { count: 0 }
    const signal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        signalApplied.count++
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "signal-module",
    }

    const changedModule = makeModule("needs-apply", "changed")
    const applyRecipe = recipe(
      "test-recipe",
      [changedModule, signals.flush("checkpoint"), changedModule],
      { signals: [signal] }
    ).apply
    await applyRecipe(null, emptyEnv)

    expect(signalApplied.count).toBe(2)
  })

  it("sets the recipe status to failed when a signal returns failed", async () => {
    const signal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { status: "failed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "signal-module",
    }

    const mod = makeModule("needs-apply", "changed")
    const r = recipe("test-recipe", [mod], { signals: [signal] })
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("keeps the recipe status failed when a later signal succeeds", async () => {
    const firstSignal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { status: "failed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "first-signal",
    }
    const secondSignal: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "second-signal",
    }

    const mod = makeModule("needs-apply", "changed")
    const r = recipe("test-recipe", [mod], { signals: [firstSignal, secondSignal] })
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("sets the recipe status to failed when a signal throws", async () => {
    const signal: Module = {
      apply: vi.fn().mockRejectedValue(new Error("signal failed")),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "signal-module",
    }

    const mod = makeModule("needs-apply", "changed")
    const r = recipe("test-recipe", [mod], { signals: [signal] })
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it.each(["SIGINT", "SIGTERM"] as const)(
    "stops before the next recipe signal when shutdown was requested during %s",
    async (signalName) => {
      let receivedSignal: NodeJS.Signals | null = null
      const firstSignal: Module = {
        // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
        async apply() {
          receivedSignal = signalName
          return { status: "changed" }
        },
        // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
        async check() {
          return "needs-apply"
        },
        name: "first-signal",
      }
      const secondSignal: Module = {
        apply: vi.fn().mockResolvedValue({ status: "changed" }),
        check: vi.fn().mockResolvedValue("needs-apply"),
        name: "second-signal",
      }

      const mod = makeModule("needs-apply", "changed")
      const r = recipe("test-recipe", [mod], { signals: [firstSignal, secondSignal] })
      const result = await r.apply(null, emptyEnv, { shutdownSignal: () => receivedSignal })

      expect(result.status).toBe("changed")
      expect(secondSignal.apply).not.toHaveBeenCalled()
    }
  )

  it("check returns ok for a recipe with no child modules", async () => {
    const r = recipe("empty", [])
    const result = await r.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("aggregates dry-run blocker markers from nested recipe children", () => {
    const nestedRecipe = recipe("nested-recipe", [assert(() => false, "must pass")])
    const outerRecipe = recipe("outer-recipe", [nestedRecipe])

    expect(nestedRecipe._dryRunBlocker).toBe(true)
    expect(nestedRecipe._applyDryRun).toStrictEqual(expect.any(Function))
    expect(outerRecipe._dryRunBlocker).toBe(true)
    expect(outerRecipe._applyDryRun).toStrictEqual(expect.any(Function))
  })

  it("treats nested fail() as a blocker in recipe dry-run mode", async () => {
    const laterChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "later-child",
    }
    const outerRecipe = recipe("outer-recipe", [
      recipe("nested-recipe", [fail("stop here")]),
      laterChild,
    ])

    const result = await dryRunRecipeModule({
      environment: emptyEnv,
      recipeModule: outerRecipe,
      ssh: createMockSsh(),
    })

    expect(result.status).toBe("failed")
    expect(result.shouldBreak).toBe(true)
    expect(laterChild.check).not.toHaveBeenCalled()
    expect(laterChild.apply).not.toHaveBeenCalled()
  })

  it("propagates nested dry-run meta producer env to later recipe children", async () => {
    const metaProducer: Module = {
      _dryRunMetaProducer: true,
      apply: vi.fn().mockResolvedValue({
        meta: [
          {
            kind: "env",
            name: "TOKEN",
            async resolve() {
              await Promise.resolve()
              return "nested-secret"
            },
            valueType: "string",
          },
        ],
        status: "ok",
      }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "meta-producer",
    }
    let receivedEnvInCheck: Environment | undefined
    const dependentChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" }),
      check: vi.fn().mockImplementation(async (_ssh, env: Environment) => {
        await Promise.resolve()
        receivedEnvInCheck = env
        return "ok" as const
      }),
      name: "dependent-child",
    }
    const outerRecipe = recipe("outer-recipe", [
      recipe("nested-recipe", [metaProducer]),
      dependentChild,
    ])

    await dryRunRecipeModule({
      environment: emptyEnv,
      recipeModule: outerRecipe,
      ssh: createMockSsh(),
    })

    expect(receivedEnvInCheck).toBeDefined()
    await expect(resolveEnvironment(receivedEnvInCheck!, "TOKEN")).resolves.toBe("nested-secret")
    expect(dependentChild.apply).not.toHaveBeenCalled()
  })

  it("check returns ok when all child modules report ok", async () => {
    const mod1 = makeModule("ok", "ok", "mod-1")
    const mod2 = makeModule("ok", "ok", "mod-2")
    const r = recipe("test-recipe", [mod1, mod2])
    const result = await r.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when any child module reports needs-apply", async () => {
    const mod1 = makeModule("ok", "ok", "mod-1")
    const mod2 = makeModule("needs-apply", "changed", "mod-2")
    const r = recipe("test-recipe", [mod1, mod2])
    const result = await r.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check short-circuits on first needs-apply", async () => {
    const mod1 = makeModule("needs-apply", "changed", "mod-1")
    const mod2: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" }),
      check: vi.fn().mockResolvedValue("ok"),
      name: "mod-2",
    }
    const r = recipe("test-recipe", [mod1, mod2])
    await r.check(null, emptyEnv)
    expect(mod2.check).not.toHaveBeenCalled()
  })

  it("passes null to local child module in check()", async () => {
    const localMod: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("ok"),
      local: true,
      name: "local-mod",
    }
    const mockSsh = createMockSsh()
    const r = recipe("test-recipe", [localMod])
    await r.check(mockSsh, emptyEnv)
    expect(localMod.check).toHaveBeenCalledWith(null, emptyEnv)
  })

  it("passes null to local child module in apply()", async () => {
    const localMod: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      local: true,
      name: "local-mod",
    }
    const mockSsh = createMockSsh()
    const r = recipe("test-recipe", [localMod])
    await r.apply(mockSsh, emptyEnv)
    expect(localMod.apply).toHaveBeenCalledWith(null, emptyEnv)
  })

  it("passes null to local recipe signal in apply()", async () => {
    const localSignal: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      local: true,
      name: "local-signal",
    }
    const mod = makeModule("needs-apply", "changed")
    const mockSsh = createMockSsh()
    const r = recipe("test-recipe", [mod], { signals: [localSignal] })

    await r.apply(mockSsh, emptyEnv)

    expect(localSignal.apply).toHaveBeenCalledWith(null, emptyEnv)
  })

  it("stops before the next child module when shutdown was requested during recipe execution", async () => {
    let receivedSignal: NodeJS.Signals | null = null
    const firstModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        receivedSignal = "SIGINT"
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "first-mod",
    }
    const secondModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "second-mod",
    }

    const r = recipe("test-recipe", [firstModule, secondModule])
    const result = await r.apply(null, emptyEnv, { shutdownSignal: () => receivedSignal })

    expect(result.status).toBe("changed")
    expect(secondModule.check).not.toHaveBeenCalled()
    expect(secondModule.apply).not.toHaveBeenCalled()
  })

  it("does not start child apply() when shutdown was requested after check()", async () => {
    let receivedSignal: NodeJS.Signals | null = null
    const firstModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        receivedSignal = "SIGTERM"
        return "needs-apply"
      },
      name: "first-mod",
    }
    const secondModule: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "second-mod",
    }

    const r = recipe("test-recipe", [firstModule, secondModule])
    const result = await r.apply(null, emptyEnv, { shutdownSignal: () => receivedSignal })

    expect(result.status).toBe("ok")
    expect(firstModule.apply).not.toHaveBeenCalled()
    expect(secondModule.check).not.toHaveBeenCalled()
    expect(secondModule.apply).not.toHaveBeenCalled()
  })

  it("check propagates exceptions from child module check()", async () => {
    const failing: Module = {
      apply: vi.fn().mockResolvedValue({ status: "ok" }),
      check: vi.fn().mockRejectedValue(new Error("check failed")),
      name: "failing-mod",
    }
    const r = recipe("test-recipe", [failing])
    await expect(r.check(null, emptyEnv)).rejects.toThrow("[failing-mod] check failed")
  })

  it("propagates shutdownSignal into nested recipe loops (R-0000091)", async () => {
    // R-0000091: when a child of an outer recipe is itself a RecipeModule,
    // the outer loop must forward its shutdownSignal so the inner recipe
    // loop also breaks early on SIGINT/SIGTERM. Without the fix, the inner
    // applyRecipe receives parameters=undefined and defaults to () => null,
    // so SIGINT does not abort the inner loop.
    let receivedSignal: NodeJS.Signals | null = null
    const innerFirst: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        receivedSignal = "SIGINT"
        return { status: "changed" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "inner-first",
    }
    const innerSecond: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "inner-second",
    }
    const innerRecipe = recipe("inner-recipe", [innerFirst, innerSecond])
    const outerRecipe = recipe("outer-recipe", [innerRecipe])

    const result = await outerRecipe.apply(null, emptyEnv, {
      shutdownSignal: () => receivedSignal,
    })

    expect(result.status).toBe("changed")
    expect(innerSecond.check).not.toHaveBeenCalled()
    expect(innerSecond.apply).not.toHaveBeenCalled()
  })

  it("honors the runner abort signal between children in check (R-0000096)", async () => {
    // R-0000096: recipe.check used to iterate every child synchronously
    // without observing the runner abort signal. When earlier check()
    // implementations are slow, SIGINT only takes effect after the whole
    // recipe finished checking. After the fix, the loop bails out as soon
    // as the abort signal is set and reports "ok" so no apply runs.
    const controller = new AbortController()
    const firstChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        controller.abort()
        return "ok"
      },
      name: "first-check",
    }
    const secondChild: Module = {
      apply: vi.fn().mockResolvedValue({ status: "changed" }),
      check: vi.fn().mockResolvedValue("needs-apply"),
      name: "second-check",
    }

    setRunnerAbortSignal(controller.signal)
    try {
      const r = recipe("test-recipe", [firstChild, secondChild])
      const result = await r.check(null, emptyEnv)

      expect(result).toBe("ok")
      expect(secondChild.check).not.toHaveBeenCalled()
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })
})
