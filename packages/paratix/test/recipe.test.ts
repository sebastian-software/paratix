import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module } from "../src/types.js"

import { firstRun } from "../src/builtins.js"
import { recipe } from "../src/recipe.js"
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

  it("aggregates status as changed when at least one module changed", async () => {
    const mod1 = makeModule("ok", "ok", "mod-1")
    const mod2 = makeModule("needs-apply", "changed", "mod-2")

    const r = recipe("test-recipe", [mod1, mod2])
    // eslint-disable-next-line prefer-spread
    const result = await r.apply(null, emptyEnv)

    expect(result.status).toBe("changed")
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
})
