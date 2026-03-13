import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module } from "../src/types.js"

import { recipe } from "../src/recipe.js"

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

  it("recipe check always returns needs-apply", async () => {
    const mod = makeModule("ok", "ok")
    const r = recipe("test-recipe", [mod])
    const result = await r.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
