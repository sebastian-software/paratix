import { describe, expect, it, vi } from "vitest"

import type { Module } from "../src/types.js"

import { createConditionalModule } from "../src/conditionalModules.js"
import { createSkipModule } from "../src/moduleFilter.js"
import { recipe } from "../src/recipe.js"
import {
  collectSecretPrewarmCarrierNames,
  prewarmSecrets,
  resolveCachedSecret,
  withSecretPrewarmScope,
} from "../src/secretPrewarm.js"

function makeCarrier(name: string, hook: () => Promise<void>): Module {
  return {
    _prewarmSecrets: hook,
    apply: vi.fn().mockResolvedValue({ status: "ok" }),
    check: vi.fn().mockResolvedValue("ok"),
    name,
  }
}

function makePlainModule(name: string): Module {
  return {
    apply: vi.fn().mockResolvedValue({ status: "ok" }),
    check: vi.fn().mockResolvedValue("ok"),
    name,
  }
}

// ---------------------------------------------------------------------------
// prewarmSecrets — walk coverage
// ---------------------------------------------------------------------------

describe("prewarmSecrets — walk coverage", () => {
  it("reaches a top-level carrier", async () => {
    const hook = vi.fn().mockResolvedValue(undefined)
    const carrier = makeCarrier("top-level-carrier", hook)

    await prewarmSecrets([carrier])

    expect(hook).toHaveBeenCalledOnce()
  })

  it("reaches a carrier nested inside a recipe's _modules", async () => {
    const hook = vi.fn().mockResolvedValue(undefined)
    const carrier = makeCarrier("recipe-child-carrier", hook)
    const wrapped = recipe("wrapper-recipe", [makePlainModule("plain-sibling"), carrier])

    await prewarmSecrets([wrapped])

    expect(hook).toHaveBeenCalledOnce()
  })

  it("reaches a carrier nested inside a recipe's _signals", async () => {
    const hook = vi.fn().mockResolvedValue(undefined)
    const carrier = makeCarrier("recipe-signal-carrier", hook)
    const wrapped = recipe("wrapper-recipe", [makePlainModule("plain-child")], {
      signals: [carrier],
    })

    await prewarmSecrets([wrapped])

    expect(hook).toHaveBeenCalledOnce()
  })

  it("reaches a carrier nested inside a when(...) block via its own delegation hook", async () => {
    const hook = vi.fn().mockResolvedValue(undefined)
    const carrier = makeCarrier("guarded-carrier", hook)
    const guardCondition = vi.fn(() => true)
    const block = createConditionalModule({
      condition: guardCondition,
      modules: [carrier],
      name: "guard-block",
    })

    await prewarmSecrets([block])

    expect(hook).toHaveBeenCalledOnce()
    // The guard condition is remote and unresolvable before the connect, so
    // the walk must not evaluate it while descending into the block.
    expect(guardCondition).not.toHaveBeenCalled()
  })

  it("reaches a carrier passed via definition.signals-equivalent top-level list", async () => {
    // definition.signals is just another Module[] the runner concatenates
    // onto definition.run before calling prewarmSecrets — exercised here by
    // passing two independent top-level lists merged the same way runner.ts does.
    const runHook = vi.fn().mockResolvedValue(undefined)
    const signalHook = vi.fn().mockResolvedValue(undefined)
    const runCarrier = makeCarrier("run-carrier", runHook)
    const signalCarrier = makeCarrier("signal-carrier", signalHook)

    await prewarmSecrets([runCarrier, signalCarrier])

    expect(runHook).toHaveBeenCalledOnce()
    expect(signalHook).toHaveBeenCalledOnce()
  })

  it("does not invoke anything at a createSkipModule node", async () => {
    // A filtered-out carrier is replaced by a skip module before the walk
    // ever runs, so a skip module carries no _prewarmSecrets hook and there is
    // nothing to call. Assert this directly on the module the filter produces.
    const skip = createSkipModule("filtered-out")

    expect(skip._prewarmSecrets).toBeUndefined()
    const applySpy = vi.spyOn(skip, "apply")
    const checkSpy = vi.spyOn(skip, "check")

    // The walk over a skip module resolves without throwing and without
    // invoking apply/check.
    await expect(prewarmSecrets([skip])).resolves.toBeUndefined()
    expect(applySpy).not.toHaveBeenCalled()
    expect(checkSpy).not.toHaveBeenCalled()
  })

  it("calls onBeforeFirstPrewarm exactly once, only when a carrier exists", async () => {
    const onBeforeFirstPrewarm = vi.fn<() => void>()
    const hook = vi.fn().mockResolvedValue(undefined)
    const carrier = makeCarrier("carrier", hook)

    await prewarmSecrets([carrier, makeCarrier("carrier-2", hook)], { onBeforeFirstPrewarm })

    expect(onBeforeFirstPrewarm).toHaveBeenCalledOnce()
  })

  it("does not call onBeforeFirstPrewarm when the tree carries no hook", async () => {
    const onBeforeFirstPrewarm = vi.fn<() => void>()

    await prewarmSecrets([makePlainModule("plain")], { onBeforeFirstPrewarm })

    expect(onBeforeFirstPrewarm).not.toHaveBeenCalled()
  })

  it("awaits hooks sequentially, not in parallel", async () => {
    const order: string[] = []
    const first = makeCarrier("first", async () => {
      order.push("first-start")
      await Promise.resolve()
      order.push("first-end")
    })
    const second = makeCarrier("second", async () => {
      order.push("second-start")
      await Promise.resolve()
      order.push("second-end")
    })

    await prewarmSecrets([first, second])

    expect(order).toStrictEqual(["first-start", "first-end", "second-start", "second-end"])
  })
})

// ---------------------------------------------------------------------------
// collectSecretPrewarmCarrierNames
// ---------------------------------------------------------------------------

describe("collectSecretPrewarmCarrierNames", () => {
  it("finds a top-level carrier", () => {
    const carrier = makeCarrier("top-level", vi.fn())

    expect(collectSecretPrewarmCarrierNames([carrier])).toStrictEqual(new Set(["top-level"]))
  })

  it("finds a carrier nested inside a recipe", () => {
    const carrier = makeCarrier("nested-carrier", vi.fn())
    const wrapped = recipe("wrapper", [makePlainModule("plain"), carrier])

    expect(collectSecretPrewarmCarrierNames([wrapped])).toStrictEqual(new Set(["nested-carrier"]))
  })

  it("finds a when(...) block as a carrier by its own name, not its children", () => {
    const innerCarrier = makeCarrier("inner", vi.fn())
    const block = createConditionalModule({
      condition: () => true,
      modules: [innerCarrier],
      name: "guard-block",
    })

    // The block itself owns the hook (delegation), so it is the carrier —
    // its guarded children are never visited directly by the collector.
    expect(collectSecretPrewarmCarrierNames([block])).toStrictEqual(new Set(["guard-block"]))
  })

  it("ignores a createSkipModule node", () => {
    const skip = createSkipModule("filtered-out")

    expect(collectSecretPrewarmCarrierNames([skip])).toStrictEqual(new Set())
  })

  it("returns an empty set for a tree without any carrier", () => {
    expect(collectSecretPrewarmCarrierNames([makePlainModule("plain")])).toStrictEqual(new Set())
  })
})

// ---------------------------------------------------------------------------
// resolveCachedSecret
// ---------------------------------------------------------------------------

describe("resolveCachedSecret", () => {
  it("loads a key exactly once and returns the same value on a later call", async () => {
    const load = vi.fn().mockResolvedValue("resolved-value")

    await withSecretPrewarmScope(async () => {
      const first = await resolveCachedSecret("key-a", load)
      const second = await resolveCachedSecret("key-a", load)

      expect(first).toBe("resolved-value")
      expect(second).toBe("resolved-value")
      expect(load).toHaveBeenCalledOnce()
    })
  })

  it("loads distinct keys independently", async () => {
    const load = vi.fn<() => Promise<string>>().mockImplementation(async () => {
      await Promise.resolve()
      return "value"
    })

    await withSecretPrewarmScope(async () => {
      await resolveCachedSecret("key-a", load)
      await resolveCachedSecret("key-b", load)

      expect(load).toHaveBeenCalledTimes(2)
    })
  })

  it("evicts a rejected load so a later attempt starts fresh", async () => {
    const load = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("first attempt fails"))
      .mockResolvedValueOnce("second-attempt-value")

    await withSecretPrewarmScope(async () => {
      await expect(resolveCachedSecret("flaky-key", load)).rejects.toThrow("first attempt fails")
      await expect(resolveCachedSecret("flaky-key", load)).resolves.toBe("second-attempt-value")
      expect(load).toHaveBeenCalledTimes(2)
    })
  })

  it("passes load() through unchanged when no scope is active", async () => {
    const load = vi.fn().mockResolvedValue("direct-value")

    // No withSecretPrewarmScope wrapper: this is the direct-library-call /
    // unit-test shape the plan requires to behave exactly as before the cache.
    const first = await resolveCachedSecret("unscoped-key", load)
    const second = await resolveCachedSecret("unscoped-key", load)

    expect(first).toBe("direct-value")
    expect(second).toBe("direct-value")
    expect(load).toHaveBeenCalledTimes(2)
  })

  it("still evicts a rejection when no scope is active", async () => {
    const load = vi.fn().mockRejectedValue(new Error("unscoped failure"))

    await expect(resolveCachedSecret("unscoped-key", load)).rejects.toThrow("unscoped failure")
    expect(load).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// withSecretPrewarmScope
// ---------------------------------------------------------------------------

describe("withSecretPrewarmScope", () => {
  it("returns the value the body resolves to", async () => {
    const result = await withSecretPrewarmScope(async () => {
      await Promise.resolve()
      return "body-result"
    })

    expect(result).toBe("body-result")
  })

  it("reuses the enclosing cache instead of opening a second one for a nested call", async () => {
    const load = vi.fn().mockResolvedValue("nested-scope-value")

    await withSecretPrewarmScope(async () => {
      await resolveCachedSecret("shared-key", load)
      await withSecretPrewarmScope(async () => {
        await resolveCachedSecret("shared-key", load)
      })
    })

    expect(load).toHaveBeenCalledOnce()
  })
})
