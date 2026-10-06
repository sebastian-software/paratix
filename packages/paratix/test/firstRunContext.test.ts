import type { AsyncLocalStorage } from "node:async_hooks"

import { afterEach, describe, expect, it, vi } from "vitest"

import type * as FirstRunContextModule from "../src/firstRunContext.js"

/**
 * #201: the published package bundles `firstRunContext.ts` twice — once into
 * `dist/cli.js` (which opens the scope) and once into `dist/index.js` (which
 * playbooks import `isFirstRun` from). Two fresh module instances across
 * `vi.resetModules()` simulate that bundle split without a build.
 *
 * @returns Two independently evaluated instances of the module.
 */
async function importTwoInstances(): Promise<
  [typeof FirstRunContextModule, typeof FirstRunContextModule]
> {
  vi.resetModules()
  const first = await import("../src/firstRunContext.js")
  vi.resetModules()
  const second = await import("../src/firstRunContext.js")
  return [first, second]
}

describe("firstRunContext process-wide store", () => {
  afterEach(() => {
    vi.resetModules()
  })

  it("loads two distinct module instances across resetModules", async () => {
    const [first, second] = await importTwoInstances()

    expect(first).not.toBe(second)
    expect(first.isFirstRun).not.toBe(second.isFirstRun)
  })

  it("returns false outside any scope in every instance", async () => {
    const [first, second] = await importTwoInstances()

    expect(first.isFirstRun()).toBe(false)
    expect(second.isFirstRun()).toBe(false)
  })

  it("makes a scope opened through one instance visible through another instance", async () => {
    const [first, second] = await importTwoInstances()

    const observed = await first.runWithFirstRunFlag(async () => {
      await Promise.resolve()
      return { first: first.isFirstRun(), second: second.isFirstRun() }
    })

    expect(observed).toStrictEqual({ first: true, second: true })
    expect(first.isFirstRun()).toBe(false)
    expect(second.isFirstRun()).toBe(false)
  })

  it("lets a masking scope from one instance hide an outer scope opened by another instance", async () => {
    const [first, second] = await importTwoInstances()

    const observed = await first.runWithFirstRunFlag(async () => {
      const masked = await second.runWithoutFirstRunFlag(async () => {
        await Promise.resolve()
        return { first: first.isFirstRun(), second: second.isFirstRun() }
      })
      return {
        afterMask: { first: first.isFirstRun(), second: second.isFirstRun() },
        masked,
      }
    })

    expect(observed).toStrictEqual({
      afterMask: { first: true, second: true },
      masked: { first: false, second: false },
    })
  })

  it("stores the shared storage under the fixed cross-version globalThis key", async () => {
    // The key name is a cross-bundle and cross-version contract: every
    // paratix copy that carries the fix must find the same slot. Renaming it
    // splits the store again between differently versioned copies.
    const [first] = await importTwoInstances()
    const registry = globalThis as Record<symbol, AsyncLocalStorage<boolean> | undefined>
    const storage = registry[Symbol.for("paratix.firstRunContext.storage")]

    expect(storage).toBeDefined()
    const storeInsideScope = await first.runWithFirstRunFlag(async () => {
      await Promise.resolve()
      return storage?.getStore()
    })
    expect(storeInsideScope).toBe(true)
  })
})
