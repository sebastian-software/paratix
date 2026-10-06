import { afterEach, describe, expect, it, vi } from "vitest"

import type * as RunnerAbortSignalModule from "../src/runnerAbortSignal.js"

import {
  getRunnerAbortSignal,
  setRunnerAbortSignal,
  withRunnerAbortSignal,
} from "../src/runnerAbortSignal.js"

describe("runnerAbortSignal", () => {
  it("returns undefined outside any scope", () => {
    expect(getRunnerAbortSignal()).toBeUndefined()
  })

  it("scopes the signal to the async chain wrapped by withRunnerAbortSignal", async () => {
    const controller = new AbortController()
    let observed: AbortSignal | undefined
    await withRunnerAbortSignal(controller.signal, async () => {
      await Promise.resolve()
      observed = getRunnerAbortSignal()
    })
    expect(observed).toBe(controller.signal)
    // R-0000743: the scope ends with the wrapped body so the outer chain
    // is unaffected by the inner signal.
    expect(getRunnerAbortSignal()).toBeUndefined()
  })

  it("keeps parallel withRunnerAbortSignal scopes isolated", async () => {
    const controllerA = new AbortController()
    const controllerB = new AbortController()
    const observedA: Array<AbortSignal | undefined> = []
    const observedB: Array<AbortSignal | undefined> = []

    const runA = withRunnerAbortSignal(controllerA.signal, async () => {
      observedA.push(getRunnerAbortSignal())
      await Promise.resolve()
      observedA.push(getRunnerAbortSignal())
      // Yield once more so runB has a chance to interleave between the two
      // observation points without leaking its signal into this chain.
      await new Promise<void>((resolveTick) => {
        setImmediate(resolveTick)
      })
      observedA.push(getRunnerAbortSignal())
    })
    const runB = withRunnerAbortSignal(controllerB.signal, async () => {
      observedB.push(getRunnerAbortSignal())
      await Promise.resolve()
      observedB.push(getRunnerAbortSignal())
      await new Promise<void>((resolveTick) => {
        setImmediate(resolveTick)
      })
      observedB.push(getRunnerAbortSignal())
    })

    await Promise.all([runA, runB])

    expect(observedA).toStrictEqual([controllerA.signal, controllerA.signal, controllerA.signal])
    expect(observedB).toStrictEqual([controllerB.signal, controllerB.signal, controllerB.signal])
  })

  it("allows setRunnerAbortSignal to seed the current async chain", async () => {
    await withRunnerAbortSignal(undefined, async () => {
      const controller = new AbortController()
      setRunnerAbortSignal(controller.signal)
      await Promise.resolve()
      expect(getRunnerAbortSignal()).toBe(controller.signal)
      setRunnerAbortSignal(undefined)
      expect(getRunnerAbortSignal()).toBeUndefined()
    })
  })

  it("propagates the scoped signal into nested async branches", async () => {
    const controller = new AbortController()
    const observations: Array<AbortSignal | undefined> = []

    await withRunnerAbortSignal(controller.signal, async () => {
      observations.push(getRunnerAbortSignal())
      await Promise.all([
        (async () => {
          await Promise.resolve()
          observations.push(getRunnerAbortSignal())
        })(),
        (async () => {
          await new Promise<void>((resolveTick) => {
            setImmediate(resolveTick)
          })
          observations.push(getRunnerAbortSignal())
        })(),
      ])
    })

    expect(observations).toStrictEqual([controller.signal, controller.signal, controller.signal])
  })
})

/**
 * #193: the published package bundles `runnerAbortSignal.ts` twice — once
 * into `dist/cli.js` (the runner installs the signal there) and once into the
 * library chunk behind `dist/index.js` (`pause`, `net.waitFor`, `op` and user
 * recipes read it there). Fresh module instances across `vi.resetModules()`
 * simulate that bundle split without a build.
 *
 * @returns Two independently evaluated instances of the module.
 */
async function importTwoInstances(): Promise<
  [typeof RunnerAbortSignalModule, typeof RunnerAbortSignalModule]
> {
  vi.resetModules()
  const first = await import("../src/runnerAbortSignal.js")
  vi.resetModules()
  const second = await import("../src/runnerAbortSignal.js")
  return [first, second]
}

describe("runnerAbortSignal process-wide store across module copies (#193)", () => {
  afterEach(() => {
    vi.resetModules()
  })

  it("loads two distinct module instances across resetModules", async () => {
    const [first, second] = await importTwoInstances()

    expect(first).not.toBe(second)
    expect(first.getRunnerAbortSignal).not.toBe(second.getRunnerAbortSignal)
  })

  it("returns undefined outside any runner in every instance", async () => {
    const [first, second] = await importTwoInstances()

    expect(first.getRunnerAbortSignal()).toBeUndefined()
    expect(second.getRunnerAbortSignal()).toBeUndefined()
  })

  it("makes the signal installed through one instance visible through another instance", async () => {
    const [first, second] = await importTwoInstances()
    const controller = new AbortController()

    const observed = await first.withRunnerAbortSignal(controller.signal, async () => {
      await Promise.resolve()
      return { first: first.getRunnerAbortSignal(), second: second.getRunnerAbortSignal() }
    })

    expect(observed.first).toBe(controller.signal)
    expect(observed.second).toBe(controller.signal)
    expect(first.getRunnerAbortSignal()).toBeUndefined()
    expect(second.getRunnerAbortSignal()).toBeUndefined()
  })
})
