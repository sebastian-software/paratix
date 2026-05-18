import { describe, expect, it } from "vitest"

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
