import { afterEach, describe, expect, it, vi } from "vitest"

import {
  createTestSignalBus,
  getSignalBus,
  resetSignalBus,
  setSignalBus,
  type SignalHandler,
} from "../src/signalBus.js"

describe("signalBus default process bus", () => {
  afterEach(() => {
    resetSignalBus()
  })

  it("delegates listenerCount/on/off to the underlying process events", () => {
    const bus = getSignalBus()
    const interruptBefore = bus.listenerCount("SIGINT")
    const terminateBefore = bus.listenerCount("SIGTERM")

    const handler: SignalHandler = vi.fn<SignalHandler>()

    bus.on("SIGINT", handler)
    bus.on("SIGTERM", handler)

    expect(process.listenerCount("SIGINT")).toBe(interruptBefore + 1)
    expect(process.listenerCount("SIGTERM")).toBe(terminateBefore + 1)
    expect(bus.listenerCount("SIGINT")).toBe(interruptBefore + 1)
    expect(bus.listenerCount("SIGTERM")).toBe(terminateBefore + 1)

    bus.off("SIGINT", handler)
    bus.off("SIGTERM", handler)

    expect(process.listenerCount("SIGINT")).toBe(interruptBefore)
    expect(process.listenerCount("SIGTERM")).toBe(terminateBefore)
  })
})

describe("createTestSignalBus", () => {
  afterEach(() => {
    resetSignalBus()
  })

  it("tracks handlers per signal and reports listenerCount", () => {
    const bus = createTestSignalBus()
    const interruptHandler: SignalHandler = vi.fn<SignalHandler>()
    const terminateHandler: SignalHandler = vi.fn<SignalHandler>()

    expect(bus.listenerCount("SIGINT")).toBe(0)
    expect(bus.listenerCount("SIGTERM")).toBe(0)

    bus.on("SIGINT", interruptHandler)
    bus.on("SIGTERM", terminateHandler)

    expect(bus.listenerCount("SIGINT")).toBe(1)
    expect(bus.listenerCount("SIGTERM")).toBe(1)

    bus.off("SIGINT", interruptHandler)
    expect(bus.listenerCount("SIGINT")).toBe(0)
    expect(bus.listenerCount("SIGTERM")).toBe(1)
  })

  it("emits a signal synchronously to every registered handler", () => {
    const bus = createTestSignalBus()
    const firstHandler: SignalHandler = vi.fn<SignalHandler>()
    const secondHandler: SignalHandler = vi.fn<SignalHandler>()

    bus.on("SIGINT", firstHandler)
    bus.on("SIGINT", secondHandler)
    bus.emit("SIGINT")

    expect(firstHandler).toHaveBeenCalledTimes(1)
    expect(firstHandler).toHaveBeenCalledWith("SIGINT")
    expect(secondHandler).toHaveBeenCalledTimes(1)
    expect(secondHandler).toHaveBeenCalledWith("SIGINT")
  })

  it("does not invoke handlers registered for a different signal", () => {
    const bus = createTestSignalBus()
    const interruptHandler: SignalHandler = vi.fn<SignalHandler>()
    const terminateHandler: SignalHandler = vi.fn<SignalHandler>()

    bus.on("SIGINT", interruptHandler)
    bus.on("SIGTERM", terminateHandler)
    bus.emit("SIGTERM")

    expect(interruptHandler).not.toHaveBeenCalled()
    expect(terminateHandler).toHaveBeenCalledWith("SIGTERM")
  })

  it("snapshots handlers before emit so off() during dispatch does not skip remaining handlers", () => {
    const bus = createTestSignalBus()
    const second: SignalHandler = vi.fn<SignalHandler>()
    const first: SignalHandler = vi.fn<SignalHandler>(() => {
      bus.off("SIGINT", second)
    })

    bus.on("SIGINT", first)
    bus.on("SIGINT", second)
    bus.emit("SIGINT")

    expect(first).toHaveBeenCalledTimes(1)
    expect(second).toHaveBeenCalledTimes(1)
  })
})

describe("setSignalBus / resetSignalBus", () => {
  afterEach(() => {
    resetSignalBus()
  })

  it("swaps the active bus and restores the default on reset", () => {
    const initialBus = getSignalBus()
    const testBus = createTestSignalBus()

    setSignalBus(testBus)
    expect(getSignalBus()).toBe(testBus)

    resetSignalBus()
    expect(getSignalBus()).toBe(initialBus)
  })

  it("routes on/off through the active bus instance", () => {
    const testBus = createTestSignalBus()
    setSignalBus(testBus)

    const handler: SignalHandler = vi.fn<SignalHandler>()
    getSignalBus().on("SIGINT", handler)

    expect(testBus.listenerCount("SIGINT")).toBe(1)

    testBus.emit("SIGINT")
    expect(handler).toHaveBeenCalledWith("SIGINT")

    getSignalBus().off("SIGINT", handler)
    expect(testBus.listenerCount("SIGINT")).toBe(0)
  })
})
