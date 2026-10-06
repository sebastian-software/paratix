import { AsyncLocalStorage } from "node:async_hooks"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

/**
 * #193: `secretSink.ts` and `runnerAbortSignal.ts` keep their state in a
 * `Symbol.for` slot on `globalThis`, so the copy bundled into `dist/cli.js`
 * and the copy in the library chunk share one store. A slot that already
 * holds a value of the wrong shape belongs to a different paratix copy or
 * version: the import must fail closed, name the slot and leave the foreign
 * value untouched instead of overwriting it or falling back to private state.
 */
const SECRET_SINK_STATE_KEY = Symbol.for("paratix.secretSink.state")
const RUNNER_ABORT_SIGNAL_STORAGE_KEY = Symbol.for("paratix.runnerAbortSignal.storage")
const SLOT_KEYS = [SECRET_SINK_STATE_KEY, RUNNER_ABORT_SIGNAL_STORAGE_KEY] as const

const registry = globalThis as Record<symbol, unknown>

type SavedSlot = { present: boolean; value: unknown }

function saveSlots(): Map<symbol, SavedSlot> {
  return new Map(
    SLOT_KEYS.map((key) => [key, { present: Object.hasOwn(registry, key), value: registry[key] }])
  )
}

function restoreSlots(saved: Map<symbol, SavedSlot>): void {
  for (const [key, slot] of saved) {
    if (slot.present) {
      registry[key] = slot.value
    } else {
      Reflect.deleteProperty(registry, key)
    }
  }
}

describe("process-wide state slots (#193)", () => {
  let savedSlots: Map<symbol, SavedSlot>

  beforeEach(() => {
    savedSlots = saveSlots()
  })

  afterEach(() => {
    restoreSlots(savedSlots)
    vi.resetModules()
  })

  describe("secretSink slot", () => {
    it("creates the slot eagerly when the secretSink module is evaluated", async () => {
      Reflect.deleteProperty(registry, SECRET_SINK_STATE_KEY)
      vi.resetModules()

      await import("../src/secretSink.js")

      const state = registry[SECRET_SINK_STATE_KEY] as
        { counts?: unknown; scopeStorage?: unknown; version?: unknown } | undefined
      expect(state?.version).toBe(1)
      expect(state?.counts).toBeInstanceOf(Map)
      expect(state?.scopeStorage).toBeInstanceOf(AsyncLocalStorage)
    })

    it("adopts a well-shaped slot that another copy created instead of replacing it", async () => {
      const secret = "preseeded-slot-secret-FFF666"
      const existing = {
        counts: new Map([[secret, 1]]),
        scopeStorage: new AsyncLocalStorage<Map<string, number>>(),
        version: 1,
      }
      registry[SECRET_SINK_STATE_KEY] = existing
      vi.resetModules()

      const sink = await import("../src/secretSink.js")

      expect(registry[SECRET_SINK_STATE_KEY]).toBe(existing)
      expect(sink.maskRegisteredSecrets(`leak ${secret}`)).toBe("leak [REDACTED]")
    })

    it.each([
      {
        label: "a newer layout version",
        value: { counts: new Map(), scopeStorage: new AsyncLocalStorage(), version: 2 },
      },
      { label: "a plain empty object", value: {} },
      {
        label: "counts that are not a Map",
        value: { counts: {}, scopeStorage: new AsyncLocalStorage(), version: 1 },
      },
      {
        label: "a scope storage that is not an AsyncLocalStorage",
        value: { counts: new Map(), scopeStorage: {}, version: 1 },
      },
      { label: "a primitive", value: "foreign" },
    ])("fails the secretSink import closed when the slot holds $label", async ({ value }) => {
      const snapshot = Object.entries(value)
      registry[SECRET_SINK_STATE_KEY] = value
      vi.resetModules()

      await expect(import("../src/secretSink.js")).rejects.toThrow("paratix.secretSink.state")

      expect(registry[SECRET_SINK_STATE_KEY]).toBe(value)
      expect(Object.entries(value)).toStrictEqual(snapshot)
    })
  })

  describe("runnerAbortSignal slot", () => {
    it("creates the slot eagerly when the runnerAbortSignal module is evaluated", async () => {
      Reflect.deleteProperty(registry, RUNNER_ABORT_SIGNAL_STORAGE_KEY)
      vi.resetModules()

      await import("../src/runnerAbortSignal.js")

      expect(registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY]).toBeInstanceOf(AsyncLocalStorage)
    })

    it("adopts a well-shaped slot that another copy created instead of replacing it", async () => {
      const existing = new AsyncLocalStorage<AbortSignal | undefined>()
      registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY] = existing
      vi.resetModules()

      const runnerAbortSignal = await import("../src/runnerAbortSignal.js")
      const controller = new AbortController()

      expect(registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY]).toBe(existing)
      expect(existing.run(controller.signal, () => runnerAbortSignal.getRunnerAbortSignal())).toBe(
        controller.signal
      )
    })

    it.each([
      { label: "a plain empty object", value: {} },
      {
        label: "an AsyncLocalStorage look-alike",
        value: {
          enterWith(): void {
            // A foreign object that merely mimics the AsyncLocalStorage API.
          },
          getStore(): undefined {
            return undefined
          },
          run<T>(_store: unknown, body: () => T): T {
            return body()
          },
        },
      },
      { label: "a primitive", value: 42 },
    ])(
      "fails the runnerAbortSignal import closed when the slot holds $label",
      async ({ value }) => {
        registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY] = value
        vi.resetModules()

        await expect(import("../src/runnerAbortSignal.js")).rejects.toThrow(
          "paratix.runnerAbortSignal.storage"
        )

        expect(registry[RUNNER_ABORT_SIGNAL_STORAGE_KEY]).toBe(value)
      }
    )
  })
})
