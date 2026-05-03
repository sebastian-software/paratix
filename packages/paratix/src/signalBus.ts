/**
 * Swappable Signal-Bus, der die SIGINT/SIGTERM-Behandlung von runner.ts
 * von process entkoppelt, damit Tests deterministisch feuern können.
 *
 * Production: getSignalBus() liefert einen Default-Bus, der direkt an
 * process.on / process.removeListener / process.listenerCount delegiert.
 *
 * Tests: setSignalBus(createTestSignalBus()) im beforeEach, resetSignalBus()
 * im afterEach. Test-Bus exponiert emit(signal), um Handler synchron zu feuern.
 */

export type SignalName = "SIGINT" | "SIGTERM"
export type SignalHandler = (signal: SignalName) => void

export type SignalBus = {
  listenerCount: (signal: SignalName) => number
  off: (signal: SignalName, handler: SignalHandler) => void
  on: (signal: SignalName, handler: SignalHandler) => void
}

export type TestSignalBus = {
  emit: (signal: SignalName) => void
} & SignalBus

const defaultProcessSignalBus: SignalBus = {
  listenerCount: (signal) => process.listenerCount(signal),
  off: (signal, handler) => {
    process.removeListener(signal, handler)
  },
  on: (signal, handler) => {
    process.on(signal, handler)
  },
}

/**
 * Wir halten die aktive Bus-Referenz in einem Symbol-Slot auf globalThis,
 * damit Tests, die `vi.resetModules()` benutzen, weiterhin denselben
 * Test-Bus sehen wie der frisch re-importierte runner.ts. Ohne diesen
 * Trick würde jede neue Modul-Instanz ihren eigenen `let activeBus`-Slot
 * mit dem Default-Bus initialisieren und die `setSignalBus`-Registrierung
 * der vorherigen Instanz verlieren.
 */
const ACTIVE_BUS_KEY = Symbol.for("paratix.signalBus.activeBus")

function isSignalBus(value: unknown): value is SignalBus {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { listenerCount?: unknown }).listenerCount === "function" &&
    typeof (value as { off?: unknown }).off === "function" &&
    typeof (value as { on?: unknown }).on === "function"
  )
}

function readActiveBus(): SignalBus | undefined {
  const value: unknown = Reflect.get(globalThis, ACTIVE_BUS_KEY)
  return isSignalBus(value) ? value : undefined
}

function writeActiveBus(bus: SignalBus): void {
  Reflect.set(globalThis, ACTIVE_BUS_KEY, bus)
}

export function getSignalBus(): SignalBus {
  return readActiveBus() ?? defaultProcessSignalBus
}

export function setSignalBus(bus: SignalBus): void {
  writeActiveBus(bus)
}

export function resetSignalBus(): void {
  writeActiveBus(defaultProcessSignalBus)
}

export function createTestSignalBus(): TestSignalBus {
  const handlers: Record<SignalName, Set<SignalHandler>> = {
    SIGINT: new Set(),
    SIGTERM: new Set(),
  }
  return {
    emit(signal) {
      // Snapshot vor Dispatch, damit off() während eines Handlers keine
      // weiteren Handler aus der laufenden Iteration entfernen kann.
      const snapshot = new Set(handlers[signal])
      for (const handler of snapshot) handler(signal)
    },
    listenerCount(signal) {
      return handlers[signal].size
    },
    off(signal, handler) {
      handlers[signal].delete(handler)
    },
    on(signal, handler) {
      handlers[signal].add(handler)
    },
  }
}
