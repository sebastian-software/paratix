import { EventEmitter } from "node:events"
import { afterEach, beforeEach, vi } from "vitest"

import type { TestSignalBus } from "../../src/signalBus.js"
import type { Module, ModuleMetaEntry, ModuleResult } from "../../src/types.js"

import { createTestSignalBus, resetSignalBus, setSignalBus } from "../../src/signalBus.js"

let signalBus: TestSignalBus

export function installRunnerTestHooks(): void {
  // Vitest supports file-scope hooks; each split runner test file gets an isolated bus.
  beforeEach(() => {
    signalBus = createTestSignalBus()
    setSignalBus(signalBus)
  })

  afterEach(() => {
    resetSignalBus()
  })
}

export function getSignalBus(): TestSignalBus {
  return signalBus
}

function rejectUnstubbedSshMethod(methodName: string): Error {
  return new Error(`makeMockSshClass: unstubbed SSH method call: ${methodName}`)
}

export function makeMockSshClass(
  capturedConfigs: unknown[],
  overrides?: {
    addPort?: ReturnType<typeof vi.fn>
    disconnect?: ReturnType<typeof vi.fn>
    exec?: ReturnType<typeof vi.fn>
    output?: ReturnType<typeof vi.fn>
    probeSudo?: ReturnType<typeof vi.fn>
    readFile?: ReturnType<typeof vi.fn>
    reconnect?: ReturnType<typeof vi.fn>
    removePort?: ReturnType<typeof vi.fn>
    updateHost?: ReturnType<typeof vi.fn>
    writeFile?: ReturnType<typeof vi.fn>
  }
): new (host: string, config: unknown) => unknown {
  return class MockSshConnectionImpl {
    public addPort = overrides?.addPort ?? vi.fn().mockReturnValue(true)
    public connect = vi.fn().mockResolvedValue(null)
    public disconnect = overrides?.disconnect ?? vi.fn()
    public downloadFile = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("downloadFile"))
    public exec = overrides?.exec ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("exec"))
    public exists = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("exists"))
    public getConnectionInfo = vi
      .fn()
      .mockReturnValue({ host: "1.2.3.4", port: 22, privateKeyPath: "~/.ssh/id", user: "root" })
    public lines = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("lines"))
    public output =
      overrides?.output ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("output"))
    public probeSudo =
      overrides?.probeSudo ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("probeSudo"))
    public readFile =
      overrides?.readFile ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("readFile"))
    public reconnect = overrides?.reconnect ?? vi.fn().mockResolvedValue(null)
    public removePort = overrides?.removePort ?? vi.fn()
    public sha256 = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("sha256"))
    public test = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("test"))
    public updateHost = overrides?.updateHost ?? vi.fn()
    public uploadFile = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("uploadFile"))
    public writeFile =
      overrides?.writeFile ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("writeFile"))

    public constructor(_host: string, config: unknown) {
      capturedConfigs.push(config)
    }
  }
}

export function makeModuleWithMeta(metaEntries: ModuleMetaEntry[]): Module {
  return {
    apply: vi
      .fn()
      .mockResolvedValue({ meta: metaEntries, status: "changed" } satisfies ModuleResult),
    check: vi.fn().mockResolvedValue("needs-apply"),
    name: "test-module",
  }
}

type MockChildProcess = {
  stderr?: EventEmitter
  stdin?: { end: ReturnType<typeof vi.fn> } & EventEmitter
  stdout?: EventEmitter
} & EventEmitter

export function createMockSpawnChild(stdout: string, exitCode = 0): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess
  child.stdout = new EventEmitter()
  child.stderr = new EventEmitter()
  child.stdin = Object.assign(new EventEmitter(), { end: vi.fn() })

  queueMicrotask(() => {
    child.stdout?.emit("data", Buffer.from(stdout))
    child.emit("close", exitCode)
  })

  return child
}

export const setEncodingNoop = (): void => {
  /* setEncoding is a no-op on the simulated streams in runner tests */
}

export function createSuccessfulSshdDryRunExecMock(): ReturnType<typeof vi.fn> {
  return vi.fn().mockResolvedValue({ code: 0, stderr: "", stdout: "" })
}
