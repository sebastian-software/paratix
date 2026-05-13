import { EventEmitter } from "node:events"
import { afterEach, beforeEach, vi } from "vitest"

import type { TestSignalBus } from "../../src/signalBus.js"
import type { Module, ModuleMetaEntry, ModuleResult } from "../../src/types.js"

import { createTestSignalBus, resetSignalBus, setSignalBus } from "../../src/signalBus.js"

let signalBus: TestSignalBus
const DEFAULT_SSH_PORT = 22
const DEFAULT_CONFIGURED_PORTS = [DEFAULT_SSH_PORT]

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
    connect?: ReturnType<typeof vi.fn>
    disconnect?: ReturnType<typeof vi.fn>
    exec?: ReturnType<typeof vi.fn>
    getConnectionInfo?: ReturnType<typeof vi.fn>
    lifecycle?: "fail-closed" | "permissive"
    output?: ReturnType<typeof vi.fn>
    probeSudo?: ReturnType<typeof vi.fn>
    readFile?: ReturnType<typeof vi.fn>
    reconnect?: ReturnType<typeof vi.fn>
    removePort?: ReturnType<typeof vi.fn>
    updateHost?: ReturnType<typeof vi.fn>
    writeFile?: ReturnType<typeof vi.fn>
  }
): new (host: string, config: unknown) => unknown {
  const hasPermissiveLifecycle = overrides?.lifecycle === "permissive"

  return class MockSshConnectionImpl {
    public addPort =
      overrides?.addPort ??
      (hasPermissiveLifecycle
        ? vi.fn().mockReturnValue(true)
        : vi.fn(() => {
            throw rejectUnstubbedSshMethod("addPort")
          }))
    public connect =
      overrides?.connect ??
      (hasPermissiveLifecycle
        ? vi.fn().mockResolvedValue(null)
        : vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("connect")))
    public currentHost = ""
    public disconnect =
      overrides?.disconnect ??
      (hasPermissiveLifecycle
        ? vi.fn()
        : vi.fn(() => {
            throw rejectUnstubbedSshMethod("disconnect")
          }))
    public downloadFile = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("downloadFile"))
    public exec = overrides?.exec ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("exec"))
    public exists = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("exists"))
    public getConnectionInfo =
      overrides?.getConnectionInfo ??
      vi.fn(() => ({
        configuredPorts: DEFAULT_CONFIGURED_PORTS,
        host: this.currentHost,
        port: 22,
        privateKeyPath: "~/.ssh/id",
        user: "root",
      }))
    public lines = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("lines"))
    public output =
      overrides?.output ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("output"))
    public probeSudo =
      overrides?.probeSudo ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("probeSudo"))
    public readFile =
      overrides?.readFile ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("readFile"))
    public reconnect =
      overrides?.reconnect ??
      (hasPermissiveLifecycle
        ? vi.fn().mockResolvedValue(null)
        : vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("reconnect")))
    public removePort =
      overrides?.removePort ??
      (hasPermissiveLifecycle
        ? vi.fn()
        : vi.fn(() => {
            throw rejectUnstubbedSshMethod("removePort")
          }))
    public sha256 = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("sha256"))
    public test = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("test"))
    public updateHost =
      overrides?.updateHost ??
      (hasPermissiveLifecycle
        ? vi.fn((host: string) => {
            this.currentHost = host
          })
        : vi.fn(() => {
            throw rejectUnstubbedSshMethod("updateHost")
          }))
    public uploadFile = vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("uploadFile"))
    public writeFile =
      overrides?.writeFile ?? vi.fn().mockRejectedValue(rejectUnstubbedSshMethod("writeFile"))

    public constructor(host: string, config: unknown) {
      this.currentHost = host
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
