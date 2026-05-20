/* eslint-disable testing-library/await-async-utils -- net.waitFor is not Testing Library waitFor */
import { afterEach, describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { setRunnerAbortSignal } from "../../../src/runnerAbortSignal.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const mockSshInstances: Array<ReturnType<typeof createBaseMockSsh>> = []

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const mockSsh = createBaseMockSsh(responses, options)
  mockSshInstances.push(mockSsh)
  return mockSsh
}

function assertNoWriteFileCalls() {
  for (const mockSsh of mockSshInstances) {
    if (mockSsh.writeFileCalls.length > 0) {
      throw new Error(`Expected net.waitFor apply to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

describe("net.waitFor — apply", () => {
  afterEach(assertNoWriteFileCalls)

  it("rejects non-positive or non-finite timing values", () => {
    expect(() => net.waitFor({ port: 8080, timeout: 0 })).toThrow(
      "[net.waitFor] invalid timeout: value must be a finite positive number"
    )
    expect(() => net.waitFor({ interval: Number.NaN, port: 8080 })).toThrow(
      "[net.waitFor] invalid interval: value must be a finite positive number"
    )
    expect(() => net.waitFor({ interval: Number.POSITIVE_INFINITY, port: 8080 })).toThrow(
      "[net.waitFor] invalid interval: value must be a finite positive number"
    )
  })

  it("returns failed when conn is null", async () => {
    const mod = net.waitFor({ port: 8080 })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when port becomes available immediately", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '60' '127.0.0.1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.execCalls[0]?.options).toMatchObject({
      ignoreExitCode: true,
      silent: true,
    })
    expect(mockSsh.execCalls[0]?.options?.timeout).toBeGreaterThan(0)
    expect(mockSsh.execCalls[0]?.options?.timeout).toBeLessThanOrEqual(60_000)
  })

  it("returns failed on timeout when condition never becomes true", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '9999'": { code: 1 },
    })
    const mod = net.waitFor({ interval: 5, port: 9999, timeout: 10 })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("polls file contains checks as a fixed string with grep option termination", async () => {
    const mockSsh = createMockSsh({
      "grep -Fq -- '-READY.*[done]' '/tmp/status'": { code: 0 },
    })
    const mod = net.waitFor({
      contains: "-READY.*[done]",
      file: "/tmp/status",
      timeout: 10,
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("caps poll delays to the remaining timeout budget", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '9999'": { code: 1 },
    })
    const mod = net.waitFor({ interval: 60_000, port: 9999, timeout: 10 })

    const start = Date.now()
    const result = await mod.apply(mockSsh, emptyEnv)
    const elapsed = Date.now() - start

    expect(result.status).toBe("failed")
    expect(elapsed).toBeLessThan(1000)
  })

  // R-0000052: net.waitFor must observe the runner abort signal so SIGINT
  // unblocks the polling loop within the next iteration tick instead of
  // running until the configured timeout.
  it("returns failed within the next tick after the runner abort signal fires", async () => {
    const mockSsh = createMockSsh({
      // Probe always fails so the loop falls through to the delay.
      "nc -z -w '600' '127.0.0.1' '9000'": { code: 1 },
    })
    const controller = new AbortController()
    setRunnerAbortSignal(controller.signal)

    try {
      const mod = net.waitFor({
        // Long enough that the test would hang (or fail with a long delta) if
        // the abort path were missing.
        interval: 60_000,
        port: 9000,
        timeout: 600_000,
      })

      const start = Date.now()
      const applyPromise = mod.apply(mockSsh, emptyEnv)
      // Let the loop reach `delay()` before we abort. A microtask flush via
      // queueMicrotask is enough because conn.test resolves synchronously
      // through the mock.
      await new Promise<void>((resolve) => {
        queueMicrotask(resolve)
      })
      controller.abort(new Error("Terminal prompt interrupted by SIGINT"))

      const result = await applyPromise
      const elapsed = Date.now() - start

      expect(result.status).toBe("failed")
      expect(result.error).toBeInstanceOf(Error)
      expect(result.error?.message).toMatch(/aborted by shutdown signal/v)
      // The polling loop must return well before the configured timeout.
      // 5 seconds is generous for test machines while still proving we are
      // not waiting on the 60s interval or the 600s timeout.
      expect(elapsed).toBeLessThan(5000)
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })

  it("returns failed synchronously when the abort signal is already aborted at apply start", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '600' '127.0.0.1' '9001'": { code: 1 },
    })
    const controller = new AbortController()
    controller.abort(new Error("aborted before apply"))
    setRunnerAbortSignal(controller.signal)

    try {
      const mod = net.waitFor({ interval: 60_000, port: 9001, timeout: 600_000 })
      const start = Date.now()
      const result = await mod.apply(mockSsh, emptyEnv)
      const elapsed = Date.now() - start

      expect(result.status).toBe("failed")
      expect(result.error).toBeInstanceOf(Error)
      expect(result.error?.message).toMatch(/aborted by shutdown signal/v)
      expect(elapsed).toBeLessThan(1000)
      // The probe is never invoked when the signal is already aborted.
      expect(mockSsh.calls).not.toContain("nc -z -w '600' '127.0.0.1' '9001'")
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })
})
