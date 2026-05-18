import { spawn } from "node:child_process"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { ModuleMetaEntry, ModuleResult } from "../../src/types.js"

import { isSystemHostMetaEntry, isSystemRebootMetaEntry } from "../../src/meta.js"
import {
  buildRebootMetaEntriesWithTimeout,
  RESOLVE_HOST_DEFAULT_TIMEOUT_MS,
  resolveHostWithTimeout,
} from "../../src/modules/resolveHostTimeout.js"

async function resolveImmediately(): Promise<string> {
  await Promise.resolve()
  return "10.0.0.42"
}

async function resolveWithError(): Promise<string> {
  await Promise.resolve()
  throw new Error("dns failure")
}

async function resolveNeverSettling(): Promise<string> {
  return new Promise<string>(() => {
    // never settles
  })
}

async function resolveTo99(): Promise<string> {
  await Promise.resolve()
  return "10.0.0.99"
}

async function runNodeScript(script: string): Promise<{
  exitCode: null | number
  stderr: string
  stdout: string
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", script],
      {
        cwd: new URL("../..", import.meta.url),
        stdio: ["ignore", "pipe", "pipe"],
      }
    )
    let stdout = ""
    let stderr = ""
    child.stdout.setEncoding("utf8")
    child.stderr.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk
    })
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk
    })
    child.on("error", reject)
    child.on("close", (exitCode) => {
      resolve({ exitCode, stderr, stdout })
    })
  })
}

function expectMetaEntries(
  result: ModuleMetaEntry[] | ModuleResult
): asserts result is ModuleMetaEntry[] {
  expect(Array.isArray(result)).toBe(true)
}

function expectFailure(result: ModuleMetaEntry[] | ModuleResult): asserts result is ModuleResult {
  expect(Array.isArray(result)).toBe(false)
}

describe("resolveHostWithTimeout — happy path", () => {
  it("returns the resolver's value when it settles before the timeout", async () => {
    await expect(resolveHostWithTimeout(resolveImmediately)).resolves.toBe("10.0.0.42")
  })

  it("propagates resolver errors unchanged", async () => {
    await expect(resolveHostWithTimeout(resolveWithError)).rejects.toThrow("dns failure")
  })

  it("exposes a 30-second default timeout", () => {
    expect(RESOLVE_HOST_DEFAULT_TIMEOUT_MS).toBe(30_000)
  })
})

describe("resolveHostWithTimeout — timeout", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it("R-0000243: rejects with a timeout error when the resolver hangs past the deadline", async () => {
    const promise = resolveHostWithTimeout(resolveNeverSettling, 50)
    // Attach a noop catch synchronously so vitest does not flag the
    // intermediate rejection as unhandled while the fake timer advances.
    const asserted = promise.catch((error: unknown) => error)
    await vi.advanceTimersByTimeAsync(50)
    const captured = await asserted
    expect(String(captured)).toMatch(/timed out after 50ms/v)
  })

  it("R-0000849: lets a hanging resolver block the event loop without the timer pinning the process", async () => {
    // R-0000849: the internal `setTimeout` is now `unref`-ed so a timeout
    // that is still pending cannot — by itself — keep a Node process alive.
    // Real callers always pair the timeout with an in-flight resolver that
    // owns its own keepalive (DNS lookup, HTTP request, etc.) and the
    // returned promise; the rejection still arrives via that resolver's
    // microtask queue when the timer fires. To verify that the rejection
    // path still works under a real event loop (not vitest fake timers) we
    // pair the unref-ed timer with an `Interval` that keeps the loop alive
    // for the duration of the resolver. The interval is cleared as soon as
    // the timeout rejection arrives so the process can exit cleanly.
    const moduleUrl = new URL("../../src/modules/resolveHostTimeout.ts", import.meta.url).href
    const result = await runNodeScript(`
      const { resolveHostWithTimeout } = await import(${JSON.stringify(moduleUrl)})
      const keepAlive = setInterval(() => {}, 10_000)
      try {
        await resolveHostWithTimeout(() => new Promise(() => {}), 50)
        console.error("resolveHostWithTimeout resolved unexpectedly")
        process.exitCode = 2
      } catch (error) {
        console.log(error instanceof Error ? error.message : String(error))
      } finally {
        clearInterval(keepAlive)
      }
    `)
    expect(result).toStrictEqual({
      exitCode: 0,
      stderr: "",
      stdout: "resolveHost timed out after 50ms\n",
    })
  })
})

describe("buildRebootMetaEntriesWithTimeout — meta", () => {
  it("emits only system.reboot when no resolveHost is supplied", async () => {
    const result = await buildRebootMetaEntriesWithTimeout({
      failurePrefix: "[demo]",
    })
    expectMetaEntries(result)
    expect(result.some((entry) => isSystemRebootMetaEntry(entry))).toBe(true)
    expect(result.some((entry) => isSystemHostMetaEntry(entry))).toBe(false)
  })

  it("emits system.reboot and system.host on a successful resolver", async () => {
    const result = await buildRebootMetaEntriesWithTimeout({
      failurePrefix: "[demo]",
      resolveHost: resolveTo99,
    })
    expectMetaEntries(result)
    const hostEntry = result.find((entry) => isSystemHostMetaEntry(entry))
    expect(hostEntry?.host).toBe("10.0.0.99")
  })
})

describe("buildRebootMetaEntriesWithTimeout — failure", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it("R-0000243: returns failed when the resolver hangs past the timeout", async () => {
    const promise = buildRebootMetaEntriesWithTimeout({
      failurePrefix: "[demo]",
      resolveHost: resolveNeverSettling,
      timeoutMs: 25,
    })
    await vi.advanceTimersByTimeAsync(25)
    const result = await promise
    expectFailure(result)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[demo] resolveHost failed")
    expect(result.error?.message).toContain("timed out after 25ms")
    expect(result.meta?.some((entry) => isSystemRebootMetaEntry(entry))).toBe(true)
    expect(result.meta?.some((entry) => isSystemHostMetaEntry(entry))).toBe(false)
  })
})
