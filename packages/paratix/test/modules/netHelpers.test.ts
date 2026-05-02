import { describe, expect, it } from "vitest"

import { delay, isValidHeaderValue } from "../../src/modules/netHelpers.js"

describe("isValidHeaderValue", () => {
  it("returns true for a normal string without control characters", () => {
    expect(isValidHeaderValue("Bearer token123")).toBe(true)
  })

  it("returns true for an empty string", () => {
    expect(isValidHeaderValue("")).toBe(true)
  })

  it("returns true for a string with spaces and special printable chars", () => {
    expect(isValidHeaderValue("application/json; charset=utf-8")).toBe(true)
  })

  it("returns false when the value contains a carriage return (\\r)", () => {
    expect(isValidHeaderValue("value\rinjection")).toBe(false)
  })

  it("returns false when the value contains a newline (\\n)", () => {
    expect(isValidHeaderValue("value\ninjection")).toBe(false)
  })

  it("returns false when the value contains a null byte (\\0) — R-003 regression", () => {
    expect(isValidHeaderValue("value\0injection")).toBe(false)
  })

  it("returns false when the value contains only a null byte", () => {
    expect(isValidHeaderValue("\0")).toBe(false)
  })

  it("returns false when the value contains CRLF sequence", () => {
    expect(isValidHeaderValue("value\r\nX-Injected: evil")).toBe(false)
  })
})

describe("delay (R-0000052)", () => {
  it("resolves after the specified duration when no abort signal is provided", async () => {
    const start = Date.now()
    await delay(20)
    const elapsed = Date.now() - start
    expect(elapsed).toBeGreaterThanOrEqual(15)
  })

  it("rejects synchronously when the abort signal is already aborted", async () => {
    const controller = new AbortController()
    controller.abort(new Error("already aborted"))

    await expect(delay(60_000, controller.signal)).rejects.toThrow(/already aborted/v)
  })

  it("rejects promptly when the abort signal fires during the wait", async () => {
    const controller = new AbortController()
    const start = Date.now()
    const pending = delay(60_000, controller.signal)
    queueMicrotask(() => {
      controller.abort(new Error("aborted mid-delay"))
    })
    await expect(pending).rejects.toThrow(/aborted mid-delay/v)
    expect(Date.now() - start).toBeLessThan(1000)
  })

  it("uses a default reason when the signal aborts with a string reason", async () => {
    const controller = new AbortController()
    const pending = delay(60_000, controller.signal)
    queueMicrotask(() => {
      controller.abort("custom string reason")
    })
    await expect(pending).rejects.toThrow(/custom string reason/v)
  })
})
