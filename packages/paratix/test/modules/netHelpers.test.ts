import { describe, expect, it } from "vitest"

import { isValidHeaderValue } from "../../src/modules/netHelpers.js"

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
