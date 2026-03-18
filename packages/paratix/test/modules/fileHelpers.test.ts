import { describe, expect, it } from "vitest"

import { hexHashesEqual } from "../../src/modules/fileHelpers.js"

describe("hexHashesEqual", () => {
  it("returns true when both hashes are identical", () => {
    const hash = "a".repeat(64)
    expect(hexHashesEqual(hash, hash)).toBe(true)
  })

  it("returns true for two equal SHA-256 hex hashes", () => {
    const hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    expect(hexHashesEqual(hash, hash)).toBe(true)
  })

  it("returns false when hashes differ", () => {
    const hashA = "a".repeat(64)
    const hashB = "b".repeat(64)
    expect(hexHashesEqual(hashA, hashB)).toBe(false)
  })

  it("returns false when only one character differs", () => {
    const hashA = `${"a".repeat(63)}b`
    const hashB = "a".repeat(64)
    expect(hexHashesEqual(hashA, hashB)).toBe(false)
  })

  it("returns false when first parameter is null", () => {
    const hash = "a".repeat(64)
    expect(hexHashesEqual(null, hash)).toBe(false)
  })
})
