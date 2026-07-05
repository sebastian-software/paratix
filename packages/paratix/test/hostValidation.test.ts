import { describe, expect, it } from "vitest"

import type { HostValidationFailure } from "../src/hostValidation.js"

import { describeHostValidationFailure, validateHostLabel } from "../src/hostValidation.js"

const DEL = String.fromCodePoint(0x7f)
const START_OF_HEADING = String.fromCodePoint(0x01)
const NON_BREAKING_SPACE = String.fromCodePoint(0xa0)

describe("validateHostLabel", () => {
  it("rejects non-string input with a 'type' failure", () => {
    expect(validateHostLabel(42)).toBe("type")
    expect(validateHostLabel(null)).toBe("type")
    expect(validateHostLabel(undefined)).toBe("type")
    expect(validateHostLabel({ host: "x" })).toBe("type")
  })

  it("rejects an empty string with an 'empty' failure", () => {
    expect(validateHostLabel("")).toBe("empty")
  })

  it("rejects ASCII control characters (including tab and DEL) with a 'control' failure", () => {
    expect(validateHostLabel("host\nname")).toBe("control")
    expect(validateHostLabel("host\tname")).toBe("control")
    expect(validateHostLabel(`host${DEL}name`)).toBe("control")
    expect(validateHostLabel(`host${START_OF_HEADING}name`)).toBe("control")
  })

  it("rejects non-control whitespace with a 'whitespace' failure", () => {
    expect(validateHostLabel("host name")).toBe("whitespace")
    expect(validateHostLabel(`host${NON_BREAKING_SPACE}name`)).toBe("whitespace")
  })

  it("rejects OpenSSH known_hosts pattern metacharacters", () => {
    expect(validateHostLabel("host*")).toBe("metacharacter")
    expect(validateHostLabel("ho,st")).toBe("metacharacter")
    expect(validateHostLabel("ho?st")).toBe("metacharacter")
    expect(validateHostLabel("!host")).toBe("metacharacter")
  })

  it("accepts a clean host label", () => {
    expect(validateHostLabel("example.com")).toBeNull()
    expect(validateHostLabel("192.0.2.1")).toBeNull()
    expect(validateHostLabel("[2001:db8::1]:2222")).toBeNull()
  })
})

describe("describeHostValidationFailure", () => {
  const cases: Array<[HostValidationFailure, string]> = [
    ["control", "must not contain control characters"],
    ["empty", "must be a non-empty string"],
    ["metacharacter", "must not contain OpenSSH known_hosts pattern metacharacters"],
    ["type", "must be a string"],
    ["whitespace", "must not contain whitespace"],
  ]

  for (const [failure, message] of cases) {
    it(`describes the '${failure}' failure`, () => {
      expect(describeHostValidationFailure(failure)).toBe(message)
    })
  }
})
