import { describe, expect, it } from "vitest"

import { buildCurlConfigPayload, isValidHeaderName } from "../../src/modules/curlHelpers.js"

describe("buildCurlConfigPayload", () => {
  it("rejects URL values containing curl config line separators", () => {
    expect(() => {
      buildCurlConfigPayload({
        routeUrlThroughConfig: true,
        url: 'https://example.com/file\nheader = "X-Injected: yes"',
      })
    }).toThrow("URL must not contain CR, LF, or NUL characters")
  })

  it("rejects URL values containing NUL bytes", () => {
    expect(() => {
      buildCurlConfigPayload({
        routeUrlThroughConfig: true,
        url: 'https://example.com/file\0url = "https://evil.example/file"',
      })
    }).toThrow("URL must not contain CR, LF, or NUL characters")
  })
})

describe("isValidHeaderName", () => {
  it("accepts RFC 7230 token special characters", () => {
    expect(
      isValidHeaderName(
        "!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
      )
    ).toBe(true)
  })

  it("rejects whitespace in header names", () => {
    expect(isValidHeaderName("X Custom")).toBe(false)
    expect(isValidHeaderName("X\tCustom")).toBe(false)
  })

  it("rejects separator characters outside the HTTP token grammar", () => {
    for (const name of [
      "Bad:Name",
      "Bad/Name",
      "Bad;Name",
      "Bad,Name",
      "Bad(Name)",
      "Bad[Name]",
      "Bad{Name}",
      "Bad=Name",
      "Bad@Name",
      'Bad"Name',
      "Bad\\Name",
    ]) {
      expect(isValidHeaderName(name)).toBe(false)
    }
  })
})
