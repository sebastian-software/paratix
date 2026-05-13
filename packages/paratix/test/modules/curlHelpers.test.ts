import { describe, expect, it } from "vitest"

import {
  buildCurlConfigPayload,
  hasSensitiveHeaders,
  isValidHeaderName,
} from "../../src/modules/curlHelpers.js"

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

describe("hasSensitiveHeaders", () => {
  it("returns false for an empty header map", () => {
    expect(hasSensitiveHeaders({})).toBe(false)
  })

  it("matches Authorization regardless of casing", () => {
    expect(hasSensitiveHeaders({ Authorization: "Bearer token" })).toBe(true)
    expect(hasSensitiveHeaders({ AUTHORIZATION: "Bearer token" })).toBe(true)
    expect(hasSensitiveHeaders({ authorization: "Bearer token" })).toBe(true)
  })

  it("matches Cookie, Set-Cookie, X-Api-Key, and Proxy-Authorization", () => {
    expect(hasSensitiveHeaders({ Cookie: "session=abc" })).toBe(true)
    expect(hasSensitiveHeaders({ "Set-Cookie": "session=abc" })).toBe(true)
    expect(hasSensitiveHeaders({ "X-Api-Key": "k123" })).toBe(true)
    expect(hasSensitiveHeaders({ "Proxy-Authorization": "Basic abc" })).toBe(true)
  })

  it("matches custom credential header name tokens", () => {
    expect(hasSensitiveHeaders({ "X-Client-Token": "token" })).toBe(true)
    expect(hasSensitiveHeaders({ XServiceAuth: "auth" })).toBe(true)
    expect(hasSensitiveHeaders({ "X-Signing-Signature": "sig" })).toBe(true)
    expect(hasSensitiveHeaders({ "X-Api-Secret": "secret" })).toBe(true)
    expect(hasSensitiveHeaders({ "X-Credential-Id": "credential" })).toBe(true)
  })

  it("returns false for non-sensitive headers", () => {
    expect(
      hasSensitiveHeaders({
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Authored-By": "deploy",
        "X-Monkey": "banana",
        "X-Trace-Id": "abc",
      })
    ).toBe(false)
  })
})
