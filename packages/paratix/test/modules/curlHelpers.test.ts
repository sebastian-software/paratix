import { describe, expect, it } from "vitest"

import { buildCurlConfigPayload } from "../../src/modules/curlHelpers.js"

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
