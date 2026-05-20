import { afterEach, describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
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
      throw new Error(`Expected net.request check to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

function getFirstCurlExecCall(mockSsh: ReturnType<typeof createMockSsh>) {
  const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
  expect(curlCall).toBeDefined()
  if (curlCall == null) throw new Error("Expected a curl exec call")
  return curlCall
}

describe("net.request — check", () => {
  afterEach(assertNoWriteFileCalls)

  it("returns needs-apply when conn is null", async () => {
    const mod = net.request("https://example.com/health")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when status matches (200)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("passes custom curl timeout flags and SSH exec timeout", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '2.5' --max-time '15' 'https://example.com/health'":
        { stdout: "200" },
    })
    const mod = net.request("https://example.com/health", {
      connectTimeout: 2500,
      timeout: 15_000,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    const curlCall = getFirstCurlExecCall(mockSsh)
    expect(result).toBe("ok")
    expect(curlCall.options?.timeout).toBe(15_000)
  })

  it("returns needs-apply when status does not match", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        { stdout: "503" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when status AND body match", async () => {
    const mockSsh = createMockSsh({
      "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        {
          stdout: "OK\n__PARATIX_HTTP_STATUS__:200",
        },
    })
    const mod = net.request("https://example.com/health", { body: "OK" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expect(mockSsh.calls).toStrictEqual([
      "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'",
    ])
  })

  it("returns needs-apply when body does not match even if status matches", async () => {
    const mockSsh = createMockSsh({
      "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        {
          stdout: "ERROR\n__PARATIX_HTTP_STATUS__:200",
        },
    })
    const mod = net.request("https://example.com/health", { body: "OK" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok with custom method (POST)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '10' --max-time '300' -X 'POST' 'https://example.com/api'":
        {
          stdout: "200",
        },
    })
    const mod = net.request("https://example.com/api", { method: "POST" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it.each(["PATCH", "M-SEARCH", "PURGE"])("allows valid HTTP token method %s", (method) => {
    expect(() => net.request("https://example.com/api", { method })).not.toThrow()
  })

  it.each([
    ["empty", ""],
    ["space", "POST GET"],
    ["tab", "POST\tGET"],
    ["CRLF", "POST\r\nInjected: true"],
    ["LF", "POST\nInjected: true"],
    ["NUL", "POST\0GET"],
    ["separator", "POST:GET"],
  ])("rejects invalid HTTP method with %s", (_label, method) => {
    expect(() => net.request("https://example.com/api", { method })).toThrow(
      "[net.request] invalid method: value must be a non-empty HTTP token without whitespace, control characters, or separators"
    )
  })

  it("does not echo an injected method in the validation error", () => {
    const injectedMethod = "POST\r\nInjected: true"

    expect(() => net.request("https://example.com/api", { method: injectedMethod })).toThrow(
      /invalid method: value must be a non-empty HTTP token/v
    )

    const thrown = (() => {
      try {
        net.request("https://example.com/api", { method: injectedMethod })
      } catch (error) {
        return error
      }
      throw new Error("Expected net.request to reject the injected method")
    })()
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).message).not.toContain(injectedMethod)
  })

  it("has correct name format: net.request: GET <url>", async () => {
    const mod = net.request("https://example.com/health")
    expect(mod.name).toBe("net.request: GET https://example.com/health")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("has correct name format with custom method: net.request: POST <url>", async () => {
    const mod = net.request("https://example.com/api", { method: "POST" })
    expect(mod.name).toBe("net.request: POST https://example.com/api")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("allows http URLs for endpoint checks", () => {
    const mod = net.request("http://example.com/health")
    expect(mod.name).toBe("net.request: GET http://example.com/health")
  })

  it("rejects file URLs before building a curl command", () => {
    expect(() => net.request("file:///etc/passwd")).toThrow(/Unsupported URL scheme 'file'/v)
  })

  it("rejects ftp URLs before building a curl command", () => {
    expect(() => net.request("ftp://example.com/file")).toThrow(/Unsupported URL scheme 'ftp'/v)
  })

  it("rejects http URLs that carry an Authorization header", () => {
    expect(() =>
      net.request("http://example.com/health", {
        headers: { Authorization: "Bearer token" },
      })
    ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
  })

  it("rejects http URLs that carry a Cookie header (case-insensitive match)", () => {
    expect(() =>
      net.request("http://example.com/health", {
        headers: { COOKIE: "session=abc" },
      })
    ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
  })

  it("rejects http URLs that carry an X-Api-Key header", () => {
    expect(() =>
      net.request("http://example.com/health", {
        headers: { "x-api-key": "k123" },
      })
    ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
  })

  it("rejects http URLs that carry custom credential-like headers", () => {
    expect(() =>
      net.request("http://example.com/health", {
        headers: { "X-Webhook-Signature": "sig" },
      })
    ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
  })

  it("allows http URLs with sensitive headers when allowInsecureHttpHeaders is true", () => {
    expect(() =>
      net.request("http://example.com/health", {
        allowInsecureHttpHeaders: true,
        headers: { Authorization: "Bearer token" },
      })
    ).not.toThrow()
  })

  it("rejects http URLs that carry user info", () => {
    expect(() => net.request("http://deploy:s3cr3t@example.com/health")).toThrow(
      /refusing to send sensitive URL credentials or query parameters over plaintext http: http:\/\/REDACTED:REDACTED@example.com\/health/v
    )
  })

  it.each([
    ["token", "http://example.com/health?token=REDACTED"],
    ["api_key", "http://example.com/health?api_key=REDACTED"],
    ["apiKey", "http://example.com/health?apiKey=REDACTED"],
    ["password", "http://example.com/health?password=REDACTED"],
  ])(
    "rejects http URLs that carry a sensitive %s query parameter",
    (parameterName, expectedDisplayUrl) => {
      expect(() => net.request(`http://example.com/health?${parameterName}=s3cr3t`)).toThrow(
        `refusing to send sensitive URL credentials or query parameters over plaintext http: ${expectedDisplayUrl}`
      )
    }
  )

  it("allows http URLs with non-sensitive query parameters", () => {
    expect(() => net.request("http://example.com/health?monkey=banana&download=true")).not.toThrow()
  })

  it("allows https URLs with URL secrets and masks them in the module name", () => {
    const mod = net.request("https://deploy:s3cr3t@example.com/health?token=abc&download=true")
    expect(mod.name).toBe(
      "net.request: GET https://REDACTED:REDACTED@example.com/health?token=REDACTED&download=true"
    )
  })

  it("allows https URLs with sensitive headers without an opt-in", () => {
    expect(() =>
      net.request("https://example.com/health", {
        headers: { Authorization: "Bearer token" },
      })
    ).not.toThrow()
  })

  it("allows http URLs without sensitive headers", () => {
    expect(() =>
      net.request("http://example.com/health", {
        headers: { "X-Trace-Id": "abc" },
      })
    ).not.toThrow()
  })
})
