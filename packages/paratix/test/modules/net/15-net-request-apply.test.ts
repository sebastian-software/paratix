import { describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { createMockSsh } from "../../helpers/mockSsh.js"

const emptyEnv = {}

// ─── net.request ──────────────────────────────────────────────────────────────

describe("net.request — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = net.request("https://example.com/health")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns ok when request succeeds", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(mockSsh.writeFileCalls).toStrictEqual([])
  })

  it("returns failed when request fails (wrong status)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        { stdout: "503" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(mockSsh.writeFileCalls).toStrictEqual([])
  })
})

// R-0000072/R-0000144: Header values must be routed through
// `curl --config -` over stdin instead of being inlined into argv, where
// `ps -ef` and sudo logging would capture them. The header values must also
// be registered in the process-scoped secret sink so CommandError stack traces
// are masked when curl fails.
