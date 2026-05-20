import { afterEach, describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const mockSshInstances: Array<ReturnType<typeof createBaseMockSsh>> = []

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const mockSsh = createBaseMockSsh(responses, {
    ...options,
    // R-0000275: net.resolv.check now probes /etc/resolv.conf existence
    // before reading. Default to "file exists" so existing fixtures keep
    // passing; the missing-file regression test stubs `{ code: 1 }` (user
    // stubs win because they are placed first).
    responseStubs: [
      ...(options?.responseStubs ?? []),
      { command: "[ -e '/etc/resolv.conf' ]", result: { code: 0 } },
      { command: "[ -L '/etc/resolv.conf' ]", result: { code: 1 } },
    ],
  })
  mockSshInstances.push(mockSsh)
  return mockSsh
}

function assertNoWriteFileCalls() {
  for (const mockSsh of mockSshInstances) {
    if (mockSsh.writeFileCalls.length > 0) {
      throw new Error(`Expected net.resolv check to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

describe("net.resolv — check", () => {
  afterEach(assertNoWriteFileCalls)

  it("returns needs-apply when conn is null", async () => {
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when resolv.conf content matches", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "nameserver 1.1.1.1\n" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000275: a missing /etc/resolv.conf must surface as needs-apply, not as
  // a phase-level throw from readFile. Apply creates the file, so check defers.
  it("returns needs-apply when resolv.conf does not exist", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        responseStubs: [{ command: "[ -e '/etc/resolv.conf' ]", result: { code: 1 } }],
      }
    )
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when resolv.conf is a symlink even if target content matches", async () => {
    const mockSsh = createMockSsh(
      {
        "cat '/etc/resolv.conf'": { stdout: "nameserver 1.1.1.1\n" },
      },
      {
        responseStubs: [{ command: "[ -L '/etc/resolv.conf' ]", result: { code: 0 } }],
      }
    )
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when resolv.conf matches with search domains", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "search example.com\nnameserver 1.1.1.1\n" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"], search: ["example.com"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when resolv.conf content differs (wrong nameserver)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "nameserver 8.8.8.8\n" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when resolv.conf is empty", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when search domains are missing from resolv.conf", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "nameserver 1.1.1.1\n" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"], search: ["example.com"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when extra nameserver present in resolv.conf", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("reads /etc/resolv.conf via cat command", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/resolv.conf'": { stdout: "nameserver 1.1.1.1\n" },
    })
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/resolv.conf'")
  })
})
