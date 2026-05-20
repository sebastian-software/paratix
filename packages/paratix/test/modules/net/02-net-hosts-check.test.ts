import { afterEach, describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const mockSshInstances: Array<ReturnType<typeof createBaseMockSsh>> = []

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const mockSsh = createBaseMockSsh(responses, {
    ...options,
    // R-0000275: net.hosts.check now probes /etc/hosts existence before reading.
    // Default the probe to "file exists" so fixtures that supply the cat
    // response keep passing; tests that exercise the missing-file path stub
    // this probe explicitly with `{ code: 1 }` (user stubs win because they
    // are placed first and `find` returns the first match).
    responseStubs: [
      ...(options?.responseStubs ?? []),
      { command: "[ -e '/etc/hosts' ]", result: { code: 0 } },
      { command: "[ -L '/etc/hosts' ]", result: { code: 1 } },
    ],
  })
  mockSshInstances.push(mockSsh)
  return mockSsh
}

function assertNoWriteFileCalls() {
  for (const mockSsh of mockSshInstances) {
    if (mockSsh.writeFileCalls.length > 0) {
      throw new Error(`Expected net.hosts check to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

describe("net.hosts — check", () => {
  afterEach(assertNoWriteFileCalls)

  it("returns needs-apply when conn is null", async () => {
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when the hosts line is present (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  // R-0000275: a missing /etc/hosts must surface as needs-apply, not as a
  // phase-level throw from readFile. Apply ensures the file exists.
  it("returns needs-apply when /etc/hosts does not exist", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        responseStubs: [{ command: "[ -e '/etc/hosts' ]", result: { code: 1 } }],
      }
    )
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply without reading when /etc/hosts is a symlink", async () => {
    const mockSsh = createMockSsh(
      {
        "cat '/etc/hosts'": { stdout: "1.2.3.4 myhost\n" },
      },
      {
        responseStubs: [{ command: "[ -L '/etc/hosts' ]", result: { code: 0 } }],
      }
    )
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain("cat '/etc/hosts'")
  })

  it("returns needs-apply when the hosts line is absent (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when entry is absent (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when entry exists (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok with multiple hostnames when all are present", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n10.0.0.1 web1 web1.local\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1", "web1.local"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when only partial hostname match exists", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 web1\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1", "web1.local"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the desired hostname appears only in an inline comment", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 # web1\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when the desired hostname appears before an inline comment", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 web1 # managed host\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when desired and foreign hostnames are already consolidated", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost app.local\n" },
    })
    const mod = net.hosts("127.0.0.1", ["app.local"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when same-IP hostnames are split across multiple lines", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 api\n10.0.0.1 db\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("reads /etc/hosts via cat command", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })
})
