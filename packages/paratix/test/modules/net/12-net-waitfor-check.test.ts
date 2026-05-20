/* eslint-disable testing-library/await-async-utils -- net.waitFor is not Testing Library waitFor */
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
      throw new Error(`Expected net.waitFor check to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

describe("net.waitFor — check", () => {
  afterEach(assertNoWriteFileCalls)

  it("returns needs-apply when conn is null", async () => {
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when port is open (nc -z)", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("supports an explicit host for port checks", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '::1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ host: "::1", port: 8080 })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("throws when a port check host could be parsed as an nc option", () => {
    expect(() => net.waitFor({ host: "-w 99", port: 8080 })).toThrow(
      "[net.waitFor] invalid host: value must not be empty, start with '-', or contain whitespace/control characters"
    )
  })

  it("throws when a port check host contains whitespace", () => {
    expect(() => net.waitFor({ host: "example.com other", port: 8080 })).toThrow(
      "[net.waitFor] invalid host: value must not be empty, start with '-', or contain whitespace/control characters"
    )
  })

  it("throws when a port is outside the TCP range", () => {
    expect(() => net.waitFor({ port: 0 })).toThrow(
      "[net.waitFor] invalid port: value must be an integer between 1 and 65535"
    )
    expect(() => net.waitFor({ port: 65_536 })).toThrow(
      "[net.waitFor] invalid port: value must be an integer between 1 and 65535"
    )
  })

  it("returns needs-apply when port is closed", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '8080'": { code: 1 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when file exists (test -f)", async () => {
    const mockSsh = createMockSsh({
      "test -f '/tmp/ready'": { code: 0 },
    })
    const mod = net.waitFor({ file: "/tmp/ready" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when file does not exist", async () => {
    const mockSsh = createMockSsh({
      "test -f '/tmp/ready'": { code: 1 },
    })
    const mod = net.waitFor({ file: "/tmp/ready" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when file contains expected string (grep -Fq)", async () => {
    const mockSsh = createMockSsh({
      "grep -Fq -- 'READY' '/tmp/status'": { code: 0 },
    })
    const mod = net.waitFor({ contains: "READY", file: "/tmp/status" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when file does not contain expected string", async () => {
    const mockSsh = createMockSsh({
      "grep -Fq -- 'READY' '/tmp/status'": { code: 1 },
    })
    const mod = net.waitFor({ contains: "READY", file: "/tmp/status" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("treats contains as a fixed string when it has regex metacharacters", async () => {
    const mockSsh = createMockSsh({
      "grep -Fq -- 'READY.*[done]' '/tmp/status'": { code: 0 },
    })
    const mod = net.waitFor({ contains: "READY.*[done]", file: "/tmp/status" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("treats a leading dash in contains as data instead of a grep option", async () => {
    const mockSsh = createMockSsh({
      "grep -Fq -- '-READY' '/tmp/status'": { code: 0 },
    })
    const mod = net.waitFor({ contains: "-READY", file: "/tmp/status" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("has correct name format for port wait", async () => {
    const mod = net.waitFor({ port: 8080 })
    expect(mod.name).toBe("net.waitFor: port 8080")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("has correct name format for file wait", async () => {
    const mod = net.waitFor({ file: "/tmp/ready" })
    expect(mod.name).toBe("net.waitFor: file /tmp/ready")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("has correct name format for file contains wait", async () => {
    const mod = net.waitFor({ contains: "READY", file: "/tmp/status" })
    expect(mod.name).toBe("net.waitFor: /tmp/status contains READY")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
