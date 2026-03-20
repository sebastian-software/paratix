import { describe, expect, it } from "vitest"

import { hostname } from "../../src/modules/hostname.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("hostname.set", () => {
  it("check returns ok when the current hostname matches the desired name", async () => {
    const ssh = createMockSsh({
      hostname: { code: 0, stdout: "my-server" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the current hostname differs from the desired name", async () => {
    const ssh = createMockSsh({
      hostname: { code: 0, stdout: "old-server" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = hostname.set("my-server")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns changed when hostnamectl succeeds", async () => {
    const ssh = createMockSsh({
      "hostnamectl set-hostname 'my-server'": { code: 0 },
    })
    const mod = hostname.set("my-server")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns failed when hostnamectl fails", async () => {
    const ssh = createMockSsh({
      "hostnamectl set-hostname 'my-server'": { code: 1, stderr: "permission denied" },
    })
    const mod = hostname.set("my-server")
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain(
      "[hostname.set: my-server] hostnamectl set-hostname failed"
    )
    expect(result.error?.message).toContain("permission denied")
  })
})
