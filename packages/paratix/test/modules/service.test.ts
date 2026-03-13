import { describe, expect, it } from "vitest"

import { service } from "../../src/modules/service.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("service.running", () => {
  it("check returns ok when the service is active", async () => {
    const ssh = createMockSsh({
      "systemctl is-active --quiet 'nginx'": { code: 0 },
    })
    const mod = service.running("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the service is inactive", async () => {
    const ssh = createMockSsh({
      "systemctl is-active --quiet 'nginx'": { code: 1 },
    })
    const mod = service.running("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = service.running("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("service.enabled", () => {
  it("check returns ok when the service is enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled --quiet 'nginx'": { code: 0 },
    })
    const mod = service.enabled("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the service is not enabled", async () => {
    const ssh = createMockSsh({
      "systemctl is-enabled --quiet 'nginx'": { code: 1 },
    })
    const mod = service.enabled("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = service.enabled("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
