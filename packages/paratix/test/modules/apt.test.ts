import { describe, expect, it } from "vitest"

import { apt } from "../../src/modules/apt.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("apt.installed", () => {
  it("check returns ok when all packages are installed", async () => {
    const ssh = createMockSsh({
      "dpkg -l | grep '^ii' | grep -w 'nginx'": { code: 0 },
    })
    const mod = apt.installed("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when a package is not installed", async () => {
    const ssh = createMockSsh({
      "dpkg -l | grep '^ii' | grep -w 'nginx'": { code: 1 },
    })
    const mod = apt.installed("nginx")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.installed("nginx")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when one of multiple packages is missing", async () => {
    const ssh = createMockSsh({
      "dpkg -l | grep '^ii' | grep -w 'curl'": { code: 1 },
      "dpkg -l | grep '^ii' | grep -w 'nginx'": { code: 0 },
    })
    const mod = apt.installed("nginx", "curl")
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("apt.upgrade", () => {
  const date = "2024-01-15"
  const flagPath = `/var/lib/paratix/flags/'apt-upgrade-${date}'`

  it("check returns ok when the upgrade flag file exists", async () => {
    const ssh = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 0 },
    })
    const mod = apt.upgrade(date)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when the upgrade flag file is missing", async () => {
    const ssh = createMockSsh({
      [`[ -f ${flagPath} ]`]: { code: 1 },
    })
    const mod = apt.upgrade(date)
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("check returns needs-apply when ssh is null", async () => {
    const mod = apt.upgrade(date)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
