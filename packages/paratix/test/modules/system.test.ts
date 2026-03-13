import { describe, expect, it, vi } from "vitest"

import { system } from "../../src/modules/system.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

describe("system.reboot — check", () => {
  it("returns needs-apply with a valid ssh connection", async () => {
    const ssh = createMockSsh()
    const mod = system.reboot()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = system.reboot()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("system.reboot — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = system.reboot()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("sends shutdown -r now and returns meta with system.reboot set to true", async () => {
    const ssh = createMockSsh()
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("shutdown -r now")
    expect(result.meta?.["system.reboot"]).toBe("true")
  })

  it("does not set system.host in meta when no resolveHost option is given", async () => {
    const ssh = createMockSsh()
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.meta).not.toHaveProperty("system.host")
  })

  it("calls resolveHost and sets system.host in meta when resolveHost is provided", async () => {
    const ssh = createMockSsh()
    const resolveHost = vi.fn().mockResolvedValue("10.0.0.42")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(resolveHost).toHaveBeenCalledOnce()
    expect(result.meta?.["system.host"]).toBe("10.0.0.42")
  })

  it("catches connection-drop errors from exec and still returns changed", async () => {
    const ssh = createMockSsh()
    vi.spyOn(ssh, "exec").mockRejectedValueOnce(new Error("Connection reset by peer"))
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.["system.reboot"]).toBe("true")
  })

  it("falls back to current host when resolveHost throws", async () => {
    const ssh = createMockSsh()
    const resolveHost = vi.fn().mockRejectedValue(new Error("DNS failed"))
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.["system.reboot"]).toBe("true")
    expect(result.meta).not.toHaveProperty("system.host")
  })
})

describe("system.uptime — check", () => {
  it("returns needs-apply with a valid ssh connection", async () => {
    const ssh = createMockSsh()
    const mod = system.uptime()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = system.uptime()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("system.uptime — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = system.uptime()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("reads uptime and returns it as system.uptime meta with status ok", async () => {
    const ssh = createMockSsh({
      "awk '{print int($1)}' /proc/uptime": { code: 0, stdout: "12345\n" },
    })
    const mod = system.uptime()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(result.meta?.["system.uptime"]).toBe("12345")
  })
})
