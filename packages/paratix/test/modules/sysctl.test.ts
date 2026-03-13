import { describe, expect, it, vi } from "vitest"

import { sysctl } from "../../src/modules/sysctl.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const KEY = "net.ipv4.ip_forward"
const VALUE = "1"
const CONF_PATH = "/etc/sysctl.d/99-paratix-net-ipv4-ip_forward.conf"
const CONF_CONTENT = "net.ipv4.ip_forward = 1\n"

// ─── sysctl.set — check ───────────────────────────────────────────────────────

describe("sysctl.set — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when live value matches and config file exists with correct content", async () => {
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: CONF_CONTENT },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when live value differs", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: "0" },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config file has wrong content", async () => {
    const mockSsh = createMockSsh({
      [`cat '${CONF_PATH}'`]: { code: 0, stdout: "net.ipv4.ip_forward = 0\n" },
      [`sysctl -n '${KEY}'`]: { code: 0, stdout: VALUE },
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  // state: absent

  it("returns ok when config file does not exist (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when config file still exists (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// ─── sysctl.set — apply ───────────────────────────────────────────────────────

describe("sysctl.set — apply", () => {
  it("returns changed and executes sysctl -w and writes config file (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 0 },
    })
    const writeFileSpy = vi.spyOn(mockSsh, "writeFile")
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`sysctl -w '${KEY}=${VALUE}'`)
    expect(writeFileSpy).toHaveBeenCalledWith(CONF_PATH, CONF_CONTENT)
  })

  it("returns failed when sysctl -w fails (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`sysctl -w '${KEY}=${VALUE}'`]: { code: 1 },
    })
    const mod = sysctl.set(KEY, VALUE)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns failed when conn is null (state: present)", async () => {
    const mod = sysctl.set(KEY, VALUE)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed and removes config file (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`rm -f '${CONF_PATH}'`]: { code: 0 },
    })
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`rm -f '${CONF_PATH}'`)
  })
})

// ─── sysctl.set — name ────────────────────────────────────────────────────────

describe("sysctl.set — name", () => {
  it("has descriptive name for present state", () => {
    const mod = sysctl.set(KEY, VALUE)
    expect(mod.name).toBe(`sysctl.set: ${KEY}=${VALUE}`)
  })

  it("has descriptive name for absent state", () => {
    const mod = sysctl.set(KEY, VALUE, { state: "absent" })
    expect(mod.name).toBe(`sysctl.set: absent ${KEY}`)
  })
})
