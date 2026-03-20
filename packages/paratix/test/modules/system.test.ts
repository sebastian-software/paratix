import { describe, expect, it, vi } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import {
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
} from "../../src/meta.js"
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
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
  })

  it("does not set system.host in meta when no resolveHost option is given", async () => {
    const ssh = createMockSsh()
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
  })

  it("calls resolveHost and sets system.host in meta when resolveHost is provided", async () => {
    const ssh = createMockSsh()
    const resolveHost = vi.fn().mockResolvedValue("10.0.0.42")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(resolveHost).toHaveBeenCalledOnce()
    expect(result.meta?.find(isSystemHostMetaEntry)?.host).toBe("10.0.0.42")
  })

  it("catches connection-drop errors from exec and still returns changed", async () => {
    const ssh = createMockSsh()
    vi.spyOn(ssh, "exec").mockRejectedValueOnce(new Error("Connection reset by peer"))
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
  })

  it("falls back to current host when resolveHost throws", async () => {
    const ssh = createMockSsh()
    const resolveHost = vi.fn().mockRejectedValue(new Error("DNS failed"))
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
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
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.uptime")).resolves.toBe("12345")
  })
})

// ─── system.facts ─────────────────────────────────────────────────────────────

const FACTS_RESPONSES = {
  "cat /etc/os-release": {
    code: 0,
    stdout: 'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n',
  },
  "df -m /": {
    code: 0,
    stdout:
      "Filesystem     1M-blocks  Used Available Use% Mounted on\n/dev/sda1          49000  8000     39000  17% /\n",
  },
  "free -m": {
    code: 0,
    stdout:
      "               total        used        free\nMem:            7981        1234        5678\nSwap:              0           0           0\n",
  },
  hostname: { code: 0, stdout: "myserver\n" },
  "ip -4 addr": {
    code: 0,
    stdout: "2: eth0: <BROADCAST>\n    inet 10.0.1.5/24 brd 10.0.1.255 scope global eth0\n",
  },
  "ip -4 route get 1.1.1.1": {
    code: 0,
    stdout: "1.1.1.1 via 10.0.1.1 dev eth0 src 93.184.216.34 uid 0\n",
  },
  nproc: { code: 0, stdout: "4\n" },
  "uname -m": { code: 0, stdout: "x86_64\n" },
  "uname -r": { code: 0, stdout: "5.15.0-91-generic\n" },
}

describe("system.facts — check", () => {
  it("returns needs-apply with valid ssh", async () => {
    const ssh = createMockSsh()
    const mod = system.facts()
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = system.facts()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("system.facts — apply", () => {
  it("returns failed when ssh is null", async () => {
    const mod = system.facts()
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns ok with all meta keys populated when all commands succeed", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("ok")
    const meta = await mergeEnvironmentFromMeta({}, result.meta)
    expect(meta).toHaveProperty("system.os")
    expect(meta).toHaveProperty("system.os.version")
    expect(meta).toHaveProperty("system.os.codename")
    expect(meta).toHaveProperty("system.arch")
    expect(meta).toHaveProperty("system.hostname")
    expect(meta).toHaveProperty("system.kernel")
    expect(meta).toHaveProperty("system.ram.total")
    expect(meta).toHaveProperty("system.cpu.cores")
    expect(meta).toHaveProperty("system.ip.public")
    expect(meta).toHaveProperty("system.ip.private")
    expect(meta).toHaveProperty("system.disk.root")
  })

  it("returns failed when a command fails", async () => {
    const ssh = createMockSsh({
      ...FACTS_RESPONSES,
      "cat /etc/os-release": { code: 1, stdout: "" },
    })
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("correctly parses /etc/os-release format", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const meta = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(meta, "system.os")).resolves.toBe("ubuntu")
    await expect(resolveEnvironment(meta, "system.os.version")).resolves.toBe("22.04")
    await expect(resolveEnvironment(meta, "system.os.codename")).resolves.toBe("jammy")
  })

  it("correctly extracts RAM from free -m output", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.ram.total")).resolves.toBe("7981")
  })

  it("correctly extracts public IP from ip route output", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.ip.public")).resolves.toBe(
      "93.184.216.34"
    )
  })

  it("correctly extracts private IP from ip addr output (RFC-1918)", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.ip.private")).resolves.toBe("10.0.1.5")
  })

  it("correctly extracts disk root from df output", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.disk.root")).resolves.toBe("49000")
  })
})
