import { describe, expect, it, vi } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import {
  isSystemHostMetaEntry,
  isSystemRebootMetaEntry,
  mergeEnvironmentFromMeta,
} from "../../src/meta.js"
import { system } from "../../src/modules/system.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

const emptyEnv = {}
const successfulRebootResponses = {
  "shutdown -r now": { code: 0 },
}

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
    expect(result.error).toBeInstanceOf(Error)
  })

  it("sends shutdown -r now and returns meta with system.reboot set to true", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("shutdown -r now")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
  })

  it("does not set system.host in meta when no resolveHost option is given", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
  })

  it("calls resolveHost and sets system.host in meta when resolveHost is provided", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const resolveHost = vi.fn().mockResolvedValue("10.0.0.42")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(resolveHost).toHaveBeenCalledOnce()
    expect(result.meta?.find(isSystemHostMetaEntry)?.host).toBe("10.0.0.42")
  })

  it("returns failed with error details when shutdown exits with permission denied", async () => {
    const ssh = createMockSsh({
      "shutdown -r now": { code: 1, stderr: "shutdown: Permission denied", stdout: "" },
    })
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain("[system.reboot] shutdown -r now failed")
    expect(result.error?.message).toContain("Permission denied")
    expect(result.meta).toBeUndefined()
  })

  it("returns failed with error details when shutdown is missing", async () => {
    const ssh = createMockSsh({
      "shutdown -r now": { code: 127, stderr: "shutdown: command not found", stdout: "" },
    })
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toContain("[system.reboot] shutdown -r now failed")
    expect(result.error?.message).toContain("command not found")
    expect(result.meta).toBeUndefined()
  })

  // R-0000782: validate the resolveHost return value against an
  // IPv4/IPv6/hostname pattern. A string with embedded whitespace, a URL,
  // or other shell-unsafe content must not reach reconnect; surface a
  // structured failure but keep the `system.reboot` meta entry intact
  // because the reboot trigger already succeeded.
  it("R-0000782: returns failed when resolveHost returns an invalid host", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const resolveHost = vi.fn().mockResolvedValue("not a host with spaces")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("invalid host")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
  })

  it("R-0000782: accepts plain IPv4 hosts from resolveHost", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const resolveHost = vi.fn().mockResolvedValue("192.0.2.10")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.find(isSystemHostMetaEntry)?.host).toBe("192.0.2.10")
  })

  it("R-0000782: accepts DNS-style hostnames from resolveHost", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const resolveHost = vi.fn().mockResolvedValue("host.example.com")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.find(isSystemHostMetaEntry)?.host).toBe("host.example.com")
  })

  it("returns failed when resolveHost throws", async () => {
    const ssh = createMockSsh(successfulRebootResponses)
    const resolveHost = vi.fn().mockRejectedValue(new Error("DNS failed"))
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[system.reboot] resolveHost failed")
    expect(result.error?.message).toContain("DNS failed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
  })

  // R-0000243: a resolver that never settles must not stall the runner.
  // The wall-clock timeout surfaces as a `failed` result instead.
  it("R-0000243: returns failed when resolveHost exceeds the configured timeout", async () => {
    vi.useFakeTimers()
    try {
      const ssh = createMockSsh(successfulRebootResponses)
      const resolveHost = vi.fn().mockReturnValue(
        new Promise<string>(() => {
          // never settles
        })
      )
      const mod = system.reboot({ resolveHost, resolveHostTimeoutMs: 25 })
      const promise = mod.apply(ssh, emptyEnv)
      await vi.advanceTimersByTimeAsync(25)
      const result = await promise
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("[system.reboot] resolveHost failed")
      expect(result.error?.message).toContain("timed out after 25ms")
      expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
      expect(result.meta?.some(isSystemHostMetaEntry)).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it("treats SSH connection closed mid-shutdown as a successful reboot trigger", async () => {
    const ssh = createMockSsh()
    vi.spyOn(ssh, "exec").mockImplementation(async (command: string) => {
      ssh.calls.push(command)
      await Promise.resolve()
      throw new Error("SSH connection closed")
    })
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(ssh.calls).toContain("shutdown -r now")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
  })

  it("treats ECONNRESET disconnect during shutdown as a successful reboot trigger", async () => {
    const ssh = createMockSsh()
    vi.spyOn(ssh, "exec").mockImplementation(async (command: string) => {
      ssh.calls.push(command)
      await Promise.resolve()
      throw new Error("read ECONNRESET")
    })
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
  })

  it("emits system.host meta on disconnect when resolveHost is provided", async () => {
    const ssh = createMockSsh()
    vi.spyOn(ssh, "exec").mockImplementation(async (command: string) => {
      ssh.calls.push(command)
      await Promise.resolve()
      throw new Error("Connection reset by peer")
    })
    const resolveHost = vi.fn().mockResolvedValue("10.0.0.99")
    const mod = system.reboot({ resolveHost })
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(result.meta?.some(isSystemRebootMetaEntry)).toBe(true)
    expect(result.meta?.find(isSystemHostMetaEntry)?.host).toBe("10.0.0.99")
  })

  it("still returns failed when exec throws a non-disconnect error", async () => {
    const ssh = createMockSsh()
    vi.spyOn(ssh, "exec").mockImplementation(async (command: string) => {
      ssh.calls.push(command)
      await Promise.resolve()
      throw new Error("Permission denied (publickey)")
    })
    const mod = system.reboot()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[system.reboot] shutdown -r now failed")
    expect(result.error?.message).toContain("Permission denied")
    expect(result.meta).toBeUndefined()
  })
})

describe("system.uptime — check", () => {
  it("is marked as a dry-run meta producer", () => {
    const mod = system.uptime()
    expect(mod._dryRunMetaProducer).toBe(true)
  })

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

  it("returns failed when reading /proc/uptime exits with a non-zero code", async () => {
    const ssh = createMockSsh({
      "awk '{print int($1)}' /proc/uptime": {
        code: 1,
        stderr: "awk: can't open /proc/uptime",
        stdout: "",
      },
    })
    const mod = system.uptime()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[system.uptime] failed to read /proc/uptime")
    expect(result.meta).toBeUndefined()
  })

  it("returns failed when /proc/uptime returns empty output", async () => {
    const ssh = createMockSsh({
      "awk '{print int($1)}' /proc/uptime": { code: 0, stdout: "" },
    })
    const mod = system.uptime()
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("[system.uptime] /proc/uptime returned empty output")
    expect(result.meta).toBeUndefined()
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
  it("is marked as a dry-run meta producer", () => {
    const mod = system.facts()
    expect(mod._dryRunMetaProducer).toBe(true)
  })

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

  it("ignores public IP captures with octets greater than 255", async () => {
    const ssh = createMockSsh({
      ...FACTS_RESPONSES,
      "ip -4 route get 1.1.1.1": {
        code: 0,
        stdout: "1.1.1.1 via 10.0.1.1 dev eth0 src 999.0.0.10 uid 0\n",
      },
    })
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.ip.public")).resolves.toBe("")
  })

  it("correctly extracts private IP from ip addr output (RFC-1918)", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.ip.private")).resolves.toBe("10.0.1.5")
  })

  // R-0000781: the `\d+\.\d+\.\d+\.\d+` regex in `findPrivateIp` accepts
  // octets > 255 because `\d+` is unbounded. Without per-octet validation a
  // captured string like `10.999.0.1` would pass the `startsWith("10.")`
  // gate and surface as `system.ip.private`, polluting downstream meta. The
  // first valid private IP later in the output must still win.
  it("R-0000781: skips IPv4 captures with octets > 255 and falls through to the next valid private IP", async () => {
    const ssh = createMockSsh({
      ...FACTS_RESPONSES,
      "ip -4 addr": {
        code: 0,
        stdout:
          "2: eth0: <BROADCAST>\n    inet 10.999.0.1/24 scope global eth0\n    inet 192.168.1.42/24 scope global eth0\n",
      },
    })
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.ip.private")).resolves.toBe(
      "192.168.1.42"
    )
  })

  it("correctly extracts disk root from df output", async () => {
    const ssh = createMockSsh(FACTS_RESPONSES)
    const mod = system.facts()
    const result = await mod.apply(ssh, emptyEnv)
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "system.disk.root")).resolves.toBe("49000")
  })
})
