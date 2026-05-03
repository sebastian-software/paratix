import { describe, expect, it } from "vitest"

import { net } from "../../src/index.js"
import { setRunnerAbortSignal } from "../../src/runnerAbortSignal.js"
import {
  clearRegisteredSecrets,
  getRegisteredSecrets,
  registerSecret,
} from "../../src/secretSink.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

// ─── net.hosts ────────────────────────────────────────────────────────────────

describe("net.hosts — check", () => {
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

  it("reads /etc/hosts via cat command", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })
})

describe("net.hosts — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when entry is appended (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns ok when entry already exists (no duplicate added)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when entry is removed (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("reads /etc/hosts before writing (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })

  it("only removes the exact matching line (state: absent), not other entries for same IP", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 web1\n10.0.0.1 db1\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("reads /etc/hosts before writing (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })

  it("writes /etc/hosts back with mode 0644 instead of the generic 0600 default", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writes).toHaveLength(1)
    expect(writes[0]).toStrictEqual({
      content: "127.0.0.1 localhost\n1.2.3.4 myhost\n",
      mode: "0644",
      path: "/etc/hosts",
    })
  })
})

// ─── net.resolv ───────────────────────────────────────────────────────────────

describe("net.resolv — check", () => {
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

describe("net.resolv — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed after writing resolv.conf", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("does not unconditionally rm -f /etc/resolv.conf before writing", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
  })

  it("returns changed with search domains", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1", "8.8.8.8"], search: ["example.com"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("does not rm -f /etc/resolv.conf even with multiple nameservers and search domains", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({
      nameservers: ["1.1.1.1", "8.8.4.4"],
      search: ["example.com", "local"],
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
  })

  it("regression: preserves /etc/resolv.conf when writeFile fails", async () => {
    // Stub writeFile to simulate a failure (disk full, sudo error, etc.).
    // The previous implementation removed /etc/resolv.conf before writeFile,
    // which left the host without resolver configuration on any failure.
    const writeFileError = new Error("simulated disk full")
    const mockSsh = createMockSsh()
    const original = mockSsh.writeFile
    mockSsh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
      throw writeFileError
    }
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(writeFileError)

    // No destructive action occurred against /etc/resolv.conf before the failed write.
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
    expect(mockSsh.calls.some((call: string) => /\brm\b.*\/etc\/resolv\.conf/v.test(call))).toBe(
      false
    )

    mockSsh.writeFile = original
  })
})

// ─── net.route ────────────────────────────────────────────────────────────────

describe("net.route — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when route is present (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route is absent (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ip route show '10.0.0.0/24'": { stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when route is absent (state: absent) and drop-in is gone", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`test -f '${dropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route is present (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when route via different gateway (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.254 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("checks route via ip route show command", async () => {
    const mockSsh = createMockSsh({
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route show '10.0.0.0/24'")
  })

  // R-0000061: persistent drop-in must be validated alongside live route.
  it("returns needs-apply when live route matches but drop-in is missing (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`test -f '${dropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when drop-in has a stale gateway (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const staleDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: staleDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route is gone but drop-in still exists (state: absent)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when both live route and drop-in match (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })
})

describe("net.route — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed after adding a route (state: present)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs ip route replace (state: present)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route replace '10.0.0.0/24' via '192.168.1.1'")
  })

  it("runs ip route replace with dev when device is given (state: present)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route replace '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
  })

  it("reloads networkctl after adding route (state: present)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("returns changed after removing a route (state: absent)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs ip route del (state: absent)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route del '10.0.0.0/24'")
  })

  it("removes drop-in file when state is absent", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`rm -f '${dropinPath}'`)
  })

  it("reloads networkctl after removing route (state: absent)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("sanitizes destination with colons for drop-in filename", async () => {
    // IPv6 destination: colons replaced with dashes
    const mockSsh = createMockSsh()
    const mod = net.route("fd00::/64", "fe80::1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    // drop-in path uses sanitized destination
    const dropinPath = "/etc/systemd/network/50-paratix-route-fd00---64.network"
    expect(mockSsh.calls).toContain(`rm -f '${dropinPath}'`)
  })
})

// ─── net.interface ────────────────────────────────────────────────────────────

describe("net.interface — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.interface("eth0", {})
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when Netplan config matches", async () => {
    const expectedYaml = [
      "network:",
      "  version: 2",
      "  ethernets:",
      "    eth0:",
      "      dhcp4: true",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/netplan/60-paratix-eth0.yaml'": { stdout: `${expectedYaml}\n` },
      "test -d '/etc/netplan'": { code: 0 },
      "test -f '/etc/netplan/60-paratix-eth0.yaml'": { code: 0 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when networkd config matches (no Netplan)", async () => {
    const expectedConfig = ["[Match]", "Name=eth0", "", "[Network]", "DHCP=yes"].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 0 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when Netplan config does not exist", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
      "test -f '/etc/netplan/60-paratix-eth0.yaml'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when Netplan config content differs", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/netplan/60-paratix-eth0.yaml'": { stdout: "network:\n  version: 1\n" },
      "test -d '/etc/netplan'": { code: 0 },
      "test -f '/etc/netplan/60-paratix-eth0.yaml'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when networkd config does not exist (no Netplan)", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when networkd config content differs (no Netplan)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: "[Match]\nName=wrong\n" },
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("uses Netplan config path when /etc/netplan/ directory exists", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
      "test -f '/etc/netplan/60-paratix-eth0.yaml'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("test -f '/etc/netplan/60-paratix-eth0.yaml'")
  })

  it("uses networkd config path when /etc/netplan/ directory is absent", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("test -f '/etc/systemd/network/60-paratix-eth0.network'")
  })

  it("checks for /etc/netplan directory to detect Netplan", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("test -d '/etc/netplan'")
  })

  it("does not check networkd path when Netplan is detected", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
      "test -f '/etc/netplan/60-paratix-eth0.yaml'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("test -f '/etc/systemd/network/60-paratix-eth0.network'")
  })
})

describe("net.interface — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.interface("eth0", {})
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed in Netplan mode", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs netplan apply in Netplan mode", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("netplan apply")
  })

  it("returns changed in networkd mode", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs networkctl reload in networkd mode", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("does not run netplan apply in networkd mode", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("netplan apply")
  })

  it("does not run networkctl reload in Netplan mode", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("writes Netplan config when dhcp is enabled", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("writes networkd config when addresses are given (networkd mode)", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {
      addresses: ["192.168.1.10/24"],
      gateway: "192.168.1.1",
      nameservers: ["1.1.1.1"],
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("writes Netplan config with addresses, gateway and nameservers (Netplan mode)", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {
      addresses: ["192.168.1.10/24"],
      gateway: "192.168.1.1",
      nameservers: ["1.1.1.1", "8.8.8.8"],
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("netplan apply")
  })

  it("detects Netplan via test -d command during apply", async () => {
    const mockSsh = createMockSsh({
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("test -d '/etc/netplan'")
  })
})

// ─── net.waitFor ──────────────────────────────────────────────────────────────

/* eslint-disable testing-library/await-async-utils -- net.waitFor is not testing-library waitFor */

describe("net.waitFor — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when port is open (nc -z)", async () => {
    const mockSsh = createMockSsh({
      "nc -z '127.0.0.1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when port is closed", async () => {
    const mockSsh = createMockSsh({
      "nc -z '127.0.0.1' '8080'": { code: 1 },
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

  it("returns ok when file contains expected string (grep -q)", async () => {
    const mockSsh = createMockSsh({
      "grep -q 'READY' '/tmp/status'": { code: 0 },
    })
    const mod = net.waitFor({ contains: "READY", file: "/tmp/status" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when file does not contain expected string", async () => {
    const mockSsh = createMockSsh({
      "grep -q 'READY' '/tmp/status'": { code: 1 },
    })
    const mod = net.waitFor({ contains: "READY", file: "/tmp/status" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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

describe("net.waitFor — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = net.waitFor({ port: 8080 })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when port becomes available immediately", async () => {
    const mockSsh = createMockSsh({
      "nc -z '127.0.0.1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns failed on timeout when condition never becomes true", async () => {
    const mockSsh = createMockSsh({
      "nc -z '127.0.0.1' '9999'": { code: 1 },
    })
    const mod = net.waitFor({ interval: 5, port: 9999, timeout: 10 })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  // R-0000052: net.waitFor must observe the runner abort signal so SIGINT
  // unblocks the polling loop within the next iteration tick instead of
  // running until the configured timeout.
  it("returns failed within the next tick after the runner abort signal fires", async () => {
    const mockSsh = createMockSsh({
      // Probe always fails so the loop falls through to the delay.
      "nc -z '127.0.0.1' '9000'": { code: 1 },
    })
    const controller = new AbortController()
    setRunnerAbortSignal(controller.signal)

    try {
      const mod = net.waitFor({
        // Long enough that the test would hang (or fail with a long delta) if
        // the abort path were missing.
        interval: 60_000,
        port: 9000,
        timeout: 600_000,
      })

      const start = Date.now()
      const applyPromise = mod.apply(mockSsh, emptyEnv)
      // Let the loop reach `delay()` before we abort. A microtask flush via
      // queueMicrotask is enough because conn.test resolves synchronously
      // through the mock.
      await new Promise<void>((resolve) => {
        queueMicrotask(resolve)
      })
      controller.abort(new Error("Terminal prompt interrupted by SIGINT"))

      const result = await applyPromise
      const elapsed = Date.now() - start

      expect(result.status).toBe("failed")
      expect(result.error).toBeInstanceOf(Error)
      expect(result.error?.message).toMatch(/aborted by shutdown signal/v)
      // The polling loop must return well before the configured timeout.
      // 5 seconds is generous for test machines while still proving we are
      // not waiting on the 60s interval or the 600s timeout.
      expect(elapsed).toBeLessThan(5000)
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })

  it("returns failed synchronously when the abort signal is already aborted at apply start", async () => {
    const mockSsh = createMockSsh({
      "nc -z '127.0.0.1' '9001'": { code: 1 },
    })
    const controller = new AbortController()
    controller.abort(new Error("aborted before apply"))
    setRunnerAbortSignal(controller.signal)

    try {
      const mod = net.waitFor({ interval: 60_000, port: 9001, timeout: 600_000 })
      const start = Date.now()
      const result = await mod.apply(mockSsh, emptyEnv)
      const elapsed = Date.now() - start

      expect(result.status).toBe("failed")
      expect(result.error).toBeInstanceOf(Error)
      expect(result.error?.message).toMatch(/aborted by shutdown signal/v)
      expect(elapsed).toBeLessThan(1000)
      // The probe is never invoked when the signal is already aborted.
      expect(mockSsh.calls).not.toContain("nc -z '127.0.0.1' '9001'")
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })
})

/* eslint-enable testing-library/await-async-utils */

// ─── net.request ──────────────────────────────────────────────────────────────

describe("net.request — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.request("https://example.com/health")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when status matches (200)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when status does not match", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "503" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when status AND body match", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
      "curl -s 'https://example.com/health'": { stdout: "OK" },
    })
    const mod = net.request("https://example.com/health", { body: "OK" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when body does not match even if status matches", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
      "curl -s 'https://example.com/health'": { stdout: "ERROR" },
    })
    const mod = net.request("https://example.com/health", { body: "OK" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok with custom method (POST)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' -X 'POST' 'https://example.com/api'": {
        stdout: "200",
      },
    })
    const mod = net.request("https://example.com/api", { method: "POST" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("has correct name format: net.request: GET <url>", async () => {
    const mod = net.request("https://example.com/health")
    expect(mod.name).toBe("net.request: GET https://example.com/health")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("has correct name format with custom method: net.request: POST <url>", async () => {
    const mod = net.request("https://example.com/api", { method: "POST" })
    expect(mod.name).toBe("net.request: POST https://example.com/api")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

describe("net.request — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = net.request("https://example.com/health")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns ok when request succeeds", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns failed when request fails (wrong status)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "503" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

// R-0000072: Authorization (and other sensitive) header values must be routed
// through `curl --config -` over stdin instead of being inlined into argv,
// where `ps -ef` and sudo logging would capture them. The header values must
// also be registered in the process-scoped secret sink so CommandError stack
// traces are masked when curl fails.
describe("net.request — R-0000072 sensitive header masking", () => {
  it("never inlines the Authorization header value on the curl command line (check)", async () => {
    const token = "Bearer super-secret-PAT-XYZ123"
    const mockSsh = createMockSsh()

    const mod = net.request("https://example.com/health", {
      headers: { Authorization: token },
    })
    await mod.check(mockSsh, emptyEnv)

    // Every executed curl command must omit the secret token. Mocking returns
    // status "" so the check returns needs-apply; we only care about the
    // command shape here.
    for (const command of mockSsh.calls) {
      expect(command).not.toContain(token)
      expect(command).not.toContain("-H 'Authorization:")
    }
    // Sanity: the command was a curl invocation.
    expect(mockSsh.calls.some((c) => c.startsWith("curl "))).toBe(true)
  })

  it("forwards the Authorization header via the curl --config - stdin payload", async () => {
    const token = "Bearer super-secret-PAT-XYZ123"
    const mockSsh = createMockSsh()

    const mod = net.request("https://example.com/health", {
      headers: { Authorization: token },
    })
    await mod.check(mockSsh, emptyEnv)

    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
    expect(curlCall).toBeDefined()
    expect(curlCall?.command).toContain("--config -")
    expect(curlCall?.options?.input).toContain(`Authorization: ${token}`)
    expect(curlCall?.options?.secrets).toContain(token)
  })

  it("registers the Authorization header value as a process-scoped secret during apply", async () => {
    clearRegisteredSecrets()
    const token = "Bearer super-secret-PAT-XYZ123"
    const seen: string[] = []
    const mockSsh = createMockSsh()
    // Capture the secrets registered while the curl call is running.
    const originalExec = mockSsh.exec
    mockSsh.exec = async (command, options) => {
      seen.push(...getRegisteredSecrets())
      return originalExec(command, options)
    }

    const mod = net.request("https://example.com/health", {
      headers: { Authorization: token },
      status: 200,
    })
    await mod.apply(mockSsh, emptyEnv)

    expect(seen).toContain(token)
    // Sink is rebalanced after apply finishes.
    expect(getRegisteredSecrets()).not.toContain(token)
    clearRegisteredSecrets()
  })

  it("does not register a secret when no Authorization header is present", async () => {
    clearRegisteredSecrets()
    // Pre-register an unrelated value to confirm we never rely on a leftover.
    registerSecret("unrelated-secret-marker")
    try {
      const mockSsh = createMockSsh({
        "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
      })
      const mod = net.request("https://example.com/health")
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toStrictEqual([])
      expect(curlCall?.options?.input).toBeUndefined()
    } finally {
      clearRegisteredSecrets()
    }
  })

  it("masks signed-URL query parameters by routing the URL through stdin", async () => {
    clearRegisteredSecrets()
    const url = "https://example.com/object?signature=abc123&token=xyz789"
    const mockSsh = createMockSsh()

    const mod = net.request(url)
    await mod.check(mockSsh, emptyEnv)

    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
    expect(curlCall).toBeDefined()
    expect(curlCall?.command).not.toContain(url)
    expect(curlCall?.command).toContain("--config -")
    expect(curlCall?.options?.input).toContain(`url = "${url}"`)
    expect(curlCall?.options?.secrets).toContain(url)
    clearRegisteredSecrets()
  })
})
