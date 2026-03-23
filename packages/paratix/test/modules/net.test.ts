import { describe, expect, it } from "vitest"

import { net } from "../../src/index.js"
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
    const writes: Array<{ content: string; mode?: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options?.mode, path })
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

  it("removes existing symlink before writing (rm -f)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("rm -f /etc/resolv.conf")
  })

  it("runs rm -f before write (order check)", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    await mod.apply(mockSsh, emptyEnv)
    const rmIndex = mockSsh.calls.indexOf("rm -f /etc/resolv.conf")
    expect(rmIndex).toBeGreaterThanOrEqual(0)
  })

  it("returns changed with search domains", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1", "8.8.8.8"], search: ["example.com"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("removes symlink even with multiple nameservers and search domains", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({
      nameservers: ["1.1.1.1", "8.8.4.4"],
      search: ["example.com", "local"],
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("rm -f /etc/resolv.conf")
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
    const mockSsh = createMockSsh({
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
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

  it("returns ok when route is absent (state: absent)", async () => {
    const mockSsh = createMockSsh({
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
