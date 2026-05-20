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
      throw new Error(`Expected net.interface check to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

function regularFileCheck(remotePath: string): string {
  return `[ -f '${remotePath}' ] && [ ! -L '${remotePath}' ]`
}

describe("net.interface — check", () => {
  afterEach(assertNoWriteFileCalls)

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
      [regularFileCheck("/etc/netplan/60-paratix-eth0.yaml")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when networkd config matches (no Netplan)", async () => {
    const expectedConfig = ["[Match]", "Name=eth0", "", "[Network]", "DHCP=yes"].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when static config and live interface state match", async () => {
    const expectedConfig = [
      "[Match]",
      "Name=eth0",
      "",
      "[Network]",
      "DHCP=no",
      "Address=192.168.1.10/24",
      "",
      "[Route]",
      "Gateway=192.168.1.1",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      "ip -4 route show default dev 'eth0'": {
        stdout: "default via 192.168.1.1 dev eth0 proto static\n",
      },
      "ip -o addr show dev 'eth0'": {
        stdout: "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n",
      },
      "ip link show dev 'eth0'": { code: 0 },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {
      addresses: ["192.168.1.10/24"],
      gateway: "192.168.1.1",
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when IPv6 static config and live interface state match", async () => {
    const expectedConfig = [
      "[Match]",
      "Name=eth0",
      "",
      "[Network]",
      "DHCP=no",
      "Address=2001:db8::10/64",
      "",
      "[Route]",
      "Gateway=fe80::1",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      "ip -6 route show default dev 'eth0'": {
        stdout: "default via fe80::1 dev eth0 proto static\n",
      },
      "ip -o addr show dev 'eth0'": {
        stdout: "2: eth0    inet6 2001:db8::10/64 scope global\n",
      },
      "ip link show dev 'eth0'": { code: 0 },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {
      addresses: ["2001:db8::10/64"],
      gateway: "fe80::1",
    })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain("ip -6 route show default dev 'eth0'")
    expect(mockSsh.calls).not.toContain("ip -4 route show default dev 'eth0'")
  })

  it("returns needs-apply when live gateway only matches as a prefix", async () => {
    const expectedConfig = [
      "[Match]",
      "Name=eth0",
      "",
      "[Network]",
      "DHCP=no",
      "Address=10.0.0.20/24",
      "",
      "[Route]",
      "Gateway=10.0.0.1",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      "ip -4 route show default dev 'eth0'": {
        stdout: "default via 10.0.0.10 dev eth0 proto static\n",
      },
      "ip -o addr show dev 'eth0'": {
        stdout: "2: eth0    inet 10.0.0.20/24 brd 10.0.0.255 scope global eth0\n",
      },
      "ip link show dev 'eth0'": { code: 0 },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {
      addresses: ["10.0.0.20/24"],
      gateway: "10.0.0.1",
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when config matches but live address is missing", async () => {
    const expectedConfig = [
      "[Match]",
      "Name=eth0",
      "",
      "[Network]",
      "DHCP=no",
      "Address=192.168.1.10/24",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      "ip -o addr show dev 'eth0'": {
        stdout: "2: eth0    inet 192.168.1.11/24 brd 192.168.1.255 scope global eth0\n",
      },
      "ip link show dev 'eth0'": { code: 0 },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", { addresses: ["192.168.1.10/24"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the live address only contains the expected CIDR as a substring", async () => {
    const expectedConfig = [
      "[Match]",
      "Name=eth0",
      "",
      "[Network]",
      "DHCP=no",
      "Address=10.0.0.1/24",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      "ip -o addr show dev 'eth0'": {
        stdout: "2: eth0    inet 110.0.0.1/24 brd 110.0.0.255 scope global eth0\n",
      },
      "ip link show dev 'eth0'": { code: 0 },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", { addresses: ["10.0.0.1/24"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when Netplan config does not exist", async () => {
    const mockSsh = createMockSsh({
      [regularFileCheck("/etc/netplan/60-paratix-eth0.yaml")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when Netplan config is a symlink even if target content matches", async () => {
    const expectedYaml = [
      "network:",
      "  version: 2",
      "  ethernets:",
      "    eth0:",
      "      dhcp4: true",
    ].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/netplan/60-paratix-eth0.yaml'": { stdout: `${expectedYaml}\n` },
      [regularFileCheck("/etc/netplan/60-paratix-eth0.yaml")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when Netplan config content differs", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/netplan/60-paratix-eth0.yaml'": { stdout: "network:\n  version: 1\n" },
      [regularFileCheck("/etc/netplan/60-paratix-eth0.yaml")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when networkd config does not exist (no Netplan)", async () => {
    const mockSsh = createMockSsh({
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when networkd config is a symlink even if target content matches", async () => {
    const expectedConfig = ["[Match]", "Name=eth0", "", "[Network]", "DHCP=yes"].join("\n")
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: `${expectedConfig}\n` },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when networkd config content differs (no Netplan)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/systemd/network/60-paratix-eth0.network'": { stdout: "[Match]\nName=wrong\n" },
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("uses Netplan config path when /etc/netplan/ directory exists", async () => {
    const mockSsh = createMockSsh({
      [regularFileCheck("/etc/netplan/60-paratix-eth0.yaml")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(regularFileCheck("/etc/netplan/60-paratix-eth0.yaml"))
  })

  it("uses networkd config path when /etc/netplan/ directory is absent", async () => {
    const mockSsh = createMockSsh({
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(
      regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")
    )
  })

  it("checks for /etc/netplan directory to detect Netplan", async () => {
    const mockSsh = createMockSsh({
      [regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("test -d '/etc/netplan'")
  })

  it("does not check networkd path when Netplan is detected", async () => {
    const mockSsh = createMockSsh({
      [regularFileCheck("/etc/netplan/60-paratix-eth0.yaml")]: { code: 1 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const mod = net.interface("eth0", {})
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(
      regularFileCheck("/etc/systemd/network/60-paratix-eth0.network")
    )
  })
})
