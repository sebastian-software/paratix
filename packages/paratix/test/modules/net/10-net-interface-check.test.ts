/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { sha256String } from "../../../src/modules/fileHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const NET_WRITE_ALLOWLIST = [
  { options: { mode: "0644" }, remotePath: "/etc/hosts" },
  { options: { mode: "0644" }, remotePath: "/etc/resolv.conf" },
  { options: { mode: "0644" }, remotePath: /^\/etc\/netplan\/60-paratix-.+\.yaml$/v },
  {
    options: { mode: "0644" },
    remotePath: /^\/etc\/systemd\/network\/50-paratix-route-.+\.network$/v,
  },
  { options: { mode: "0644" }, remotePath: /^\/etc\/systemd\/network\/60-paratix-.+\.network$/v },
] as const

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [...NET_WRITE_ALLOWLIST, ...(options?.allowWrites ?? [])],
  })

const emptyEnv = {}
const routeDropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
const SUCCESSFUL_ROUTE_APPLY_OPTIONS = {
  responseStubs: [
    { command: /^ip route replace '[^']+' via '[^']+'$/v, result: { code: 0 } },
    { command: /^ip route replace '[^']+' via '[^']+' dev '[^']+'$/v, result: { code: 0 } },
    { command: /^ip route del '[^']+' via '[^']+'$/v, result: { code: 0 } },
    { command: /^ip route del '[^']+' via '[^']+' dev '[^']+'$/v, result: { code: 0 } },
    {
      command: /^rm -f '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network'$/v,
      result: { code: 0 },
    },
    { command: "networkctl reload", result: { code: 0 } },
    { command: "mkdir -p /var/lib/paratix/flags", result: { code: 0 } },
    {
      command:
        /^find \/var\/lib\/paratix\/flags -maxdepth 1 -name 'net-route-[^']+-\*' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\/'net-route-[^']+'$/v,
      result: { code: 0 },
    },
    { command: /^ip route show '[^']+'$/v, result: { code: 0, stdout: "" } },
  ],
} satisfies NonNullable<Parameters<typeof createMockSsh>[1]>
const APPLY_TO_NEW_FILE_OPTIONS = {
  responseStubs: [
    { command: /^test -f '\/etc\/netplan\/60-paratix-[^']+\.yaml'$/v, result: { code: 1 } },
    {
      command: /^test -f '\/etc\/systemd\/network\/60-paratix-[^']+\.network'$/v,
      result: { code: 1 },
    },
    { command: "netplan apply", result: { code: 0 } },
    { command: "networkctl reload", result: { code: 0 } },
    {
      command: /^rm -f '\/etc\/netplan\/60-paratix-[^']+\.yaml'$/v,
      result: { code: 0 },
    },
    {
      command: /^rm -f '\/etc\/systemd\/network\/60-paratix-[^']+\.network'$/v,
      result: { code: 0 },
    },
  ],
} satisfies NonNullable<Parameters<typeof createMockSsh>[1]>

function buildRouteReloadFlagCheck(input: {
  destination: string
  device?: string
  gateway: string
}): string {
  const routeKey = `${input.destination}\n${input.gateway}\n${input.device ?? ""}`
  const dropin = `[Match]\nName=${input.device ?? "*"}\n\n[Route]\nDestination=${input.destination}\nGateway=${input.gateway}\n`
  const flagName = `net-route-${sha256String(routeKey).slice(0, 16)}-${sha256String(dropin).slice(0, 16)}`
  return `[ -f /var/lib/paratix/flags/'${flagName}' ]`
}

function getFirstCurlExecCall(mockSsh: ReturnType<typeof createMockSsh>) {
  const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
  expect(curlCall).toBeDefined()
  if (curlCall == null) throw new Error("Expected a curl exec call")
  return curlCall
}

// ─── net.hosts ────────────────────────────────────────────────────────────────

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
      "ip -o addr show dev 'eth0'": {
        stdout: "2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n",
      },
      "ip link show dev 'eth0'": { code: 0 },
      "ip route show default dev 'eth0'": {
        stdout: "default via 192.168.1.1 dev eth0 proto static\n",
      },
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 0 },
    })
    const mod = net.interface("eth0", {
      addresses: ["192.168.1.10/24"],
      gateway: "192.168.1.1",
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
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
      "test -d '/etc/netplan'": { code: 1 },
      "test -f '/etc/systemd/network/60-paratix-eth0.network'": { code: 0 },
    })
    const mod = net.interface("eth0", { addresses: ["192.168.1.10/24"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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
