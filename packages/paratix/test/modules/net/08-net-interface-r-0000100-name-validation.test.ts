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

describe("net.interface — R-0000100 name validation", () => {
  it("throws when the name contains path traversal segments", () => {
    expect(() => net.interface("../../etc/passwd", {})).toThrow(/invalid interface name/v)
  })

  it("throws when the name is the empty string", () => {
    expect(() => net.interface("", {})).toThrow(/invalid interface name/v)
  })

  it("throws when the name contains a forward slash", () => {
    expect(() => net.interface("eth0/../foo", {})).toThrow(/invalid interface name/v)
  })

  it("accepts valid POSIX interface names", () => {
    expect(() => net.interface("eth0", {})).not.toThrow()
    expect(() => net.interface("enp3s0", {})).not.toThrow()
    expect(() => net.interface("br-lan", {})).not.toThrow()
    expect(() => net.interface("vlan.100", {})).not.toThrow()
  })
})

describe("net.route — device name validation", () => {
  it("throws when the device contains path traversal segments", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "../../eth0" })).toThrow(
      /invalid route device/v
    )
  })

  it("throws when the device contains a forward slash", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0/../foo" })).toThrow(
      /invalid route device/v
    )
  })

  it("throws when the device contains whitespace", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth 0" })).toThrow(
      /invalid route device/v
    )
  })

  it("throws when the device contains shell metacharacters", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0;touch" })).toThrow(
      /invalid route device/v
    )
  })

  it("accepts valid POSIX device names", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })).not.toThrow()
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "br-lan" })).not.toThrow()
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "vlan.100" })).not.toThrow()
  })
})
