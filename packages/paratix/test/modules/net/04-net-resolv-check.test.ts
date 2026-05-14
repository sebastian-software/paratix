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
    // R-0000275: net.resolv.check now probes /etc/resolv.conf existence
    // before reading. Default to "file exists" so existing fixtures keep
    // passing; the missing-file regression test stubs `{ code: 1 }` (user
    // stubs win because they are placed first).
    responseStubs: [
      ...(options?.responseStubs ?? []),
      { command: "[ -e '/etc/resolv.conf' ]", result: { code: 0 } },
      { command: "[ -L '/etc/resolv.conf' ]", result: { code: 1 } },
    ],
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

  // R-0000275: a missing /etc/resolv.conf must surface as needs-apply, not as
  // a phase-level throw from readFile. Apply creates the file, so check defers.
  it("returns needs-apply when resolv.conf does not exist", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        responseStubs: [{ command: "[ -e '/etc/resolv.conf' ]", result: { code: 1 } }],
      }
    )
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when resolv.conf is a symlink even if target content matches", async () => {
    const mockSsh = createMockSsh(
      {
        "cat '/etc/resolv.conf'": { stdout: "nameserver 1.1.1.1\n" },
      },
      {
        responseStubs: [{ command: "[ -L '/etc/resolv.conf' ]", result: { code: 0 } }],
      }
    )
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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
