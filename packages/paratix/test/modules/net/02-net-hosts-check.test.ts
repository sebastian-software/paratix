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
    // R-0000275: net.hosts.check now probes /etc/hosts existence before reading.
    // Default the probe to "file exists" so fixtures that supply the cat
    // response keep passing; tests that exercise the missing-file path stub
    // this probe explicitly with `{ code: 1 }` (user stubs win because they
    // are placed first and `find` returns the first match).
    responseStubs: [
      ...(options?.responseStubs ?? []),
      { command: "[ -e '/etc/hosts' ]", result: { code: 0 } },
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

  // R-0000275: a missing /etc/hosts must surface as needs-apply, not as a
  // phase-level throw from readFile. Apply ensures the file exists.
  it("returns needs-apply when /etc/hosts does not exist", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        responseStubs: [{ command: "[ -e '/etc/hosts' ]", result: { code: 1 } }],
      }
    )
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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

  it("returns needs-apply when the desired hostname appears only in an inline comment", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 # web1\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when the desired hostname appears before an inline comment", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 web1 # managed host\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when desired and foreign hostnames are already consolidated", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost app.local\n" },
    })
    const mod = net.hosts("127.0.0.1", ["app.local"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when same-IP hostnames are split across multiple lines", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 api\n10.0.0.1 db\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web"])
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
