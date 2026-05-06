/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */
/* eslint-disable testing-library/await-async-utils -- net.waitFor is not Testing Library waitFor */
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

describe("net.waitFor — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when port is open (nc -z)", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when port is closed", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '8080'": { code: 1 },
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
