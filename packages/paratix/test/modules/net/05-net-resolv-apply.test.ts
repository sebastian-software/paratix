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

// R-0000222: net.resolv refuses to write through a symlink (typical
// systemd-resolved layout). Tests that exercise the success path stub
// `[ -L '/etc/resolv.conf' ]` to return non-zero (= regular file).
const RESOLV_NOT_SYMLINK_STUB = {
  "[ -L '/etc/resolv.conf' ]": { code: 1 },
} satisfies NonNullable<Parameters<typeof createMockSsh>[0]>

describe("net.resolv — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed after writing resolv.conf", async () => {
    const mockSsh = createMockSsh(RESOLV_NOT_SYMLINK_STUB)
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("does not unconditionally rm -f /etc/resolv.conf before writing", async () => {
    const mockSsh = createMockSsh(RESOLV_NOT_SYMLINK_STUB)
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
  })

  it("returns changed with search domains", async () => {
    const mockSsh = createMockSsh(RESOLV_NOT_SYMLINK_STUB)
    const mod = net.resolv({ nameservers: ["1.1.1.1", "8.8.8.8"], search: ["example.com"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("does not rm -f /etc/resolv.conf even with multiple nameservers and search domains", async () => {
    const mockSsh = createMockSsh(RESOLV_NOT_SYMLINK_STUB)
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
    const mockSsh = createMockSsh(RESOLV_NOT_SYMLINK_STUB)
    const original = mockSsh.writeFile
    mockSsh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
      throw writeFileError
    }
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("failed to write /etc/resolv.conf")
    expect(result.error?.message).toContain(writeFileError.message)

    // No destructive action occurred against /etc/resolv.conf before the failed write.
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
    expect(mockSsh.calls.some((call: string) => /\brm\b.*\/etc\/resolv\.conf/v.test(call))).toBe(
      false
    )

    mockSsh.writeFile = original
  })

  it("R-0000222: refuses to write when /etc/resolv.conf is a symlink", async () => {
    // systemd-resolved manages /etc/resolv.conf as a symlink to
    // /run/systemd/resolve/stub-resolv.conf — apply must refuse rather than
    // racing or replacing the upstream stub.
    const mockSsh = createMockSsh({
      "[ -L '/etc/resolv.conf' ]": { code: 0 },
    })
    let writeFileCalled = false
    mockSsh.writeFile = async (): Promise<void> => {
      writeFileCalled = true
      await Promise.resolve()
    }
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("symlink")
    expect(writeFileCalled).toBe(false)
  })
})

// ─── net.route ────────────────────────────────────────────────────────────────
