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
    // R-0000277: net.route apply probes the dropin path with `[ -L … ]`
    // (isSymlink) before writing. Default to "not a symlink" so existing
    // fixtures keep passing; the symlink-refusal regression stubs `{ code: 0 }`
    // explicitly.
    responseStubs: [
      ...(options?.responseStubs ?? []),
      {
        command: /^\[ -L '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network' \]$/v,
        result: { code: 1 },
      },
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
      command: /^test -f '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network'$/v,
      result: { code: 0 },
    },
    {
      command: /^cat '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network'$/v,
      result: {
        stdout: `[Match]\nName=*\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`,
      },
    },
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

describe("net.route — apply", () => {
  const routeShowCommand = "ip route show '10.0.0.0/24'"
  const liveRouteOutput = "10.0.0.0/24 via 192.168.1.1 dev eth0"

  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed after adding a route (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs ip route replace (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route replace '10.0.0.0/24' via '192.168.1.1'")
  })

  it("runs ip route replace with dev when device is given (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route replace '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
  })

  it("writes the persistent systemd-networkd drop-in when adding a route", async () => {
    const writtenFiles: Array<{
      content: string
      options?: { mode?: string }
      path: string
    }> = []
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    mockSsh.writeFile = async (
      path: string,
      content: string,
      options?: { mode?: string }
    ): Promise<void> => {
      writtenFiles.push({ content, options, path })
      await Promise.resolve()
    }
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    await mod.apply(mockSsh, emptyEnv)

    expect(writtenFiles).toContainEqual({
      content:
        "[Match]\n" +
        "Name=eth0\n" +
        "\n" +
        "[Route]\n" +
        "Destination=10.0.0.0/24\n" +
        "Gateway=192.168.1.1\n",
      options: { mode: "0644" },
      path: "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network",
    })
  })

  it("reloads networkctl after adding route (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("returns failed when ip route replace fails (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ip route replace '10.0.0.0/24' via '192.168.1.1'": {
        code: 2,
        stderr: "Nexthop has invalid gateway",
      },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("ip route replace failed")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("returns failed when networkctl reload fails after adding route", async () => {
    const reloadFlagCheck = buildRouteReloadFlagCheck({
      destination: "10.0.0.0/24",
      gateway: "192.168.1.1",
    }).replace("[ -f ", "touch ")
    const reloadFlagPath = reloadFlagCheck.slice(0, -2)
    const mockSsh = createMockSsh(
      {
        "networkctl reload": { code: 1, stderr: "reload failed" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
    expect(mockSsh.calls.some((call) => call.includes(reloadFlagPath))).toBe(false)
  })

  it("returns changed after removing a route (state: absent)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs ip route del with the checked gateway (state: absent)", async () => {
    const mockSsh = createMockSsh(
      {
        [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route del '10.0.0.0/24' via '192.168.1.1'")
  })

  it("runs ip route del with the checked gateway and device (state: absent)", async () => {
    const mockSsh = createMockSsh(
      {
        [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", {
      device: "eth0",
      state: "absent",
    })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
  })

  it("returns failed when ip route del fails (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "ip route del '10.0.0.0/24' via '192.168.1.1'": {
        code: 2,
        stderr: "No such process",
      },
      [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("ip route del failed")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("removes drop-in when state is absent and the live route is already gone", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh(
      {
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.some((call) => call.startsWith("ip route del "))).toBe(false)
    expect(mockSsh.calls).toContain(`rm -f '${dropinPath}'`)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("removes drop-in file when state is absent", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`rm -f '${dropinPath}'`)
  })

  it("leaves a foreign drop-in with the same destination in place", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const foreignDropin = `[Match]\nName=eth1\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh(
      {
        [`cat '${dropinPath}'`]: { stdout: foreignDropin },
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(`rm -f '${dropinPath}'`)
  })

  it("returns failed when drop-in removal fails (state: absent)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=*\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`rm -f '${dropinPath}'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [routeShowCommand]: { code: 0, stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("drop-in removal failed")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("reloads networkctl after removing route (state: absent)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("returns failed when networkctl reload fails after removing route", async () => {
    const mockSsh = createMockSsh(
      {
        "networkctl reload": { code: 1, stderr: "reload failed" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
  })

  it("returns ok and skips networkctl reload when nothing to remove (state: absent)", async () => {
    // R-0000219: when applyAbsentRoute is a no-op (live route absent and no
    // matching drop-in), the module must report `ok` and must not invoke
    // networkctl reload. Otherwise direct-apply (signal) paths fire spurious
    // change signals.
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh(
      {
        // No live route and no drop-in present.
        [`test -f '${dropinPath}'`]: { code: 1 },
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain("networkctl reload")
    expect(mockSsh.calls.some((call) => call.startsWith("ip route del "))).toBe(false)
    expect(mockSsh.calls).not.toContain(`rm -f '${dropinPath}'`)
  })

  it("sanitizes destination with colons for drop-in filename", async () => {
    // IPv6 destination: colons replaced with dashes
    const dropinPath = "/etc/systemd/network/50-paratix-route-fd00---64.network"
    const expectedDropin = `[Match]\nName=*\n\n[Route]\nDestination=fd00::/64\nGateway=fe80::1\n`
    const mockSsh = createMockSsh(
      {
        [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("fd00::/64", "fe80::1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    // drop-in path uses sanitized destination
    expect(mockSsh.calls).toContain(`rm -f '${dropinPath}'`)
  })
})

// ─── net.interface ────────────────────────────────────────────────────────────

// R-0000100: net.interface must reject names that contain path-traversal
// payloads or empty strings, because the name is interpolated into the
// Netplan/networkd file paths and would otherwise allow writing to arbitrary
// locations under /etc.
