/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { describe, expect, it, vi } from "vitest"

import { net } from "../../../src/index.js"
import { sha256String } from "../../../src/modules/fileHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const NET_WRITE_ALLOWLIST = [
  { options: { mode: "0644" }, remotePath: "/etc/hosts" },
  { options: { mode: "0644" }, remotePath: "/etc/resolv.conf" },
  { options: { mode: "0644" }, remotePath: /^\/etc\/netplan\/60-paratix-.+\.yaml$/v },
  {
    options: { mode: "0644" },
    remotePath:
      /^\/etc\/systemd\/network\/60-paratix-[^\/]+\.network\.d\/50-paratix-route-.+\.conf$/v,
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
        command:
          /^\[ -f '\/etc\/systemd\/network\/(?:60-paratix-[^\/]+\.network\.d\/50-paratix-route-[^']+\.conf|50-paratix-route-[^']+\.network)' \] && \[ ! -L '\/etc\/systemd\/network\/(?:60-paratix-[^\/]+\.network\.d\/50-paratix-route-[^']+\.conf|50-paratix-route-[^']+\.network)' \]$/v,
        result: { code: 1 },
      },
      {
        command:
          /^\[ -L '\/etc\/systemd\/network\/60-paratix-[^\/]+\.network\.d\/50-paratix-route-[^']+\.conf' \]$/v,
        result: { code: 1 },
      },
    ],
  })

const emptyEnv = {}

function buildRouteDropinPath(input: {
  destination: string
  device: string
  gateway: string
}): string {
  const routeKey = `${input.destination}\n${input.gateway}\n${input.device}`
  const routeHash = sha256String(routeKey).slice(0, 16)
  const sanitized = input.destination.replaceAll("/", "-").replaceAll(":", "-").replace(/^-+/v, "")
  return `/etc/systemd/network/60-paratix-${input.device}.network.d/50-paratix-route-${sanitized}-${routeHash}.conf`
}

const routeDropinPath = buildRouteDropinPath({
  destination: "10.0.0.0/24",
  device: "eth0",
  gateway: "192.168.1.1",
})
const legacyRouteDropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
const SUCCESSFUL_ROUTE_APPLY_OPTIONS = {
  responseStubs: [
    { command: /^ip -4 route replace '[^']+' via '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -4 route replace '[^']+' via '[^']+' dev '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -6 route replace '[^']+' via '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -6 route replace '[^']+' via '[^']+' dev '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -4 route del '[^']+' via '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -4 route del '[^']+' via '[^']+' dev '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -6 route del '[^']+' via '[^']+'$/v, result: { code: 0 } },
    { command: /^ip -6 route del '[^']+' via '[^']+' dev '[^']+'$/v, result: { code: 0 } },
    {
      command:
        /^test -f '\/etc\/systemd\/network\/60-paratix-[^\/]+\.network\.d\/50-paratix-route-[^']+\.conf'$/v,
      result: { code: 0 },
    },
    {
      command:
        /^cat '\/etc\/systemd\/network\/60-paratix-[^\/]+\.network\.d\/50-paratix-route-[^']+\.conf'$/v,
      result: {
        stdout: `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`,
      },
    },
    {
      command: /^test -f '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network'$/v,
      result: { code: 1 },
    },
    {
      command:
        /^rm -f -- '\/etc\/systemd\/network\/60-paratix-[^\/]+\.network\.d\/50-paratix-route-[^']+\.conf'$/v,
      result: { code: 0 },
    },
    {
      command: /^rm -f -- '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network'$/v,
      result: { code: 0 },
    },
    { command: "networkctl reload", result: { code: 0 } },
    {
      command: /^mkdir -p '\/etc\/systemd\/network\/60-paratix-[^\/]+\.network\.d'$/v,
      result: { code: 0 },
    },
    { command: "mkdir -p /var/lib/paratix/flags", result: { code: 0 } },
    {
      command:
        /^find \/var\/lib\/paratix\/flags -maxdepth 1 -type f -name 'net-route-[^']+-\*' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\/'net-route-[^']+'$/v,
      result: { code: 0 },
    },
    { command: /^ip -4 route show '[^']+'$/v, result: { code: 0, stdout: "" } },
    { command: /^ip -6 route show '[^']+'$/v, result: { code: 0, stdout: "" } },
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
      command: /^rm -f -- '\/etc\/netplan\/60-paratix-[^']+\.yaml'$/v,
      result: { code: 0 },
    },
    {
      command: /^rm -f -- '\/etc\/systemd\/network\/60-paratix-[^']+\.network'$/v,
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
  const dropin = `[Route]\nDestination=${input.destination}\nGateway=${input.gateway}\n`
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
  const routeShowCommand = "ip -4 route show '10.0.0.0/24'"
  const liveRouteOutput = "10.0.0.0/24 via 192.168.1.1 dev eth0"

  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed after adding a route (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs ip -4 route replace (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' via '192.168.1.1' dev 'eth0'"
    )
  })

  it("runs ip -4 route replace with dev when device is given (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' via '192.168.1.1' dev 'eth0'"
    )
  })

  it("runs ip -6 route replace for IPv6 routes", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("fd00::/64", "fe80::1", { device: "eth0" })

    await mod.apply(mockSsh, emptyEnv)

    expect(mockSsh.calls).toContain("ip -6 route replace 'fd00::/64' via 'fe80::1' dev 'eth0'")
    expect(mockSsh.calls).not.toContain("ip -4 route replace 'fd00::/64' via 'fe80::1' dev 'eth0'")
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
      content: "[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n",
      options: { mode: "0644" },
      path: routeDropinPath,
    })
  })

  it("uses distinct drop-in paths for the same destination with different gateways", async () => {
    const firstPath = buildRouteDropinPath({
      destination: "10.0.0.0/24",
      device: "eth0",
      gateway: "192.168.1.1",
    })
    const secondPath = buildRouteDropinPath({
      destination: "10.0.0.0/24",
      device: "eth0",
      gateway: "192.168.1.254",
    })
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)

    await net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" }).apply(mockSsh, emptyEnv)
    await net.route("10.0.0.0/24", "192.168.1.254", { device: "eth0" }).apply(mockSsh, emptyEnv)

    expect(firstPath).not.toBe(secondPath)
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toContain(firstPath)
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toContain(secondPath)
  })

  it("uses distinct drop-in paths for the same destination and gateway with different devices", async () => {
    const firstPath = buildRouteDropinPath({
      destination: "10.0.0.0/24",
      device: "eth0",
      gateway: "192.168.1.1",
    })
    const secondPath = buildRouteDropinPath({
      destination: "10.0.0.0/24",
      device: "eth1",
      gateway: "192.168.1.1",
    })
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)

    await net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" }).apply(mockSsh, emptyEnv)
    await net.route("10.0.0.0/24", "192.168.1.1", { device: "eth1" }).apply(mockSsh, emptyEnv)

    expect(firstPath).not.toBe(secondPath)
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toContain(firstPath)
    expect(mockSsh.writeFileCalls.map((call) => call.remotePath)).toContain(secondPath)
  })

  it("fails closed when no persistent target device is given", () => {
    // R-0000486: `net.route` now surfaces the missing-device error at
    // construction time instead of letting `check()` report `needs-apply`
    // and `apply()` then fail. The fixture must therefore assert that the
    // factory throws synchronously and never reaches a mock SSH connection.
    expect(() => net.route("10.0.0.0/24", "192.168.1.1")).toThrow(/options\.device/v)
  })

  it("fails closed when state is absent and no persistent target device is given", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })).toThrow(
      /options\.device/v
    )
  })

  it("returns failed without reload when the persistent route drop-in cannot be written", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    vi.spyOn(mockSsh, "writeFile").mockRejectedValue(new Error("disk full"))
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("persistent drop-in write failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(String(result.error)).toContain("disk full")
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' via '192.168.1.1' dev 'eth0'"
    )
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
    expect(mockSsh.calls).not.toContain("networkctl reload")
    expect(mockSsh.calls.some((call) => call.includes("/var/lib/paratix/flags"))).toBe(false)
  })

  it("restores the previous drop-in when a route write fails after replacing the live route", async () => {
    const previousDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh(
      {
        [`[ -f '${routeDropinPath}' ] && [ ! -L '${routeDropinPath}' ]`]: { code: 0 },
        [`cat '${routeDropinPath}'`]: { stdout: previousDropin },
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const originalWriteFile = mockSsh.writeFile.bind(mockSsh)
    vi.spyOn(mockSsh, "writeFile")
      .mockRejectedValueOnce(new Error("disk full"))
      .mockImplementation(originalWriteFile)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.writeFileCalls).toContainEqual({
      content: previousDropin,
      options: { mode: "0644" },
      remotePath: routeDropinPath,
    })
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("rolls back the exact previous live route when multiple routes share a destination", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.1' 'dev' 'eth0'": { code: 0 },
        [routeShowCommand]: {
          code: 0,
          stdout: [
            "10.0.0.0/24 via 192.168.1.254 dev eth1",
            "10.0.0.0/24 via 192.168.1.1 dev eth0",
          ].join("\n"),
        },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    vi.spyOn(mockSsh, "writeFile").mockRejectedValue(new Error("disk full"))
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.1' 'dev' 'eth0'"
    )
    expect(mockSsh.calls).not.toContain(
      "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.254' 'dev' 'eth1'"
    )
  })

  it("snapshots the replaced IPv4 route by destination and device when gateway changes", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.254' 'dev' 'eth0'": { code: 0 },
        [routeShowCommand]: {
          code: 0,
          stdout: "10.0.0.0/24 via 192.168.1.254 dev eth0",
        },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    vi.spyOn(mockSsh, "writeFile").mockRejectedValue(new Error("disk full"))
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.254' 'dev' 'eth0'"
    )
    expect(mockSsh.calls).not.toContain(
      "ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'"
    )
  })

  it("snapshots the replaced IPv6 route by destination and device when gateway changes", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -6 route replace 'fd00::/64' 'via' 'fe80::2' 'dev' 'eth0'": { code: 0 },
        "ip -6 route show 'fd00::/64'": {
          code: 0,
          stdout: "fd00::/64 via fe80::2 dev eth0",
        },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    vi.spyOn(mockSsh, "writeFile").mockRejectedValue(new Error("disk full"))
    const mod = net.route("fd00::/64", "fe80::1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.calls).toContain("ip -6 route replace 'fd00::/64' 'via' 'fe80::2' 'dev' 'eth0'")
    expect(mockSsh.calls).not.toContain("ip -6 route del 'fd00::/64' via 'fe80::1' dev 'eth0'")
  })

  it("rolls back the full route state without reload when the drop-in becomes a symlink after replace", async () => {
    const mockSsh = createMockSsh(
      {
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const originalTest = mockSsh.test.bind(mockSsh)
    vi.spyOn(mockSsh, "test")
      .mockImplementationOnce(originalTest)
      .mockImplementationOnce(originalTest)
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true)
      .mockImplementation(originalTest)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("symlink")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
    expect(mockSsh.calls).toContain(`rm -f -- '${routeDropinPath}'`)
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("refuses a symlinked persistent route drop-in without reload or flag writes", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        ...SUCCESSFUL_ROUTE_APPLY_OPTIONS,
        responseStubs: [
          {
            command: `[ -L '${routeDropinPath}' ]`,
            result: { code: 0 },
          },
          ...SUCCESSFUL_ROUTE_APPLY_OPTIONS.responseStubs,
        ],
      }
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("symlink")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
    expect(mockSsh.calls).not.toContain("networkctl reload")
    expect(mockSsh.calls.some((call) => call.includes("/var/lib/paratix/flags"))).toBe(false)
  })

  it("reloads networkctl after adding route (state: present)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("returns failed when ip -4 route replace fails (state: present)", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -4 route replace '10.0.0.0/24' via '192.168.1.1'": {
          code: 2,
          stderr: "Nexthop has invalid gateway",
        },
        "ip -4 route replace '10.0.0.0/24' via '192.168.1.1' dev 'eth0'": {
          code: 2,
          stderr: "Nexthop has invalid gateway",
        },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("ip -4 route replace failed")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("returns failed when networkctl reload fails after adding route", async () => {
    const reloadFlagCheck = buildRouteReloadFlagCheck({
      destination: "10.0.0.0/24",
      device: "eth0",
      gateway: "192.168.1.1",
    }).replace("[ -f ", "touch ")
    const reloadFlagPath = reloadFlagCheck.slice(0, -2)
    const mockSsh = createMockSsh(
      {
        "networkctl reload": { code: 1, stderr: "reload failed" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
    expect(mockSsh.calls.some((call) => call.includes(reloadFlagPath))).toBe(false)
  })

  it("rolls back live route and drop-in when networkctl reload fails after adding route", async () => {
    const mockSsh = createMockSsh(
      {
        "networkctl reload": { code: 1, stderr: "reload failed" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
    expect(mockSsh.calls).toContain(`rm -f -- '${routeDropinPath}'`)
    expect(mockSsh.calls.some((call) => call.includes("/var/lib/paratix/flags"))).toBe(false)
  })

  it("rolls back route state and reloads again when the reload flag cannot be written", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        ...SUCCESSFUL_ROUTE_APPLY_OPTIONS,
        responseStubs: [
          {
            command:
              /^find \/var\/lib\/paratix\/flags -maxdepth 1 -type f -name 'net-route-[^']+-\*' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\/'net-route-[^']+'$/v,
            result: { code: 1, stderr: "read-only filesystem" },
          },
          ...SUCCESSFUL_ROUTE_APPLY_OPTIONS.responseStubs,
        ],
      }
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(String(result.error)).toContain("read-only filesystem")
    expect(mockSsh.calls.filter((call) => call === "networkctl reload")).toHaveLength(2)
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
    expect(mockSsh.calls).toContain(`rm -f -- '${routeDropinPath}'`)
  })

  it("surfaces rollback failure when reload failure rollback cannot restore live route", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'": {
          code: 2,
          stderr: "rollback failed",
        },
        "networkctl reload": { code: 1, stderr: "reload failed" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
    expect(String(result.error)).toContain("rollback failed")
    expect(String(result.error)).toContain("live route rollback failed")
  })

  it("returns changed after removing a route (state: absent)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs ip -4 route del with the checked gateway (state: absent)", async () => {
    const mockSsh = createMockSsh(
      {
        [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
  })

  it("runs ip -4 route del with the checked gateway and device (state: absent)", async () => {
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
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
  })

  it("runs ip -6 route del for IPv6 routes", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -6 route show 'fd00::/64'": { code: 0, stdout: "fd00::/64 via fe80::1 dev eth0" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("fd00::/64", "fe80::1", {
      device: "eth0",
      state: "absent",
    })

    await mod.apply(mockSsh, emptyEnv)

    expect(mockSsh.calls).toContain("ip -6 route del 'fd00::/64' via 'fe80::1' dev 'eth0'")
    expect(mockSsh.calls).not.toContain("ip -4 route del 'fd00::/64' via 'fe80::1' dev 'eth0'")
  })

  it("returns failed when ip -4 route del fails (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "ip -4 route del '10.0.0.0/24' via '192.168.1.1'": {
        code: 2,
        stderr: "No such process",
      },
      "ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'": {
        code: 2,
        stderr: "No such process",
      },
      [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("ip -4 route del failed")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("removes drop-in when state is absent and the live route is already gone", async () => {
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh(
      {
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.some((call) => call.startsWith("ip -4 route del "))).toBe(false)
    expect(mockSsh.calls).toContain(`rm -f -- '${dropinPath}'`)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("removes drop-in file when state is absent", async () => {
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain(`rm -f -- '${dropinPath}'`)
  })

  it("leaves a foreign drop-in with the same destination in place", async () => {
    const dropinPath = legacyRouteDropinPath
    const foreignDropin = `[Match]\nName=eth1\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh(
      {
        [`cat '${dropinPath}'`]: { stdout: foreignDropin },
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain(`rm -f -- '${dropinPath}'`)
  })

  it("returns failed when drop-in removal fails (state: absent)", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`rm -f -- '${dropinPath}'`]: { code: 1, stderr: "permission denied" },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [routeShowCommand]: { code: 0, stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("drop-in removal failed")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("rolls the live route back when drop-in removal fails after deleting the route", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh(
      {
        [`cat '${dropinPath}'`]: { stdout: expectedDropin },
        [`rm -f -- '${dropinPath}'`]: { code: 1, stderr: "permission denied" },
        [`test -f '${dropinPath}'`]: { code: 0 },
        "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.1' 'dev' 'eth0'": { code: 0 },
        [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("drop-in removal failed")
    expect(String(result.error)).toContain("live route was rolled back")
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.1' 'dev' 'eth0'"
    )
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("reloads networkctl after removing route (state: absent)", async () => {
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
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
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
  })

  it("rolls back live route and drop-in when networkctl reload fails after removing route", async () => {
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh(
      {
        [`cat '${routeDropinPath}'`]: { stdout: expectedDropin },
        "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.1' 'dev' 'eth0'": { code: 0 },
        "networkctl reload": { code: 1, stderr: "reload failed" },
        [routeShowCommand]: { code: 0, stdout: liveRouteOutput },
      },
      {
        ...SUCCESSFUL_ROUTE_APPLY_OPTIONS,
        responseStubs: [
          {
            command:
              /^\[ -f '\/etc\/systemd\/network\/60-paratix-eth0\.network\.d\/50-paratix-route-10\.0\.0\.0-24-faf00cb4d15f7f16\.conf' \] && \[ ! -L '\/etc\/systemd\/network\/60-paratix-eth0\.network\.d\/50-paratix-route-10\.0\.0\.0-24-faf00cb4d15f7f16\.conf' \]$/v,
            result: { code: 0 },
          },
          ...SUCCESSFUL_ROUTE_APPLY_OPTIONS.responseStubs,
        ],
      }
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.calls).toContain("ip -4 route del '10.0.0.0/24' via '192.168.1.1' dev 'eth0'")
    expect(mockSsh.calls).toContain(
      "ip -4 route replace '10.0.0.0/24' 'via' '192.168.1.1' 'dev' 'eth0'"
    )
    expect(mockSsh.writeFileCalls).toContainEqual({
      content: expectedDropin,
      options: { mode: "0644" },
      remotePath: routeDropinPath,
    })
  })

  it("uses ip -6 route when rolling back an IPv6 route", async () => {
    const mockSsh = createMockSsh(
      {
        "ip -6 route replace 'fd00::/64' 'via' 'fe80::1' 'dev' 'eth0'": { code: 0 },
        "ip -6 route show 'fd00::/64'": { code: 0, stdout: "fd00::/64 via fe80::1 dev eth0" },
        "networkctl reload": { code: 1, stderr: "reload failed" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("fd00::/64", "fe80::1", { device: "eth0", state: "absent" })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("route state was rolled back")
    expect(mockSsh.calls).toContain("ip -6 route del 'fd00::/64' via 'fe80::1' dev 'eth0'")
    expect(mockSsh.calls).toContain("ip -6 route replace 'fd00::/64' 'via' 'fe80::1' 'dev' 'eth0'")
    expect(mockSsh.calls).not.toContain("ip -4 route del 'fd00::/64' via 'fe80::1' dev 'eth0'")
  })

  it("returns ok and skips networkctl reload when nothing to remove (state: absent)", async () => {
    // R-0000219: when applyAbsentRoute is a no-op (live route absent and no
    // matching drop-in), the module must report `ok` and must not invoke
    // networkctl reload. Otherwise direct-apply (signal) paths fire spurious
    // change signals.
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh(
      {
        // No live route and no drop-in present.
        [`test -f '${dropinPath}'`]: { code: 1 },
        [routeShowCommand]: { code: 0, stdout: "" },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
    expect(mockSsh.calls).not.toContain("networkctl reload")
    expect(mockSsh.calls.some((call) => call.startsWith("ip -4 route del "))).toBe(false)
    expect(mockSsh.calls).not.toContain(`rm -f -- '${dropinPath}'`)
  })

  it("sanitizes destination with colons for drop-in filename", async () => {
    // IPv6 destination: colons replaced with dashes
    const dropinPath = buildRouteDropinPath({
      destination: "fd00::/64",
      device: "eth0",
      gateway: "fe80::1",
    })
    const expectedDropin = `[Route]\nDestination=fd00::/64\nGateway=fe80::1\n`
    const mockSsh = createMockSsh(
      {
        [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      },
      SUCCESSFUL_ROUTE_APPLY_OPTIONS
    )
    const mod = net.route("fd00::/64", "fe80::1", { device: "eth0", state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    // drop-in path uses sanitized destination
    expect(mockSsh.calls).toContain(`rm -f -- '${dropinPath}'`)
  })
})

// ─── net.interface ────────────────────────────────────────────────────────────

// R-0000100: net.interface must reject names that contain path-traversal
// payloads or empty strings, because the name is interpolated into the
// Netplan/networkd file paths and would otherwise allow writing to arbitrary
// locations under /etc.
