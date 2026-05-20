import { afterEach, describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { sha256String } from "../../../src/modules/fileHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../../helpers/mockSsh.js"

const mockSshInstances: Array<ReturnType<typeof createBaseMockSsh>> = []

const createMockSsh: typeof createBaseMockSsh = (responses, options) => {
  const mockSsh = createBaseMockSsh(responses, {
    ...options,
    responseStubs: [
      {
        command: /^\[ -L '\/etc\/systemd\/network\/.+(?:\.conf|\.network)' \]$/v,
        result: { code: 1 },
      },
      ...(options?.responseStubs ?? []),
    ],
  })
  mockSshInstances.push(mockSsh)
  return mockSsh
}

function assertNoWriteFileCalls() {
  for (const mockSsh of mockSshInstances) {
    if (mockSsh.writeFileCalls.length > 0) {
      throw new Error(`Expected net.route check to perform no writes`)
    }
  }
  mockSshInstances.length = 0
}

const emptyEnv = {}

function regularFileCheck(remotePath: string): string {
  return `[ -f '${remotePath}' ] && [ ! -L '${remotePath}' ]`
}

function symlinkCheck(remotePath: string): string {
  return `[ -L '${remotePath}' ]`
}

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

describe("net.route — check", () => {
  afterEach(assertNoWriteFileCalls)

  it("returns needs-apply when conn is null", async () => {
    // R-0000486: `net.route` now requires `options.device` at construction
    // time when `state` defaults to "present", so this conn-null fixture
    // must provide a device even though the check short-circuits before
    // touching it.
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("throws when state is absent and no persistent target device is given", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })).toThrow(
      /options\.device/v
    )
  })

  it("returns ok when route is present (state: present)", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route is absent (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(routeDropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when route is absent (state: absent) and drop-in is gone", async () => {
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(dropinPath)]: { code: 1 },
      [regularFileCheck(legacyRouteDropinPath)]: { code: 1 },
      [symlinkCheck(dropinPath)]: { code: 1 },
      [symlinkCheck(legacyRouteDropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when the managed drop-in is a symlink (state: absent)", async () => {
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(dropinPath)]: { code: 1 },
      [symlinkCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the legacy drop-in is a symlink (state: absent)", async () => {
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(dropinPath)]: { code: 1 },
      [symlinkCheck(dropinPath)]: { code: 1 },
      [symlinkCheck(legacyRouteDropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when a foreign current drop-in symlink exists (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(routeDropinPath)]: { code: 1 },
      [symlinkCheck(routeDropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when route is present (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(routeDropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when route via different gateway (state: present)", async () => {
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.254 dev eth0" },
      [regularFileCheck(routeDropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("checks route via ip -4 route show command", async () => {
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1" },
      [regularFileCheck(routeDropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip -4 route show '10.0.0.0/24'")
  })

  it("checks IPv6 routes via ip -6 route show", async () => {
    const dropinPath = buildRouteDropinPath({
      destination: "fd00::/64",
      device: "eth0",
      gateway: "fe80::1",
    })
    const expectedDropin = `[Route]\nDestination=fd00::/64\nGateway=fe80::1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "fd00::/64",
        device: "eth0",
        gateway: "fe80::1",
      })]: { code: 0 },
      "ip -6 route show 'fd00::/64'": { stdout: "fd00::/64 via fe80::1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("fd00::/64", "fe80::1", { device: "eth0" })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain("ip -6 route show 'fd00::/64'")
    expect(mockSsh.calls).not.toContain("ip -4 route show 'fd00::/64'")
  })

  it("checks IPv6 default routes via the gateway family", async () => {
    const dropinPath = buildRouteDropinPath({
      destination: "default",
      device: "eth0",
      gateway: "fe80::1",
    })
    const expectedDropin = `[Route]\nDestination=default\nGateway=fe80::1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "default",
        device: "eth0",
        gateway: "fe80::1",
      })]: { code: 0 },
      "ip -6 route show 'default'": { stdout: "default via fe80::1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("default", "fe80::1", { device: "eth0" })

    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain("ip -6 route show 'default'")
    expect(mockSsh.calls).not.toContain("ip -4 route show 'default'")
  })

  // R-0000061: persistent drop-in must be validated alongside live route.
  it("returns needs-apply when live route matches but drop-in is missing (state: present)", async () => {
    const dropinPath = routeDropinPath
    const mockSsh = createMockSsh({
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when drop-in is a symlink even if target content matches", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when drop-in has a stale gateway (state: present)", async () => {
    const dropinPath = routeDropinPath
    const staleDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: staleDropin },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route uses the wrong device (state: present)", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth1" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route gateway only has a prefix match", async () => {
    const dropinPath = buildRouteDropinPath({
      destination: "10.0.0.0/24",
      device: "eth0",
      gateway: "10.0.0.1",
    })
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=10.0.0.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "10.0.0.1",
      })]: { code: 0 },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 10.0.0.10 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "10.0.0.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route device only has a prefix match", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip -4 route show '10.0.0.0/24'": {
        stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0.10",
      },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route is gone but drop-in still exists (state: absent)", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when live route is gone and a foreign drop-in with the same destination exists", async () => {
    const dropinPath = legacyRouteDropinPath
    const foreignDropin = `[Match]\nName=eth1\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: foreignDropin },
      "ip -4 route show '10.0.0.0/24'": { stdout: "" },
      [regularFileCheck(dropinPath)]: { code: 0 },
      [regularFileCheck(routeDropinPath)]: { code: 1 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0", state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when both live route and drop-in match (state: present)", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route and drop-in match but reload marker is missing", async () => {
    const dropinPath = routeDropinPath
    const expectedDropin = `[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 1 },
      "ip -4 route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
      [regularFileCheck(dropinPath)]: { code: 0 },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})
