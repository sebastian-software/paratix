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
    remotePath: /^\/etc\/systemd\/network\/50-paratix-route-.+\.network$/v,
  },
  { options: { mode: "0644" }, remotePath: /^\/etc\/systemd\/network\/60-paratix-.+\.network$/v },
] as const

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowWrites: [...NET_WRITE_ALLOWLIST, ...(options?.allowWrites ?? [])],
    // R-0000277: net.interface apply probes the destination path with
    // `[ -L … ]` (isSymlink) before writing. Default to "not a symlink" so
    // existing fixtures keep passing; the symlink-refusal regression stubs
    // `{ code: 0 }` explicitly.
    responseStubs: [
      ...(options?.responseStubs ?? []),
      {
        command: /^\[ -L '\/etc\/netplan\/60-paratix-[^']+\.yaml' \]$/v,
        result: { code: 1 },
      },
      {
        command: /^\[ -L '\/etc\/systemd\/network\/60-paratix-[^']+\.network' \]$/v,
        result: { code: 1 },
      },
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
      command: /^rm -f -- '\/etc\/systemd\/network\/50-paratix-route-[^']+\.network'$/v,
      result: { code: 0 },
    },
    { command: "networkctl reload", result: { code: 0 } },
    { command: "mkdir -p /var/lib/paratix/flags", result: { code: 0 } },
    {
      command:
        /^find \/var\/lib\/paratix\/flags -maxdepth 1 -type f -name 'net-route-[^']+-\*' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\/'net-route-[^']+'$/v,
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

describe("net.interface — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.interface("eth0", {})
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("R-0000277: refuses to write through a symlinked netplan path", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      {
        responseStubs: [
          {
            command: /^\[ -L '\/etc\/netplan\/60-paratix-[^']+\.yaml' \]$/v,
            result: { code: 0 },
          },
        ],
      }
    )
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("symlink")
  })

  it("refuses to write through a symlinked networkd path", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 1 },
      },
      {
        responseStubs: [
          {
            command: /^\[ -L '\/etc\/systemd\/network\/60-paratix-[^']+\.network' \]$/v,
            result: { code: 0 },
          },
        ],
      }
    )
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("symlink")
    expect(mockSsh.writeFileCalls).toStrictEqual([])
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("returns changed in Netplan mode", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs netplan apply in Netplan mode", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("netplan apply")
  })

  it("returns failed when netplan apply fails", async () => {
    const mockSsh = createMockSsh(
      {
        "netplan apply": { code: 1, stderr: "bad netplan" },
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("netplan apply failed")
  })

  it("returns failed when writing the initial Netplan config fails", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const mockSsh = createMockSsh({
      [`test -f '${netplanPath}'`]: { code: 1 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const writeError = new Error("disk full")
    vi.spyOn(mockSsh, "writeFile").mockRejectedValue(writeError)
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(`write failed for ${netplanPath}`)
    expect(String(result.error)).toContain("netplan apply was not run")
    expect(String(result.error)).toContain("disk full")
    expect(mockSsh.calls).not.toContain("netplan apply")
  })

  it("restores the previous Netplan config when netplan apply fails", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const previousConfig = "network:\n  version: 2\n"
    const mockSsh = createMockSsh({
      [`cat '${netplanPath}'`]: { stdout: previousConfig },
      [`test -f '${netplanPath}'`]: { code: 0 },
      "netplan apply": { code: 1, stderr: "bad netplan" },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const writeFile = vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writeFile).toHaveBeenLastCalledWith(netplanPath, previousConfig, {
      mode: "0644",
    })
  })

  it("returns failed when restoring the previous Netplan config cannot be written", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const previousConfig = "network:\n  version: 2\n"
    const mockSsh = createMockSsh({
      [`cat '${netplanPath}'`]: { stdout: previousConfig },
      [`test -f '${netplanPath}'`]: { code: 0 },
      "netplan apply": { code: 1, stderr: "bad netplan" },
      "test -d '/etc/netplan'": { code: 0 },
    })
    const writeError = new Error("read-only filesystem")
    vi.spyOn(mockSsh, "writeFile").mockResolvedValueOnce().mockRejectedValueOnce(writeError)
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("rollback restore failed")
    expect(String(result.error)).toContain("network configuration was not restored")
    expect(String(result.error)).toContain("read-only filesystem")
  })

  it("re-runs netplan apply after restoring the previous config (live state recovery)", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const previousConfig = "network:\n  version: 2\n"
    const mockSsh = createMockSsh({
      [`cat '${netplanPath}'`]: { stdout: previousConfig },
      [`test -f '${netplanPath}'`]: { code: 0 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const exec = vi
      .spyOn(mockSsh, "exec")
      .mockResolvedValueOnce({ code: 1, stderr: "bad netplan", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("netplan apply failed")
    expect(String(result.error)).not.toContain("diverges")
    const netplanApplyCalls = exec.mock.calls.filter(([cmd]) => cmd === "netplan apply")
    expect(netplanApplyCalls).toHaveLength(2)
  })

  it("reports live divergence when re-applying the previous Netplan config also fails", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const previousConfig = "network:\n  version: 2\n"
    const mockSsh = createMockSsh({
      [`cat '${netplanPath}'`]: { stdout: previousConfig },
      [`test -f '${netplanPath}'`]: { code: 0 },
      "test -d '/etc/netplan'": { code: 0 },
    })
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "exec")
      .mockResolvedValueOnce({ code: 1, stderr: "bad netplan", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "still broken", stdout: "" })
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("diverges")
  })

  it("removes a newly-created Netplan config when netplan apply fails", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const mockSsh = createMockSsh(
      {
        [`test -f '${netplanPath}'`]: { code: 1 },
        "netplan apply": { code: 1, stderr: "bad netplan" },
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(mockSsh.calls).toContain(`rm -f -- '${netplanPath}'`)
  })

  it("returns failed when removing a newly-created Netplan config fails during rollback", async () => {
    const netplanPath = "/etc/netplan/60-paratix-eth0.yaml"
    const mockSsh = createMockSsh(
      {
        [`rm -f -- '${netplanPath}'`]: { code: 1, stderr: "permission denied" },
        [`test -f '${netplanPath}'`]: { code: 1 },
        "netplan apply": { code: 1, stderr: "bad netplan" },
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", { dhcp: true })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("rollback removal failed")
    expect(String(result.error)).toContain(netplanPath)
    expect(String(result.error)).toContain("permission denied")
  })

  it("returns changed in networkd mode", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 1 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("runs networkctl reload in networkd mode", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 1 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("networkctl reload")
  })

  it("returns failed when networkctl reload fails", async () => {
    const mockSsh = createMockSsh(
      {
        "networkctl reload": { code: 1, stderr: "reload failed" },
        "test -d '/etc/netplan'": { code: 1 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
  })

  it("returns failed when writing the initial networkd config fails", async () => {
    const networkdPath = "/etc/systemd/network/60-paratix-eth0.network"
    const mockSsh = createMockSsh({
      [`test -f '${networkdPath}'`]: { code: 1 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const writeError = new Error("read-only filesystem")
    vi.spyOn(mockSsh, "writeFile").mockRejectedValue(writeError)
    const mod = net.interface("eth0", { dhcp: false })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(`write failed for ${networkdPath}`)
    expect(String(result.error)).toContain("networkctl reload was not run")
    expect(String(result.error)).toContain("read-only filesystem")
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("restores the previous networkd config when networkctl reload fails", async () => {
    const networkdPath = "/etc/systemd/network/60-paratix-eth0.network"
    const previousConfig = "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
    const mockSsh = createMockSsh({
      [`cat '${networkdPath}'`]: { stdout: previousConfig },
      [`test -f '${networkdPath}'`]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const writeFile = vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const exec = vi
      .spyOn(mockSsh, "exec")
      .mockResolvedValueOnce({ code: 1, stderr: "reload failed", stdout: "" })
      .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
    const mod = net.interface("eth0", { dhcp: false })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
    expect(String(result.error)).not.toContain("diverges")
    expect(writeFile).toHaveBeenLastCalledWith(networkdPath, previousConfig, {
      mode: "0644",
    })
    const reloadCalls = exec.mock.calls.filter(([cmd]) => cmd === "networkctl reload")
    expect(reloadCalls).toHaveLength(2)
  })

  it("reports live divergence when re-applying the previous networkd config also fails", async () => {
    const networkdPath = "/etc/systemd/network/60-paratix-eth0.network"
    const previousConfig = "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
    const mockSsh = createMockSsh({
      [`cat '${networkdPath}'`]: { stdout: previousConfig },
      [`test -f '${networkdPath}'`]: { code: 0 },
      "test -d '/etc/netplan'": { code: 1 },
    })
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const exec = vi
      .spyOn(mockSsh, "exec")
      .mockResolvedValueOnce({ code: 1, stderr: "reload failed", stdout: "" })
      .mockResolvedValueOnce({ code: 1, stderr: "still broken", stdout: "" })
    const mod = net.interface("eth0", { dhcp: false })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("networkctl reload failed")
    expect(String(result.error)).toContain("rollback restored the configuration file")
    expect(String(result.error)).toContain("re-applying the previous configuration also failed")
    expect(String(result.error)).toContain("diverges")
    expect(String(result.error)).toContain("still broken")
    const reloadCalls = exec.mock.calls.filter(([cmd]) => cmd === "networkctl reload")
    expect(reloadCalls).toHaveLength(2)
  })

  it("does not run netplan apply in networkd mode", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 1 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("netplan apply")
  })

  it("does not run networkctl reload in Netplan mode", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("networkctl reload")
  })

  it("writes Netplan config when dhcp is enabled", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", { dhcp: true })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("writes networkd config when addresses are given (networkd mode)", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 1 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {
      addresses: ["192.168.1.10/24"],
      gateway: "192.168.1.1",
      nameservers: ["1.1.1.1"],
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("writes Netplan config with addresses, gateway and nameservers (Netplan mode)", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {
      addresses: ["192.168.1.10/24"],
      gateway: "192.168.1.1",
      nameservers: ["1.1.1.1", "8.8.8.8"],
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain("netplan apply")
  })

  it("detects Netplan via test -d command during apply", async () => {
    const mockSsh = createMockSsh(
      {
        "test -d '/etc/netplan'": { code: 0 },
      },
      APPLY_TO_NEW_FILE_OPTIONS
    )
    const mod = net.interface("eth0", {})
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("test -d '/etc/netplan'")
  })
})

// ─── net.waitFor ──────────────────────────────────────────────────────────────
