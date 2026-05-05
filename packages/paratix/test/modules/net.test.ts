import { afterEach, describe, expect, it, vi } from "vitest"

import { net } from "../../src/index.js"
import { sha256String } from "../../src/modules/fileHelpers.js"
import { setRunnerAbortSignal } from "../../src/runnerAbortSignal.js"
import {
  clearRegisteredSecrets,
  getRegisteredSecrets,
  registerSecret,
} from "../../src/secretSink.js"
import { shellQuote } from "../../src/ssh.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

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

describe("net.hosts — validation", () => {
  it("accepts valid IPv4 hosts entries", () => {
    expect(() => net.hosts("1.2.3.4", ["myhost", "myhost.local"])).not.toThrow()
  })

  it("accepts valid IPv6 hosts entries", () => {
    expect(() => net.hosts("2001:db8::1", ["myhost", "myhost.local"])).not.toThrow()
  })

  it("rejects an empty hostname list", () => {
    expect(() => net.hosts("1.2.3.4", [])).toThrow(
      "[net.hosts] invalid hostnames: at least one hostname is required"
    )
  })

  it("rejects empty tokens", () => {
    expect(() => net.hosts("", ["myhost"])).toThrow("[net.hosts] invalid IP address")
    expect(() => net.hosts("1.2.3.4", [""])).toThrow("[net.hosts] invalid hostname")
  })

  it("rejects LF injection in hosts tokens", () => {
    expect(() => net.hosts("1.2.3.4\n5.6.7.8", ["myhost"])).toThrow(
      "[net.hosts] invalid IP address"
    )
    expect(() => net.hosts("1.2.3.4", ["myhost\n5.6.7.8 injected"])).toThrow(
      "[net.hosts] invalid hostname"
    )
  })

  it("rejects CR injection in hosts tokens", () => {
    expect(() => net.hosts("1.2.3.4\r5.6.7.8", ["myhost"])).toThrow(
      "[net.hosts] invalid IP address"
    )
    expect(() => net.hosts("1.2.3.4", ["myhost\r5.6.7.8 injected"])).toThrow(
      "[net.hosts] invalid hostname"
    )
  })

  it("rejects whitespace in hosts tokens", () => {
    expect(() => net.hosts("1.2.3.4 5.6.7.8", ["myhost"])).toThrow("[net.hosts] invalid IP address")
    expect(() => net.hosts("1.2.3.4", ["myhost injected"])).toThrow("[net.hosts] invalid hostname")
  })
})

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

  it("reads /etc/hosts via cat command", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })
})

describe("net.hosts — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when entry is appended (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns ok when entry already exists (no duplicate added)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when entry is removed (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  // R-0000086: when the hosts entry is already missing, apply must short-circuit
  // to `ok` without rewriting /etc/hosts, mirroring the `present` + alreadyPresent
  // branch and aligning apply with check (which returns `ok` in this case).
  it("returns ok without writing when entry is already absent (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(writes).toHaveLength(0)
  })

  it("reads /etc/hosts before writing (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"])
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })

  it("only removes the exact matching line (state: absent), not other entries for same IP", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "10.0.0.1 web1\n10.0.0.1 db1\n" },
    })
    const mod = net.hosts("10.0.0.1", ["web1"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("reads /etc/hosts before writing (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "1.2.3.4 myhost\n" },
    })
    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("cat '/etc/hosts'")
  })

  // R-0000101: hosts entries are normalized by IP. When `state: "present"`
  // is applied for an IP that already has a different hostname set on disk,
  // the stale line must be replaced rather than left next to the new entry,
  // so resolution is unambiguous after apply.
  it("replaces a stale entry for the same IP instead of duplicating it (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n192.168.1.1 host1\n" },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("192.168.1.1", ["host2"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writes).toHaveLength(1)
    expect(writes[0]?.content).toBe("127.0.0.1 localhost\n192.168.1.1 host2\n")
    // The previous host1 entry must be gone, not coexist with host2.
    expect(writes[0]?.content).not.toContain("host1")
  })

  // R-0000101: matching for `state: "absent"` must be tolerant of whitespace
  // and hostname order so an entry written as `1.2.3.4 alpha beta` still
  // gets removed when the playbook lists `["beta", "alpha"]`.
  it("removes an entry whose hostnames match the desired set in any order (state: absent)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n10.0.0.1   alpha   beta\n" },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("10.0.0.1", ["beta", "alpha"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writes).toHaveLength(1)
    expect(writes[0]?.content).not.toContain("10.0.0.1")
  })

  // R-0000101: check must report drift when the on-disk hostname set differs
  // from the desired set, even if the IP already has a line.
  it("returns needs-apply from check when same IP has a different hostname set", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "192.168.1.1 host1\n" },
    })
    const mod = net.hosts("192.168.1.1", ["host2"])
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("writes /etc/hosts back with mode 0644 instead of the generic 0600 default", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writes).toHaveLength(1)
    expect(writes[0]).toStrictEqual({
      content: "127.0.0.1 localhost\n1.2.3.4 myhost\n",
      mode: "0644",
      path: "/etc/hosts",
    })
  })
})

// ─── net.resolv ───────────────────────────────────────────────────────────────

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

describe("net.resolv — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed after writing resolv.conf", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("does not unconditionally rm -f /etc/resolv.conf before writing", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })
    await mod.apply(mockSsh, emptyEnv)
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
  })

  it("returns changed with search domains", async () => {
    const mockSsh = createMockSsh()
    const mod = net.resolv({ nameservers: ["1.1.1.1", "8.8.8.8"], search: ["example.com"] })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("does not rm -f /etc/resolv.conf even with multiple nameservers and search domains", async () => {
    const mockSsh = createMockSsh()
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
    const mockSsh = createMockSsh()
    const original = mockSsh.writeFile
    mockSsh.writeFile = async (): Promise<void> => {
      await Promise.resolve()
      throw writeFileError
    }
    const mod = net.resolv({ nameservers: ["1.1.1.1"] })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(writeFileError)

    // No destructive action occurred against /etc/resolv.conf before the failed write.
    expect(mockSsh.calls).not.toContain("rm -f /etc/resolv.conf")
    expect(mockSsh.calls.some((call: string) => /\brm\b.*\/etc\/resolv\.conf/v.test(call))).toBe(
      false
    )

    mockSsh.writeFile = original
  })
})

// ─── net.route ────────────────────────────────────────────────────────────────

describe("net.route — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when route is present (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route is absent (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${routeDropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when route is absent (state: absent) and drop-in is gone", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`test -f '${dropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route is present (state: absent)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${routeDropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when route via different gateway (state: present)", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${routeDropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.254 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("checks route via ip route show command", async () => {
    const mockSsh = createMockSsh({
      [`test -f '${routeDropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1")
    await mod.check(mockSsh, emptyEnv)
    expect(mockSsh.calls).toContain("ip route show '10.0.0.0/24'")
  })

  // R-0000061: persistent drop-in must be validated alongside live route.
  it("returns needs-apply when live route matches but drop-in is missing (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`test -f '${dropinPath}'`]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when drop-in has a stale gateway (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const staleDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.254\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: staleDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route uses the wrong device (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth1" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route gateway only has a prefix match", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=10.0.0.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "10.0.0.1",
      })]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 10.0.0.10 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "10.0.0.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route device only has a prefix match", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip route show '10.0.0.0/24'": {
        stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0.10",
      },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when live route is gone but drop-in still exists (state: absent)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`test -f '${dropinPath}'`]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { state: "absent" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when both live route and drop-in match (state: present)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 0 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when route and drop-in match but reload marker is missing", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const expectedDropin = `[Match]\nName=eth0\n\n[Route]\nDestination=10.0.0.0/24\nGateway=192.168.1.1\n`
    const mockSsh = createMockSsh({
      [`cat '${dropinPath}'`]: { stdout: expectedDropin },
      [`test -f '${dropinPath}'`]: { code: 0 },
      [buildRouteReloadFlagCheck({
        destination: "10.0.0.0/24",
        device: "eth0",
        gateway: "192.168.1.1",
      })]: { code: 1 },
      "ip route show '10.0.0.0/24'": { stdout: "10.0.0.0/24 via 192.168.1.1 dev eth0" },
    })
    const mod = net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

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

  it("returns failed when drop-in removal fails (state: absent)", async () => {
    const dropinPath = "/etc/systemd/network/50-paratix-route-10.0.0.0-24.network"
    const mockSsh = createMockSsh({
      [`rm -f '${dropinPath}'`]: { code: 1, stderr: "permission denied" },
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

  it("sanitizes destination with colons for drop-in filename", async () => {
    // IPv6 destination: colons replaced with dashes
    const mockSsh = createMockSsh({}, SUCCESSFUL_ROUTE_APPLY_OPTIONS)
    const mod = net.route("fd00::/64", "fe80::1", { state: "absent" })
    await mod.apply(mockSsh, emptyEnv)
    // drop-in path uses sanitized destination
    const dropinPath = "/etc/systemd/network/50-paratix-route-fd00---64.network"
    expect(mockSsh.calls).toContain(`rm -f '${dropinPath}'`)
  })
})

// ─── net.interface ────────────────────────────────────────────────────────────

// R-0000100: net.interface must reject names that contain path-traversal
// payloads or empty strings, because the name is interpolated into the
// Netplan/networkd file paths and would otherwise allow writing to arbitrary
// locations under /etc.
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

describe("net writers — CR/LF validation", () => {
  it("rejects interface addresses containing line breaks", () => {
    expect(() =>
      net.interface("eth0", { addresses: ["192.168.1.10/24\n      dhcp4: true"] })
    ).toThrow(/interface address.*CR or LF/v)
  })

  it("rejects interface gateways containing line breaks", () => {
    expect(() => net.interface("eth0", { gateway: "192.168.1.1\nDNS=1.1.1.1" })).toThrow(
      /interface gateway.*CR or LF/v
    )
  })

  it("rejects resolv nameservers containing line breaks", () => {
    expect(() => net.resolv({ nameservers: ["1.1.1.1\nsearch injected.local"] })).toThrow(
      /resolv nameserver.*CR or LF/v
    )
  })

  it("rejects empty resolv nameservers", () => {
    expect(() => net.resolv({ nameservers: [] })).toThrow(/at least one nameserver/v)
  })

  it("rejects invalid resolv nameserver addresses", () => {
    expect(() => net.resolv({ nameservers: [""] })).toThrow(/valid IPv4 or IPv6 address/v)
    expect(() => net.resolv({ nameservers: ["999.999.999.999"] })).toThrow(
      /valid IPv4 or IPv6 address/v
    )
    expect(() => net.resolv({ nameservers: ["not-an-ip"] })).toThrow(/valid IPv4 or IPv6 address/v)
  })

  it("accepts IPv4 and IPv6 resolv nameservers", () => {
    expect(() => net.resolv({ nameservers: ["1.1.1.1", "2001:4860:4860::8888"] })).not.toThrow()
  })

  it("rejects resolv search domains containing line breaks", () => {
    expect(() =>
      net.resolv({
        nameservers: ["1.1.1.1"],
        search: ["example.com\nnameserver 9.9.9.9"],
      })
    ).toThrow(/resolv search domain.*CR or LF/v)
  })

  it("rejects invalid resolv search domains", () => {
    const invalidDomains = [
      "",
      "bad domain",
      "_srv.example",
      "-example.com",
      "example-.com",
      "a..b",
    ]
    for (const domain of invalidDomains) {
      expect(() => net.resolv({ nameservers: ["1.1.1.1"], search: [domain] })).toThrow(
        /invalid search domain/v
      )
    }
  })

  it("accepts single-label resolv search domains", () => {
    expect(() => net.resolv({ nameservers: ["1.1.1.1"], search: ["local"] })).not.toThrow()
  })

  it("rejects route destinations containing line breaks", () => {
    expect(() => net.route("10.0.0.0/24\nGateway=1.2.3.4", "192.168.1.1")).toThrow(
      /route destination.*CR or LF/v
    )
  })

  it("rejects route devices containing line breaks", () => {
    expect(() => net.route("10.0.0.0/24", "192.168.1.1", { device: "eth0\n[Route]" })).toThrow(
      /route device.*CR or LF/v
    )
  })
})

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

describe("net.interface — apply", () => {
  it("returns failed when conn is null", async () => {
    const conn = null
    const mod = net.interface("eth0", {})
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
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
    expect(mockSsh.calls).toContain(`rm -f '${netplanPath}'`)
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

  it("restores the previous networkd config when networkctl reload fails", async () => {
    const networkdPath = "/etc/systemd/network/60-paratix-eth0.network"
    const previousConfig = "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n"
    const mockSsh = createMockSsh({
      [`cat '${networkdPath}'`]: { stdout: previousConfig },
      [`test -f '${networkdPath}'`]: { code: 0 },
      "networkctl reload": { code: 1, stderr: "reload failed" },
      "test -d '/etc/netplan'": { code: 1 },
    })
    const writeFile = vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const mod = net.interface("eth0", { dhcp: false })

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writeFile).toHaveBeenLastCalledWith(networkdPath, previousConfig, {
      mode: "0644",
    })
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

/* eslint-disable testing-library/await-async-utils -- net.waitFor is not testing-library waitFor */

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

describe("net.waitFor — apply", () => {
  it("rejects non-positive or non-finite timing values", () => {
    expect(() => net.waitFor({ port: 8080, timeout: 0 })).toThrow(
      "[net.waitFor] invalid timeout: value must be a finite positive number"
    )
    expect(() => net.waitFor({ interval: Number.NaN, port: 8080 })).toThrow(
      "[net.waitFor] invalid interval: value must be a finite positive number"
    )
    expect(() => net.waitFor({ interval: Number.POSITIVE_INFINITY, port: 8080 })).toThrow(
      "[net.waitFor] invalid interval: value must be a finite positive number"
    )
  })

  it("returns failed when conn is null", async () => {
    const mod = net.waitFor({ port: 8080 })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when port becomes available immediately", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '60' '127.0.0.1' '8080'": { code: 0 },
    })
    const mod = net.waitFor({ port: 8080 })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    expect(mockSsh.execCalls[0]?.options).toMatchObject({
      ignoreExitCode: true,
      silent: true,
    })
    expect(mockSsh.execCalls[0]?.options?.timeout).toBeGreaterThan(0)
    expect(mockSsh.execCalls[0]?.options?.timeout).toBeLessThanOrEqual(60_000)
  })

  it("returns failed on timeout when condition never becomes true", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '9999'": { code: 1 },
    })
    const mod = net.waitFor({ interval: 5, port: 9999, timeout: 10 })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("caps poll delays to the remaining timeout budget", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '1' '127.0.0.1' '9999'": { code: 1 },
    })
    const mod = net.waitFor({ interval: 60_000, port: 9999, timeout: 10 })

    const start = Date.now()
    const result = await mod.apply(mockSsh, emptyEnv)
    const elapsed = Date.now() - start

    expect(result.status).toBe("failed")
    expect(elapsed).toBeLessThan(1000)
  })

  // R-0000052: net.waitFor must observe the runner abort signal so SIGINT
  // unblocks the polling loop within the next iteration tick instead of
  // running until the configured timeout.
  it("returns failed within the next tick after the runner abort signal fires", async () => {
    const mockSsh = createMockSsh({
      // Probe always fails so the loop falls through to the delay.
      "nc -z -w '600' '127.0.0.1' '9000'": { code: 1 },
    })
    const controller = new AbortController()
    setRunnerAbortSignal(controller.signal)

    try {
      const mod = net.waitFor({
        // Long enough that the test would hang (or fail with a long delta) if
        // the abort path were missing.
        interval: 60_000,
        port: 9000,
        timeout: 600_000,
      })

      const start = Date.now()
      const applyPromise = mod.apply(mockSsh, emptyEnv)
      // Let the loop reach `delay()` before we abort. A microtask flush via
      // queueMicrotask is enough because conn.test resolves synchronously
      // through the mock.
      await new Promise<void>((resolve) => {
        queueMicrotask(resolve)
      })
      controller.abort(new Error("Terminal prompt interrupted by SIGINT"))

      const result = await applyPromise
      const elapsed = Date.now() - start

      expect(result.status).toBe("failed")
      expect(result.error).toBeInstanceOf(Error)
      expect(result.error?.message).toMatch(/aborted by shutdown signal/v)
      // The polling loop must return well before the configured timeout.
      // 5 seconds is generous for test machines while still proving we are
      // not waiting on the 60s interval or the 600s timeout.
      expect(elapsed).toBeLessThan(5000)
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })

  it("returns failed synchronously when the abort signal is already aborted at apply start", async () => {
    const mockSsh = createMockSsh({
      "nc -z -w '600' '127.0.0.1' '9001'": { code: 1 },
    })
    const controller = new AbortController()
    controller.abort(new Error("aborted before apply"))
    setRunnerAbortSignal(controller.signal)

    try {
      const mod = net.waitFor({ interval: 60_000, port: 9001, timeout: 600_000 })
      const start = Date.now()
      const result = await mod.apply(mockSsh, emptyEnv)
      const elapsed = Date.now() - start

      expect(result.status).toBe("failed")
      expect(result.error).toBeInstanceOf(Error)
      expect(result.error?.message).toMatch(/aborted by shutdown signal/v)
      expect(elapsed).toBeLessThan(1000)
      // The probe is never invoked when the signal is already aborted.
      expect(mockSsh.calls).not.toContain("nc -z -w '600' '127.0.0.1' '9001'")
    } finally {
      setRunnerAbortSignal(undefined)
    }
  })
})

/* eslint-enable testing-library/await-async-utils */

// ─── net.request ──────────────────────────────────────────────────────────────

describe("net.request — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = net.request("https://example.com/health")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when status matches (200)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when status does not match", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "503" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when status AND body match", async () => {
    const mockSsh = createMockSsh({
      "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}' 'https://example.com/health'": {
        stdout: "OK\n__PARATIX_HTTP_STATUS__:200",
      },
    })
    const mod = net.request("https://example.com/health", { body: "OK" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expect(mockSsh.calls).toStrictEqual([
      "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}' 'https://example.com/health'",
    ])
  })

  it("returns needs-apply when body does not match even if status matches", async () => {
    const mockSsh = createMockSsh({
      "curl -s -w '\\n__PARATIX_HTTP_STATUS__:%{http_code}' 'https://example.com/health'": {
        stdout: "ERROR\n__PARATIX_HTTP_STATUS__:200",
      },
    })
    const mod = net.request("https://example.com/health", { body: "OK" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok with custom method (POST)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' -X 'POST' 'https://example.com/api'": {
        stdout: "200",
      },
    })
    const mod = net.request("https://example.com/api", { method: "POST" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("has correct name format: net.request: GET <url>", async () => {
    const mod = net.request("https://example.com/health")
    expect(mod.name).toBe("net.request: GET https://example.com/health")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("has correct name format with custom method: net.request: POST <url>", async () => {
    const mod = net.request("https://example.com/api", { method: "POST" })
    expect(mod.name).toBe("net.request: POST https://example.com/api")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("allows http URLs for endpoint checks", () => {
    const mod = net.request("http://example.com/health")
    expect(mod.name).toBe("net.request: GET http://example.com/health")
  })

  it("rejects file URLs before building a curl command", () => {
    expect(() => net.request("file:///etc/passwd")).toThrow(/Unsupported URL scheme 'file'/v)
  })

  it("rejects ftp URLs before building a curl command", () => {
    expect(() => net.request("ftp://example.com/file")).toThrow(/Unsupported URL scheme 'ftp'/v)
  })
})

describe("net.request — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = net.request("https://example.com/health")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns ok when request succeeds", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns failed when request fails (wrong status)", async () => {
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "503" },
    })
    const mod = net.request("https://example.com/health")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

// R-0000072/R-0000144: Header values must be routed through
// `curl --config -` over stdin instead of being inlined into argv, where
// `ps -ef` and sudo logging would capture them. The header values must also
// be registered in the process-scoped secret sink so CommandError stack traces
// are masked when curl fails.
describe("net.request — header masking", () => {
  // R-0000133: clear the process-scoped secret sink after every test so a
  // failing assertion cannot leak registered secrets into following tests.
  // Mirrors the pattern used by `secretSink.test.ts:17`.
  afterEach(() => {
    clearRegisteredSecrets()
  })

  it("never inlines the Authorization header value on the curl command line (check)", async () => {
    const token = "Bearer super-secret-PAT-XYZ123"
    const mockSsh = createMockSsh()

    const mod = net.request("https://example.com/health", {
      headers: { Authorization: token },
    })
    await mod.check(mockSsh, emptyEnv)

    // Every executed curl command must omit the secret token. Mocking returns
    // status "" so the check returns needs-apply; we only care about the
    // command shape here.
    for (const command of mockSsh.calls) {
      expect(command).not.toContain(token)
      expect(command).not.toContain("-H 'Authorization:")
    }
    // Sanity: the command was a curl invocation.
    expect(mockSsh.calls.some((c) => c.startsWith("curl "))).toBe(true)
  })

  it("forwards the Authorization header via the curl --config - stdin payload", async () => {
    const token = "Bearer super-secret-PAT-XYZ123"
    const mockSsh = createMockSsh()

    const mod = net.request("https://example.com/health", {
      headers: { Authorization: token },
    })
    await mod.check(mockSsh, emptyEnv)

    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
    expect(curlCall).toBeDefined()
    expect(curlCall?.command).toContain("--config -")
    expect(curlCall?.options?.input).toContain(`Authorization: ${token}`)
    expect(curlCall?.options?.secrets).toContain(token)
  })

  it("forwards arbitrary headers via stdin and registers their values as secrets", async () => {
    const apiKey = "super-secret-api-key-XYZ123"
    const mockSsh = createMockSsh()

    const mod = net.request("https://example.com/health", {
      headers: { "X-Api-Key": apiKey },
    })
    await mod.check(mockSsh, emptyEnv)

    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
    expect(curlCall).toBeDefined()
    expect(curlCall?.command).not.toContain(apiKey)
    expect(curlCall?.command).not.toContain("-H 'X-Api-Key:")
    expect(curlCall?.command).toContain("--config -")
    expect(curlCall?.options?.input).toContain(`header = "X-Api-Key: ${apiKey}"`)
    expect(curlCall?.options?.secrets).toContain(apiKey)
  })

  it("registers the Authorization header value as a process-scoped secret during apply", async () => {
    const token = "Bearer super-secret-PAT-XYZ123"
    const seen: string[] = []
    const mockSsh = createMockSsh()
    // Capture the secrets registered while the curl call is running.
    const originalExec = mockSsh.exec
    mockSsh.exec = async (command, options) => {
      seen.push(...getRegisteredSecrets())
      return originalExec(command, options)
    }

    const mod = net.request("https://example.com/health", {
      headers: { Authorization: token },
      status: 200,
    })
    await mod.apply(mockSsh, emptyEnv)

    expect(seen).toContain(token)
    // Sink is rebalanced after apply finishes.
    expect(getRegisteredSecrets()).not.toContain(token)
  })

  it("does not register a secret when no headers are present", async () => {
    // Pre-register an unrelated value to confirm we never rely on a leftover.
    registerSecret("unrelated-secret-marker")
    const mockSsh = createMockSsh({
      "curl -s -o /dev/null -w '%{http_code}' 'https://example.com/health'": { stdout: "200" },
    })
    const mod = net.request("https://example.com/health")
    await mod.apply(mockSsh, emptyEnv)

    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
    expect(curlCall).toBeDefined()
    expect(curlCall?.options?.secrets).toStrictEqual([])
    expect(curlCall?.options?.input).toBeUndefined()
  })

  it("masks signed-URL query parameters by routing the URL through stdin", async () => {
    const url = "https://example.com/object?signature=abc123&token=xyz789"
    const mockSsh = createMockSsh()

    const mod = net.request(url)
    await mod.check(mockSsh, emptyEnv)

    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl "))
    expect(curlCall).toBeDefined()
    expect(curlCall?.command).not.toContain(url)
    expect(curlCall?.command).toContain("--config -")
    expect(curlCall?.options?.input).toContain(`url = "${url}"`)
    expect(curlCall?.options?.secrets).toContain(url)
  })

  it("masks camelcase and separated sensitive query parameters without substring matches", async () => {
    const url =
      "https://example.com/object?apiKey=abc123&clientSecret=def456&accessKey=ghi789&access_token=jkl012&monkey=banana"
    const mockSsh = createMockSsh()

    const mod = net.request(url)
    await mod.check(mockSsh, emptyEnv)

    const curlCall = getFirstCurlExecCall(mockSsh)
    expect(curlCall.command).not.toContain(url)
    expect(curlCall.command).toContain("--config -")
    expect(curlCall.options?.input).toContain(`url = "${url}"`)
    expect(curlCall.options?.secrets).toContain(url)
    expect(mod.name).toBe(
      "net.request: GET https://example.com/object?apiKey=REDACTED&clientSecret=REDACTED&accessKey=REDACTED&access_token=REDACTED&monkey=banana"
    )
  })

  it("does not treat non-sensitive query substrings as secrets", async () => {
    const url = "https://example.com/object?monkey=banana&partition=1"
    const mockSsh = createMockSsh()

    const mod = net.request(url)
    await mod.check(mockSsh, emptyEnv)

    const curlCall = getFirstCurlExecCall(mockSsh)
    expect(curlCall.command).toContain(shellQuote(url))
    expect(curlCall.command).not.toContain("--config -")
    expect(curlCall.options?.input).toBeUndefined()
    expect(curlCall.options?.secrets).toStrictEqual([])
    expect(mod.name).toBe(`net.request: GET ${url}`)
  })

  it("masks URL userinfo by routing the URL through stdin", async () => {
    const url = "https://user:password@example.com/health"
    const mockSsh = createMockSsh()

    const mod = net.request(url)
    await mod.check(mockSsh, emptyEnv)

    const curlCall = getFirstCurlExecCall(mockSsh)
    expect(curlCall.command).not.toContain(url)
    expect(curlCall.command).not.toContain("user")
    expect(curlCall.command).not.toContain("password")
    expect(curlCall.command).toContain("--config -")
    expect(curlCall.options?.input).toContain(`url = "${url}"`)
    expect(curlCall.options?.secrets).toContain(url)
    expect(curlCall.options?.secrets).toContain("user")
    expect(curlCall.options?.secrets).toContain("password")
  })

  it("redacts sensitive signed-URL query values from the module name", () => {
    const mod = net.request("https://example.com/object?signature=abc123&token=xyz789&part=1")

    expect(mod.name).toBe(
      "net.request: GET https://example.com/object?signature=REDACTED&token=REDACTED&part=1"
    )
    expect(mod.name).not.toContain("abc123")
    expect(mod.name).not.toContain("xyz789")
  })

  it("redacts URL userinfo from the module name", () => {
    const mod = net.request("https://user:password@example.com/health")

    expect(mod.name).toBe("net.request: GET https://REDACTED:REDACTED@example.com/health")
    expect(mod.name).not.toContain("user")
    expect(mod.name).not.toContain("password")
  })

  it("redacts URL userinfo and sensitive query values from the module name", () => {
    const mod = net.request("https://user:password@example.com/object?token=abc123&part=1")

    expect(mod.name).toBe(
      "net.request: GET https://REDACTED:REDACTED@example.com/object?token=REDACTED&part=1"
    )
    expect(mod.name).not.toContain("user")
    expect(mod.name).not.toContain("password")
    expect(mod.name).not.toContain("abc123")
  })

  it("redacts sensitive signed-URL query values from apply failure messages", async () => {
    const rawUrl = "https://example.com/object?signature=abc123&token=xyz789"
    const mockSsh = createMockSsh()
    const mod = net.request(rawUrl)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("signature=REDACTED")
    expect(String(result.error)).toContain("token=REDACTED")
    expect(String(result.error)).not.toContain("abc123")
    expect(String(result.error)).not.toContain("xyz789")
  })

  it("redacts URL userinfo from apply failure messages", async () => {
    const rawUrl = "https://user:password@example.com/health"
    const mockSsh = createMockSsh()
    const mod = net.request(rawUrl)

    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("https://REDACTED:REDACTED@example.com/health")
    expect(String(result.error)).not.toContain("user")
    expect(String(result.error)).not.toContain("password")
  })
})
