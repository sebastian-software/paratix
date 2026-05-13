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
    allowFlagLockInternalDefaults: true,
    allowWrites: [...NET_WRITE_ALLOWLIST, ...(options?.allowWrites ?? [])],
    // R-0000275: net.hosts.check now probes /etc/hosts existence before reading.
    // Default to "file exists" so apply-path fixtures (which return the cat
    // response) keep passing.
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

  it("creates /etc/hosts when it is missing (state: present)", async () => {
    const mockSsh = createMockSsh(
      {
        "cat '/etc/hosts'": { code: 1, stderr: "cat: /etc/hosts: No such file or directory" },
      },
      {
        responseStubs: [{ command: "[ -e '/etc/hosts' ]", result: { code: 1 } }],
      }
    )

    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFileCalls).toStrictEqual([
      {
        content: "1.2.3.4 myhost\n",
        options: { mode: "0644" },
        remotePath: "/etc/hosts",
      },
    ])
  })

  it("returns ok without writing when /etc/hosts is missing (state: absent)", async () => {
    const mockSsh = createMockSsh(
      {
        "cat '/etc/hosts'": { code: 1, stderr: "cat: /etc/hosts: No such file or directory" },
      },
      {
        responseStubs: [{ command: "[ -e '/etc/hosts' ]", result: { code: 1 } }],
      }
    )

    const mod = net.hosts("1.2.3.4", ["myhost"], { state: "absent" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("ok")
    expect(mockSsh.writeFileCalls).toHaveLength(0)
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

  // Hosts entries are normalized by IP. When `state: "present"` is applied
  // for an IP that already has a different hostname set on disk, the existing
  // hostnames are preserved and the desired hostnames are added to the same
  // consolidated line.
  it("merges a stale entry for the same IP instead of duplicating it (state: present)", async () => {
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
    expect(writes[0]?.content).toBe("127.0.0.1 localhost\n192.168.1.1 host1 host2\n")
  })

  it("preserves foreign hostnames on the same IP when adding a hostname (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("127.0.0.1", ["app.local"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writes).toHaveLength(1)
    expect(writes[0]?.content).toBe("127.0.0.1 localhost app.local\n")
  })

  it("consolidates multiple same-IP lines while preserving hostname order (state: present)", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": {
        stdout: "127.0.0.1 localhost\n10.0.0.1 api\n10.0.0.1 db api\n",
      },
    })
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("10.0.0.1", ["web", "api"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(writes).toHaveLength(1)
    expect(writes[0]?.content).toBe("127.0.0.1 localhost\n10.0.0.1 api db web\n")
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

  // R-0000169: read-modify-write on /etc/hosts must be serialized through a
  // mutex lock so concurrent Paratix runs cannot lose updates between the
  // read and the write.
  it("acquires and releases the etc-hosts mutex lock around the write", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })

    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const lockMkdir = "mkdir /var/lib/paratix/flags/'etc-hosts-mutex'"
    const lockRmdir = "rmdir /var/lib/paratix/flags/'etc-hosts-mutex'"
    expect(mockSsh.calls).toContain(lockMkdir)
    expect(mockSsh.calls).toContain(lockRmdir)
    const acquireIndex = mockSsh.calls.indexOf(lockMkdir)
    const writeReadIndex = mockSsh.calls.indexOf("cat '/etc/hosts'")
    const releaseIndex = mockSsh.calls.indexOf(lockRmdir)
    expect(acquireIndex).toBeLessThan(writeReadIndex)
    expect(writeReadIndex).toBeLessThan(releaseIndex)
  })

  // R-0000169: when a concurrent process modifies /etc/hosts between the
  // read and the write, the guarded write must abort instead of silently
  // overwriting the foreign change. This protects callers even if a future
  // refactor weakens the mutex serialization guarantee.
  it("aborts the write when /etc/hosts changes between read and write", async () => {
    const mockSsh = createMockSsh({
      "cat '/etc/hosts'": { stdout: "127.0.0.1 localhost\n" },
    })
    let readCount = 0
    const originalReadFile = mockSsh.readFile.bind(mockSsh)
    mockSsh.readFile = async (remotePath: string): Promise<string> => {
      readCount += 1
      // oxlint-disable-next-line eslint-plugin-vitest(no-conditional-in-test) -- simulating the race between an initial read and a concurrent /etc/hosts modification before the guarded re-read requires a counter-based switch in a single mock function
      if (readCount === 1) return originalReadFile(remotePath)
      // Simulate a concurrent modification that landed between the initial
      // read and the guarded re-read just before the write.
      return "127.0.0.1 localhost\n9.9.9.9 intruder\n"
    }
    const writes: Array<{ content: string; mode: string; path: string }> = []
    mockSsh.writeFile = async (path, content, options) => {
      writes.push({ content, mode: options.mode, path })
      await Promise.resolve()
    }

    const mod = net.hosts("1.2.3.4", ["myhost"])
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(writes).toHaveLength(0)
    // The mutex lock must still be released even when the guarded write
    // refuses, otherwise the next run would hang forever.
    expect(mockSsh.calls).toContain("rmdir /var/lib/paratix/flags/'etc-hosts-mutex'")
  })
})

// ─── net.resolv ───────────────────────────────────────────────────────────────
