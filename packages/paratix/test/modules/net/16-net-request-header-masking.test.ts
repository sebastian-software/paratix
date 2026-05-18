/* oxlint-disable no-unused-vars -- shared fixtures are duplicated by the mechanical test split */

import { afterEach, describe, expect, it } from "vitest"

import { net } from "../../../src/index.js"
import { sha256String } from "../../../src/modules/fileHelpers.js"
import {
  clearRegisteredSecrets,
  getRegisteredSecrets,
  registerSecret,
} from "../../../src/secretSink.js"
import { shellQuote } from "../../../src/ssh.js"
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
      "curl -s -o /dev/null -w '%{http_code}' --connect-timeout '10' --max-time '300' 'https://example.com/health'":
        { stdout: "200" },
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
