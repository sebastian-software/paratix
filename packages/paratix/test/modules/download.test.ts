import { describe, expect, it } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { download } from "../../src/modules/download.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

type MockSshWithOptions = {
  exec: (
    command: string,
    options?: ExecOptions
  ) => Promise<{ code: number; stderr: string; stdout: string }>
  execCalls: Array<{ command: string; options?: ExecOptions }>
} & ReturnType<typeof createMockSsh>

/**
 * Extended mock that records exec options (e.g. secrets) alongside commands.
 *
 * @returns A mock SSH connection that stores each exec call with its options.
 */
function createMockSshWithOptions(): MockSshWithOptions {
  const base = createMockSsh()
  const execCalls: Array<{ command: string; options?: ExecOptions }> = []
  const mock: MockSshWithOptions = {
    ...base,
    exec: async (command: string, options?: ExecOptions) => {
      execCalls.push({ command, options })
      return base.exec(command, options)
    },
    execCalls,
  }
  return mock
}

describe("download.url", () => {
  const destination = "/usr/local/bin/mytool"
  const url = "https://example.com/mytool"
  const sha256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

  describe("check", () => {
    it("returns ok when SHA-256 matches", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when SHA-256 does not match", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${destination}`,
        },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when file exists (no sha256)", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when file does not exist (no sha256)", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 1 },
      })
      const mod = download.url(destination, url)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when force is true", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, { force: true })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when ssh is null", async () => {
      const mod = download.url(destination, url)
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("apply", () => {
    it("downloads file via curl and returns changed", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`curl -fsSL -o '${destination}' '${url}'`)
    })

    it("creates target directory via mkdir -p", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url)
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`mkdir -p "$(dirname '${destination}')"`)
    })

    it("sets mode via chmod when mode is specified", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url, { mode: "0755" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chmod '0755' '${destination}'`)
    })

    it("sets owner and group via chown when both are specified", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url, { group: "wheel", owner: "root" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chown 'root:wheel' '${destination}'`)
    })

    it("sets only owner via chown when owner is specified without group", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url, { owner: "deploy" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chown 'deploy:' '${destination}'`)
    })

    it("sets only group via chown when group is specified without owner", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url, { group: "staff" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chown ':staff' '${destination}'`)
    })

    it("sends headers via -H when headers are specified", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url, {
        headers: { Authorization: "Bearer mytoken" },
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${destination}' -H 'Authorization: Bearer mytoken' '${url}'`
      )
    })

    it("verifies SHA-256 after download and returns changed on match", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
    })

    it("returns failed when SHA-256 does not match after download", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${destination}`,
        },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("removes file when SHA-256 verification fails", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${destination}`,
        },
      })
      const mod = download.url(destination, url, { sha256 })
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`rm -f '${destination}'`)
    })

    it("returns failed when ssh is null", async () => {
      const mod = download.url(destination, url)
      const conn = null
      const result = await mod.apply(conn, emptyEnv)
      expect(result.status).toBe("failed")
    })
  })

  describe("name", () => {
    it("has correct format containing destination path", () => {
      const mod = download.url(destination, url)
      expect(mod.name).toBe(`download.url: ${destination}`)
    })
  })
})

describe("download.github", () => {
  const destination = "/usr/local/bin/terraform"
  const repo = "hashicorp/terraform"
  const tag = "v1.5.0"
  const asset = "terraform_1.5.0_linux_amd64.zip"
  const expectedUrl = `https://github.com/${repo}/releases/download/${tag}/${asset}`
  const sha256 = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"

  describe("check", () => {
    it("returns ok when file exists (no sha256)", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
      })
      const mod = download.github(destination, { asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when file does not exist", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 1 },
      })
      const mod = download.github(destination, { asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when SHA-256 matches", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.github(destination, { asset, repo, sha256, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when ssh is null", async () => {
      const mod = download.github(destination, { asset, repo, tag })
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("apply", () => {
    it("builds correct GitHub release URL in curl command", async () => {
      const mockSsh = createMockSsh()
      const mod = download.github(destination, { asset, repo, tag })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`curl -fsSL -o '${destination}' '${expectedUrl}'`)
    })

    it("sends Authorization and Accept headers when token is provided", async () => {
      const token = "ghp_supersecrettoken"
      const mockSsh = createMockSsh()
      const mod = download.github(destination, { asset, repo, tag, token })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      const authHeader = `-H 'Authorization: token ${token}'`
      const acceptHeader = `-H 'Accept: application/octet-stream'`
      const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      expect(curlCall).toContain(authHeader)
      expect(curlCall).toContain(acceptHeader)
    })

    it("does not send Authorization header when no token is provided", async () => {
      const mockSsh = createMockSsh()
      const mod = download.github(destination, { asset, repo, tag })
      await mod.apply(mockSsh, emptyEnv)
      const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      expect(curlCall).not.toContain("Authorization")
    })

    it("returns failed when ssh is null", async () => {
      const mod = download.github(destination, { asset, repo, tag })
      const conn = null
      const result = await mod.apply(conn, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("creates target directory via mkdir -p", async () => {
      const mockSsh = createMockSsh()
      const mod = download.github(destination, { asset, repo, tag })
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`mkdir -p "$(dirname '${destination}')"`)
    })
  })

  describe("validation", () => {
    it("throws on invalid repo format with path traversal", () => {
      expect(() =>
        download.github(destination, { asset, repo: "foo/bar/../../evil.com/x", tag })
      ).toThrow("Invalid GitHub repo format")
    })

    it("throws on repo without slash", () => {
      expect(() => download.github(destination, { asset, repo: "noslash", tag })).toThrow(
        "Invalid GitHub repo format"
      )
    })

    it("accepts valid repo format", () => {
      expect(() => download.github(destination, { asset, repo, tag })).not.toThrow()
    })

    it("throws on tag with path traversal", () => {
      expect(() => download.github(destination, { asset, repo, tag: "../../evil" })).toThrow(
        "Invalid GitHub release tag"
      )
    })

    it("throws on empty tag", () => {
      expect(() => download.github(destination, { asset, repo, tag: "" })).toThrow(
        "Invalid GitHub release tag"
      )
    })

    it("throws on asset with path traversal", () => {
      expect(() => download.github(destination, { asset: "../../etc/passwd", repo, tag })).toThrow(
        "Invalid GitHub release asset"
      )
    })

    it("throws on empty asset", () => {
      expect(() => download.github(destination, { asset: "", repo, tag })).toThrow(
        "Invalid GitHub release asset"
      )
    })
  })

  describe("name", () => {
    it("has correct format repo@tag/asset", () => {
      const mod = download.github(destination, { asset, repo, tag })
      expect(mod.name).toBe(`download.github: ${repo}@${tag}/${asset}`)
    })
  })
})

// ─── download.large ───────────────────────────────────────────────────────────

describe("download.large", () => {
  const destination = "/opt/data/large-file.iso"
  const url = "https://example.com/large-file.iso"
  // SHA-256 of the URL, matching the flag name computed in the implementation
  const urlHash = "b7c3ff8df8e2258a442ec7d03db1667124ea34ff39bd3197136e4238fab27fb3"
  const flagName = `download-${urlHash}`

  describe("check", () => {
    it("returns needs-apply when conn is null", async () => {
      const mod = download.large(destination, url)
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when flag file exists", async () => {
      const mockSsh = createMockSsh({
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when flag file does not exist", async () => {
      const mockSsh = createMockSsh({
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
      })
      const mod = download.large(destination, url)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("apply", () => {
    it("returns failed when conn is null", async () => {
      const mod = download.large(destination, url)
      // eslint-disable-next-line prefer-spread
      const result = await mod.apply(null, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("downloads file and sets flag on success", async () => {
      const mockSsh = createMockSsh()
      const mod = download.large(destination, url)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`curl -fsSL -o '${destination}' '${url}'`)
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
    })

    it("creates flags directory before setting flag", async () => {
      const mockSsh = createMockSsh()
      const mod = download.large(destination, url)
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain("mkdir -p /var/lib/paratix/flags")
      const mkdirIndex = mockSsh.calls.indexOf("mkdir -p /var/lib/paratix/flags")
      const touchIndex = mockSsh.calls.indexOf(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mkdirIndex).toBeLessThan(touchIndex)
    })
  })

  describe("name", () => {
    // eslint-disable-next-line @typescript-eslint/require-await
    it("has correct format: download.large: <destination>", async () => {
      const mod = download.large(destination, url)
      expect(mod.name).toBe(`download.large: ${destination}`)
    })
  })
})

// ─── Header-Name-Validierung (Regressionstests) ───────────────────────────────

describe("buildCurlCommand — header name validation", () => {
  const destination = "/tmp/file"
  const url = "https://example.com/file"

  it("throws when header name contains \\r\\n (CRLF injection)", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { "X-Evil\r\nX-Injected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\n", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { "X-Evil\nInjected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\r", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { "X-Evil\rInjected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a control character (\\x01)", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { "X-Bad\x01Name": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a colon", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { "X-Bad:Name": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("accepts a valid single-word header name", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { Authorization: "Bearer token123" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((c) => c.startsWith("curl"))
    expect(curlCall).toContain("-H 'Authorization: Bearer token123'")
  })

  it("accepts a valid hyphenated header name", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      headers: { "X-Custom-Header": "some-value" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((c) => c.startsWith("curl"))
    expect(curlCall).toContain("-H 'X-Custom-Header: some-value'")
  })
})

// ─── download.github — secrets-Weitergabe (Regressionstests) ─────────────────

describe("download.github — secrets propagation", () => {
  const destination = "/usr/local/bin/terraform"
  const repo = "hashicorp/terraform"
  const tag = "v1.5.0"
  const asset = "terraform_1.5.0_linux_amd64.zip"

  it("passes token as secrets when exec is called for curl", async () => {
    const token = "ghp_supersecrettoken"
    const mock = createMockSshWithOptions()
    const mod = download.github(destination, { asset, repo, tag, token })
    await mod.apply(mock, emptyEnv)

    const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
    expect(curlCall).toBeDefined()
    expect(curlCall?.options?.secrets).toContain(token)
  })

  it("does not set secrets when no token is provided", async () => {
    const mock = createMockSshWithOptions()
    const mod = download.github(destination, { asset, repo, tag })
    await mod.apply(mock, emptyEnv)

    const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
    expect(curlCall).toBeDefined()
    expect(curlCall?.options?.secrets).toBeUndefined()
  })
})
