import { createHash } from "node:crypto"
import { describe, expect, it } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { download } from "../../src/modules/download.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}
const allowUnverifiedDownload = { allowUnverifiedDownload: true } as const
const httpsOnlyCurlProtocolFlags = "--proto '=https' --proto-redir '=https'"
const insecureHttpCurlProtocolFlags = "--proto '=http,https' --proto-redir '=http,https'"

function buildLargeDownloadFlagName(parameters: {
  destination: string
  headers?: Record<string, string>
  url: string
}): string {
  const flagKey = JSON.stringify({
    destination: parameters.destination,
    headers: JSON.stringify(
      Object.entries(parameters.headers ?? {}).sort(([leftName], [rightName]) =>
        leftName.localeCompare(rightName)
      )
    ),
    url: parameters.url,
  })
  return `download-${createHash("sha256").update(flagKey).digest("hex")}`
}

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
  const temporaryDestination = "/usr/local/bin/.paratix-download.ABC123"
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
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when file does not exist (no sha256)", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 1 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when force is true", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, { ...allowUnverifiedDownload, force: true })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when ssh is null", async () => {
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("apply", () => {
    it("downloads file via curl and returns changed", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} '${url}'`
      )
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("creates target directory via mkdir -p", async () => {
      const mockSsh = createMockSsh()
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`mkdir -p "$(dirname '${destination}')"`)
    })

    it("sets mode via chmod when mode is specified", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, { ...allowUnverifiedDownload, mode: "0755" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chmod '0755' '${temporaryDestination}'`)
    })

    it("sets owner and group via chown when both are specified", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        group: "wheel",
        owner: "root",
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chown 'root:wheel' '${temporaryDestination}'`)
    })

    it("sets only owner via chown when owner is specified without group", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, { ...allowUnverifiedDownload, owner: "deploy" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chown 'deploy:' '${temporaryDestination}'`)
    })

    it("sets only group via chown when group is specified without owner", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, { ...allowUnverifiedDownload, group: "staff" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chown ':staff' '${temporaryDestination}'`)
    })

    it("sends headers via -H when headers are specified", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { Authorization: "Bearer mytoken" },
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} -H 'Authorization: Bearer mytoken' '${url}'`
      )
    })

    it("verifies SHA-256 after download and returns changed on match", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: { stdout: `${sha256}  ${temporaryDestination}` },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
    })

    it("returns failed when SHA-256 does not match after download", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("cleans up only the temporary file when SHA-256 verification fails", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.url(destination, url, { sha256 })
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`rm -f '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`rm -f '${destination}'`)
      expect(mockSsh.calls).not.toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("returns failed when ssh is null", async () => {
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const conn = null
      const result = await mod.apply(conn, emptyEnv)
      expect(result.status).toBe("failed")
    })
  })

  describe("name", () => {
    it("has correct format containing destination path", () => {
      const mod = download.url(destination, url, allowUnverifiedDownload)
      expect(mod.name).toBe(`download.url: ${destination}`)
    })
  })

  describe("validation", () => {
    it("throws on file:// URL with message containing scheme", () => {
      expect(() => download.url(destination, "file:///etc/passwd")).toThrow("file")
    })

    it("throws on ftp:// URL", () => {
      expect(() => download.url(destination, "ftp://example.com/file")).toThrow(
        "Unsupported URL scheme"
      )
    })

    it("throws on gopher:// URL", () => {
      expect(() => download.url(destination, "gopher://evil.com")).toThrow("Unsupported URL scheme")
    })

    it("throws on invalid URL syntax", () => {
      expect(() => download.url(destination, "not-a-url")).toThrow("Invalid URL")
    })

    it("throws for https:// URLs without sha256 or explicit opt-out", () => {
      expect(() => download.url(destination, "https://example.com/file")).toThrow(
        "requires options.sha256"
      )
    })

    it("accepts https:// URL with explicit opt-out", () => {
      expect(() =>
        download.url(destination, "https://example.com/file", allowUnverifiedDownload)
      ).not.toThrow()
    })

    it("rejects http:// URL without explicit opt-in", () => {
      expect(() => download.url(destination, "http://example.com/file")).toThrow(
        "Insecure URL scheme"
      )
    })

    it("accepts http:// URL when allowInsecureHttp is true", () => {
      expect(() =>
        download.url(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
        })
      ).not.toThrow()
    })
  })

  describe("secrets propagation", () => {
    it("passes header values as secrets when exec is called for curl", async () => {
      const token = "supersecret-bearer-token"
      const mock = createMockSshWithOptions()
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { Authorization: `Bearer ${token}` },
      })
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toContain(`Bearer ${token}`)
    })

    it("passes an empty secrets array when no headers are provided", async () => {
      const mock = createMockSshWithOptions()
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toStrictEqual([])
    })
  })
})

describe("download.github", () => {
  const destination = "/usr/local/bin/terraform"
  const temporaryDestination = "/usr/local/bin/.paratix-download.GH1234"
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
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when file does not exist", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 1 },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
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
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("apply", () => {
    it("builds correct GitHub release URL in curl command", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} '${expectedUrl}'`
      )
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("sends Authorization and Accept headers when token is provided", async () => {
      const token = "ghp_supersecrettoken"
      const mockSsh = createMockSsh()
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo,
        tag,
        token,
      })
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
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      await mod.apply(mockSsh, emptyEnv)
      const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      expect(curlCall).not.toContain("Authorization")
    })

    it("returns failed when ssh is null", async () => {
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const conn = null
      const result = await mod.apply(conn, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("creates target directory via mkdir -p", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`mkdir -p "$(dirname '${destination}')"`)
    })

    it("keeps the destination untouched when SHA-256 verification fails", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.github(destination, { asset, repo, sha256, tag })
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(mockSsh.calls).toContain(`rm -f '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`rm -f '${destination}'`)
      expect(mockSsh.calls).not.toContain(`mv '${temporaryDestination}' '${destination}'`)
    })
  })

  describe("validation", () => {
    it("throws without sha256 or explicit opt-out", () => {
      expect(() => download.github(destination, { asset, repo, tag })).toThrow(
        "requires options.sha256"
      )
    })

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
      expect(() =>
        download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      ).not.toThrow()
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
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      expect(mod.name).toBe(`download.github: ${repo}@${tag}/${asset}`)
    })
  })

  describe("URL encoding", () => {
    it("percent-encodes special characters in tag when building the download URL", async () => {
      // Tags like "v1.5.0+build.1" or "release 2024" contain characters that
      // must be percent-encoded in a URL. The current implementation uses a
      // plain template literal without encodeURIComponent, so the raw characters
      // end up in the curl command instead of their encoded equivalents.
      const tagWithSpecialChars = "v1.5.0+build.1"
      const mockSsh = createMockSsh()
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo,
        tag: tagWithSpecialChars,
      })
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // The "+" must appear as "%2B" in the URL, not as a literal "+"
      expect(curlCall).toContain(encodeURIComponent(tagWithSpecialChars))
      expect(curlCall).not.toContain(`/${tagWithSpecialChars}/`)
    })

    it("percent-encodes special characters in asset when building the download URL", async () => {
      // Asset names like "my tool 1.0.zip" contain spaces that must be
      // percent-encoded. Without encodeURIComponent the space is passed raw,
      // which produces an invalid URL in the curl command.
      const assetWithSpace = "my tool 1.0.zip"
      const mockSsh = createMockSsh()
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset: assetWithSpace,
        repo,
        tag,
      })
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // The space must appear as "%20" in the URL, not as a literal space
      expect(curlCall).toContain(encodeURIComponent(assetWithSpace))
      expect(curlCall).not.toContain(` ${assetWithSpace}'`)
    })

    it("percent-encodes special characters in owner and repo when building the download URL", async () => {
      // Regression test: owner and repo parts of the GitHub URL must be
      // individually encoded via encodeURIComponent. A repo like "my+org/my%repo"
      // contains "+" (encoded as "%2B") and "%" (encoded as "%25") which must
      // not appear raw in the curl command.
      const repoWithSpecialChars = "my+org/my%repo"
      const [encodedOwner, encodedRepo] = repoWithSpecialChars
        .split("/")
        .map((part) => encodeURIComponent(part))
      const mockSsh = createMockSsh()
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo: repoWithSpecialChars,
        tag,
      })
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // Both owner and repo must appear percent-encoded in the URL
      expect(curlCall).toContain(`https://github.com/${encodedOwner}/${encodedRepo}/`)
      // The raw "+" and "%" must not appear in the path segments
      expect(curlCall).not.toContain("/my+org/")
      expect(curlCall).not.toContain("/my%repo/")
    })
  })
})

// ─── download.large ───────────────────────────────────────────────────────────

describe("download.large", () => {
  const destination = "/opt/data/large-file.iso"
  const temporaryDestination = "/opt/data/.paratix-download.LARGE1"
  const url = "https://example.com/large-file.iso"
  const flagName = buildLargeDownloadFlagName({ destination, url })

  describe("check", () => {
    it("returns needs-apply when conn is null", async () => {
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when flag file exists", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when flag file does not exist", async () => {
      const mockSsh = createMockSsh({
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when flag exists but destination file is missing", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when flag exists and sha256 matches", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when flag exists but sha256 does not match", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${destination}`,
        },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when flag does not exist and sha256 is set", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("insecure HTTP opt-in", () => {
    it("throws without sha256 or explicit opt-out", () => {
      expect(() => download.large(destination, url)).toThrow("requires options.sha256")
    })

    it("rejects http:// URL without explicit opt-in", () => {
      expect(() => download.large(destination, "http://example.com/large-file.iso")).toThrow(
        "Insecure URL scheme"
      )
    })

    it("accepts http:// URL when allowInsecureHttp is true", () => {
      expect(() =>
        download.large(destination, "http://example.com/large-file.iso", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
        })
      ).not.toThrow()
    })
  })

  describe("apply", () => {
    it("returns failed when conn is null", async () => {
      const mod = download.large(destination, url, allowUnverifiedDownload)
      // eslint-disable-next-line prefer-spread
      const result = await mod.apply(null, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("downloads file and sets flag on success", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} '${url}'`
      )
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
    })

    it("creates flags directory before setting flag", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain("mkdir -p /var/lib/paratix/flags")
      const mkdirIndex = mockSsh.calls.indexOf("mkdir -p /var/lib/paratix/flags")
      const touchIndex = mockSsh.calls.indexOf(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mkdirIndex).toBeLessThan(touchIndex)
    })

    it("returns changed and sets flag when sha256 matches after download", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: { stdout: `${sha256}  ${temporaryDestination}` },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
    })

    it("returns failed and does not set flag when sha256 does not match after download", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(mockSsh.calls).not.toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mockSsh.calls).toContain(`rm -f '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`rm -f '${destination}'`)
      expect(mockSsh.calls).not.toContain(`mv '${temporaryDestination}' '${destination}'`)
    })
  })

  describe("name", () => {
    // eslint-disable-next-line @typescript-eslint/require-await
    it("has correct format: download.large: <destination>", async () => {
      const mod = download.large(destination, url, allowUnverifiedDownload)
      expect(mod.name).toBe(`download.large: ${destination}`)
    })
  })

  describe("validation", () => {
    it("throws on file:// URL with message containing scheme", () => {
      expect(() => download.large(destination, "file:///etc/passwd")).toThrow("file")
    })

    it("throws on ftp:// URL", () => {
      expect(() => download.large(destination, "ftp://example.com/file")).toThrow(
        "Unsupported URL scheme"
      )
    })

    it("throws on gopher:// URL", () => {
      expect(() => download.large(destination, "gopher://evil.com")).toThrow(
        "Unsupported URL scheme"
      )
    })

    it("throws on invalid URL syntax", () => {
      expect(() => download.large(destination, "not-a-url")).toThrow("Invalid URL")
    })

    it("accepts https:// URL with explicit opt-out", () => {
      expect(() =>
        download.large(destination, "https://example.com/file", allowUnverifiedDownload)
      ).not.toThrow()
    })

    it("rejects http:// URL without explicit opt-in", () => {
      expect(() => download.large(destination, "http://example.com/file")).toThrow(
        "Insecure URL scheme"
      )
    })
  })

  describe("secrets propagation", () => {
    it("passes header values as secrets when exec is called for curl", async () => {
      const token = "supersecret-bearer-token"
      const mock = createMockSshWithOptions()
      const mod = download.large(destination, url, {
        ...allowUnverifiedDownload,
        headers: { Authorization: `Bearer ${token}` },
      })
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toContain(`Bearer ${token}`)
    })

    it("passes an empty secrets array when no headers are provided", async () => {
      const mock = createMockSshWithOptions()
      const mod = download.large(destination, url, allowUnverifiedDownload)
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toStrictEqual([])
    })

    it("uses distinct flag names for the same URL with different destinations", () => {
      const otherDestination = "/srv/cache/large-file.iso"

      expect(buildLargeDownloadFlagName({ destination, url })).not.toBe(
        buildLargeDownloadFlagName({ destination: otherDestination, url })
      )
    })

    it("uses distinct flag names for the same URL and destination with different headers", () => {
      expect(
        buildLargeDownloadFlagName({
          destination,
          headers: { Authorization: "Bearer token-a" },
          url,
        })
      ).not.toBe(
        buildLargeDownloadFlagName({
          destination,
          headers: { Authorization: "Bearer token-b" },
          url,
        })
      )
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
      ...allowUnverifiedDownload,
      headers: { "X-Evil\r\nX-Injected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\n", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Evil\nInjected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\r", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Evil\rInjected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a control character (\\x01)", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Bad\x01Name": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a colon", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Bad:Name": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("accepts a valid single-word header name", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
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
      ...allowUnverifiedDownload,
      headers: { "X-Custom-Header": "some-value" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((c) => c.startsWith("curl"))
    expect(curlCall).toContain("-H 'X-Custom-Header: some-value'")
  })
})

// ─── Header-Value-Validierung (Regressionstests) ──────────────────────────────

describe("buildCurlCommand — header value validation", () => {
  const destination = "/tmp/file"
  const url = "https://example.com/file"

  it("throws when header value contains \\r (CR injection)", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom": "value\rX-Injected: injected" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "Invalid HTTP header value for X-Custom: value contains newline characters"
    )
  })

  it("throws when header value contains \\n (LF injection)", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom": "value\nX-Injected: injected" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "Invalid HTTP header value for X-Custom: value contains newline characters"
    )
  })

  it("accepts a normal header value without newline characters", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom": "safe-value" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((c) => c.startsWith("curl"))
    expect(curlCall).toContain("-H 'X-Custom: safe-value'")
  })
})

describe("buildCurlCommand — redirect protocol policy", () => {
  const destination = "/tmp/file"
  const httpsUrl = "https://example.com/file"

  it("restricts initial URL and redirects to https by default", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, httpsUrl, allowUnverifiedDownload)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
    expect(curlCall).toContain(httpsOnlyCurlProtocolFlags)
  })

  it("allows http and https for initial URL and redirects when allowInsecureHttp is true", async () => {
    const mockSsh = createMockSsh()
    const mod = download.url(destination, "http://example.com/file", {
      ...allowUnverifiedDownload,
      allowInsecureHttp: true,
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
    expect(curlCall).toContain(insecureHttpCurlProtocolFlags)
  })

  it("uses https-only redirect policy for github downloads by default", async () => {
    const mockSsh = createMockSsh()
    const mod = download.github("/usr/local/bin/terraform", {
      ...allowUnverifiedDownload,
      asset: "terraform_1.5.0_linux_amd64.zip",
      repo: "hashicorp/terraform",
      tag: "v1.5.0",
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
    expect(curlCall).toContain(httpsOnlyCurlProtocolFlags)
  })

  it("propagates insecure http redirect opt-in for large downloads", async () => {
    const mockSsh = createMockSsh()
    const mod = download.large("/var/cache/big.iso", "http://example.com/big.iso", {
      ...allowUnverifiedDownload,
      allowInsecureHttp: true,
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
    expect(curlCall).toContain(insecureHttpCurlProtocolFlags)
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
    const mod = download.github(destination, {
      ...allowUnverifiedDownload,
      asset,
      repo,
      tag,
      token,
    })
    await mod.apply(mock, emptyEnv)

    const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
    expect(curlCall).toBeDefined()
    expect(curlCall?.options?.secrets).toContain(token)
  })

  it("does not set secrets when no token is provided", async () => {
    const mock = createMockSshWithOptions()
    const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
    await mod.apply(mock, emptyEnv)

    const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
    expect(curlCall).toBeDefined()
    expect(curlCall?.options?.secrets).toBeUndefined()
  })
})
