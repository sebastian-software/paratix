import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { download } from "../../src/modules/download.js"
import { createMockSsh as createBaseMockSsh, type ExecCall } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    responseStubs: [
      { command: /^\[ -e '\/(?:opt|usr)\//v, result: { code: 1 } },
      { command: /^\[ -f '\/(?:opt|usr)\//v, result: { code: 1 } },
      { command: /^stat -c '%a %U %G' '\/(?:opt|usr)\//v, result: { stdout: "644 root root" } },
      { command: /^mkdir -p /v, result: { code: 0 } },
      { command: /^mktemp /v, result: { stdout: "/tmp/.paratix-download.stub" } },
      { command: /^curl /v, result: { code: 0 } },
      { command: /^chmod /v, result: { code: 0 } },
      { command: /^chown /v, result: { code: 0 } },
      { command: /^mv /v, result: { code: 0 } },
      { command: /^rm -f /v, result: { code: 0 } },
      { command: /^\[ -f \/var\/lib\/paratix\/flags\//v, result: { code: 1 } },
      { command: /^mkdir \/var\/lib\/paratix\/flags\/.*\.lock'/v, result: { code: 0 } },
      { command: /^rmdir \/var\/lib\/paratix\/flags\/.*\.lock'/v, result: { code: 0 } },
      { command: /^touch \/var\/lib\/paratix\/flags\//v, result: { code: 0 } },
      ...(options?.responseStubs ?? []),
    ],
  })

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
  execCalls: ExecCall[]
} & ReturnType<typeof createMockSsh>

/**
 * Extended mock that records exec options (e.g. secrets) alongside commands.
 *
 * @param responses - Optional response map forwarded to {@link createMockSsh}.
 * @returns A mock SSH connection that stores each exec call with its options.
 */
function createMockSshWithOptions(
  responses?: Parameters<typeof createMockSsh>[0]
): MockSshWithOptions {
  const base = createMockSsh(responses)
  const execCalls: ExecCall[] = []
  const mock: MockSshWithOptions = {
    ...base,
    async exec(command: string, options?: ExecOptions) {
      execCalls.push({ command, options })
      return base.exec(command, options)
    },
    execCalls,
  }
  return mock
}

/**
 * R-0000107 helper: build a mktemp stub for tests that exercise download.url
 * / download.large / download.github apply paths. The stub returns a
 * deterministic temporary path that satisfies the validateMktempPath
 * contract (`<dirname>/.paratix-download.<suffix>`).
 *
 * @param destination - The download destination path (matches the directory
 *   the mktemp stdout must live under).
 * @param temporaryPath - The temporary path the stub should return.
 * @returns A response map for {@link createMockSsh}.
 */
function downloadMktempStub(
  destination: string,
  temporaryPath: string
): Parameters<typeof createMockSsh>[0] {
  return {
    [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
      stdout: `${temporaryPath}\n`,
    },
  }
}

function createMockSshWithFailingCurl(parameters: {
  curlCommand: string
  curlError: Error
  destination: string
  temporaryDestination: string
}): ReturnType<typeof createMockSsh> {
  const base = createMockSsh(
    downloadMktempStub(parameters.destination, parameters.temporaryDestination)
  )

  return {
    ...base,
    async exec(command: string, options?: ExecOptions) {
      if (command === parameters.curlCommand) {
        base.calls.push(command)
        base.execCalls.push({ command, options })
        throw parameters.curlError
      }

      return base.exec(command, options)
    },
  }
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
        [`[ -f '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when file does not exist (no sha256)", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 1 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when the destination exists but is not a regular file", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 1 },
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

    it("returns needs-apply when mode drifts despite matching SHA-256", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
        [`stat -c '%a %U %G' '${destination}'`]: { stdout: "644 root root" },
      })
      const mod = download.url(destination, url, { mode: "0755", sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when owner and group drift without sha256", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`stat -c '%a %U %G' '${destination}'`]: { stdout: "755 root wheel" },
      })
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        group: "staff",
        owner: "deploy",
      })
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
    it("downloads file via curl --config from stdin and returns changed", async () => {
      // R-0000037: URLs (including signed/presigned ones) and Authorization
      // headers must not appear on argv. They are passed to curl via
      // `--config -` from stdin so they never leak into /var/log/auth.log
      // (sudo logging) or /proc/<pid>/cmdline / ps -ef.
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      )
      // The URL must not be on argv any more.
      expect(mockSsh.calls.every((c) => !c.includes(url))).toBe(true)
      // The URL must be delivered via stdin instead.
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall?.options?.input).toBe(`url = "${url}"\n`)
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("cleans up the temporary file and leaves destination untouched when curl fails", async () => {
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      const curlError = new Error("curl failed")
      const mockSsh = createMockSshWithFailingCurl({
        curlCommand,
        curlError,
        destination,
        temporaryDestination,
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)

      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toBe(curlError)

      expect(mockSsh.calls).toContain(curlCommand)
      expect(mockSsh.calls).toContain(`rm -f '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("creates target directory via mkdir -p", async () => {
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
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
      expect(mockSsh.calls).toContain(`chown -- 'root:wheel' '${temporaryDestination}'`)
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
      expect(mockSsh.calls).toContain(`chown -- 'deploy:' '${temporaryDestination}'`)
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
      expect(mockSsh.calls).toContain(`chown -- ':staff' '${temporaryDestination}'`)
    })

    it("rejects option-like owner specs before chown", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        owner: "--reference=/etc/shadow",
      })

      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
        'chown owner component must not start with "-": "--reference=/etc/shadow"'
      )
      expect(mockSsh.calls).not.toContain(
        `chown -- '--reference=/etc/shadow:' '${temporaryDestination}'`
      )
    })

    it("rejects option-like group specs before chown", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, { ...allowUnverifiedDownload, group: "-R" })

      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
        'chown group component must not start with "-": "-R"'
      )
    })

    it("sends Authorization header via stdin so the bearer token is not on argv", async () => {
      // R-0000037: Bearer tokens, GitHub PATs, and Basic-Auth credentials in
      // Authorization-style headers are routed via curl --config from stdin
      // and must not appear on argv.
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
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall?.command).toBe(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      )
      // Neither the URL nor the Authorization header value may appear on argv.
      expect(curlCall?.command).not.toContain("Bearer mytoken")
      expect(curlCall?.command).not.toContain(url)
      // Both flow through the curl config payload on stdin instead.
      expect(curlCall?.options?.input).toBe(
        `url = "${url}"\nheader = "Authorization: Bearer mytoken"\n`
      )
    })

    it("sends arbitrary headers via stdin so values are not on argv", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { Accept: "application/octet-stream", "User-Agent": "paratix/1.0" },
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall?.command).not.toContain("-H ")
      expect(curlCall?.command).not.toContain("application/octet-stream")
      expect(curlCall?.command).not.toContain("paratix/1.0")
      expect(curlCall?.options?.input).toBe(
        `url = "${url}"\nheader = "Accept: application/octet-stream"\nheader = "User-Agent: paratix/1.0"\n`
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

    it("R-0000107: rejects a poisoned mktemp output (locale warning) without curl/mv/rm", async () => {
      // Older paratix versions handed every byte from `mktemp` straight
      // into curl, mv, chmod/chown and rm -f. A locale warning prepended
      // by a hostile or misconfigured shell would turn into a path like
      //   "mktemp: ungültiges Format ...\n/usr/local/bin/.paratix-download.AbCdEf"
      // and silently steer the curl pipeline at an unexpected location.
      // validateMktempPath rejects the entire payload instead.
      const poisonedOutput =
        "mktemp: ungültiges Format ...\n/usr/local/bin/.paratix-download.AbCdEf"
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: poisonedOutput,
        },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
        /mktemp produced an unexpected path/v
      )
      // The downstream pipeline must not have run.
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mv "))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("rm -f"))).toBe(true)
    })

    it("R-0000107: rejects a mktemp output that escapes the destination directory", async () => {
      // A `mktemp` whose stdout points to a different directory (e.g.
      // /tmp instead of /usr/local/bin) must not be used as the temp
      // path — curl, mv and rm -f would otherwise act on a file outside
      // the dedicated namespace.
      const escapedTemporaryPath = "/tmp/.paratix-download.AbCdEf"
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${escapedTemporaryPath}\n`,
        },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
        /mktemp produced an unexpected path/v
      )
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mv "))).toBe(true)
    })

    it("preserves the primary download error when cleanup also fails", async () => {
      const primaryError = new Error("curl failed")
      const cleanupError = new Error("cleanup failed")
      const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)
      try {
        const base = createMockSsh({
          [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
        })
        const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
        const cleanupCommand = `rm -f '${temporaryDestination}'`
        const execMock = vi
          .fn<(command: string) => Promise<{ code: number; stderr: string; stdout: string }>>()
          .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
          .mockRejectedValueOnce(primaryError)
          .mockRejectedValueOnce(cleanupError)
        const mockSsh = {
          ...base,
          async exec(command: string) {
            base.calls.push(command)
            return execMock(command)
          },
        }

        const mod = download.url(destination, url, allowUnverifiedDownload)
        await expect(mod.apply(mockSsh, emptyEnv)).rejects.toBe(primaryError)
        expect(execMock).toHaveBeenCalledTimes(3)
        expect(base.calls).toStrictEqual([
          `mkdir -p "$(dirname '${destination}')"`,
          `mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`,
          curlCommand,
          cleanupCommand,
        ])
        expect(stderrSpy).toHaveBeenCalledWith(
          `Warning: failed to remove temp file ${temporaryDestination}: Error: cleanup failed\n`
        )
      } finally {
        stderrSpy.mockRestore()
      }
    })

    // ─── R-0000062: metadata-only fast path ─────────────────────────────────
    describe("metadata-only fast path", () => {
      it("returns ok when sha256 and requested metadata already match", async () => {
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
          [`stat -c '%a %U %G' '${destination}'`]: { stdout: "755 deploy staff" },
        })
        const mod = download.url(destination, url, {
          group: "staff",
          mode: "0755",
          owner: "deploy",
          sha256,
        })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("ok")
        expect(mockSsh.calls).toContain(`stat -c '%a %U %G' '${destination}'`)
        expect(mockSsh.calls.every((c) => !c.startsWith("chmod"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("chown"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      })

      it("returns changed and applies only drifted metadata when sha256 matches", async () => {
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
          [`stat -c '%a %U %G' '${destination}'`]: { stdout: "755 root staff" },
        })
        const mod = download.url(destination, url, {
          group: "staff",
          mode: "0755",
          owner: "deploy",
          sha256,
        })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls).not.toContain(`chmod '0755' '${destination}'`)
        expect(mockSsh.calls).toContain(`chown -- 'deploy:staff' '${destination}'`)
        expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      })

      it("heals mode drift via chmod only when sha256 matches and destination exists", async () => {
        // Existing destination already matches the expected sha256 — only
        // mode drifted. Apply must chmod and skip curl entirely.
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
        })
        const mod = download.url(destination, url, { mode: "0755", sha256 })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls).toContain(`chmod '0755' '${destination}'`)
        expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("mv "))).toBe(true)
      })

      it("heals owner drift via chown only when sha256 matches and destination exists", async () => {
        // Existing destination already matches the expected sha256 — only
        // owner drifted. Apply must chown the existing file and skip curl.
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
        })
        const mod = download.url(destination, url, { owner: "deploy", sha256 })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls).toContain(`chown -- 'deploy:' '${destination}'`)
        expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
      })

      it("falls back to a full curl download when sha256 does not match", async () => {
        // Destination exists but its hash is wrong — fast path must bail and
        // the slow path must run a real curl transfer through a temp file.
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
          [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
          [`sha256sum '${destination}'`]: {
            stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${destination}`,
          },
          [`sha256sum '${temporaryDestination}'`]: {
            stdout: `${sha256}  ${temporaryDestination}`,
          },
        })
        const mod = download.url(destination, url, { sha256 })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls).toContain(
          `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
        )
        expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
      })

      it("forces a full curl download when force is true even if sha256 matches", async () => {
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
          [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
          [`sha256sum '${temporaryDestination}'`]: {
            stdout: `${sha256}  ${temporaryDestination}`,
          },
        })
        const mod = download.url(destination, url, { force: true, sha256 })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls).not.toContain(`sha256sum '${destination}'`)
        expect(mockSsh.calls).toContain(
          `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
        )
        expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
      })

      it("never enters the fast path when sha256 is not provided", async () => {
        // Without sha256 the hash check cannot vouch for the on-disk content,
        // so apply must always run curl through the slow path.
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
        })
        const mod = download.url(destination, url, allowUnverifiedDownload)
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls).toContain(
          `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
        )
      })

      it("registers parameters.secrets so secret-sink behavior remains identical on the fast path", async () => {
        // Authorization-style headers must remain registered with the secret
        // sink even when curl is skipped, so any error masking still works.
        const token = "supersecret-bearer-token"
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
        })
        const mod = download.url(destination, url, {
          headers: { Authorization: `Bearer ${token}` },
          mode: "0755",
          sha256,
        })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("changed")
        expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
        expect(mockSsh.calls).toContain(`chmod '0755' '${destination}'`)
      })
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

    it("redacts URL credentials from rejected download.url schemes", () => {
      const secretUrl = "http://user:s3cr3t@example.com/file?download=true"

      expect(() => download.url(destination, secretUrl, allowUnverifiedDownload)).toThrow(
        "http://REDACTED:REDACTED@example.com/file?download=true"
      )
      expect(() => download.url(destination, secretUrl, allowUnverifiedDownload)).not.toThrow(
        /user|s3cr3t/v
      )
    })

    it("redacts sensitive query values from rejected download.url schemes", () => {
      const secretUrl =
        "http://example.com/file?token=abc123&signature=sig456&download=true&monkey=banana"

      expect(() => download.url(destination, secretUrl, allowUnverifiedDownload)).toThrow(
        "token=REDACTED&signature=REDACTED&download=true&monkey=banana"
      )
      expect(() => download.url(destination, secretUrl, allowUnverifiedDownload)).not.toThrow(
        /abc123|sig456/v
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

    it("rejects URLs with embedded credentials", () => {
      expect(() =>
        download.url(destination, "https://user:secret@example.com/file", allowUnverifiedDownload)
      ).toThrow("must not embed credentials")
    })
  })

  describe("secrets propagation", () => {
    const stub = downloadMktempStub(destination, temporaryDestination)

    it("passes header values as secrets when exec is called for curl", async () => {
      const token = "supersecret-bearer-token"
      const mock = createMockSshWithOptions(stub)
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
      const mock = createMockSshWithOptions(stub)
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toStrictEqual([])
    })

    it("passes presigned URLs as secrets when query parameters look sensitive", async () => {
      const presignedUrl =
        "https://example.com/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=super-secret-signature"
      const mock = createMockSshWithOptions(stub)
      const mod = download.url(destination, presignedUrl, allowUnverifiedDownload)
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toContain(presignedUrl)
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
        [`[ -f '${destination}' ]`]: { code: 0 },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when file does not exist", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 1 },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when the destination exists but is not a regular file", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 1 },
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

    it("returns needs-apply when owner or group drift", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`stat -c '%a %U %G' '${destination}'`]: { stdout: "755 root wheel" },
      })
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        group: "staff",
        owner: "deploy",
        repo,
        tag,
      })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when ssh is null", async () => {
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(null, emptyEnv)
      expect(result).toBe("needs-apply")
    })
  })

  describe("apply", () => {
    it("builds correct GitHub release URL via curl --config from stdin", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      )
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall?.options?.input).toBe(`url = "${expectedUrl}"\n`)
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("cleans up the temporary file and leaves destination untouched when curl fails", async () => {
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      const curlError = new Error("curl failed")
      const mockSsh = createMockSshWithFailingCurl({
        curlCommand,
        curlError,
        destination,
        temporaryDestination,
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })

      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toBe(curlError)

      expect(mockSsh.calls).toContain(curlCommand)
      expect(mockSsh.calls).toContain(`rm -f '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv '${temporaryDestination}' '${destination}'`)
    })

    it("sends Authorization and Accept via stdin when a token is provided", async () => {
      // R-0000037: the GitHub PAT must not be inlined into the curl argv,
      // because sudo logging would persist it in /var/log/auth.log and
      // ps -ef / /proc/<pid>/cmdline would expose it during the download.
      const token = "ghp_supersecrettoken"
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo,
        tag,
        token,
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // Neither custom header value may appear on argv.
      expect(curlCall?.command).not.toContain("application/octet-stream")
      expect(curlCall?.command).not.toContain("Authorization")
      expect(curlCall?.command).not.toContain(token)
      // Headers are delivered via stdin.
      expect(curlCall?.options?.input).toContain(`header = "Authorization: token ${token}"`)
      expect(curlCall?.options?.input).toContain(`header = "Accept: application/octet-stream"`)
    })

    it("does not send Authorization header when no token is provided", async () => {
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      await mod.apply(mockSsh, emptyEnv)
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.command).not.toContain("Authorization")
      expect(curlCall?.options?.input).not.toContain("Authorization")
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
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo,
        tag: tagWithSpecialChars,
      })
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // The "+" must appear as "%2B" in the URL, not as a literal "+"
      expect(curlCall?.options?.input).toContain(encodeURIComponent(tagWithSpecialChars))
      expect(curlCall?.options?.input).not.toContain(`/${tagWithSpecialChars}/`)
    })

    it("percent-encodes special characters in asset when building the download URL", async () => {
      // Asset names like "my tool 1.0.zip" contain spaces that must be
      // percent-encoded. Without encodeURIComponent the space is passed raw,
      // which produces an invalid URL in the curl command.
      const assetWithSpace = "my tool 1.0.zip"
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset: assetWithSpace,
        repo,
        tag,
      })
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // The space must appear as "%20" in the URL, not as a literal space
      expect(curlCall?.options?.input).toContain(encodeURIComponent(assetWithSpace))
      expect(curlCall?.options?.input).not.toContain(` ${assetWithSpace}"`)
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
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo: repoWithSpecialChars,
        tag,
      })
      await mod.apply(mockSsh, emptyEnv)

      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall).toBeDefined()
      // Both owner and repo must appear percent-encoded in the URL
      expect(curlCall?.options?.input).toContain(
        `https://github.com/${encodedOwner}/${encodedRepo}/`
      )
      // The raw "+" and "%" must not appear in the path segments
      expect(curlCall?.options?.input).not.toContain("/my+org/")
      expect(curlCall?.options?.input).not.toContain("/my%repo/")
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
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when flag and destination both do not exist", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when flag exists but destination file is missing", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when flag exists but destination is not a regular file", async () => {
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when flag exists and sha256 matches", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
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

    it("returns needs-apply when mode drifts despite flag and matching SHA-256", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
        [`stat -c '%a %U %G' '${destination}'`]: { stdout: "644 root root" },
      })
      const mod = download.large(destination, url, { mode: "0600", sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when group drifts despite flag and existing destination", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
        [`stat -c '%a %U %G' '${destination}'`]: { stdout: "644 root wheel" },
      })
      const mod = download.large(destination, url, {
        ...allowUnverifiedDownload,
        group: "staff",
      })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when flag does not exist and destination is missing despite sha256", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply without setting the flag when destination exists and sha256 matches but flag is missing", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
      expect(mockSsh.calls).not.toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mockSsh.calls).not.toContain(`sha256sum '${destination}'`)
    })

    it("does not set the flag during recovery when sha256 mismatches", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 1 },
        [`sha256sum '${destination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${destination}`,
        },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
      expect(mockSsh.calls).not.toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
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

    it("direct apply returns ok without downloading when the flag already exists", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result).toStrictEqual({ status: "ok" })
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
      expect(mockSsh.calls).not.toContain(`mkdir /var/lib/paratix/flags/'${flagName}.lock'`)
    })

    it("repairs a missing destination even when the flag already exists", async () => {
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [`[ -f '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      )
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
    })

    it("repairs metadata drift when the flag already exists", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
        [`stat -c '%a %U %G' '${destination}'`]: { stdout: "644 root root" },
      })
      const mod = download.large(destination, url, { mode: "0755", sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chmod '0755' '${destination}'`)
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
    })

    it("downloads file via curl --config from stdin and sets flag on success", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      )
      const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl -fsSL"))
      expect(curlCall?.options?.input).toBe(`url = "${url}"\n`)
      expect(mockSsh.calls).toContain(`mv '${temporaryDestination}' '${destination}'`)
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
    })

    it("cleans up the temporary file and does not set the flag when curl fails", async () => {
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      const curlError = new Error("curl failed")
      const mockSsh = createMockSshWithFailingCurl({
        curlCommand,
        curlError,
        destination,
        temporaryDestination,
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)

      await expect(mod.apply(mockSsh, emptyEnv)).rejects.toBe(curlError)

      expect(mockSsh.calls).toContain(curlCommand)
      expect(mockSsh.calls).toContain(`rm -f '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv '${temporaryDestination}' '${destination}'`)
      expect(mockSsh.calls).not.toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
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

    // R-0000062: download.large must still invoke setFlag when the metadata-only
    // fast path returns "changed", because performDownload exits without going
    // through the curl + mv sequence that historically preceded setFlag.
    it("sets flag after the fast-path metadata heal when sha256 matches existing destination", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.large(destination, url, { mode: "0755", sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`chmod '0755' '${destination}'`)
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
    })

    it("sets flag and reports changed when fast path finds matching content and metadata", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(`touch /var/lib/paratix/flags/'${flagName}'`)
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
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

    it("does not echo malformed download.large URLs in validation errors", () => {
      const secretUrl = "https://example .com/large-file.iso?token=abc123"

      expect(() => download.large(destination, secretUrl, allowUnverifiedDownload)).toThrow(
        "Invalid URL: expected an http or https URL"
      )
      expect(() => download.large(destination, secretUrl, allowUnverifiedDownload)).not.toThrow(
        /abc123|example \.com/v
      )
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

    it("redacts URL credentials and sensitive query values from rejected download.large schemes", () => {
      const secretUrl = "http://user:s3cr3t@example.com/large-file.iso?sig=abc123&expires=123"

      expect(() => download.large(destination, secretUrl, allowUnverifiedDownload)).toThrow(
        "http://REDACTED:REDACTED@example.com/large-file.iso?sig=REDACTED&expires=123"
      )
      expect(() => download.large(destination, secretUrl, allowUnverifiedDownload)).not.toThrow(
        /user|s3cr3t|abc123/v
      )
    })
  })

  describe("secrets propagation", () => {
    const stub = downloadMktempStub(destination, temporaryDestination)

    it("passes all non-empty header values as secrets when exec is called for curl", async () => {
      const token = "supersecret-bearer-token"
      const apiKey = "supersecret-api-key"
      const mock = createMockSshWithOptions(stub)
      const mod = download.large(destination, url, {
        ...allowUnverifiedDownload,
        headers: { Authorization: `Bearer ${token}`, "X-Api-Key": apiKey, "X-Empty": "" },
      })
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toContain(`Bearer ${token}`)
      expect(curlCall?.options?.secrets).toContain(apiKey)
      expect(curlCall?.options?.secrets).not.toContain("")
    })

    it("passes an empty secrets array when no headers are provided", async () => {
      const mock = createMockSshWithOptions(stub)
      const mod = download.large(destination, url, allowUnverifiedDownload)
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toStrictEqual([])
    })

    it("passes presigned URLs as secrets when query parameters look sensitive", async () => {
      const presignedUrl =
        "https://example.com/large-file.iso?token=opaque-download-token&expires=123"
      const mock = createMockSshWithOptions(stub)
      const mod = download.large(destination, presignedUrl, allowUnverifiedDownload)
      await mod.apply(mock, emptyEnv)

      const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
      expect(curlCall).toBeDefined()
      expect(curlCall?.options?.secrets).toContain(presignedUrl)
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
  const temporaryDestination = "/tmp/.paratix-download.HDR1"
  const url = "https://example.com/file"
  const stub = downloadMktempStub(destination, temporaryDestination)

  it("throws when header name contains \\r\\n (CRLF injection)", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Evil\r\nX-Injected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\n", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Evil\nInjected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\r", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Evil\rInjected": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a control character (\\x01)", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Bad\x01Name": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a colon", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Bad:Name": "value" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow("Invalid HTTP header name")
  })

  it("accepts a valid single-word header name (Authorization routed via stdin)", async () => {
    // R-0000037: Authorization is sensitive and is now passed via curl
    // --config from stdin. The header name stays accepted by the validator,
    // but no longer appears on argv.
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { Authorization: "Bearer token123" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl"))
    expect(curlCall?.command).not.toContain("-H 'Authorization")
    expect(curlCall?.options?.input).toContain(`header = "Authorization: Bearer token123"`)
  })

  it("accepts a valid hyphenated header name", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom-Header": "some-value" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl"))
    expect(curlCall?.command).not.toContain("-H 'X-Custom-Header")
    expect(curlCall?.options?.input).toContain(`header = "X-Custom-Header: some-value"`)
  })
})

// ─── Header-Value-Validierung (Regressionstests) ──────────────────────────────

describe("buildCurlCommand — header value validation", () => {
  const destination = "/tmp/file"
  const temporaryDestination = "/tmp/.paratix-download.HDR2"
  const url = "https://example.com/file"
  const stub = downloadMktempStub(destination, temporaryDestination)

  it("throws when header value contains \\r (CR injection)", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom": "value\rX-Injected: injected" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "Invalid HTTP header value for X-Custom: value contains newline characters"
    )
  })

  it("throws when header value contains \\n (LF injection)", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom": "value\nX-Injected: injected" },
    })
    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      "Invalid HTTP header value for X-Custom: value contains newline characters"
    )
  })

  it("accepts a normal header value without newline characters", async () => {
    const mockSsh = createMockSsh(stub)
    const mod = download.url(destination, url, {
      ...allowUnverifiedDownload,
      headers: { "X-Custom": "safe-value" },
    })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const curlCall = mockSsh.execCalls.find((entry) => entry.command.startsWith("curl"))
    expect(curlCall?.command).not.toContain("-H 'X-Custom")
    expect(curlCall?.options?.input).toContain(`header = "X-Custom: safe-value"`)
  })
})

describe("buildCurlCommand — URL config value validation", () => {
  const destination = "/tmp/file"
  const unsafeUrl = 'https://example.com/file\nheader = "X-Injected: yes"?token=secret'

  it("throws when download.url receives a URL containing a newline", () => {
    expect(() => {
      download.url(destination, unsafeUrl, allowUnverifiedDownload)
    }).toThrow("URL must not contain CR, LF, or NUL characters")
  })

  it("does not echo unsafe download.url values in validation errors", () => {
    expect(() => {
      download.url(destination, unsafeUrl, allowUnverifiedDownload)
    }).toThrow(/^(?!.*token=secret).*$/v)
  })

  it("throws when download.large receives a URL containing a newline", () => {
    expect(() => {
      download.large(destination, unsafeUrl, allowUnverifiedDownload)
    }).toThrow("URL must not contain CR, LF, or NUL characters")
  })
})

describe("buildCurlCommand — redirect protocol policy", () => {
  const destination = "/tmp/file"
  const httpsUrl = "https://example.com/file"
  const tempPath = "/tmp/.paratix-download.RDR1"
  const githubDestination = "/usr/local/bin/terraform"
  const githubTempPath = "/usr/local/bin/.paratix-download.RDR2"
  const largeDestination = "/var/cache/big.iso"
  const largeTempPath = "/var/cache/.paratix-download.RDR3"

  it("restricts initial URL and redirects to https by default", async () => {
    const mockSsh = createMockSsh(downloadMktempStub(destination, tempPath))
    const mod = download.url(destination, httpsUrl, allowUnverifiedDownload)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const curlCall = mockSsh.calls.find((call) => call.startsWith("curl -fsSL"))
    expect(curlCall).toContain(httpsOnlyCurlProtocolFlags)
  })

  it("allows http and https for initial URL and redirects when allowInsecureHttp is true", async () => {
    const mockSsh = createMockSsh(downloadMktempStub(destination, tempPath))
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
    const mockSsh = createMockSsh(downloadMktempStub(githubDestination, githubTempPath))
    const mod = download.github(githubDestination, {
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
    const mockSsh = createMockSsh(downloadMktempStub(largeDestination, largeTempPath))
    const mod = download.large(largeDestination, "http://example.com/big.iso", {
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
  const temporaryDestination = "/usr/local/bin/.paratix-download.GH9999"
  const repo = "hashicorp/terraform"
  const tag = "v1.5.0"
  const asset = "terraform_1.5.0_linux_amd64.zip"
  const stub = downloadMktempStub(destination, temporaryDestination)

  it("passes token as secrets when exec is called for curl", async () => {
    const token = "ghp_supersecrettoken"
    const mock = createMockSshWithOptions(stub)
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
    const mock = createMockSshWithOptions(stub)
    const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
    await mod.apply(mock, emptyEnv)

    const curlCall = mock.execCalls.find(({ command }) => command.startsWith("curl"))
    expect(curlCall).toBeDefined()
    expect(curlCall?.options?.secrets).toBeUndefined()
  })
})
