import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"

import type { ExecOptions } from "../../src/types.js"

import { download } from "../../src/modules/download.js"
import { registerSecret, unregisterSecret } from "../../src/secretSink.js"
import { createMockSsh as createBaseMockSsh, type ExecCall } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    allowFlagLockInternalDefaults: true,
    allowWrites: [
      { options: { mode: "0644" }, remotePath: /^.*\.sha256$/v },
      ...(options?.allowWrites ?? []),
    ],
    responseStubs: [
      { command: /^\[ -e '\/(?:opt|usr)\//v, result: { code: 1 } },
      { command: /^\[ -d '\/(?:opt|tmp|usr|var)\//v, result: { code: 1 } },
      { command: /^\[ -f '\/(?:opt|usr)\//v, result: { code: 1 } },
      // eslint-disable-next-line security/detect-unsafe-regex -- bounded character class, not user input
      { command: /^\[ -L '\/(?:opt|tmp|usr|var)(?:\/[^']*)?' \]$/v, result: { code: 1 } },
      { command: /^stat -c '%a %U %G' '\/(?:opt|usr)\//v, result: { stdout: "644 root root" } },
      // R-0000673: createDownloadTargetDirectory walks each ancestor of the
      // download dirname and creates missing levels with a per-level
      // [ ! -L ] guard rather than a single `mkdir -p`. The stub matches the
      // composite "if [ -L X ]; then …; mkdir -- X …" command for any
      // ancestor under the allowed prefixes.
      {
        // eslint-disable-next-line security/detect-unsafe-regex -- bounded character class, not user input
        command: /^if \[ -L '\/(?:opt|tmp|usr|var)(?:\/[^']*)?' \];/v,
        result: { code: 0 },
      },
      ...buildSafeDownloadApplyStubs(),
      { command: /^\[ -f \/var\/lib\/paratix\/flags\//v, result: { code: 1 } },
      { command: /^mkdir \/var\/lib\/paratix\/flags\/.*\.lock'/v, result: { code: 0 } },
      { command: /^rmdir \/var\/lib\/paratix\/flags\/.*\.lock'/v, result: { code: 0 } },
      { command: /^touch \/var\/lib\/paratix\/flags\//v, result: { code: 0 } },
      // R-0000274: download.large now persists its flag via setVersionedFlag,
      // which combines `find … -delete` with `touch …` in a single command.
      // Stub matches both download-large- and the legacy download- prefix.
      {
        command:
          /^find \/var\/lib\/paratix\/flags -maxdepth 1 -name '[^']+' ! -name '\*\.lock' -delete && touch \/var\/lib\/paratix\/flags\//v,
        result: { code: 0 },
      },
      // R-0000167: download.url's hash marker write is best-effort. The
      // sha256 probe / writeFile allowlist lets pre-marker tests
      // succeed without stubbing every post-mv destination probe. The
      // marker file probe is stubbed false so legacy tests that do not
      // exercise the marker take the "missing marker" path.
      { command: /^\[ -L '[^']*\.sha256' \]$/v, result: { code: 1 } },
      { command: /^\[ -f '[^']*\.sha256' \]$/v, result: { code: 1 } },
      { command: /^\[ -f '\/tmp\/file' \]$/v, result: { code: 0 } },
      { command: /^sha256sum '\/tmp\/file'$/v, result: { stdout: `${"0".repeat(64)}  /tmp/file` } },
      { command: /^cat '[^']*\.sha256'$/v, result: { stdout: "" } },
      ...(options?.responseStubs ?? []),
    ],
  })

const emptyEnv = {}
const allowUnverifiedDownload = { allowUnverifiedDownload: true } as const
const defaultCurlTimeoutFlags = "--connect-timeout '10' --max-time '300'"
const httpsOnlyCurlProtocolFlags = `${defaultCurlTimeoutFlags} --proto '=https' --proto-redir '=https'`
const insecureHttpCurlProtocolFlags = `${defaultCurlTimeoutFlags} --proto '=http,https' --proto-redir '=http,https'`

function buildSafeDownloadApplyStubs(): NonNullable<
  NonNullable<Parameters<typeof createBaseMockSsh>[1]>["responseStubs"]
> {
  return [
    {
      command:
        // eslint-disable-next-line security/detect-unsafe-regex -- bounded mock command regex, not user input
        /^curl -fsSL -o '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*\/\.paratix-download\.[^\/']+' --connect-timeout '10' --max-time '300' --proto '=(?:https|http,https)' --proto-redir '=(?:https|http,https)' --config -$/v,
      result: { code: 0 },
    },
    {
      // eslint-disable-next-line security/detect-unsafe-regex -- bounded mock command regex, not user input
      command: /^chmod '[0-7]{3,4}' '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*'$/v,
      result: { code: 0 },
    },
    {
      command:
        // eslint-disable-next-line security/detect-unsafe-regex -- bounded mock command regex, not user input
        /^chown -- '(?:\w[\w.\-]*)?:(?:\w[\w.\-]*)?' '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*'$/v,
      result: { code: 0 },
    },
    {
      command:
        // R-0000696: the final mv now runs as a single shell pipeline with
        // inline parent/destination symlink and directory guards so any
        // attacker-planted symlink between the earlier probe and the rename
        // is rejected before mv resolves the destination path.
        // eslint-disable-next-line security/detect-unsafe-regex -- bounded mock command regex, not user input
        /^\[ ! -L '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*' \] && \[ ! -L '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*' \] && \[ ! -d '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*' \] && mv -T -- '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*\/\.paratix-download\.[^\/']+' '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*'$/v,
      result: { code: 0 },
    },
    {
      // eslint-disable-next-line security/detect-unsafe-regex -- bounded mock command regex, not user input
      command: /^rm -f -- '\/(?:opt|tmp|usr|var)(?:\/[^\/']+)*\/\.paratix-download\.[^\/']+'$/v,
      result: { code: 0 },
    },
  ]
}

// R-0000274: keep this helper aligned with `buildLargeDownloadFlagInfo` in
// download.ts: a destination-keyed prefix wraps the URL/headers-keyed
// flag hash so older flag files for the same destination get evicted on
// re-convergence by setVersionedFlag.
function buildLargeDownloadFlagPrefix(destination: string): string {
  const destinationHash = createHash("sha256").update(destination).digest("hex")
  return `download-large-${destinationHash}-`
}

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
  const flagHash = createHash("sha256").update(flagKey).digest("hex")
  return `${buildLargeDownloadFlagPrefix(parameters.destination)}${flagHash}`
}

/**
 * R-0000274: replicate the exact `find … -delete && touch …` command
 * `setVersionedFlag` issues, so existing assertions can pivot from
 * `touch …` to the combined command without each test redoing the math.
 *
 * @param parameters - Destination context.
 * @param parameters.destination - Download destination (drives the flag prefix).
 * @param parameters.flagName - The full versioned flag name written on success.
 * @returns The exact shell command string the helper executes.
 */
function buildLargeDownloadVersionedFlagCommand(parameters: {
  destination: string
  flagName: string
}): string {
  const flagPrefix = buildLargeDownloadFlagPrefix(parameters.destination)
  return `find /var/lib/paratix/flags -maxdepth 1 -name '${flagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${parameters.flagName}'`
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
    [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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

function createMockSshWithDestinationSymlinkAfterFirstProbe(parameters: {
  destination: string
  temporaryDestination: string
}): ReturnType<typeof createMockSsh> {
  const base = createMockSsh(
    downloadMktempStub(parameters.destination, parameters.temporaryDestination)
  )
  let destinationSymlinkChecks = 0
  const baseTest = base.test.bind(base)

  return {
    ...base,
    async test(command: string) {
      if (command === `[ -L '${parameters.destination}' ]`) {
        base.calls.push(command)
        destinationSymlinkChecks += 1
        return destinationSymlinkChecks > 1
      }

      return baseTest(command)
    },
  }
}

function buildGuardedMoveCommand(parameters: {
  destination: string
  temporaryDestination: string
}): string {
  const lastSlash = parameters.destination.lastIndexOf("/")
  const parentDirectory = lastSlash <= 0 ? "/" : parameters.destination.slice(0, lastSlash)
  // R-0000696: must match the single-pipeline guarded mv in
  // `finalizeDownloadedFile` (parent symlink, destination symlink and
  // destination directory probes followed by the atomic rename).
  return (
    `[ ! -L '${parentDirectory}' ] && ` +
    `[ ! -L '${parameters.destination}' ] && ` +
    `[ ! -d '${parameters.destination}' ] && ` +
    `mv -T -- '${parameters.temporaryDestination}' '${parameters.destination}'`
  )
}

function expectSafeCurlDownloadPipeline(parameters: {
  destination: string
  mockSsh: ReturnType<typeof createMockSsh>
  protocolFlags?: string
  temporaryDestination: string
  urlInput: string
}): void {
  const protocolFlags = parameters.protocolFlags ?? httpsOnlyCurlProtocolFlags
  const curlCommand = `curl -fsSL -o '${parameters.temporaryDestination}' ${protocolFlags} --config -`
  const moveCommand = buildGuardedMoveCommand({
    destination: parameters.destination,
    temporaryDestination: parameters.temporaryDestination,
  })
  const cleanupCommand = `rm -f -- '${parameters.temporaryDestination}'`
  const curlCall = parameters.mockSsh.execCalls.find((entry) => entry.command === curlCommand)

  expect(parameters.mockSsh.calls).toContain(
    `mktemp "$(dirname -- '${parameters.destination}')/.paratix-download.XXXXXX"`
  )
  expect(curlCall).toBeDefined()
  expect(curlCall?.command).not.toContain(parameters.urlInput)
  expect(curlCall?.options?.input).toBe(`url = "${parameters.urlInput}"\n`)
  expect(parameters.mockSsh.calls).toContain(moveCommand)
  expect(parameters.mockSsh.calls).toContain(cleanupCommand)
  expect(parameters.mockSsh.calls).not.toContain(`rm -f -- '${parameters.destination}'`)
}

function commandIndexes(calls: string[], expectedCommand: string): number[] {
  return calls.flatMap((command, index) => (command === expectedCommand ? [index] : []))
}

// R-0000673: createDownloadTargetDirectory issues one command per ancestor of
// the download dirname instead of a single `mkdir -p`. The shell snippet
// guards each level with `[ -L ]` before and after `mkdir`, closing the race
// where an attacker could plant a symlink between the pre-check and a
// recursive `mkdir -p` resolving missing levels.
function buildAncestorMkdirCommand(ancestor: string): string {
  const quoted = `'${ancestor.replaceAll("'", "'\\''")}'`
  return (
    `if [ -L ${quoted} ]; then ` +
    `printf 'ancestor is symlink: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi; ` +
    `if [ ! -e ${quoted} ]; then ` +
    `mkdir -- ${quoted} || exit 1; ` +
    `if [ -L ${quoted} ]; then ` +
    `printf 'ancestor became symlink after mkdir: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi; ` +
    `elif [ ! -d ${quoted} ]; then ` +
    `printf 'ancestor exists but is not a directory: %s\\n' ${quoted} >&2; exit 1; ` +
    `fi`
  )
}

function buildAncestorMkdirCommandsForDestination(destinationPath: string): string[] {
  const targetDirectory = destinationPath.slice(0, destinationPath.lastIndexOf("/"))
  const ancestors: string[] = []
  let current = targetDirectory
  while (current !== "" && current !== "/") {
    ancestors.push(current)
    const lastSlash = current.lastIndexOf("/")
    current = lastSlash <= 0 ? "/" : current.slice(0, lastSlash)
  }
  return ancestors.toReversed().map((ancestor) => buildAncestorMkdirCommand(ancestor))
}

function lastAncestorMkdirCommandForDestination(destinationPath: string): string {
  const commands = buildAncestorMkdirCommandsForDestination(destinationPath)
  const last = commands.at(-1)
  if (last === undefined) {
    throw new Error(`destination has no ancestor directories: ${destinationPath}`)
  }
  return last
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

    it("returns ok when file and marker hash match (no sha256, allowUnverifiedDownload)", async () => {
      // R-0000167: with allowUnverifiedDownload + no sha256, the check now
      // requires `<destination>.sha256` to exist and to match the actual
      // file digest. Existence alone is not sufficient any more.
      // R-0000529: symlink guard and read are fused into a single shell command.
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const markerPath = `${destination}.sha256`
      const fusedMarkerCommand = `[ ! -L '${markerPath}' ] && [ -f '${markerPath}' ] && cat -- '${markerPath}'`
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f '${markerPath}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${recordedHash}  ${destination}` },
        [fusedMarkerCommand]: { code: 0, stdout: `${recordedHash}\n` },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when the marker path is a symlink", async () => {
      // R-0000529: the fused command `[ ! -L p ] && [ -f p ] && cat -- p`
      // exits non-zero when the marker is a symlink (first guard fails),
      // so compareUnverifiedHashMarker returns "drift".
      const markerPath = `${destination}.sha256`
      const fusedMarkerCommand = `[ ! -L '${markerPath}' ] && [ -f '${markerPath}' ] && cat -- '${markerPath}'`
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f '${markerPath}' ]`]: { code: 0 },
        [fusedMarkerCommand]: { code: 1 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
      expect(mockSsh.calls).not.toContain(`cat '${markerPath}'`)
    })

    it("returns needs-apply when marker file is missing (no sha256)", async () => {
      // R-0000167: a file from a pre-marker run (or from an out-of-band
      // copy) has no `<destination>.sha256` next to it. Check must report
      // needs-apply so the next apply run records the marker.
      const mockSsh = createMockSsh({
        [`[ -f '${destination}.sha256' ]`]: { code: 1 },
        [`[ -f '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when marker hash differs from current file hash (no sha256)", async () => {
      // R-0000167: post-write tampering (or a stale URL update) flips the
      // file digest while the marker stays at the previous value. Check
      // must surface that as needs-apply so apply re-downloads.
      // R-0000529: symlink guard and read are fused into a single shell command.
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const tamperedHash = "1111111111111111111111111111111111111111111111111111111111111111"
      const markerPath = `${destination}.sha256`
      const fusedMarkerCommand = `[ ! -L '${markerPath}' ] && [ -f '${markerPath}' ] && cat -- '${markerPath}'`
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f '${markerPath}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${tamperedHash}  ${destination}` },
        [fusedMarkerCommand]: { code: 0, stdout: `${recordedHash}\n` },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when the marker cannot be read", async () => {
      // R-0000529: symlink guard and read are fused; a non-zero exit code
      // (e.g. permission error or symlink) causes compareUnverifiedHashMarker
      // to return "drift" → needs-apply.
      const markerPath = `${destination}.sha256`
      const fusedMarkerCommand = `[ ! -L '${markerPath}' ] && [ -f '${markerPath}' ] && cat -- '${markerPath}'`
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f '${markerPath}' ]`]: { code: 0 },
        [fusedMarkerCommand]: { code: 13, stderr: "cat: Permission denied\n" },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
      expect(mockSsh.execCalls).toContainEqual({
        command: fusedMarkerCommand,
        options: { ignoreExitCode: true, silent: true },
      })
    })

    it("returns needs-apply when file path is a symlink to a regular file", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -L '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply for a symlink even when SHA-256 would match its target", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -L '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.url(destination, url, { sha256 })
      const result = await mod.check(mockSsh, emptyEnv)

      expect(result).toBe("needs-apply")
      expect(mockSsh.calls).not.toContain(`sha256sum '${destination}'`)
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
    // R-0000226: download.url must refuse to write through a symlink at the
    // destination or any ancestor of dirname(destination). Otherwise a
    // symlinked dirname would steer the temp file into an attacker-controlled
    // tree and `mv -T` could clobber the link target instead of the file.
    it("R-0000226: returns failed when destination itself is a symlink", async () => {
      const mockSsh = createMockSsh({
        [`[ -L '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("destination is a symlink")
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mv "))).toBe(true)
    })

    it("R-0000226: returns failed when an ancestor of dirname(destination) is a symlink", async () => {
      const mockSsh = createMockSsh({
        "[ -L '/usr/local/bin' ]": { code: 0 },
        [`[ -L '${destination}' ]`]: { code: 1 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("is a symlink: /usr/local/bin")
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
    })

    it("returns failed when destination becomes a symlink after curl but before mv", async () => {
      const mockSsh = createMockSshWithDestinationSymlinkAfterFirstProbe({
        destination,
        temporaryDestination,
      })
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      const mvCommand = `mv -T -- '${temporaryDestination}' '${destination}'`

      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("destination is a symlink")
      expect(mockSsh.calls).toContain(curlCommand)
      expect(mockSsh.calls).not.toContain(mvCommand)
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      const destinationSymlinkProbeIndexes = commandIndexes(
        mockSsh.calls,
        `[ -L '${destination}' ]`
      )
      expect(destinationSymlinkProbeIndexes).toHaveLength(2)
      expect(destinationSymlinkProbeIndexes[0]).toBeLessThan(mockSsh.calls.indexOf(curlCommand))
      expect(mockSsh.calls.indexOf(curlCommand)).toBeLessThan(destinationSymlinkProbeIndexes[1])
    })

    it("downloads file via curl --config from stdin and returns changed", async () => {
      // R-0000037: URLs (including signed/presigned ones) and Authorization
      // headers must not appear on argv. They are passed to curl via
      // `--config -` from stdin so they never leak into /var/log/auth.log
      // (sudo logging) or /proc/<pid>/cmdline / ps -ef.
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expectSafeCurlDownloadPipeline({
        destination,
        mockSsh,
        temporaryDestination,
        urlInput: url,
      })
    })

    it("passes custom curl timeout flags and SSH exec timeout", async () => {
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' --connect-timeout '2.5' --max-time '15' --proto '=https' --proto-redir '=https' --config -`
      const mockSsh = createMockSsh(
        {
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
        },
        {
          responseStubs: [{ command: curlCommand, result: { code: 0 } }],
        }
      )
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        connectTimeout: 2500,
        timeout: 15_000,
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      const curlCall = mockSsh.execCalls.find((entry) => entry.command === curlCommand)
      expect(result.status).toBe("changed")
      expect(curlCall?.options?.timeout).toBe(15_000)
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
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
    })

    it("fails and cleans up when the destination already exists as a directory", async () => {
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [`[ -d '${destination}' ]`]: { code: 0 },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("destination is a directory")
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
    })

    it("creates target directory via per-level guarded mkdir", async () => {
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await mod.apply(mockSsh, emptyEnv)
      for (const command of buildAncestorMkdirCommandsForDestination(destination)) {
        expect(mockSsh.calls).toContain(command)
      }
    })

    // R-0000673: closing the TOCTOU between ensureDownloadDestinationNotSymlinked
    // and `mkdir -p` requires the create step to walk the ancestors top-down
    // with a per-level [ ! -L ] guard. Verify the ordering and that no plain
    // `mkdir -p "$(dirname ...)"` slips back in.
    it("walks ancestors top-down with per-level symlink guard", async () => {
      const mockSsh = createMockSsh(downloadMktempStub(destination, temporaryDestination))
      const mod = download.url(destination, url, allowUnverifiedDownload)
      await mod.apply(mockSsh, emptyEnv)
      const ancestorCommands = buildAncestorMkdirCommandsForDestination(destination)
      const indexes = ancestorCommands.map((command) => mockSsh.calls.indexOf(command))
      expect(indexes.every((index) => index >= 0)).toBe(true)
      for (let i = 1; i < indexes.length; i += 1) {
        expect(indexes[i]).toBeGreaterThan(indexes[i - 1])
      }
      expect(mockSsh.calls.some((command) => command.startsWith(`mkdir -p "$(dirname `))).toBe(
        false
      )
    })

    it("returns failedCommand and aborts before mktemp when target directory creation fails", async () => {
      const mkdirCommand = lastAncestorMkdirCommandForDestination(destination)
      const mockSsh = createMockSsh({
        [mkdirCommand]: { code: 1, stderr: "mkdir: Permission denied\n" },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("failed to create target directory")
      expect(result.error?.message).toContain("Permission denied")
      expect(
        mockSsh.execCalls.find((entry) => entry.command === mkdirCommand)?.options
      ).toMatchObject({
        ignoreExitCode: true,
        secrets: [],
        silent: true,
      })
      expect(mockSsh.calls).not.toContain(
        `mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`
      )
      expect(mockSsh.calls.every((command) => !command.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls).not.toContain(`rm -f -- '${temporaryDestination}'`)
    })

    // R-0000158: curl/mv/chmod/chown failures must surface as failedCommand
    // results instead of throwing, so callers see maskable errors with the
    // captured stdout/stderr.
    it("returns failed when curl exits non-zero (e.g. 404 / network error)", async () => {
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [curlCommand]: { code: 22, stderr: "curl: (22) HTTP error 404\n" },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("curl failed")
      expect(result.error?.message).toContain("HTTP error 404")
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
    })

    it("returns failed when mv into place exits non-zero", async () => {
      const mvCommand = buildGuardedMoveCommand({ destination, temporaryDestination })
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [mvCommand]: { code: 1, stderr: "mv: cannot move: Permission denied\n" },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("mv into place failed")
      expect(result.error?.message).toContain("Permission denied")
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
    })

    it("returns failed when chmod exits non-zero", async () => {
      const chmodCommand = `chmod '0755' '${temporaryDestination}'`
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [chmodCommand]: { code: 1, stderr: "chmod: operation not permitted\n" },
      })
      const mod = download.url(destination, url, { ...allowUnverifiedDownload, mode: "0755" })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("chmod failed")
      expect(result.error?.message).toContain("operation not permitted")
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
    })

    it("returns failed when chown exits non-zero", async () => {
      const chownCommand = `chown -- 'deploy:' '${temporaryDestination}'`
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [chownCommand]: { code: 1, stderr: "chown: invalid user\n" },
      })
      const mod = download.url(destination, url, {
        ...allowUnverifiedDownload,
        owner: "deploy",
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("chown failed")
      expect(result.error?.message).toContain("invalid user")
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
    })

    it("sets mode via chmod when mode is specified", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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

    it("writes the unverified hash marker through writeFile", async () => {
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -L '${destination}.sha256' ]`]: { code: 1 },
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${destination}'`]: { stdout: `${recordedHash}  ${destination}` },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(mockSsh.writeFileCalls).toStrictEqual([
        {
          content: `${recordedHash}\n`,
          options: { mode: "0644" },
          remotePath: `${destination}.sha256`,
        },
      ])
      expect(mockSsh.calls).not.toContain(
        `printf '%s\\n' '${recordedHash}' > '${destination}.sha256'`
      )
    })

    it("does not write the unverified hash marker through a symlink", async () => {
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -L '${destination}.sha256' ]`]: { code: 0 },
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${destination}'`]: { stdout: `${recordedHash}  ${destination}` },
      })
      const mod = download.url(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(mockSsh.writeFileCalls).toStrictEqual([])
    })

    it("verifies SHA-256 after download and returns changed on match", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.url(destination, url, { sha256 })
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`rm -f -- '${destination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
        })
        const ancestorMkdirCommands = buildAncestorMkdirCommandsForDestination(destination)
        const curlCommand = `curl -fsSL -o '${temporaryDestination}' ${httpsOnlyCurlProtocolFlags} --config -`
        const cleanupCommand = `rm -f -- '${temporaryDestination}'`
        const execMock =
          vi.fn<(command: string) => Promise<{ code: number; stderr: string; stdout: string }>>()
        // R-0000673: ancestor-by-ancestor mkdir means one resolved value per
        // ancestor before the primary error path triggers on mktemp.
        for (const _ of ancestorMkdirCommands) {
          execMock.mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
        }
        execMock.mockRejectedValueOnce(primaryError).mockRejectedValueOnce(cleanupError)
        const mockSsh = {
          ...base,
          async exec(command: string) {
            base.calls.push(command)
            return execMock(command)
          },
        }

        const mod = download.url(destination, url, allowUnverifiedDownload)
        await expect(mod.apply(mockSsh, emptyEnv)).rejects.toBe(primaryError)
        expect(execMock).toHaveBeenCalledTimes(ancestorMkdirCommands.length + 2)
        // R-0000226: the symlink guard runs `[ -L ... ]` for the destination
        // and every ancestor of dirname before the mkdir/mktemp/curl flow.
        expect(base.calls).toStrictEqual([
          `[ -L '${destination}' ]`,
          `[ -L '/usr/local/bin' ]`,
          `[ -L '/usr/local' ]`,
          `[ -L '/usr' ]`,
          ...ancestorMkdirCommands,
          `mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`,
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

    // R-0000675: the cleanup warning must mask every secret registered in the
    // global sink — not just the URL/header values the call site happens to
    // know about. A `CommandError` rejection from `rm -f` could otherwise
    // surface a `--config` stdin fragment, sudo password or op-resolved value
    // that the local `parameters.secrets` list does not include.
    it("R-0000675: cleanup warning routes through the global secret sink", async () => {
      const globalSecret = "super-secret-value-that-should-be-masked"
      const cleanupError = new Error(`rm failed: leaked ${globalSecret} via stderr`)
      const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true)
      registerSecret(globalSecret)
      try {
        const base = createMockSsh({
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
        })
        const ancestorMkdirCommands = buildAncestorMkdirCommandsForDestination(destination)
        const execMock =
          vi.fn<(command: string) => Promise<{ code: number; stderr: string; stdout: string }>>()
        for (const _ of ancestorMkdirCommands) {
          execMock.mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
        }
        // mktemp + curl succeed; the temp-file cleanup rejects with a message
        // that embeds a secret only known to the global sink.
        execMock
          .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
          .mockResolvedValueOnce({ code: 0, stderr: "", stdout: "" })
          .mockRejectedValueOnce(cleanupError)
        const mockSsh = {
          ...base,
          async exec(command: string) {
            base.calls.push(command)
            return execMock(command)
          },
        }

        const mod = download.url(destination, url, allowUnverifiedDownload)
        await mod.apply(mockSsh, emptyEnv)

        const stderrCalls = stderrSpy.mock.calls.map((entry) => String(entry[0]))
        const warning = stderrCalls.find((entry) =>
          entry.startsWith(`Warning: failed to remove temp file ${temporaryDestination}:`)
        )
        expect(warning).toBeDefined()
        expect(warning).not.toContain(globalSecret)
      } finally {
        unregisterSecret(globalSecret)
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

      // R-0000253 regression: BusyBox/POSIX `stat` may emit tabs or multiple
      // spaces between the columns. The parser must split on any whitespace
      // run (mirroring mount.ts/archive.ts) instead of a single space, or
      // else the owner/group fields end up empty and the metadata-only fast
      // path falsely reports drift.
      it("R-0000253: tolerates tabs and multiple spaces in stat output", async () => {
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
          [`stat -c '%a %U %G' '${destination}'`]: { stdout: "755\tdeploy   staff" },
        })
        const mod = download.url(destination, url, {
          group: "staff",
          mode: "0755",
          owner: "deploy",
          sha256,
        })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("ok")
        expect(mockSsh.calls.every((c) => !c.startsWith("chmod"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("chown"))).toBe(true)
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

      it("returns failed when sha256 matches but an ancestor is a symlink", async () => {
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`[ -L '/usr/local/bin' ]`]: { code: 0 },
          [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
          [`stat -c '%a %U %G' '${destination}'`]: { stdout: "644 root staff" },
        })
        const mod = download.url(destination, url, {
          group: "staff",
          mode: "0755",
          owner: "deploy",
          sha256,
        })
        const result = await mod.apply(mockSsh, emptyEnv)
        expect(result.status).toBe("failed")
        expect(result.error?.message).toContain("is a symlink: /usr/local/bin")
        expect(mockSsh.calls).toContain(`[ -L '/usr/local/bin' ]`)
        expect(mockSsh.calls.every((c) => !c.startsWith("chmod"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("chown"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
        expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
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
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        expect(mockSsh.calls).toContain(
          buildGuardedMoveCommand({ destination, temporaryDestination })
        )
      })

      it("forces a full curl download when force is true even if sha256 matches", async () => {
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`[ -f '${destination}' ]`]: { code: 0 },
          [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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
        expect(mockSsh.calls).toContain(
          buildGuardedMoveCommand({ destination, temporaryDestination })
        )
      })

      it("never enters the fast path when sha256 is not provided", async () => {
        // Without sha256 the hash check cannot vouch for the on-disk content,
        // so apply must always run curl through the slow path.
        const mockSsh = createMockSsh({
          [`[ -e '${destination}' ]`]: { code: 0 },
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
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

    it("rejects http:// URL with sensitive headers unless separately opted in", () => {
      expect(() =>
        download.url(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { Authorization: "Bearer token" },
        })
      ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
    })

    it("matches sensitive download.url headers case-insensitively", () => {
      expect(() =>
        download.url(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { COOKIE: "session=abc" },
        })
      ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
    })

    it("rejects http:// URL with custom credential-like headers", () => {
      expect(() =>
        download.url(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { "X-Client-Token": "abc" },
        })
      ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
    })

    it("allows http:// URL with sensitive headers when allowInsecureHttpHeaders is true", () => {
      expect(() =>
        download.url(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          allowInsecureHttpHeaders: true,
          headers: { Authorization: "Bearer token" },
        })
      ).not.toThrow()
    })

    it("allows http:// URL with non-sensitive headers", () => {
      expect(() =>
        download.url(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { "X-Trace-Id": "abc" },
        })
      ).not.toThrow()
    })

    it("rejects URLs with embedded credentials", () => {
      expect(() =>
        download.url(destination, "https://user:secret@example.com/file", allowUnverifiedDownload)
      ).toThrow("must not embed credentials")
    })

    it("rejects an empty destination path", () => {
      expect(() => download.url("", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must not be empty"
      )
    })

    it("rejects destinations padded with whitespace", () => {
      expect(() => download.url(" /tmp/file", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must not start or end with whitespace:  /tmp/file"
      )
      expect(() => download.url("/tmp/file\n", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must not start or end with whitespace: /tmp/file\n"
      )
    })

    it("rejects destinations that start with a dash", () => {
      expect(() => download.url("-rf", url, allowUnverifiedDownload)).toThrow(
        '[download.url] destination must not start with "-": -rf'
      )
    })

    it("rejects relative destination paths", () => {
      expect(() => download.url("tmp/file", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must be an absolute path: tmp/file"
      )
      expect(() => download.url(".", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must be an absolute path: ."
      )
    })

    it("rejects the root path as destination", () => {
      expect(() => download.url("/", url, allowUnverifiedDownload)).toThrow(
        "[download.url] refusing to use root path as destination: /"
      )
    })

    it("rejects destinations that are not normalized", () => {
      expect(() => download.url("/tmp//file", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must be normalized: /tmp//file"
      )
      expect(() => download.url("/tmp/./file", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must be normalized: /tmp/./file"
      )
      expect(() => download.url("/tmp/../file", url, allowUnverifiedDownload)).toThrow(
        "[download.url] destination must be normalized: /tmp/../file"
      )
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
    it("returns needs-apply when marker file is missing (no sha256)", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}.sha256' ]`]: { code: 1 },
        [`[ -f '${destination}' ]`]: { code: 0 },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns ok when file and marker hash match (no sha256)", async () => {
      // R-0000529: symlink guard and read are fused into a single shell command.
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const markerPath = `${destination}.sha256`
      const fusedMarkerCommand = `[ ! -L '${markerPath}' ] && [ -f '${markerPath}' ] && cat -- '${markerPath}'`
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f '${markerPath}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${recordedHash}  ${destination}` },
        [fusedMarkerCommand]: { code: 0, stdout: `${recordedHash}\n` },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("ok")
    })

    it("returns needs-apply when marker hash differs from current file hash (no sha256)", async () => {
      // R-0000529: symlink guard and read are fused into a single shell command.
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const tamperedHash = "1111111111111111111111111111111111111111111111111111111111111111"
      const markerPath = `${destination}.sha256`
      const fusedMarkerCommand = `[ ! -L '${markerPath}' ] && [ -f '${markerPath}' ] && cat -- '${markerPath}'`
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f '${markerPath}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${tamperedHash}  ${destination}` },
        [fusedMarkerCommand]: { code: 0, stdout: `${recordedHash}\n` },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
    })

    it("returns needs-apply when file path is a symlink to a regular file", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -L '${destination}' ]`]: { code: 0 },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
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
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expectSafeCurlDownloadPipeline({
        destination,
        mockSsh,
        temporaryDestination,
        urlInput: expectedUrl,
      })
    })

    it("returns failedCommand and aborts before mktemp when target directory creation fails", async () => {
      const mkdirCommand = lastAncestorMkdirCommandForDestination(destination)
      const token = "ghp_secret_token"
      const mockSsh = createMockSsh({
        [mkdirCommand]: { code: 1, stderr: "mkdir: Read-only file system\n" },
      })
      const mod = download.github(destination, {
        ...allowUnverifiedDownload,
        asset,
        repo,
        tag,
        token,
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("failed to create target directory")
      expect(result.error?.message).toContain("Read-only file system")
      expect(
        mockSsh.execCalls.find((entry) => entry.command === mkdirCommand)?.options
      ).toMatchObject({
        ignoreExitCode: true,
        secrets: [token],
        silent: true,
      })
      expect(mockSsh.calls).not.toContain(
        `mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`
      )
      expect(mockSsh.calls.every((command) => !command.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls).not.toContain(`rm -f -- '${temporaryDestination}'`)
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
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
    })

    it("fails and cleans up when the destination already exists as a directory", async () => {
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [`[ -d '${destination}' ]`]: { code: 0 },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("destination is a directory")
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
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

    it("writes the unverified hash marker through writeFile", async () => {
      const recordedHash = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -L '${destination}.sha256' ]`]: { code: 1 },
        ...downloadMktempStub(destination, temporaryDestination),
        [`sha256sum '${destination}'`]: { stdout: `${recordedHash}  ${destination}` },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("changed")
      expect(mockSsh.writeFileCalls).toStrictEqual([
        {
          content: `${recordedHash}\n`,
          options: { mode: "0644" },
          remotePath: `${destination}.sha256`,
        },
      ])
    })

    it("returns failed when ssh is null", async () => {
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      const conn = null
      const result = await mod.apply(conn, emptyEnv)
      expect(result.status).toBe("failed")
    })

    it("creates target directory via per-level guarded mkdir", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.github(destination, { ...allowUnverifiedDownload, asset, repo, tag })
      await mod.apply(mockSsh, emptyEnv)
      for (const command of buildAncestorMkdirCommandsForDestination(destination)) {
        expect(mockSsh.calls).toContain(command)
      }
    })

    it("keeps the destination untouched when SHA-256 verification fails", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.github(destination, { asset, repo, sha256, tag })
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`rm -f -- '${destination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
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

    it("rejects an empty destination path", () => {
      expect(() => download.github("", { ...allowUnverifiedDownload, asset, repo, tag })).toThrow(
        "[download.github] destination must not be empty"
      )
    })

    it("rejects destinations padded with whitespace", () => {
      expect(() =>
        download.github(" /tmp/asset", { ...allowUnverifiedDownload, asset, repo, tag })
      ).toThrow("[download.github] destination must not start or end with whitespace:  /tmp/asset")
    })

    it("rejects destinations that start with a dash", () => {
      expect(() =>
        download.github("-rf", { ...allowUnverifiedDownload, asset, repo, tag })
      ).toThrow('[download.github] destination must not start with "-": -rf')
    })

    it("rejects relative destination paths", () => {
      expect(() =>
        download.github("tmp/asset", { ...allowUnverifiedDownload, asset, repo, tag })
      ).toThrow("[download.github] destination must be an absolute path: tmp/asset")
    })

    it("rejects destinations that are not normalized", () => {
      expect(() =>
        download.github("/tmp//asset", { ...allowUnverifiedDownload, asset, repo, tag })
      ).toThrow("[download.github] destination must be normalized: /tmp//asset")
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

    it("returns needs-apply when flag exists but destination is a symlink to a regular file", async () => {
      const mockSsh = createMockSsh({
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`[ -f /var/lib/paratix/flags/'${flagName}' ]`]: { code: 0 },
        [`[ -L '${destination}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.check(mockSsh, emptyEnv)
      expect(result).toBe("needs-apply")
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
      expect(mockSsh.calls).not.toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
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
      expect(mockSsh.calls).not.toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
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
      expect(mockSsh.calls).toContain(
        buildGuardedMoveCommand({ destination, temporaryDestination })
      )
      expect(mockSsh.calls).toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
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
      expect(mockSsh.calls).toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
    })

    it("downloads file via curl --config from stdin and sets flag on success", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expectSafeCurlDownloadPipeline({
        destination,
        mockSsh,
        temporaryDestination,
        urlInput: url,
      })
      expect(mockSsh.calls).toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
    })

    it("passes custom curl timeout flags and SSH exec timeout", async () => {
      const curlCommand = `curl -fsSL -o '${temporaryDestination}' --connect-timeout '2.5' --max-time '15' --proto '=https' --proto-redir '=https' --config -`
      const mockSsh = createMockSsh(
        {
          [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
            stdout: `${temporaryDestination}\n`,
          },
        },
        {
          responseStubs: [{ command: curlCommand, result: { code: 0 } }],
        }
      )
      const mod = download.large(destination, url, {
        ...allowUnverifiedDownload,
        connectTimeout: 2500,
        timeout: 15_000,
      })
      const result = await mod.apply(mockSsh, emptyEnv)
      const curlCall = mockSsh.execCalls.find((entry) => entry.command === curlCommand)
      expect(result.status).toBe("changed")
      expect(curlCall?.options?.timeout).toBe(15_000)
    })

    it("returns failedCommand and aborts before mktemp or flag writes when target directory creation fails", async () => {
      const mkdirCommand = lastAncestorMkdirCommandForDestination(destination)
      const mockSsh = createMockSsh({
        [mkdirCommand]: { code: 1, stderr: "mkdir: No space left on device\n" },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("failed to create target directory")
      expect(result.error?.message).toContain("No space left on device")
      expect(
        mockSsh.execCalls.find((entry) => entry.command === mkdirCommand)?.options
      ).toMatchObject({
        ignoreExitCode: true,
        secrets: [],
        silent: true,
      })
      expect(mockSsh.calls).not.toContain(
        `mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`
      )
      expect(mockSsh.calls.every((command) => !command.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls).not.toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
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
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
      expect(mockSsh.calls).not.toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
    })

    it("fails, cleans up, and does not set the flag when the destination is a directory", async () => {
      const mockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [`[ -d '${destination}' ]`]: { code: 0 },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(result.error?.message).toContain("destination is a directory")
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
      expect(mockSsh.calls).not.toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
    })

    it("creates flags directory before setting flag", async () => {
      const mockSsh = createMockSsh({
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
      })
      const mod = download.large(destination, url, allowUnverifiedDownload)
      await mod.apply(mockSsh, emptyEnv)
      expect(mockSsh.calls).toContain("mkdir -p /var/lib/paratix/flags")
      const mkdirIndex = mockSsh.calls.indexOf("mkdir -p /var/lib/paratix/flags")
      const touchIndex = mockSsh.calls.indexOf(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
      expect(mkdirIndex).toBeLessThan(touchIndex)
    })

    it("returns changed and sets flag when sha256 matches after download", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: { stdout: `${sha256}  ${temporaryDestination}` },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      expect(mockSsh.calls).toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
    })

    it("returns failed and does not set flag when sha256 does not match after download", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -f '${temporaryDestination}' ]`]: { code: 0 },
        [`mktemp "$(dirname -- '${destination}')/.paratix-download.XXXXXX"`]: {
          stdout: `${temporaryDestination}\n`,
        },
        [`sha256sum '${temporaryDestination}'`]: {
          stdout: `0000000000000000000000000000000000000000000000000000000000000000  ${temporaryDestination}`,
        },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("failed")
      expect(mockSsh.calls).not.toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
      expect(mockSsh.calls).toContain(`rm -f -- '${temporaryDestination}'`)
      expect(mockSsh.calls).not.toContain(`rm -f -- '${destination}'`)
      expect(mockSsh.calls).not.toContain(`mv -T -- '${temporaryDestination}' '${destination}'`)
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
      expect(mockSsh.calls).toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
      expect(mockSsh.calls.every((c) => !c.startsWith("curl"))).toBe(true)
      expect(mockSsh.calls.every((c) => !c.startsWith("mktemp"))).toBe(true)
    })

    // R-0000156: when performDownload returns { status: "ok" } because the
    // existing destination already matches sha256 and metadata, apply must
    // honor the "ok" status instead of forcing "changed". Direct apply
    // invocations via signal targets (e.g. service.restart) would otherwise
    // re-fire on every run even though no real change happened.
    it("sets flag and reports ok when fast path finds matching content and metadata", async () => {
      const sha256 = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd"
      const mockSsh = createMockSsh({
        [`[ -e '${destination}' ]`]: { code: 0 },
        [`[ -f '${destination}' ]`]: { code: 0 },
        [`sha256sum '${destination}'`]: { stdout: `${sha256}  ${destination}` },
      })
      const mod = download.large(destination, url, { sha256 })
      const result = await mod.apply(mockSsh, emptyEnv)
      expect(result.status).toBe("ok")
      expect(mockSsh.calls).toContain(
        buildLargeDownloadVersionedFlagCommand({ destination, flagName })
      )
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

    it("rejects http:// URL with sensitive headers unless separately opted in", () => {
      expect(() =>
        download.large(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { "X-Api-Key": "k123" },
        })
      ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
    })

    it("matches sensitive download.large headers case-insensitively", () => {
      expect(() =>
        download.large(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { "proxy-authorization": "Basic abc" },
        })
      ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
    })

    it("rejects http:// URL with custom credential-like headers", () => {
      expect(() =>
        download.large(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { XServiceAuth: "abc" },
        })
      ).toThrow(/refusing to send sensitive headers .* over plaintext http/v)
    })

    it("allows http:// URL with sensitive headers when allowInsecureHttpHeaders is true", () => {
      expect(() =>
        download.large(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          allowInsecureHttpHeaders: true,
          headers: { "X-Api-Key": "k123" },
        })
      ).not.toThrow()
    })

    it("allows http:// URL with non-sensitive headers", () => {
      expect(() =>
        download.large(destination, "http://example.com/file", {
          ...allowUnverifiedDownload,
          allowInsecureHttp: true,
          headers: { "X-Trace-Id": "abc" },
        })
      ).not.toThrow()
    })

    it("rejects an empty destination path", () => {
      expect(() => download.large("", url, allowUnverifiedDownload)).toThrow(
        "[download.large] destination must not be empty"
      )
    })

    it("rejects destinations padded with whitespace", () => {
      expect(() =>
        download.large(" /opt/data/large-file.iso", url, allowUnverifiedDownload)
      ).toThrow(
        "[download.large] destination must not start or end with whitespace:  /opt/data/large-file.iso"
      )
    })

    it("rejects destinations that start with a dash", () => {
      expect(() => download.large("-rf", url, allowUnverifiedDownload)).toThrow(
        '[download.large] destination must not start with "-": -rf'
      )
    })

    it("rejects relative destination paths", () => {
      expect(() => download.large("opt/data/file", url, allowUnverifiedDownload)).toThrow(
        "[download.large] destination must be an absolute path: opt/data/file"
      )
    })

    it("rejects destinations that are not normalized", () => {
      expect(() => download.large("/opt//data/file", url, allowUnverifiedDownload)).toThrow(
        "[download.large] destination must be normalized: /opt//data/file"
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

    // R-0000274: a versioned flag prefix keyed to the destination must drop
    // older flag files for the same destination on the next successful
    // apply. Otherwise rotating URLs or auth headers leak an unbounded
    // number of `/var/lib/paratix/flags/download-…` entries.
    it("uses a destination-keyed flag prefix so older URL hashes are evicted on re-convergence", async () => {
      const firstUrl = "https://example.com/large-file.iso"
      const secondUrl = "https://mirror.example.com/large-file.iso"
      const firstFlagName = buildLargeDownloadFlagName({ destination, url: firstUrl })
      const secondFlagName = buildLargeDownloadFlagName({ destination, url: secondUrl })

      expect(firstFlagName).not.toBe(secondFlagName)

      const flagPrefix = buildLargeDownloadFlagPrefix(destination)
      const findPrefix = `find /var/lib/paratix/flags -maxdepth 1 -name '${flagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${flagPrefix}`
      const isVersionedFlagCall = (call: string): boolean => call.startsWith(findPrefix)

      const firstMockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [`[ -f '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${firstFlagName}' ]`]: { code: 1 },
      })
      const firstMod = download.large(destination, firstUrl, allowUnverifiedDownload)
      const firstResult = await firstMod.apply(firstMockSsh, emptyEnv)
      expect(firstResult.status).toBe("changed")
      const firstVersionedCalls = firstMockSsh.calls.filter(isVersionedFlagCall)
      expect(firstVersionedCalls).toStrictEqual([
        buildLargeDownloadVersionedFlagCommand({ destination, flagName: firstFlagName }),
      ])

      const secondMockSsh = createMockSsh({
        ...downloadMktempStub(destination, temporaryDestination),
        [`[ -f '${destination}' ]`]: { code: 1 },
        [`[ -f /var/lib/paratix/flags/'${secondFlagName}' ]`]: { code: 1 },
      })
      const secondMod = download.large(destination, secondUrl, allowUnverifiedDownload)
      const secondResult = await secondMod.apply(secondMockSsh, emptyEnv)
      expect(secondResult.status).toBe("changed")
      const secondVersionedCalls = secondMockSsh.calls.filter(isVersionedFlagCall)
      expect(secondVersionedCalls).toStrictEqual([
        buildLargeDownloadVersionedFlagCommand({ destination, flagName: secondFlagName }),
      ])
    })
  })
})

// ─── Header-Name-Validierung (Regressionstests) ───────────────────────────────

describe("buildCurlCommand — header name validation", () => {
  const destination = "/tmp/file"
  const temporaryDestination = "/tmp/.paratix-download.HDR1"
  const url = "https://example.com/file"
  const stub = downloadMktempStub(destination, temporaryDestination)

  // R-0000701: header pairs are validated synchronously at module construction
  // so malformed names/values fail fast before any apply work is scheduled.
  it("throws when header name contains \\r\\n (CRLF injection)", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Evil\r\nX-Injected": "value" },
      })
    ).toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\n", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Evil\nInjected": "value" },
      })
    ).toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a bare \\r", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Evil\rInjected": "value" },
      })
    ).toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a control character (\\x01)", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Bad\x01Name": "value" },
      })
    ).toThrow("Invalid HTTP header name")
  })

  it("throws when header name contains a colon", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Bad:Name": "value" },
      })
    ).toThrow("Invalid HTTP header name")
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

  // R-0000701: header pairs are validated synchronously at module construction
  // so malformed values fail fast before any apply work is scheduled.
  it("throws when header value contains \\r (CR injection)", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Custom": "value\rX-Injected: injected" },
      })
    ).toThrow("Invalid HTTP header value for X-Custom: value contains newline characters")
  })

  it("throws when header value contains \\n (LF injection)", () => {
    expect(() =>
      download.url(destination, url, {
        ...allowUnverifiedDownload,
        headers: { "X-Custom": "value\nX-Injected: injected" },
      })
    ).toThrow("Invalid HTTP header value for X-Custom: value contains newline characters")
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
