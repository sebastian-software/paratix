import { describe, expect, it, vi } from "vitest"

import type { ExecResult, ModuleResult } from "../../src/types.js"

import { archive } from "../../src/modules/archive.js"
import {
  ARCHIVE_CAPTURE_LIMIT_BYTES,
  listArchiveMembers,
} from "../../src/modules/archiveMemberValidation.js"
import {
  buildMemberTypeProbeScript,
  buildOwnershipProbeScript,
  buildSymlinkProbeScript,
} from "../../src/modules/archiveProbe.js"
import { CAPTURE_TRUNCATION_MARKER } from "../../src/sshHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const src = "/tmp/app.tar.gz"
const destination = "/opt/app"
const alternateDestination = "/opt/app-alt"
const safeTarListing = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/file"
const archiveListingMaxOutputBytes = ARCHIVE_CAPTURE_LIMIT_BYTES
const legacyCaptureLimitBytes = 1_048_576

// Stable hash of `${src}\n${destination}` for marker file naming.
const srcHash = "2889be4b654d6b7f7922971e7fb3fdf1c5ebd92b9c52462be2683a735c7562ef"
const marker = `/var/lib/paratix/flags/archive-${srcHash}.sha256`
const membersMarker = `${marker}.members`
const archiveSha = "abc123def456"
const extractedFileMember = { kind: "file", path: `${destination}/app/file` } as const
const symlinkProbeCommand = buildSymlinkProbeScript()
const extractedFileTypeProbe = buildMemberTypeProbeScript()
const batchedChownCommand = "xargs -0 chown -h -- 'www-data:www-data'"
const memberTypeMatchResponse = { code: 0, stdout: "" }
const memberTypeDriftResponse = { code: 0, stdout: `${destination}/app/file\u0000` }

function ownershipProbeCommand(owner: string): string {
  const [user = "", group = ""] = owner.split(":", 2)
  return buildOwnershipProbeScript(user, group)
}

/**
 * Ownership-probe stub. The remote script only pre-filters, so reporting a path
 * is always valid: `ownerMatchesStat` re-decides in TypeScript. Tests therefore
 * report unconditionally and let the production rule produce the verdict.
 *
 * @param path - The reported path.
 * @param stat - The `%U %G %u %g` output to transport.
 * @returns A probe response reporting that path.
 */
function ownershipReport(path: string, stat: string): { code: number; stdout: string } {
  const fields = stat.trim().split(/\s+/v)
  return { code: 0, stdout: [path, ...fields].map((field) => `${field}\u0000`).join("") }
}

// R-0000162: archive.extract now extracts into a paratix-controlled staging
// directory under the destination via `mktemp -d`, then atomically moves the
// extracted entries into the destination. Tests stub the staging-directory
// allocation, the move command and the staging-dir cleanup with regex stubs
// so individual tests can keep their familiar `tar … -C '${destination}'`
// expectations.
const archiveStageDirectory = "/opt/app/.paratix-stage.AbCdEfGh"
const archiveStageMktempPattern = /^mktemp -d '\/opt\/app\/\.paratix-stage\.X{8}'$/v
const archiveStageMovePattern =
  /^find '\/opt\/app\/\.paratix-stage\.[^']+' -mindepth 1 -maxdepth 1 -exec sh -c '.*cp -aT --no-dereference --remove-destination "\$source_path" "\$target_path" \|\| exit \$\?; done' sh '\/opt\/app' '\/opt\/app' '[^']*' \{\} \+$/sv
const archiveStageCleanupPattern = /^rm -rf -- '\/opt\/app\/\.paratix-stage\.[^']+'$/v
const archiveAlternateStageMktempPattern = /^mktemp -d '\/opt\/app-alt\/\.paratix-stage\.X{8}'$/v
const archiveAlternateStageMovePattern =
  /^find '\/opt\/app-alt\/\.paratix-stage\.[^']+' -mindepth 1 -maxdepth 1 -exec sh -c '.*cp -aT --no-dereference --remove-destination "\$source_path" "\$target_path" \|\| exit \$\?; done' sh '\/opt\/app-alt' '\/opt\/app-alt' '[^']*' \{\} \+$/sv
const archiveAlternateStageCleanupPattern = /^rm -rf -- '\/opt\/app-alt\/\.paratix-stage\.[^']+'$/v
const archiveMembersMarkerPattern =
  /^cat '\/var\/lib\/paratix\/flags\/archive-[a-f0-9]+\.sha256\.members'$/v

function guardedArchiveDestinationMkdirCommand(path: string): string {
  return [
    `if [ -L '${path}' ]; then`,
    `  printf '%s\\n' 'destination path is a symlink' >&2`,
    `  exit 1`,
    `fi`,
    `if [ -e '${path}' ] && [ ! -d '${path}' ]; then`,
    `  printf '%s\\n' 'destination path exists and is not a directory' >&2`,
    `  exit 1`,
    `fi`,
    `if [ ! -d '${path}' ]; then`,
    `  mkdir -- '${path}'`,
    `fi`,
  ].join("\n")
}

function findGuardedArchiveMkdirCall(calls: string[], path: string): string | undefined {
  return calls.find(
    (call) => call.includes(`if [ -L '${path}' ];`) && call.includes(`mkdir -- '${path}'`)
  )
}

const archiveCleanupPaths = [
  "/tmp/paratix-upload.AbCdEfGh",
  "/tmp/paratix-upload.FAIL1234",
  "/tmp/paratix-upload.FIRST111",
  "/tmp/paratix-upload.SECOND22",
]

function tarListingForMemberPaths(memberPaths: string[]): string {
  return memberPaths
    .map((memberPath) => `-rw-r--r-- root/root 0 1970-01-01 00:00 ${memberPath}`)
    .join("\n")
}

function listingLargerThanLegacyCaptureLimit(memberLine: string): string {
  const line = `${memberLine}\n`
  return line.repeat(Math.floor(legacyCaptureLimitBytes / line.length) + 1)
}

function singleMemberTarListingOfUtf8Size(sizeBytes: number, suffix = ""): string {
  const prefix = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/"
  const paddingBytes =
    sizeBytes - Buffer.byteLength(prefix, "utf8") - Buffer.byteLength(suffix, "utf8")
  if (paddingBytes < 1) throw new Error("tar listing size is too small for a valid member")
  return `${prefix}${"a".repeat(paddingBytes)}${suffix}`
}

function expectArchiveCaptureExecCall(mockSsh: MockSsh, command: string, pinCLocale = false): void {
  expect(mockSsh.execCalls).toContainEqual({
    command,
    options: {
      ...(pinCLocale ? { env: { LC_ALL: "C" } } : {}),
      ignoreExitCode: true,
      maxOutputBytes: archiveListingMaxOutputBytes,
      silent: true,
    },
  })
}

const archiveApplyResponseStubs: NonNullable<
  Parameters<typeof createBaseMockSsh>[1]
>["responseStubs"] = [
  { command: archiveMembersMarkerPattern, result: { code: 1, stderr: "cat: No such file" } },
  { command: symlinkProbeCommand, result: { code: 0, stdout: "" } },
  { command: extractedFileTypeProbe, result: { code: 0, stdout: "" } },
  { command: batchedChownCommand, result: { code: 0 } },
  {
    command: `[ -d '${destination}' ] && [ ! -L '${destination}' ]`,
    result: { code: 0 },
  },
  {
    command: `[ -d '${alternateDestination}' ] && [ ! -L '${alternateDestination}' ]`,
    result: { code: 0 },
  },
  { command: guardedArchiveDestinationMkdirCommand("/opt"), result: { code: 0 } },
  { command: guardedArchiveDestinationMkdirCommand(destination), result: { code: 0 } },
  { command: guardedArchiveDestinationMkdirCommand(alternateDestination), result: { code: 0 } },
  { command: `readlink -f -- '${destination}'`, result: { code: 0, stdout: `${destination}\n` } },
  {
    command: `readlink -f -- '${alternateDestination}'`,
    result: { code: 0, stdout: `${alternateDestination}\n` },
  },
  { command: "mkdir -p '/var/lib/paratix/flags'", result: { code: 0 } },
  { command: archiveStageMktempPattern, result: { code: 0, stdout: archiveStageDirectory } },
  { command: archiveStageMovePattern, result: { code: 0 } },
  { command: archiveStageCleanupPattern, result: { code: 0 } },
  {
    command: archiveAlternateStageMktempPattern,
    result: { code: 0, stdout: "/opt/app-alt/.paratix-stage.AbCdEfGh" },
  },
  { command: archiveAlternateStageMovePattern, result: { code: 0 } },
  { command: archiveAlternateStageCleanupPattern, result: { code: 0 } },
  ...archiveCleanupPaths.map((path) => ({
    command: `rm -f -- '${path}'`,
    result: { code: 0 },
  })),
]

/**
 * Report a symlink violation only for the sweep whose payload actually carries
 * the path. Every sweep issues the identical batched command, so the
 * transported stdin is the only thing that tells them apart — the exact-match
 * mock cannot.
 *
 * @param mockSsh - The mock connection to patch.
 * @param memberPath - The member path whose recheck should report a symlink.
 * @returns A handle exposing how many member-carrying sweeps ran.
 */
function stubSymlinkRecheck(mockSsh: MockSsh, memberPath: string): { sweeps: () => number } {
  const originalExec = mockSsh.exec.bind(mockSsh)
  let sweeps = 0
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    if (command !== symlinkProbeCommand) return originalExec(command, options)
    mockSsh.calls.push(command)
    const carriesMember = (options?.input ?? "").includes(`${memberPath}\u0000`)
    if (!carriesMember) return { code: 0, stderr: "", stdout: "" }
    sweeps += 1
    // Only the recheck reports, so a failure can only originate from the sweep
    // that runs after extraction.
    return { code: 0, stderr: "", stdout: sweeps >= 2 ? `${memberPath}\u0000` : "" }
  })
  return { sweeps: () => sweeps }
}

/**
 * Report a symlink violation only for the sweep whose payload carries the path.
 *
 * @param mockSsh - The mock connection to patch.
 * @param path - The path to report as a symlink.
 */
function stubSymlinkViolationFor(mockSsh: MockSsh, path: string): void {
  const originalExec = mockSsh.exec.bind(mockSsh)
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    if (command !== symlinkProbeCommand) return originalExec(command, options)
    mockSsh.calls.push(command)
    const payload = options?.input ?? ""
    const reported = payload.includes(`${path}\u0000`) ? `${path}\u0000` : ""
    return { code: 0, stderr: "", stdout: reported }
  })
}

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    // Test-supplied stubs take priority over the module-scope defaults so a
    // single test can override e.g. the staging-dir mktemp / move / cleanup
    // commands without having to disable the shared stubs entirely.
    responseStubs: [...(options?.responseStubs ?? []), ...archiveApplyResponseStubs],
  })

type MockSsh = ReturnType<typeof createMockSsh>
function validMembersMarkerResponse(member = extractedFileMember): ExecResult {
  return { code: 0, stderr: "", stdout: JSON.stringify([member]) }
}

function expectNoTarExtractCalls(mockSsh: MockSsh): void {
  const tarExtractCalls = mockSsh.calls.filter((command) => /^tar\b.*\s-x\S*\s/v.test(command))
  expect(tarExtractCalls).toStrictEqual([])
}

function expectNoUnzipExtractCalls(mockSsh: MockSsh): void {
  const unzipExtractCalls = mockSsh.calls.filter((command) => command.startsWith("unzip -o "))
  expect(unzipExtractCalls).toStrictEqual([])
}

function expectNoArchiveMarkerWrite(mockSsh: MockSsh): void {
  expect(mockSsh.writeFileCalls).toHaveLength(0)
}

function rotateUploadMktempResponses(mockSsh: MockSsh, responses: readonly string[]): void {
  const originalOutput = mockSsh.output.bind(mockSsh)
  const remaining = [...responses]
  vi.spyOn(mockSsh, "output").mockImplementation(async (command) => {
    const isUploadMktemp = command === "mktemp /tmp/paratix-upload.XXXXXXXX"
    return isUploadMktemp
      ? consumeNextUploadMktemp(mockSsh, command, remaining)
      : originalOutput(command)
  })
}

async function consumeNextUploadMktemp(
  mockSsh: MockSsh,
  command: string,
  remaining: string[]
): Promise<string> {
  await Promise.resolve()
  mockSsh.calls.push(command)
  return remaining.shift() ?? ""
}

// Issue #219: builders for inline `tar -tv` listings with directory, symlink
// and hardlink members, plus recorders for the batched symlink probe payloads
// and the staging-merge guard paths.
const tarListingLineFields = "root/root 0 1970-01-01 00:00"
const stagedTarExtractCommand = `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`
const archiveStageMergeGuardPathsPattern =
  / sh '\/opt\/app' '\/opt\/app' '(?<guards>[^']*)' \{\} \+$/v

function tarFileLine(path: string): string {
  return `-rw-r--r-- ${tarListingLineFields} ${path}`
}

function tarDirectoryLine(path: string): string {
  return `drwxr-xr-x ${tarListingLineFields} ${path}`
}

function tarSymlinkLine(path: string, target: string): string {
  return `lrwxrwxrwx ${tarListingLineFields} ${path} -> ${target}`
}

function tarHardlinkLine(path: string, target: string): string {
  return `hrw-r--r-- ${tarListingLineFields} ${path} link to ${target}`
}

type SymlinkProbeRecord = { callIndex: number; entries: string[] }

/**
 * Record the NUL-separated payload of every batched symlink probe and report
 * the given host paths as symlinks whenever a probe carries them.
 *
 * @param mockSsh - The mock connection to patch.
 * @param hostSymlinks - Absolute host paths the probe reports as symlinks.
 * @returns The recorded probes, in call order, with their position in `mockSsh.calls`.
 */
function recordSymlinkProbes(
  mockSsh: MockSsh,
  hostSymlinks: readonly string[] = []
): SymlinkProbeRecord[] {
  const originalExec = mockSsh.exec.bind(mockSsh)
  const probes: SymlinkProbeRecord[] = []
  vi.spyOn(mockSsh, "exec").mockImplementation(async (command, options) => {
    const result = await originalExec(command, options)
    if (command !== symlinkProbeCommand) return result
    const entries = (options?.input ?? "").split("\u0000").filter((entry) => entry !== "")
    probes.push({ callIndex: mockSsh.calls.length - 1, entries })
    const reported = entries.filter((entry) => hostSymlinks.includes(entry))
    if (reported.length === 0) return result
    return { ...result, stdout: reported.map((entry) => `${entry}\u0000`).join("") }
  })
  return probes
}

type TarListingApplyRun = {
  markerWrites: () => number
  mockSsh: MockSsh
  probes: SymlinkProbeRecord[]
  result: ModuleResult
}

async function applyTarListing(
  lines: readonly string[],
  options: { hostSymlinks?: readonly string[] } = {}
): Promise<TarListingApplyRun> {
  const mockSsh = createMockSsh({
    [`tar -tvzf '${src}'`]: { code: 0, stdout: `${lines.join("\n")}\n` },
    [stagedTarExtractCommand]: { code: 0 },
  })
  vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
  const writeFile = vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
  const probes = recordSymlinkProbes(mockSsh, options.hostSymlinks)
  const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)
  return { markerWrites: () => writeFile.mock.calls.length, mockSsh, probes, result }
}

/**
 * Condense an apply run into the facts the link-target tests assert on. The
 * summary carries the rejection reason, so a failing acceptance case prints
 * why it was refused.
 *
 * @param run - The recorded apply run.
 * @returns Status, error text, `tar -x` invocations and whether markers were written.
 */
function extractionSummary(run: TarListingApplyRun): {
  error: string | undefined
  markerWritten: boolean
  status: ModuleResult["status"]
  tarExtractCalls: string[]
} {
  return {
    error: run.result.error === undefined ? undefined : String(run.result.error),
    markerWritten: run.markerWrites() > 0,
    status: run.result.status,
    tarExtractCalls: run.mockSsh.calls.filter((command) => /^tar\b.*\s-x\S*\s/v.test(command)),
  }
}

const extractedThroughStaging = {
  error: undefined,
  markerWritten: true,
  status: "changed",
  tarExtractCalls: [stagedTarExtractCommand],
}

function refusedBeforeExtraction(reason: string): ReturnType<typeof extractionSummary> {
  return {
    error: expect.stringContaining(`[archive.extract] refusing to extract ${src}: ${reason}`),
    markerWritten: false,
    status: "failed",
    tarExtractCalls: [],
  }
}

/**
 * Collect the entries of every symlink probe issued after the archive listing
 * and before the staged `tar -x`, i.e. the pre-staging member probe.
 *
 * @param run - The recorded apply run.
 * @returns The probed host paths.
 */
function preStagingProbeEntries(run: TarListingApplyRun): string[] {
  const listingIndex = run.mockSsh.calls.indexOf(`tar -tvzf '${src}'`)
  const extractIndex = run.mockSsh.calls.indexOf(stagedTarExtractCommand)
  const endIndex = extractIndex === -1 ? Number.POSITIVE_INFINITY : extractIndex
  return run.probes
    .filter((probe) => probe.callIndex > listingIndex && probe.callIndex < endIndex)
    .flatMap((probe) => probe.entries)
}

function stagingMergeGuardPaths(mockSsh: MockSsh): string[] {
  const mergeCommand = mockSsh.calls.find((command) => archiveStageMovePattern.test(command))
  const guards = archiveStageMergeGuardPathsPattern.exec(mergeCommand ?? "")?.groups?.guards
  return guards === undefined ? [] : guards.split("\n")
}

describe("archive.extract — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = archive.extract(src, destination)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when destination does not exist", async () => {
    const mockSsh = createMockSsh(
      {},
      {
        responseStubs: [
          {
            command: `[ -d '${destination}' ] && [ ! -L '${destination}' ]`,
            result: { code: 1 },
          },
        ],
      }
    )
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when destination is a symlink to a directory", async () => {
    const mockSsh = createMockSsh(
      {
        [`test -f '${marker}'`]: { code: 0 },
      },
      {
        responseStubs: [
          {
            command: `[ -d '${destination}' ] && [ ! -L '${destination}' ]`,
            result: { code: 1 },
          },
        ],
      }
    )
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when destination resolves elsewhere", async () => {
    const mockSsh = createMockSsh(
      {
        [`test -f '${marker}'`]: { code: 0 },
      },
      {
        responseStubs: [
          {
            command: `readlink -f -- '${destination}'`,
            result: { code: 0, stdout: "/tmp/attacker-target\n" },
          },
        ],
      }
    )
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when marker file does not exist", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 1 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when marker matches remote archive sha256", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
  })

  it("returns needs-apply when an extracted member was deleted after extraction", async () => {
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeDriftResponse,
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when an extracted directory was replaced by a symlink", async () => {
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "directory", path: `${destination}/app` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: { code: 0, stdout: `${destination}/app\u0000` },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when the members marker is missing", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: { code: 1, stderr: "cat: No such file or directory" },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when the members marker contains invalid JSON", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: { code: 0, stdout: "{not-json" },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
  })

  it("returns needs-apply when the members marker read was truncated", async () => {
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: `${JSON.stringify([extractedFileMember])}${CAPTURE_TRUNCATION_MARKER}`,
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })

    const result = await archive.extract(src, destination).check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
    expect(mockSsh.calls).not.toContain(extractedFileTypeProbe)
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when the members marker has an invalid schema", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "socket", path: `${destination}/app/file` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns ok when marker matches and extracted owner matches", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expectArchiveCaptureExecCall(mockSsh, `cat '${membersMarker}'`)
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
  })

  it("returns needs-apply when extracted owner has drifted", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "root root 0 0"
      ),
    })
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${ownerPathsMarker}'`)
    expect(mockSsh.calls).toContain(ownershipProbeCommand("www-data:www-data"))
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("issues one ownership probe no matter how many members are recorded", async () => {
    // Issue #180: this used to assert that at most eight owner checks ran
    // concurrently. There is no concurrency left to bound — the whole set now
    // travels in a single probe, which is the stronger property.
    const memberPaths = Array.from({ length: 500 }, (_value, index) => `app/file-${String(index)}`)
    const ownerPathsMarker = `${marker}.owner-paths`
    const ownerProbe = ownershipProbeCommand("www-data:www-data")
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify(
          memberPaths.map((path) => ({ kind: "file", path: `${destination}/${path}` }))
        ),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify(memberPaths.map((path) => `${destination}/${path}`)),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [ownerProbe]: { code: 0, stdout: "" },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls.filter((command) => command === ownerProbe)).toHaveLength(1)
  })

  it("returns needs-apply when marker does not match remote archive sha256", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: "old-hash" },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
    })
    const sha256Spy = vi.spyOn(mockSsh, "sha256").mockResolvedValue("new-hash")
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${marker}'`)
    expect(sha256Spy).toHaveBeenCalledWith(src)
  })

  it("uses a distinct marker for a second destination with the same archive", async () => {
    const alternateMarkerHash = "cde8e7e8eb1b5af4f516117a5a2ed09a67b8a0fbbcc792d793901f00f15bc9a0"
    const alternateMarker = `/var/lib/paratix/flags/archive-${alternateMarkerHash}.sha256`
    const mockSsh = createMockSsh({
      [`test -d '${alternateDestination}'`]: { code: 0 },
      [`test -f '${alternateMarker}'`]: { code: 1 },
    })

    const mod = archive.extract(src, alternateDestination)
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`test -f '${marker}'`)
  })

  it("R-0000276: returns needs-apply when marker cat fails with a non-missing error", async () => {
    // Permission-denied (or any non "No such file" error) on the marker
    // must not abort the whole run. Treat the unreadable marker as drift
    // so apply rewrites the marker on the next run instead of throwing
    // past the runner.
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 1, stderr: `cat: '${marker}': Permission denied` },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${marker}'`)
  })

  it("R-0000105: returns needs-apply when marker cat reports 'No such file'", async () => {
    // Race between test -f and cat (e.g. concurrent cleanup): treat the
    // missing marker as a regular needs-apply, identical to the case where
    // test -f already failed.
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 1, stderr: `cat: '${marker}': No such file or directory` },
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${marker}'`)
  })

  it("R-0000276: returns needs-apply when owner-paths marker cat fails with permission denied", async () => {
    // Permission drift on the owner-paths marker (or any non-"no such file"
    // stderr) must not abort the run, but it also must not be confused with a
    // genuinely missing legacy marker. Fail closed without consulting a live
    // archive that may no longer describe the extracted paths.
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 1,
        stderr: `cat: '${ownerPathsMarker}': Permission denied`,
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
    })
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${ownerPathsMarker}'`)
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
    expect(mockSsh.calls).not.toContain(ownershipProbeCommand("www-data:www-data"))
  })

  it("computes local sha256 when upload is true without uploading", async () => {
    const localFile = "/local/app.tar.gz"
    const localFileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    // sha256String of `${localFile}\n${destination}` for marker name
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`

    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${localMarker}.members'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${localMarker}'`]: { code: 0, stdout: localFileHash },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${localMarker}'`]: { code: 0 },
    })

    const fileHelpers = await import("../../src/modules/fileHelpers.js")
    vi.spyOn(fileHelpers, "localSha256").mockResolvedValue(localFileHash)

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    // Verify no upload was triggered during check.
    expect(mockSsh.calls).not.toContain(expect.stringContaining("upload"))

    vi.restoreAllMocks()
  })

  it("returns ok for upload archives when the stored owner paths still match", async () => {
    const localFile = "/local/app.tar.gz"
    const localFileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`
    const ownerPathsMarker = `${localMarker}.owner-paths`

    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${localMarker}.members'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${localMarker}'`]: { code: 0, stdout: localFileHash },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${localMarker}'`]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
    })

    const fileHelpers = await import("../../src/modules/fileHelpers.js")
    vi.spyOn(fileHelpers, "localSha256").mockResolvedValue(localFileHash)
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()

    vi.restoreAllMocks()
  })

  it("returns needs-apply for upload archives when a stored owner path drifts", async () => {
    const localFile = "/local/app.tar.gz"
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`
    const ownerPathsMarker = `${localMarker}.owner-paths`

    const mockSsh = createMockSsh({
      [`cat '${localMarker}.members'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${localMarker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "root root 0 0"
      ),
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).toContain(`cat '${ownerPathsMarker}'`)
    expect(mockSsh.calls).toContain(ownershipProbeCommand("www-data:www-data"))
    expect(mockSsh.calls).not.toContain(`cat '${localMarker}'`)
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })
})

describe("archive.extract — apply", () => {
  it("returns failed when conn is null", async () => {
    const mod = archive.extract(src, destination)
    const conn = null
    const result = await mod.apply(conn, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
  })

  // R-0000067: tar invocations now run with `--no-same-owner --no-overwrite-dir`
  // and a member-validation step. Each apply test stubs the member listing
  // with a single safe entry so the validation step passes.
  const safeZipListing = "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file\n"

  it("extracts tar.gz archive and writes marker", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, "/opt")).toBeDefined()
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeDefined()
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`
    )
    expect(mockSsh.calls).toContain(`mkdir -p '/var/lib/paratix/flags'`)
    // R-0000162: extraction must run into the staging dir, never directly into destination.
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`
    )
    expect(mockSsh.writeFile).toHaveBeenCalledWith(marker, archiveSha, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      membersMarker,
      JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      { mode: "0644" }
    )
  })

  it("extracts .tar archive", async () => {
    const tarSrc = "/tmp/app.tar"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xf '${tarSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvf '${tarSrc}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tarSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xf '${tarSrc}' -C '${archiveStageDirectory}'`
    )
  })

  it("extracts .tar.bz2 archive", async () => {
    const bz2Src = "/tmp/app.tar.bz2"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xjf '${bz2Src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvjf '${bz2Src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(bz2Src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xjf '${bz2Src}' -C '${archiveStageDirectory}'`
    )
  })

  it("extracts .tar.xz archive", async () => {
    const xzSrc = "/tmp/app.tar.xz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xJf '${xzSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvJf '${xzSrc}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(xzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xJf '${xzSrc}' -C '${archiveStageDirectory}'`
    )
  })

  it("extracts .zip archive", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -o '${zipSrc}' -d '${archiveStageDirectory}'`]: { code: 0 },
      [`unzip -Zs '${zipSrc}'`]: { code: 0, stdout: safeZipListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`unzip -o '${zipSrc}' -d '${archiveStageDirectory}'`)
  })

  it("extracts .tgz archive", async () => {
    const tgzSrc = "/tmp/app.tgz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${tgzSrc}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tgzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${archiveStageDirectory}'`
    )
  })

  // Issue #206: realistic distribution archives can emit more than the SSH
  // layer's default 1 MiB capture limit while every member is still safe.
  // The mock does not apply capture limits, so the options assertion is the
  // evidence that production requests the archive-specific 16 MiB budget.
  it.each([
    {
      extractCommand: `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`,
      format: "tar",
      listingCommand: `tar -tvzf '${src}'`,
      memberLine: safeTarListing,
      source: src,
    },
    {
      extractCommand: `unzip -o '/tmp/app.zip' -d '${archiveStageDirectory}'`,
      format: "zip",
      listingCommand: "unzip -Zs '/tmp/app.zip'",
      memberLine: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file",
      source: "/tmp/app.zip",
    },
  ])("accepts a safe $format listing above the legacy capture limit", async (testCase) => {
    const listing = listingLargerThanLegacyCaptureLimit(testCase.memberLine)
    expect(listing.length).toBeGreaterThan(legacyCaptureLimitBytes)
    const mockSsh = createMockSsh({
      [testCase.extractCommand]: { code: 0 },
      [testCase.listingCommand]: { code: 0, stdout: listing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(testCase.source, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expectArchiveCaptureExecCall(mockSsh, testCase.listingCommand)
  })

  it("accepts a complete archive listing at the exact capture limit", async () => {
    const listing = singleMemberTarListingOfUtf8Size(archiveListingMaxOutputBytes)
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
    })

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(Buffer.byteLength(listing, "utf8")).toBe(archiveListingMaxOutputBytes)
    expect(result).toMatchObject({ members: [{ format: "tar", kind: "file" }] })
    expectArchiveCaptureExecCall(mockSsh, `tar -tvzf '${src}'`)
  })

  it("treats the truncation marker as authoritative at the capture boundary", async () => {
    const listing = singleMemberTarListingOfUtf8Size(
      archiveListingMaxOutputBytes,
      CAPTURE_TRUNCATION_MARKER
    )
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
    })

    const result = await listArchiveMembers(mockSsh, { archivePath: src, source: src })

    expect(Buffer.byteLength(listing, "utf8")).toBe(archiveListingMaxOutputBytes)
    expect(result).toStrictEqual({
      failureReason: expect.stringMatching(/truncat/iv),
    })
    expectArchiveCaptureExecCall(mockSsh, `tar -tvzf '${src}'`)
  })

  it("reports an actionable failure when the archive listing is truncated", async () => {
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: {
        code: 0,
        stdout: `${safeTarListing}${CAPTURE_TRUNCATION_MARKER}`,
      },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    const message = String(result.error)
    expect(message).toMatch(/truncat/iv)
    expect(message).toContain(String(archiveListingMaxOutputBytes))
    expect(message).not.toContain("could not parse tar listing line")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeUndefined()
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a UTF-8 members marker above the byte limit before destination mutation", async () => {
    const unicodeMemberPath = `app/${"é".repeat(Math.floor(archiveListingMaxOutputBytes / 2))}`
    const listing = `-rw-r--r-- root/root 0 1970-01-01 00:00 ${unicodeMemberPath}`
    const expectedPayload = JSON.stringify([
      { kind: "file", path: `${destination}/${unicodeMemberPath}` },
    ])
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
    })

    const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)

    expect(expectedPayload.length).toBeLessThan(archiveListingMaxOutputBytes)
    expect(Buffer.byteLength(expectedPayload, "utf8")).toBeGreaterThan(archiveListingMaxOutputBytes)
    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("archive members marker payload")
    expect(String(result.error)).toContain(String(Buffer.byteLength(expectedPayload, "utf8")))
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeUndefined()
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("limits chown to extracted members when owner is specified", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(batchedChownCommand)
    expect(mockSsh.calls).not.toContain(`chown -R 'www-data:www-data' '${destination}'`)
  })

  it("issues one chown no matter how many members are extracted", async () => {
    const memberPaths = Array.from({ length: 500 }, (_value, index) => `app/file-${String(index)}`)
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.filter((command) => command === batchedChownCommand)).toHaveLength(1)
  })

  it("keeps the symlink probe count constant as the member count grows", async () => {
    // The bound is deliberately a fixed number rather than a ratio: a
    // regression back to per-path probing would push this far past it, which is
    // what makes the assertion worth having.
    const runWith = async (memberCount: number): Promise<number> => {
      const memberPaths = Array.from(
        { length: memberCount },
        (_value, index) => `app/file-${String(index)}`
      )
      const mockSsh = createMockSsh({
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
      })
      vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
      vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

      const result = await archive.extract(src, destination).apply(mockSsh, emptyEnv)
      expect(result.status).toBe("changed")
      return mockSsh.calls.filter((command) => command === symlinkProbeCommand).length
    }

    const few = await runWith(5)
    const many = await runWith(500)

    expect(many).toBe(few)
    expect(many).toBeLessThanOrEqual(4)
  })

  it("R-0000267: returns failed when chown of an extracted member fails", async () => {
    // chown errors (EPERM, ENOENT, quota) must surface as a maskable
    // failedCommand result instead of leaking past Promise.all in the
    // concurrency-limited mapper as an uncaught CommandError.
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: {
        code: 1,
        stderr: "chown: changing ownership of '/opt/app/app/file': Operation not permitted",
      },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("chown failed for")
    expect(String(result.error)).toContain(`${destination}/app/file`)
    // Marker must not be written when chown fails — otherwise the next check
    // would flag the broken state as ok.
    expect(mockSsh.writeFile).not.toHaveBeenCalled()
  })

  it("rejects option-like owner specs before member chown", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "-R" })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      'chown owner component must not start with "-": "-R"'
    )
    expect(mockSsh.calls).not.toContain("xargs -0 chown -h -- '-R'")
  })

  // R-0000700 / R-0000706: invalid destinations now fail fast at module
  // construction so no apply/check work is ever scheduled. The tests below
  // therefore assert that the constructor throws instead of yielding a
  // `failed` ModuleResult.
  it("rejects root destination before extracting when owner is specified", () => {
    expect(() => archive.extract(src, "/", { owner: "www-data:www-data" })).toThrow(
      /refusing to extract/v
    )
  })

  it.each(["/", "/tmp/..", "/var/.."])(
    "rejects destination %s after POSIX normalization",
    (rootLikeDestination) => {
      expect(() => archive.extract(src, rootLikeDestination)).toThrow(/destructive destination \//v)
    }
  )

  it("rejects relative destinations before extracting", () => {
    expect(() => archive.extract(src, "opt/app")).toThrow(/destination must be an absolute path/v)
  })

  // R-0000672: control characters in the extract destination must be rejected
  // before moveExtractedContentsIntoDestination feeds the guard-paths list into
  // the symlink walk. A literal `\n` in destination would split the list and
  // bypass the per-ancestor symlink probes; `\x00` would terminate the path
  // early when interpolated into a shell argument. Tests use JavaScript escape
  // sequences instead of literal control bytes so the source stays
  // grep-friendly and the intent of each case is explicit.
  it.each([
    ["newline", "/opt/app\n/etc"],
    ["carriage return", "/opt/app\r/etc"],
    ["NUL", "/opt/app\u0000/etc"],
    ["tab", "/opt/app\t/etc"],
  ])("rejects destinations containing %s control characters", (_label, destinationWithControl) => {
    expect(() => archive.extract(src, destinationWithControl)).toThrow(
      /must not contain control characters/v
    )
  })

  it("uploads file via mktemp-allocated path and cleans up when upload is true", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.uploadFile).toHaveBeenCalledWith(localFile, remoteTmp)
    expect(mockSsh.calls).toContain(`rm -f -- '${remoteTmp}'`)
  })

  it("persists extracted owner paths for upload archives with owner", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`
    const ownerPathsMarker = `${localMarker}.owner-paths`

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFile).toHaveBeenCalledWith(localMarker, archiveSha, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      `${localMarker}.members`,
      JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      { mode: "0644" }
    )
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      ownerPathsMarker,
      JSON.stringify([`${destination}/app/file`]),
      { mode: "0644" }
    )
  })

  it("regression: allocates a fresh remote upload path per invocation, even with identical local sources", async () => {
    const localFile = "/local/app.tar.gz"
    const firstRemoteTmp = "/tmp/paratix-upload.FIRST111"
    const secondRemoteTmp = "/tmp/paratix-upload.SECOND22"

    const responses: string[] = [firstRemoteTmp, secondRemoteTmp]
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${firstRemoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${secondRemoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 0,
        },
      [`tar -tvzf '${firstRemoteTmp}'`]: { code: 0, stdout: safeTarListing },
      [`tar -tvzf '${secondRemoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: "ignored-by-spy" },
    })
    // mktemp is queried via conn.output; rotate the response so concurrent
    // upload invocations produce different paths even though the local source
    // is identical. The staging-dir mktemp -d (R-0000162) is delegated to the
    // base output implementation so it still resolves via the response stubs
    // configured at module scope.
    rotateUploadMktempResponses(mockSsh, responses)
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const modA = archive.extract(localFile, destination, { upload: true })
    const modB = archive.extract(localFile, destination, { upload: true })

    const resultA = await modA.apply(mockSsh, emptyEnv)
    const resultB = await modB.apply(mockSsh, emptyEnv)

    expect(resultA.status).toBe("changed")
    expect(resultB.status).toBe("changed")
    expect(mockSsh.uploadFile).toHaveBeenNthCalledWith(1, localFile, firstRemoteTmp)
    expect(mockSsh.uploadFile).toHaveBeenNthCalledWith(2, localFile, secondRemoteTmp)
    expect(firstRemoteTmp).not.toBe(secondRemoteTmp)
    expect(mockSsh.calls).toContain(`rm -f -- '${firstRemoteTmp}'`)
    expect(mockSsh.calls).toContain(`rm -f -- '${secondRemoteTmp}'`)
  })

  it("regression: rejects with a clear error when mktemp returns an empty string", async () => {
    const localFile = "/local/app.tar.gz"
    const mockSsh = createMockSsh({
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: "" },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp did not return a remote path/v
    )
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })

  it("R-0000106: rejects a poisoned mktemp output (locale warning) without uploading", async () => {
    // Older paratix versions handed every byte from `mktemp` straight into
    // `uploadFile` / `tar -xzf` / `rm -f`. A locale warning prepended by a
    // hostile or misconfigured shell would turn into a path like
    //   "mktemp: ungültiges Format ...\n/tmp/paratix-upload.AbCdEfGh"
    // and silently corrupt the upload pipeline. The validateMktempPath
    // guard rejects the entire payload instead of using the second line.
    const localFile = "/local/app.tar.gz"
    const poisonedOutput = "mktemp: ungültiges Format ...\n/tmp/paratix-upload.AbCdEfGh"
    const mockSsh = createMockSsh({
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: poisonedOutput },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp produced an unexpected path/v
    )
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })

  it("R-0000106: rejects a mktemp output with the wrong prefix without uploading", async () => {
    // A `mktemp` whose stdout escapes /tmp/paratix-upload.* (e.g. the
    // operator pinned an alternate template via PATH=/usr/local/bin) must
    // not be used as the upload path — uploadFile and tar would otherwise
    // touch a file outside the dedicated namespace.
    const localFile = "/local/app.tar.gz"
    const mockSsh = createMockSsh({
      "mktemp /tmp/paratix-upload.XXXXXXXX": {
        code: 0,
        stdout: "/tmp/other-prefix.AbCdEfGh",
      },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp produced an unexpected path/v
    )
    expect(mockSsh.uploadFile).not.toHaveBeenCalled()
  })

  it("returns failed when extraction fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 1,
        stderr: "tar: unexpected EOF",
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("[archive.extract] failed to extract")
    // R-0000162: even when extraction fails, the staging directory must be cleaned up.
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("returns failed for unsupported archive format", async () => {
    const badSrc = "/tmp/app.rar"
    const mockSsh = createMockSsh({})

    const mod = archive.extract(badSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(String(result.error)).toContain("unsupported archive format")
  })

  it("cleans up uploaded file when extraction fails", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.FAIL1234"

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`]:
        {
          code: 1,
        },
      [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    // Cleanup must remove the same mktemp-allocated path that was used for the upload.
    expect(mockSsh.calls).toContain(`rm -f -- '${remoteTmp}'`)
  })

  it("returns failed and stops when creating the destination directory fails", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"
    const mockSsh = createMockSsh(
      {
        [`tar -tvzf '${remoteTmp}'`]: { code: 0, stdout: safeTarListing },
        "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: remoteTmp },
      },
      {
        responseStubs: [
          {
            command: guardedArchiveDestinationMkdirCommand(destination),
            result: { code: 1, stderr: "mkdir: cannot create directory: Permission denied" },
          },
        ],
      }
    )
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to create destination directory")
    expect(mockSsh.uploadFile).toHaveBeenCalledWith(localFile, remoteTmp)
    expect(mockSsh.calls).toContain(`rm -f -- '${remoteTmp}'`)
    expect(mockSsh.calls).toContain(`tar -tvzf '${remoteTmp}'`)
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${archiveStageDirectory}'`
    )
    expect(mockSsh.calls.some((command) => archiveStageMktempPattern.test(command))).toBe(false)
    expect(mockSsh.calls.some((command) => archiveStageMovePattern.test(command))).toBe(false)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("fails when the inline destination mkdir guard sees a symlink after validation", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      },
      {
        responseStubs: [
          {
            command: guardedArchiveDestinationMkdirCommand(destination),
            result: { code: 1, stderr: "destination path is a symlink\n" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to create destination directory")
    expect(mockSsh.calls).toContain(guardedArchiveDestinationMkdirCommand(destination))
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("returns failed when sha256 of remote archive is null", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(null)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("returns failed when the archive marker directory cannot be created", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      },
      {
        responseStubs: [
          {
            command: "mkdir -p '/var/lib/paratix/flags'",
            result: { code: 1, stderr: "mkdir: permission denied" },
          },
        ],
      }
    )
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to create archive marker directory")
    expect(mockSsh.writeFile).not.toHaveBeenCalled()
  })

  it("returns failed when writing the archive content marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockRejectedValueOnce(new Error("disk full"))

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write archive marker")
    expect(String(result.error)).toContain("disk full")
  })

  it("returns failed when writing the extracted members marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("quota exceeded"))

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write archive members marker")
    expect(String(result.error)).toContain("quota exceeded")
  })

  it("returns failed when writing the owner paths marker fails", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile")
      .mockResolvedValueOnce()
      .mockResolvedValueOnce()
      .mockRejectedValueOnce(new Error("read-only file system"))

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to write archive owner marker")
    expect(String(result.error)).toContain("read-only file system")
  })

  // R-0000067 regression: archive.extract must list members and reject any
  // path that escapes the destination via `..` or absolute paths, before
  // running the actual extract command. This prevents zip-slip / tar-slip
  // even when the archive's sha256 has been pinned previously but the
  // archive was crafted before the pin.
  it("rejects a tar archive that contains a `../escape` member without invoking tar -x", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 ../escape\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member is an absolute path", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 /etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose symlink target points outside the destination", async () => {
    const tarListing = `lrwxrwxrwx root/root 0 1970-01-01 00:00 link -> ../../etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose hardlink target is an absolute path", async () => {
    const tarListing = `hrw-r--r-- root/root 0 1970-01-01 00:00 app/passwd link to /etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose hardlink target traverses outside the destination", async () => {
    const tarListing = `hrw-r--r-- root/root 0 1970-01-01 00:00 app/passwd link to ../../etc/passwd\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction when an existing destination ancestor is a symlink", async () => {
    const mockSsh = createMockSsh({
      [symlinkProbeCommand]: { code: 0, stdout: `${destination}\u0000` },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("destination path")
    expect(String(result.error)).toContain("is a symlink")
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction before creating the destination when a parent directory is a symlink", async () => {
    const symlinkedDestinationAncestor = "/opt"
    const mockSsh = createMockSsh({})
    stubSymlinkViolationFor(mockSsh, symlinkedDestinationAncestor)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(JSON.stringify(symlinkedDestinationAncestor))
    expect(String(result.error)).toContain("is a symlink")
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects extraction when an existing member ancestor is a symlink", async () => {
    const symlinkedMemberAncestor = `${destination}/app`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    stubSymlinkViolationFor(mockSsh, symlinkedMemberAncestor)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(JSON.stringify(symlinkedMemberAncestor))
    expect(String(result.error)).toContain("is a symlink")
    expect(findGuardedArchiveMkdirCall(mockSsh.calls, destination)).toBeDefined()
    expect(mockSsh.calls).not.toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // Issue #219: relative symlink targets resolve from the directory that
  // contains the link, hardlink targets from the archive root. Accepted links
  // must reach the staged `tar -x`; every link that could point, write or
  // resolve outside the destination is still refused before it.
  describe("archive.extract link targets (Issue #219)", () => {
    function nodeDistributionLines(version: string): string[] {
      const root = `./externals/${version}`
      return [
        tarDirectoryLine(`${root}/`),
        tarDirectoryLine(`${root}/bin/`),
        `-rwxr-xr-x ${tarListingLineFields} ${root}/bin/node`,
        tarSymlinkLine(`${root}/bin/corepack`, "../lib/node_modules/corepack/dist/corepack.js"),
        tarSymlinkLine(`${root}/bin/npm`, "../lib/node_modules/npm/bin/npm-cli.js"),
        tarSymlinkLine(`${root}/bin/npx`, "../lib/node_modules/npm/bin/npx-cli.js"),
        tarDirectoryLine(`${root}/lib/`),
        tarDirectoryLine(`${root}/lib/node_modules/`),
        tarDirectoryLine(`${root}/lib/node_modules/corepack/`),
        tarDirectoryLine(`${root}/lib/node_modules/corepack/dist/`),
        tarFileLine(`${root}/lib/node_modules/corepack/dist/corepack.js`),
        tarDirectoryLine(`${root}/lib/node_modules/npm/`),
        tarDirectoryLine(`${root}/lib/node_modules/npm/bin/`),
        tarFileLine(`${root}/lib/node_modules/npm/bin/npm-cli.js`),
        tarFileLine(`${root}/lib/node_modules/npm/bin/npx-cli.js`),
      ]
    }

    /**
     * A chain `l0 -> l1 -> … -> l<links-1> -> end` that ends at a regular file.
     *
     * @param links - Number of symlinks in the chain.
     * @returns The listing lines, the target file last.
     */
    function symlinkChainLines(links: number): string[] {
      const chain = Array.from({ length: links - 1 }, (_value, index) =>
        tarSymlinkLine(`l${String(index)}`, `l${String(index + 1)}`)
      )
      return [...chain, tarSymlinkLine(`l${String(links - 1)}`, "end"), tarFileLine("end")]
    }

    it("extracts the actions runner layout with bin -> ../lib symlinks for node20 and node24", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("./"),
        tarDirectoryLine("./externals/"),
        ...nodeDistributionLines("node20"),
        ...nodeDistributionLines("node24"),
        `-rwxr-xr-x ${tarListingLineFields} ./run.sh`,
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("accepts a symlink into a sibling directory (a/bin/x -> ../lib/y)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/bin/"),
        tarSymlinkLine("a/bin/x", "../lib/y"),
        tarDirectoryLine("a/lib/"),
        tarFileLine("a/lib/y"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("rejects a depth-1 symlink whose target climbs two levels (a/x -> ../../y)", async () => {
      const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/x", "../../y")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/x" -> "../../y" would escape destination')
      )
    })

    it("still rejects a root-level symlink that climbs out (x -> ../y)", async () => {
      const run = await applyTarListing([tarSymlinkLine("x", "../y")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "x" -> "../y" would escape destination')
      )
    })

    it("accepts root-level symlinks to a sibling and to the destination root (x -> y, z -> .)", async () => {
      const run = await applyTarListing([
        tarSymlinkLine("x", "y"),
        tarFileLine("y"),
        tarSymlinkLine("z", "."),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it.each([".", "./"])("rejects a symlink member at the destination root (%s)", async (path) => {
      const run = await applyTarListing([tarSymlinkLine(path, "app"), tarDirectoryLine("app/")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(`member ${JSON.stringify(path)} is a link at the destination root`)
      )
    })

    it("rejects a hardlink member at the destination root", async () => {
      const run = await applyTarListing([tarFileLine("app"), tarHardlinkLine(".", "app")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "." is a link at the destination root')
      )
    })

    it("still rejects an absolute symlink target below the destination root", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarSymlinkLine("a/passwd", "/etc/passwd"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/passwd" -> "/etc/passwd" would escape destination')
      )
    })

    it("resolves hardlink targets from the archive root (a/h link to b/f)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("b/"),
        tarFileLine("b/f"),
        tarHardlinkLine("a/h", "b/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("rejects a hardlink whose archive-root-relative target climbs out (a/h link to ../f)", async () => {
      // A symlink `a/h -> ../f` would be fine; a hardlink target is a member
      // name relative to the archive root, so `../f` leaves the destination.
      const run = await applyTarListing([tarDirectoryLine("a/"), tarHardlinkLine("a/h", "../f")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/h" -> "../f" would escape destination')
      )
    })

    it("rejects a symlink that escapes through another archive symlink (a/up -> .., a/esc -> up/..)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarSymlinkLine("a/up", ".."),
        tarSymlinkLine("a/esc", "up/.."),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a/esc" -> "up/.." would escape destination')
      )
    })

    it("accepts a symlink to its parent directory on its own (a/up -> ..)", async () => {
      const run = await applyTarListing([tarDirectoryLine("a/"), tarSymlinkLine("a/up", "..")])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("accepts a symlink that resolves through an archive symlink to a directory (lib64 -> lib)", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("venv/"),
        tarDirectoryLine("venv/lib/"),
        tarFileLine("venv/lib/site.py"),
        tarSymlinkLine("venv/lib64", "lib"),
        tarDirectoryLine("venv/bin/"),
        tarSymlinkLine("venv/bin/site.py", "../lib64/site.py"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("rejects a symlink cycle with the resolution-limit reason", async () => {
      const run = await applyTarListing([tarSymlinkLine("a", "b"), tarSymlinkLine("b", "a")])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "a" -> "b" exceeds the symlink resolution limit')
      )
    })

    it("rejects a chain of more than 40 symlink hops", async () => {
      // 42 links l0 -> l1 -> … -> l41 -> end: resolving l0 needs more than the
      // 40 hops Linux allows (MAXSYMLINKS), whichever end of the chain counts.
      const run = await applyTarListing(symlinkChainLines(42))

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "l0" -> "l1" exceeds the symlink resolution limit')
      )
    })

    it("accepts a chain of 40 symlink hops that ends inside the destination", async () => {
      const run = await applyTarListing(symlinkChainLines(40))

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    // Issue #219: listed tail first, every link finds its successor already
    // memoized, so the limit is reached by summing hop counts rather than by
    // the recursion-depth cut-off. The first member over the limit in listing
    // order is the one with 41 hops: l0 in a 41-link chain, l1 in a 42-link one.
    it.each([
      { failing: "l0", links: 41, target: "l1" },
      { failing: "l1", links: 42, target: "l2" },
    ])(
      "rejects a reversed chain of $links symlinks by summing memoized hops",
      async ({ failing, links, target }) => {
        const run = await applyTarListing(symlinkChainLines(links).toReversed())

        expect(extractionSummary(run)).toStrictEqual(
          refusedBeforeExtraction(
            `member ${JSON.stringify(failing)} -> ${JSON.stringify(target)} exceeds the symlink resolution limit`
          )
        )
      }
    )

    it("accepts a reversed chain of 40 symlink hops", async () => {
      const run = await applyTarListing(symlinkChainLines(40).toReversed())

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    // Issue #219: `tar -tv` does not escape ` -> ` or ` link to ` inside names
    // or targets, so a link line that carries a separator more than once has
    // no recoverable name/target split and fails the listing before `tar -x`.
    it.each([
      {
        detail: 'link separator " -> " occurs more than once',
        line: tarSymlinkLine("d/a -> b", "../../../x"),
        name: "a symlink named d/a -> b whose real target escapes",
      },
      {
        detail: 'link separator " -> " occurs more than once',
        line: tarSymlinkLine("a -> b", "/etc"),
        name: "a symlink line a -> b -> /etc",
      },
      {
        detail: 'hardlink contains both " -> " and " link to "',
        line: tarHardlinkLine("a -> b", "d/e/c"),
        name: "a hardlink named a -> b to d/e/c",
      },
      {
        detail: 'link separator " link to " occurs more than once',
        line: tarHardlinkLine("a link to b", "c"),
        name: "a hardlink line a link to b link to c",
      },
    ])("refuses an ambiguous listing line: $name", async ({ detail, line }) => {
      const run = await applyTarListing([
        tarDirectoryLine("d/"),
        tarDirectoryLine("d/e/"),
        tarSymlinkLine("d/e/c", "../../x"),
        tarFileLine("x"),
        line,
      ])

      expect(extractionSummary(run)).toStrictEqual({
        error: expect.stringContaining(
          `[archive.extract] ambiguous tar listing line (${detail}): ${JSON.stringify(line)}`
        ),
        markerWritten: false,
        status: "failed",
        tarExtractCalls: [],
      })
    })

    it("still extracts a regular file whose name contains -> (f -> g)", async () => {
      // Only link members are split at the separator; a plain file keeps it.
      const run = await applyTarListing([tarFileLine("f -> g")])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      expect(stagingMergeGuardPaths(run.mockSsh)).toContain(`${destination}/f -> g`)
    })

    it("rejects a member below an archive symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarSymlinkLine("x/link", "y"),
        tarDirectoryLine("x/y/"),
        tarFileLine("x/link/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "x/link/f" is below archive symlink "x/link"')
      )
    })

    it("rejects a hardlink whose target passes through an archive symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarSymlinkLine("x/link", "y"),
        tarDirectoryLine("x/y/"),
        tarFileLine("x/y/f"),
        tarHardlinkLine("h", "x/link/f"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "h" hardlinks to archive symlink "x/link"')
      )
    })

    it("rejects a hardlink to an archive symlink member", async () => {
      // `link(2)` does not follow symlinks: `h` would become a second name for
      // the symlink and read `../../x` from the archive root instead of `a/b`.
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/b/"),
        tarSymlinkLine("a/b/s", "../../x"),
        tarFileLine("x"),
        tarHardlinkLine("h", "a/b/s"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction('member "h" hardlinks to archive symlink "a/b/s"')
      )
    })

    it("rejects a path that occurs as both a directory and a symlink", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("x/"),
        tarDirectoryLine("y/"),
        tarSymlinkLine("./x", "y"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(
          'member "x/" occurs more than once with conflicting link types or targets'
        )
      )
    })

    it("rejects duplicate symlink entries with different targets", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarFileLine("a/t"),
        tarFileLine("a/u"),
        tarSymlinkLine("a/l", "t"),
        tarSymlinkLine("./a/l", "u"),
      ])

      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(
          'member "a/l" occurs more than once with conflicting link types or targets'
        )
      )
    })

    it("accepts identical duplicate symlink entries", async () => {
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarFileLine("a/t"),
        tarSymlinkLine("a/l", "t"),
        tarSymlinkLine("./a/l", "t"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })

    it("probes the non-member prefixes of a link target and refuses a host symlink there", async () => {
      const hostSymlink = `${destination}/a/lib`
      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarDirectoryLine("a/bin/"), tarSymlinkLine("a/bin/x", "../lib/y")],
        { hostSymlinks: [hostSymlink] }
      )

      const probed = preStagingProbeEntries(run)
      expect(probed).toContain(hostSymlink)
      expect(probed).toContain(`${destination}/a/lib/y`)
      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(
          `link target of member "a/bin/x" passes through existing host symlink ${JSON.stringify(hostSymlink)}`
        )
      )
    })

    it("refuses a link that walks through a symlink an earlier archive left on the host", async () => {
      // An earlier archive shipped `a/up -> ..`; on its own this archive is
      // harmless, but on this host `a/esc -> up/..` resolves above `/opt/app`.
      const hostSymlink = `${destination}/a/up`
      const run = await applyTarListing(
        [tarDirectoryLine("a/"), tarSymlinkLine("a/esc", "up/..")],
        { hostSymlinks: [hostSymlink] }
      )

      expect(preStagingProbeEntries(run)).toContain(hostSymlink)
      expect(extractionSummary(run)).toStrictEqual(
        refusedBeforeExtraction(
          `link target of member "a/esc" passes through existing host symlink ${JSON.stringify(hostSymlink)}`
        )
      )
    })

    it("keeps archive symlink leaves out of the pre-staging probe and the merge guard paths", async () => {
      // Downward links only, so the listing already validates today: this case
      // isolates the guard set, which used to include the link paths themselves
      // and failed on every run where the archive's own links already existed.
      const run = await applyTarListing([
        tarDirectoryLine("a/"),
        tarDirectoryLine("a/bin/"),
        tarSymlinkLine("a/bin/x", "y"),
        tarFileLine("a/bin/y"),
        tarSymlinkLine("current", "a/bin"),
        tarFileLine("README"),
      ])

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
      const symlinkLeaves = [`${destination}/a/bin/x`, `${destination}/current`]
      const expectedGuards = [
        `${destination}/a`,
        `${destination}/a/bin`,
        `${destination}/a/bin/y`,
        `${destination}/README`,
      ]
      const probed = preStagingProbeEntries(run)
      const guardPaths = stagingMergeGuardPaths(run.mockSsh)
      expect(probed).toStrictEqual(expect.arrayContaining(expectedGuards))
      expect(guardPaths).toStrictEqual(expect.arrayContaining(expectedGuards))
      for (const leaf of symlinkLeaves) {
        expect(probed).not.toContain(leaf)
        expect(guardPaths).not.toContain(leaf)
        // The pre-merge recheck reuses the same guard set.
        expect(run.probes.flatMap((probe) => probe.entries)).not.toContain(leaf)
      }
    })

    it("validates a ~10,000-member listing with many chained and sibling symlinks", async () => {
      // Resolution is memoized per symlink, so the archive-level walk stays
      // linear; the default test timeout is the bound, not a wall-clock check.
      const lines = Array.from({ length: 1000 }, (_value, index) => {
        const directory = `d${String(index)}`
        // Each `up` points into the previous directory's chain (d0 into d999).
        const previous = `../../d${String((index + 999) % 1000)}/bin/c0`
        return [
          tarDirectoryLine(`${directory}/`),
          tarDirectoryLine(`${directory}/bin/`),
          tarDirectoryLine(`${directory}/lib/`),
          tarFileLine(`${directory}/lib/f`),
          tarSymlinkLine(`${directory}/lib64`, "lib"),
          tarSymlinkLine(`${directory}/bin/s`, "../lib/f"),
          tarSymlinkLine(`${directory}/bin/c1`, "s"),
          tarSymlinkLine(`${directory}/bin/c0`, "c1"),
          tarSymlinkLine(`${directory}/bin/up`, previous),
          tarSymlinkLine(`${directory}/bin/via64`, "../lib64/f"),
        ]
      }).flat()
      expect(lines).toHaveLength(10_000)

      const run = await applyTarListing(lines)

      expect(extractionSummary(run)).toStrictEqual(extractedThroughStaging)
    })
  })

  it("rejects a tar archive that contains a block device member", async () => {
    const tarListing = `brw-r--r-- root/root 8,0 1970-01-01 00:00 app/device\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a special file")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive with an unparsed listing line before invoking tar -x", async () => {
    const tarListing = `${safeTarListing}\nnot-a-member\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("could not parse tar listing line")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000636: control characters in archive member paths must be rejected
  // before they reach moveExtractedContentsIntoDestination, where a literal
  // newline could split the guard-paths list and bypass the per-ancestor
  // symlink protection. A NUL byte would silently terminate a path argument
  // when interpolated into a shell command. The tests use JavaScript escape
  // sequences (\x00, \x01) instead of literal control bytes so the source
  // stays grep-friendly and the intent of each test is explicit.
  it("rejects a tar archive whose member name contains a NUL byte", async () => {
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 app\x00file\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member name contains a SOH control byte", async () => {
    // We use \x01 (start of heading) as a representative low-control byte
    // that survives parseTarVerboseLine (carriage returns are already
    // rejected as unparseable because `.` in the listing regex excludes
    // line terminators). The control-character guard must catch \x01,
    // \x02, \t, … before they reach downstream guards or shell helpers.
    const tarListing = `-rw-r--r-- root/root 0 1970-01-01 00:00 app\x01file\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose symlink target contains a NUL byte", async () => {
    const tarListing = `lrwxrwxrwx root/root 0 1970-01-01 00:00 link -> target\x00evil\n`
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("link target contains control characters")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000703: tar members carrying setuid or setgid bits must be rejected
  // before `cp -aT --no-dereference` propagates the elevated permission bits
  // onto the destination filesystem. The archive validator looks at the
  // ten-character symbolic mode string and refuses members with `s`/`S` in
  // either the user- or group-execute slot. Operators who need a setuid
  // binary should chmod it in a follow-up module so the change is visible
  // in the playbook.
  it("rejects a tar archive whose member has the setuid bit set", async () => {
    const tarListing = "-rwsr-xr-x root/root 0 1970-01-01 00:00 app/suid-bin\n"
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a tar archive whose member has the setgid bit set", async () => {
    const tarListing = "-rwxr-sr-x root/root 0 1970-01-01 00:00 app/sgid-bin\n"
    const mockSsh = createMockSsh({
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListing },
    })

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
    expectNoTarExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000703: same guard for zip archives — unzip is just as willing to
  // restore setuid/setgid bits when the Unix attributes are present.
  it("rejects a zip archive whose member has the setuid bit set", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rwsr-xr-x  2.0 unx        0 b- defN 26-May-04 00:00 app/suid-bin\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("setuid or setgid bit set")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a `/etc/passwd` member without invoking unzip -o", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 /etc/passwd\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a `..` traversal member", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 ../escape\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("would escape destination")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a symlink member", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "lrwxrwxrwx  2.0 unx       11 b- stor 26-May-04 00:00 app/link\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a symlink")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  // R-0000636: zip members with control characters in their names must be
  // rejected before unzip restores them, mirroring the tar guard. NUL bytes
  // would silently truncate downstream shell arguments; carriage returns and
  // other low control bytes would let crafted archives smuggle entries past
  // the per-member guard list used by moveExtractedContentsIntoDestination.
  it("rejects a zip archive whose member name contains a NUL byte", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app\x00file\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive whose member name contains a SOH control byte", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app\x01file\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("contains control characters")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive that contains a fifo member", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "prw-r--r--  2.0 unx        0 b- stor 26-May-04 00:00 app/fifo\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("is a special file")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("rejects a zip archive with an unparsed listing line before invoking unzip -o", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -Zs '${zipSrc}'`]: {
        code: 0,
        stdout: "-rw-r--r--  2.0 unx        0 b- defN 26-May-04 00:00 app/file\nnot-a-member\n",
      },
    })

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("could not parse zip listing line")
    expect(mockSsh.calls).toContain(`unzip -Zs '${zipSrc}'`)
    expectNoUnzipExtractCalls(mockSsh)
    expectNoArchiveMarkerWrite(mockSsh)
  })

  it("has correct module name", () => {
    const mod = archive.extract(src, destination)
    expect(mod.name).toBe(`archive.extract: ${destination}`)
  })

  // R-0000162: extraction must happen into a paratix-controlled staging
  // sub-directory under the destination (`mktemp -d`), and the contents are
  // then atomically moved into the destination. This prevents a TOCTOU race
  // between `validateNoSymlinkPaths` and the `tar -xzf` / `unzip -o`
  // execution from being exploitable, because tar/unzip never writes
  // directly into a path the attacker could replace with a symlink.
  it("R-0000162: extracts into a paratix mktemp staging dir under the destination, then moves into place", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls.some((c) => archiveStageMktempPattern.test(c))).toBe(true)
    expect(mockSsh.calls.some((c) => archiveStageMovePattern.test(c))).toBe(true)
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`
    )
  })

  it("R-0000162: cleans up the staging directory when the move into the destination fails", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      },
      {
        responseStubs: [
          {
            command: archiveStageMovePattern,
            result: { code: 1, stderr: "cp: cross-device link" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to copy extracted files")
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("fails closed when the in-merge symlink guard rejects a swapped destination path", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
          code: 0,
        },
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      },
      {
        responseStubs: [
          {
            command: archiveStageMovePattern,
            result: {
              code: 64,
              stderr: `[archive.extract] refusing staging merge: destination path ${destination}/app/file is a symlink`,
            },
          },
        ],
      }
    )
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("failed to copy extracted files")
    expect(String(result.error)).toContain("refusing staging merge")
    expect(mockSsh.writeFile).not.toHaveBeenCalled()
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  it("rejects a destination that resolves elsewhere after guarded creation", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      },
      {
        responseStubs: [
          {
            command: `readlink -f -- '${destination}'`,
            result: { code: 0, stdout: "/tmp/attacker-target\n" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("destination path")
    expect(String(result.error)).toContain("/tmp/attacker-target")
    expectNoTarExtractCalls(mockSsh)
  })

  it("rechecks member destination symlinks immediately before staging merge", async () => {
    // R-0000751: the sweep before extraction and the one immediately before the
    // merge are separate on purpose, so a symlink planted in between is still
    // caught. Batching made both sweeps issue the identical command, so the
    // transported payload is what tells them apart — and the second sweep
    // carrying the member path is the recheck this asserts.
    const memberPath = `${destination}/app/file`
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    const recheck = stubSymlinkRecheck(mockSsh, memberPath)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(memberPath)
    expect(recheck.sweeps()).toBe(2)
    expect(mockSsh.calls.some((c) => archiveStageMovePattern.test(c))).toBe(false)
    expect(mockSsh.calls.some((c) => archiveStageCleanupPattern.test(c))).toBe(true)
  })

  // R-0000221: per-entry `mv -f` cannot merge into a pre-existing destination
  // sub-directory; the first conflict aborts the move and the destination is
  // left in a partial state. Per-entry `cp -aT` recurses into existing entries
  // and merges conflict-free, then the staging directory is removed wholesale.
  it("R-0000221: uses cp -aT to merge into existing destination directories conflict-free", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()
    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
    const mergeCommand = mockSsh.calls.find((c) => archiveStageMovePattern.test(c))
    expect(mergeCommand).toBeDefined()
    expect(mergeCommand).toContain("cp -aT --no-dereference --remove-destination")
    expect(mockSsh.calls.some((c) => c.includes("xargs -0 -I {} mv -f"))).toBe(false)
  })

  it("preserves existing destination directory metadata while merging staged contents", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).not.toContain(
      `cp -aT --no-dereference --remove-destination '${archiveStageDirectory}' '${destination}'`
    )
    expect(mockSsh.calls.some((c) => archiveStageMovePattern.test(c))).toBe(true)
  })

  it("hardens the staging merge so existing destination symlinks are replaced", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const mergeCommand = mockSsh.calls.find((c) => archiveStageMovePattern.test(c))
    expect(mergeCommand).toContain("cp -aT --no-dereference --remove-destination")
    expect(mergeCommand).toContain('readlink -f -- "$destination"')
    expect(mergeCommand).toContain('[ -L "$guarded_path" ]')
    expect(mergeCommand).toContain('[ -L "$target_path" ]')
    expect(mergeCommand).toContain("--remove-destination")
  })

  // R-0000751 / R-0000847: the staging merge runs exactly one
  // `[ -L "$target_path" ]` probe, placed immediately before `cp -aT` so a
  // symlink planted in the TOCTOU window between any earlier guard and the
  // copy cannot smuggle the merge through. R-0000847 removed a second
  // identical probe that had no functional effect — the surviving probe
  // sits as close to `cp` as the shell allows, which is the only window
  // that matters for the recheck-just-before-write pattern documented in
  // R-0000677.
  it("R-0000847: keeps a single target_path symlink probe immediately before cp -aT", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    const mergeCommand = mockSsh.calls.find((c) => archiveStageMovePattern.test(c))
    expect(mergeCommand).toBeDefined()
    // The shell text must contain exactly one `[ -L "$target_path" ]` probe
    // after R-0000847 removed the redundant duplicate.
    const targetSymlinkProbes = mergeCommand?.match(/\[ -L "\$target_path" \]/gv)
    expect(targetSymlinkProbes?.length).toBe(1)
    // The single surviving probe must still sit directly before `cp -aT`
    // so the recheck-just-before-write guarantee holds. We require the
    // exact one-line shell sub-segment that runs the probe, prints the
    // rejection message, closes the `if` and then invokes `cp -aT`.
    // Issue #219: the probe only refuses when the staged entry is not itself a
    // symlink, so a top-level archive symlink from an earlier run is replaced
    // by `cp --remove-destination` instead of failing every later run.
    expect(mergeCommand).toContain(
      'if [ -L "$target_path" ] && [ ! -L "$source_path" ]; then echo "[archive.extract] refusing staging merge: destination path $target_path is a symlink" >&2; exit 64; fi; cp -aT'
    )
  })

  // R-0000166: the owner-paths marker is now written for both upload and
  // non-upload extracts, so the owner re-check stays deterministic even
  // when the source archive is mutated, replaced or removed between apply
  // and the next check.
  it("R-0000166: persists extracted owner paths for non-upload archives with owner", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [batchedChownCommand]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.writeFile).toHaveBeenCalledWith(marker, archiveSha, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      membersMarker,
      JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      { mode: "0644" }
    )
    expect(mockSsh.writeFile).toHaveBeenCalledWith(
      ownerPathsMarker,
      JSON.stringify([`${destination}/app/file`]),
      { mode: "0644" }
    )
  })

  it("serializes UTF-8 bytes consistently in members and owner-paths markers", async () => {
    const unicodePath = "app/grüße-こんにちは.txt"
    const listing = `-rw-r--r-- root/root 0 1970-01-01 00:00 ${unicodePath}`
    const ownerPathsMarker = `${marker}.owner-paths`
    const membersPayload = JSON.stringify([{ kind: "file", path: `${destination}/${unicodePath}` }])
    const ownerPathsPayload = JSON.stringify([`${destination}/${unicodePath}`])
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: listing },
      [batchedChownCommand]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const result = await archive
      .extract(src, destination, { owner: "www-data:www-data" })
      .apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(Buffer.byteLength(membersPayload, "utf8")).toBeGreaterThan(membersPayload.length)
    expect(Buffer.byteLength(ownerPathsPayload, "utf8")).toBeGreaterThan(ownerPathsPayload.length)
    expect(mockSsh.writeFile).toHaveBeenCalledWith(membersMarker, membersPayload, { mode: "0644" })
    expect(mockSsh.writeFile).toHaveBeenCalledWith(ownerPathsMarker, ownerPathsPayload, {
      mode: "0644",
    })
  })

  it("R-0000166: non-upload owner check operates on the persisted member list, not the live archive", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    // The live archive on disk now contains a *different* member; without
    // the persisted marker the check would stat the wrong path. With the
    // marker the check resolves the original member and reports `ok`.
    const driftedTarListing = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/replacement"
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: driftedTarListing },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    // The check must not consult the live archive listing when the marker is
    // available — that's the entire point of R-0000166.
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
  })

  it.each([
    { label: "malformed", ownerPaths: "{not-json" },
    {
      label: "truncated",
      ownerPaths: `${JSON.stringify([extractedFileMember.path])}${CAPTURE_TRUNCATION_MARKER}`,
    },
  ])("fails closed for a $label owner-paths marker without legacy fallback", async (testCase) => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`cat '${membersMarker}'`]: validMembersMarkerResponse(),
      [`cat '${ownerPathsMarker}'`]: { code: 0, stdout: testCase.ownerPaths },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [extractedFileTypeProbe]: memberTypeMatchResponse,
    })

    const result = await archive
      .extract(src, destination, { owner: "www-data:www-data" })
      .check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
    expect(mockSsh.calls).not.toContain(ownershipProbeCommand("www-data:www-data"))
  })

  it("R-0000166: falls back to the live archive listing when the owner-paths marker is missing (legacy host)", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 1,
        stderr: "cat: No such file or directory",
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [ownershipProbeCommand("www-data:www-data")]: ownershipReport(
        `${destination}/app/file`,
        "www-data www-data 33 33"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expectArchiveCaptureExecCall(mockSsh, `cat '${ownerPathsMarker}'`, true)
    expectArchiveCaptureExecCall(mockSsh, `tar -tvzf '${src}'`)
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
  })

  it("returns ok when a numeric owner matches the extracted member ids", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      // No passwd or group entry for 65532, so GNU coreutils answers UNKNOWN
      // for the name columns; only the numeric columns can match.
      [ownershipProbeCommand("65532:65532")]: ownershipReport(
        `${destination}/app/file`,
        "UNKNOWN UNKNOWN 65532 65532"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "65532:65532" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain(ownershipProbeCommand("65532:65532"))
  })

  it("returns ok for a leading-zero numeric owner on extracted members", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [ownershipProbeCommand("065532:065532")]: ownershipReport(
        `${destination}/app/file`,
        "UNKNOWN UNKNOWN 65532 65532"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "065532:065532" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
  })

  it("returns needs-apply when a numeric owner does not match the extracted member ids", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
      [ownershipProbeCommand("65532:65532")]: ownershipReport(
        `${destination}/app/file`,
        "root root 0 0"
      ),
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "65532:65532" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("needs-apply")
  })

  it("R-0000162: rejects a poisoned mktemp -d output for the staging directory", async () => {
    const mockSsh = createMockSsh(
      {
        [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      },
      {
        responseStubs: [
          {
            command: archiveStageMktempPattern,
            result: { code: 0, stdout: "/tmp/elsewhere.AbCdEfGh" },
          },
        ],
      }
    )

    const mod = archive.extract(src, destination)

    await expect(mod.apply(mockSsh, emptyEnv)).rejects.toThrow(
      /mktemp -d produced an unexpected staging path/v
    )
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`
    )
  })
})
