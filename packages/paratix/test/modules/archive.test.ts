import { describe, expect, it, vi } from "vitest"

import type { ExecResult } from "../../src/types.js"

import { archive } from "../../src/modules/archive.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const src = "/tmp/app.tar.gz"
const destination = "/opt/app"
const alternateDestination = "/opt/app-alt"
const safeTarListing = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/file"
const archiveOwnerMemberConcurrencyLimit = 8
const archiveSymlinkCheckConcurrencyLimit = 8

// Stable hash of `${src}\n${destination}` for marker file naming.
const srcHash = "2889be4b654d6b7f7922971e7fb3fdf1c5ebd92b9c52462be2683a735c7562ef"
const marker = `/var/lib/paratix/flags/archive-${srcHash}.sha256`
const membersMarker = `${marker}.members`
const archiveSha = "abc123def456"

const archiveSymlinkCheckPaths = [
  "/opt",
  destination,
  alternateDestination,
  `${destination}/app`,
  `${destination}/app/file`,
  ...Array.from({ length: 24 }, (_value, index) => `${destination}/app/file-${String(index)}`),
]
const archiveCleanupPaths = [
  "/tmp/paratix-upload.AbCdEfGh",
  "/tmp/paratix-upload.FAIL1234",
  "/tmp/paratix-upload.FIRST111",
  "/tmp/paratix-upload.SECOND22",
]

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

const archiveApplyResponseStubs: NonNullable<
  Parameters<typeof createBaseMockSsh>[1]
>["responseStubs"] = [
  { command: archiveMembersMarkerPattern, result: { code: 1, stderr: "cat: No such file" } },
  ...archiveSymlinkCheckPaths.map((path) => ({
    command: `test ! -L '${path}'`,
    result: { code: 0 },
  })),
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

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    // Test-supplied stubs take priority over the module-scope defaults so a
    // single test can override e.g. the staging-dir mktemp / move / cleanup
    // commands without having to disable the shared stubs entirely.
    responseStubs: [...(options?.responseStubs ?? []), ...archiveApplyResponseStubs],
  })

type MockSsh = ReturnType<typeof createMockSsh>
type ExecTracker = { exec: MockSsh["exec"]; maxActive: () => number }

function tarListingForMemberPaths(memberPaths: string[]): string {
  return memberPaths
    .map((memberPath) => `-rw-r--r-- root/root 0 1970-01-01 00:00 ${memberPath}`)
    .join("\n")
}

async function waitForTrackedExecTick(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 1)
  })
}

function createTrackedExec(
  mockSsh: MockSsh,
  originalExec: MockSsh["exec"],
  parameters: {
    isTrackedCommand: (command: string) => boolean
    resultForCommand: (command: string) => ExecResult
  }
): ExecTracker {
  let active = 0
  let maxActive = 0

  return {
    async exec(command, options) {
      if (!parameters.isTrackedCommand(command)) return originalExec(command, options)
      mockSsh.calls.push(command)
      mockSsh.execCalls.push({ command, options })
      active += 1
      maxActive = Math.max(maxActive, active)
      await waitForTrackedExecTick()
      active -= 1
      return parameters.resultForCommand(command)
    },
    maxActive: () => maxActive,
  }
}

function createOwnerCheckExecTracker(mockSsh: MockSsh, originalExec: MockSsh["exec"]): ExecTracker {
  return createTrackedExec(mockSsh, originalExec, {
    isTrackedCommand: (command) =>
      command.startsWith(`[ -e '${destination}/app/file-`) ||
      command.startsWith(`stat -c '%U %G' -- '${destination}/app/file-`),
    resultForCommand: (command) =>
      command.startsWith("stat ")
        ? { code: 0, stderr: "", stdout: "www-data www-data\n" }
        : { code: 0, stderr: "", stdout: "" },
  })
}

function createOwnerChownExecTracker(mockSsh: MockSsh, originalExec: MockSsh["exec"]): ExecTracker {
  return createTrackedExec(mockSsh, originalExec, {
    isTrackedCommand: (command) => command.startsWith("chown -h -- 'www-data:www-data' "),
    resultForCommand: () => ({ code: 0, stderr: "", stdout: "" }),
  })
}

function createSymlinkCheckExecTracker(
  mockSsh: MockSsh,
  originalExec: MockSsh["exec"]
): ExecTracker {
  return createTrackedExec(mockSsh, originalExec, {
    isTrackedCommand: (command) => command.startsWith("test ! -L "),
    resultForCommand: () => ({ code: 0, stderr: "", stdout: "" }),
  })
}

function createSecondMatchingExecFailure(
  mockSsh: MockSsh,
  originalExec: MockSsh["exec"],
  commandToFail: string
): MockSsh["exec"] {
  let matchingCalls = 0
  return async (command, options) => {
    if (command !== commandToFail) return originalExec(command, options)
    matchingCalls += 1
    mockSsh.calls.push(command)
    mockSsh.execCalls.push({ command, options })
    return {
      code: matchingCalls === 2 ? 1 : 0,
      stderr: "",
      stdout: "",
    }
  }
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
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when an extracted member was deleted after extraction", async () => {
    const mockSsh = createMockSsh({
      [`[ -f '${destination}/app/file' ] && [ ! -L '${destination}/app/file' ]`]: { code: 1 },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "file", path: `${destination}/app/file` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("returns needs-apply when an extracted directory was replaced by a symlink", async () => {
    const mockSsh = createMockSsh({
      [`[ -d '${destination}/app' ] && [ ! -L '${destination}/app' ]`]: { code: 1 },
      [`cat '${membersMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([{ kind: "directory", path: `${destination}/app` }]),
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
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
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
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
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "www-data www-data\n",
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when extracted owner has drifted", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "root root\n",
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("limits concurrent owner checks across extracted archive members", async () => {
    const memberPaths = Array.from({ length: 24 }, (_value, index) => `app/file-${String(index)}`)
    const ownerPathsMarker = `${marker}.owner-paths`
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
      ...Object.fromEntries(
        memberPaths.map((path) => [
          `[ -f '${destination}/${path}' ] && [ ! -L '${destination}/${path}' ]`,
          { code: 0 },
        ])
      ),
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const originalExec = mockSsh.exec.bind(mockSsh)
    const ownerExecTracker = createOwnerCheckExecTracker(mockSsh, originalExec)

    vi.spyOn(mockSsh, "exec").mockImplementation(ownerExecTracker.exec)
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(
      mockSsh.calls.filter((command) =>
        command.startsWith(`stat -c '%U %G' -- '${destination}/app/file-`)
      )
    ).toHaveLength(memberPaths.length)
    expect(ownerExecTracker.maxActive()).toBeLessThanOrEqual(archiveOwnerMemberConcurrencyLimit)
  })

  it("returns needs-apply when marker does not match remote archive sha256", async () => {
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: "old-hash" },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue("new-hash")
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000105: returns needs-apply when marker cat reports 'No such file'", async () => {
    // Race between test -f and cat (e.g. concurrent cleanup): treat the
    // missing marker as a regular needs-apply, identical to the case where
    // test -f already failed.
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 1, stderr: `cat: '${marker}': No such file or directory` },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("R-0000276: returns needs-apply when owner-paths marker cat fails with permission denied", async () => {
    // Permission drift on the owner-paths marker (or any non-"no such file"
    // stderr) must not abort the run. Treat the unreadable marker like a
    // drift so apply heals it on the next run. With upload=false the
    // archiveOwnerMatches helper falls back to listing the source archive,
    // and reports drift when the on-disk owner does not match.
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${ownerPathsMarker}'`]: {
        code: 1,
        stderr: `cat: '${ownerPathsMarker}': Permission denied`,
      },
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "root root\n",
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
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
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "www-data www-data\n",
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${localMarker}'`]: { code: 0 },
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
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${ownerPathsMarker}'`]: {
        code: 0,
        stdout: JSON.stringify([`${destination}/app/file`]),
      },
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "root root\n",
      },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${localMarker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, {
      owner: "www-data:www-data",
      upload: true,
    })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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

  it("limits chown to extracted members when owner is specified", async () => {
    const mockSsh = createMockSsh({
      [`chown -h -- 'www-data:www-data' '${destination}/app/file'`]: { code: 0 },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`chown -h -- 'www-data:www-data' '${destination}/app/file'`)
    expect(mockSsh.calls).not.toContain(`chown -R 'www-data:www-data' '${destination}'`)
  })

  it("limits concurrent owner chown commands across extracted archive members", async () => {
    const memberPaths = Array.from({ length: 24 }, (_value, index) => `app/file-${String(index)}`)
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
    })
    const originalExec = mockSsh.exec.bind(mockSsh)
    const chownExecTracker = createOwnerChownExecTracker(mockSsh, originalExec)

    vi.spyOn(mockSsh, "exec").mockImplementation(chownExecTracker.exec)
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(
      mockSsh.calls.filter((command) => command.startsWith("chown -h -- 'www-data:www-data' "))
    ).toHaveLength(memberPaths.length)
    expect(chownExecTracker.maxActive()).toBeLessThanOrEqual(archiveOwnerMemberConcurrencyLimit)
  })

  it("limits concurrent symlink checks across archive destination paths", async () => {
    const memberPaths = Array.from({ length: 24 }, (_value, index) => `app/file-${String(index)}`)
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
    })
    const originalExec = mockSsh.exec.bind(mockSsh)
    const symlinkExecTracker = createSymlinkCheckExecTracker(mockSsh, originalExec)

    vi.spyOn(mockSsh, "exec").mockImplementation(symlinkExecTracker.exec)
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(
      mockSsh.calls.filter((command) => command.startsWith("test ! -L ")).length
    ).toBeGreaterThan(memberPaths.length)
    expect(symlinkExecTracker.maxActive()).toBeLessThanOrEqual(archiveSymlinkCheckConcurrencyLimit)
  })

  it("R-0000267: returns failed when chown of an extracted member fails", async () => {
    // chown errors (EPERM, ENOENT, quota) must surface as a maskable
    // failedCommand result instead of leaking past Promise.all in the
    // concurrency-limited mapper as an uncaught CommandError.
    const mockSsh = createMockSsh({
      [`chown -h -- 'www-data:www-data' '${destination}/app/file'`]: {
        code: 1,
        stderr: "chown: changing ownership of '/opt/app/app/file': Operation not permitted",
      },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
    expect(mockSsh.calls).not.toContain(`chown -h -- '-R' '${destination}/app/file'`)
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
    ["NUL", "/opt/app /etc"],
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
      [`chown -h -- 'www-data:www-data' '${destination}/app/file'`]: { code: 0 },
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
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${remoteTmp}'`)
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
      [`chown -h -- 'www-data:www-data' '${destination}/app/file'`]: { code: 0 },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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
      [`test ! -L '${destination}'`]: { code: 1 },
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
    const mockSsh = createMockSsh({
      [`test ! -L '${symlinkedDestinationAncestor}'`]: { code: 1 },
    })

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
      [`test ! -L '${symlinkedMemberAncestor}'`]: { code: 1 },
    })

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
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    const originalExec = mockSsh.exec.bind(mockSsh)
    vi.spyOn(mockSsh, "exec").mockImplementation(
      createSecondMatchingExecFailure(mockSsh, originalExec, `test ! -L '${destination}/app/file'`)
    )

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain(`${destination}/app/file`)
    expect(
      mockSsh.calls.filter((command) => command === `test ! -L '${destination}/app/file'`)
    ).toHaveLength(2)
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
    expect(mergeCommand).toContain(
      'if [ -L "$target_path" ]; then echo "[archive.extract] refusing staging merge: destination path $target_path is a symlink" >&2; exit 64; fi; cp -aT'
    )
  })

  // R-0000166: the owner-paths marker is now written for both upload and
  // non-upload extracts, so the owner re-check stays deterministic even
  // when the source archive is mutated, replaced or removed between apply
  // and the next check.
  it("R-0000166: persists extracted owner paths for non-upload archives with owner", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`chown -h -- 'www-data:www-data' '${destination}/app/file'`]: { code: 0 },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${archiveStageDirectory}'`]: {
        code: 0,
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
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

  it("R-0000166: non-upload owner check operates on the persisted member list, not the live archive", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    // The live archive on disk now contains a *different* member; without
    // the persisted marker the check would stat the wrong path. With the
    // marker the check resolves the original member and reports `ok`.
    const driftedTarListing = "-rw-r--r-- root/root 0 1970-01-01 00:00 app/replacement"
    const mockSsh = createMockSsh({
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
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
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "www-data www-data\n",
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: driftedTarListing },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    // The check must not consult the live archive listing when the marker is
    // available — that's the entire point of R-0000166.
    expect(mockSsh.calls).not.toContain(`tar -tvzf '${src}'`)
  })

  it("R-0000166: falls back to the live archive listing when the owner-paths marker is missing (legacy host)", async () => {
    const ownerPathsMarker = `${marker}.owner-paths`
    const mockSsh = createMockSsh({
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
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
      [`stat -c '%U %G' -- '${destination}/app/file'`]: {
        code: 0,
        stdout: "www-data www-data\n",
      },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.check(mockSsh, emptyEnv)

    expect(result).toBe("ok")
    expect(mockSsh.calls).toContain(`tar -tvzf '${src}'`)
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
