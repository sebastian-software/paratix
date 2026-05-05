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

// Stable hash of `${src}\n${destination}` for marker file naming.
const srcHash = "2889be4b654d6b7f7922971e7fb3fdf1c5ebd92b9c52462be2683a735c7562ef"
const marker = `/var/lib/paratix/flags/archive-${srcHash}.sha256`
const archiveSha = "abc123def456"

const archiveSymlinkCheckPaths = [
  "/opt",
  destination,
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
const archiveApplyResponseStubs: NonNullable<
  Parameters<typeof createBaseMockSsh>[1]
>["responseStubs"] = [
  ...archiveSymlinkCheckPaths.map((path) => ({
    command: `test ! -L '${path}'`,
    result: { code: 0 },
  })),
  { command: `mkdir -p '${destination}'`, result: { code: 0 } },
  { command: "mkdir -p '/var/lib/paratix/flags'", result: { code: 0 } },
  ...archiveCleanupPaths.map((path) => ({
    command: `rm -f '${path}'`,
    result: { code: 0 },
  })),
]

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, {
    ...options,
    responseStubs: [...archiveApplyResponseStubs, ...(options?.responseStubs ?? [])],
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

describe("archive.extract — check", () => {
  it("returns needs-apply when conn is null", async () => {
    const mod = archive.extract(src, destination)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when destination does not exist", async () => {
    const mockSsh = createMockSsh({
      [`test -d '${destination}'`]: { code: 1 },
    })
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
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
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    const mod = archive.extract(src, destination)
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when marker matches and extracted owner matches", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
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
  })

  it("returns needs-apply when extracted owner has drifted", async () => {
    const mockSsh = createMockSsh({
      [`[ -e '${destination}/app/file' ] || [ -L '${destination}/app/file' ]`]: { code: 0 },
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
    expect(mockSsh.calls).not.toContain(`cat '${marker}'`)
  })

  it("limits concurrent owner checks across extracted archive members", async () => {
    const memberPaths = Array.from({ length: 24 }, (_value, index) => `app/file-${String(index)}`)
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 0, stdout: archiveSha },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: tarListingForMemberPaths(memberPaths) },
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

  it("R-0000105: throws when marker cat fails with a non-missing error", async () => {
    // Permission-denied (or any non "No such file" error) on the marker
    // must not silently collapse to an empty stdout — that would force a
    // costly re-extract of the entire archive even though the marker
    // existed and matched. Surface the real cause instead.
    const mockSsh = createMockSsh({
      [`cat '${marker}'`]: { code: 1, stderr: `cat: '${marker}': Permission denied` },
      [`test -d '${destination}'`]: { code: 0 },
      [`test -f '${marker}'`]: { code: 0 },
    })
    const mod = archive.extract(src, destination)
    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(/marker file unreadable/v)
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

  it("computes local sha256 when upload is true without uploading", async () => {
    const localFile = "/local/app.tar.gz"
    const localFileHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    // sha256String of `${localFile}\n${destination}` for marker name
    const localSrcHash = "edd161527d28e0daec8363c041e405c2b17a6fabc2b74d3b5e956652b98a3520"
    const localMarker = `/var/lib/paratix/flags/archive-${localSrcHash}.sha256`

    const mockSsh = createMockSsh({
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
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`]: { code: 0 },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`
    )
    expect(mockSsh.calls).toContain(`mkdir -p '/var/lib/paratix/flags'`)
    expect(mockSsh.writeFile).toHaveBeenCalledOnce()
    expect(mockSsh.writeFile).toHaveBeenCalledWith(marker, archiveSha, { mode: "0644" })
  })

  it("extracts .tar archive", async () => {
    const tarSrc = "/tmp/app.tar"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xf '${tarSrc}' -C '${destination}'`]: { code: 0 },
      [`tar -tvf '${tarSrc}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tarSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xf '${tarSrc}' -C '${destination}'`
    )
  })

  it("extracts .tar.bz2 archive", async () => {
    const bz2Src = "/tmp/app.tar.bz2"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xjf '${bz2Src}' -C '${destination}'`]: { code: 0 },
      [`tar -tvjf '${bz2Src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(bz2Src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xjf '${bz2Src}' -C '${destination}'`
    )
  })

  it("extracts .tar.xz archive", async () => {
    const xzSrc = "/tmp/app.tar.xz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xJf '${xzSrc}' -C '${destination}'`]: { code: 0 },
      [`tar -tvJf '${xzSrc}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(xzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xJf '${xzSrc}' -C '${destination}'`
    )
  })

  it("extracts .zip archive", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -o '${zipSrc}' -d '${destination}'`]: { code: 0 },
      [`unzip -Zs '${zipSrc}'`]: { code: 0, stdout: safeZipListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(zipSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`unzip -o '${zipSrc}' -d '${destination}'`)
  })

  it("extracts .tgz archive", async () => {
    const tgzSrc = "/tmp/app.tgz"
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${destination}'`]: { code: 0 },
      [`tar -tvzf '${tgzSrc}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tgzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${tgzSrc}' -C '${destination}'`
    )
  })

  it("limits chown to extracted members when owner is specified", async () => {
    const mockSsh = createMockSsh({
      [`chown -h -- 'www-data:www-data' '${destination}/app/file'`]: { code: 0 },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`]: { code: 0 },
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
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`]: { code: 0 },
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

  it("rejects option-like owner specs before member chown", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`]: { code: 0 },
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

  it("rejects root destination before extracting when owner is specified", async () => {
    const rootDestination = "/"
    const mockSsh = createMockSsh({})

    const mod = archive.extract(src, rootDestination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("refusing to extract")
    expect(mockSsh.calls).not.toContain(`mkdir -p '${rootDestination}'`)
    expect(mockSsh.calls).not.toContain(
      `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${rootDestination}'`
    )
  })

  it.each(["/", "/tmp/..", "/var/.."])(
    "rejects destination %s after POSIX normalization",
    async (rootLikeDestination) => {
      const mockSsh = createMockSsh({})

      const mod = archive.extract(src, rootLikeDestination)
      const result = await mod.apply(mockSsh, emptyEnv)

      expect(result.status).toBe("failed")
      expect(String(result.error)).toContain("destructive destination /")
      expect(mockSsh.calls).not.toContain("mkdir -p '/'")
      expect(mockSsh.calls).not.toContain(
        `tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '/'`
      )
    }
  )

  it("rejects relative destinations before extracting", async () => {
    const relativeDestination = "opt/app"
    const mockSsh = createMockSsh({})

    const mod = archive.extract(src, relativeDestination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(String(result.error)).toContain("destination must be an absolute path")
    expect(mockSsh.calls).not.toContain(`mkdir -p '${relativeDestination}'`)
  })

  it("uploads file via mktemp-allocated path and cleans up when upload is true", async () => {
    const localFile = "/local/app.tar.gz"
    const remoteTmp = "/tmp/paratix-upload.AbCdEfGh"

    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${destination}'`]: {
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
    expect(mockSsh.calls).toContain(`rm -f '${remoteTmp}'`)
  })

  it("regression: allocates a fresh remote upload path per invocation, even with identical local sources", async () => {
    const localFile = "/local/app.tar.gz"
    const firstRemoteTmp = "/tmp/paratix-upload.FIRST111"
    const secondRemoteTmp = "/tmp/paratix-upload.SECOND22"

    const responses: string[] = [firstRemoteTmp, secondRemoteTmp]
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${firstRemoteTmp}' -C '${destination}'`]: {
        code: 0,
      },
      [`tar --no-same-owner --no-overwrite-dir -xzf '${secondRemoteTmp}' -C '${destination}'`]: {
        code: 0,
      },
      [`tar -tvzf '${firstRemoteTmp}'`]: { code: 0, stdout: safeTarListing },
      [`tar -tvzf '${secondRemoteTmp}'`]: { code: 0, stdout: safeTarListing },
      "mktemp /tmp/paratix-upload.XXXXXXXX": { code: 0, stdout: "ignored-by-spy" },
    })
    // mktemp is queried via conn.output; rotate the response so concurrent
    // invocations produce different paths even though the local source is identical.
    vi.spyOn(mockSsh, "output")
      .mockImplementationOnce(async (command) => {
        await Promise.resolve()
        mockSsh.calls.push(command)
        return responses[0]
      })
      .mockImplementationOnce(async (command) => {
        await Promise.resolve()
        mockSsh.calls.push(command)
        return responses[1]
      })
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
    expect(mockSsh.calls).toContain(`rm -f '${firstRemoteTmp}'`)
    expect(mockSsh.calls).toContain(`rm -f '${secondRemoteTmp}'`)
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
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`]: {
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
      [`tar --no-same-owner --no-overwrite-dir -xzf '${remoteTmp}' -C '${destination}'`]: {
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
    expect(mockSsh.calls).toContain(`rm -f '${remoteTmp}'`)
  })

  it("returns failed when sha256 of remote archive is null", async () => {
    const mockSsh = createMockSsh({
      [`tar --no-same-owner --no-overwrite-dir -xzf '${src}' -C '${destination}'`]: { code: 0 },
      [`tar -tvzf '${src}'`]: { code: 0, stdout: safeTarListing },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(null)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
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
    expect(mockSsh.calls).toContain(`mkdir -p '${destination}'`)
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
})
