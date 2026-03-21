import { describe, expect, it, vi } from "vitest"

import { archive } from "../../src/modules/archive.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

const src = "/tmp/app.tar.gz"
const destination = "/opt/app"
const alternateDestination = "/opt/app-alt"

// Stable hash of `${src}\n${destination}` for marker file naming.
const srcHash = "2889be4b654d6b7f7922971e7fb3fdf1c5ebd92b9c52462be2683a735c7562ef"
const marker = `/var/lib/paratix/flags/archive-${srcHash}.sha256`
const archiveSha = "abc123def456"

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

  it("extracts tar.gz archive and writes marker", async () => {
    const mockSsh = createMockSsh({
      [`tar xzf '${src}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`mkdir -p '${destination}'`)
    expect(mockSsh.calls).toContain(`tar xzf '${src}' -C '${destination}'`)
    expect(mockSsh.calls).toContain(`mkdir -p '/var/lib/paratix/flags'`)
  })

  it("extracts .tar archive", async () => {
    const tarSrc = "/tmp/app.tar"
    const mockSsh = createMockSsh({
      [`tar xf '${tarSrc}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tarSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`tar xf '${tarSrc}' -C '${destination}'`)
  })

  it("extracts .tar.bz2 archive", async () => {
    const bz2Src = "/tmp/app.tar.bz2"
    const mockSsh = createMockSsh({
      [`tar xjf '${bz2Src}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(bz2Src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`tar xjf '${bz2Src}' -C '${destination}'`)
  })

  it("extracts .tar.xz archive", async () => {
    const xzSrc = "/tmp/app.tar.xz"
    const mockSsh = createMockSsh({
      [`tar xJf '${xzSrc}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(xzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`tar xJf '${xzSrc}' -C '${destination}'`)
  })

  it("extracts .zip archive", async () => {
    const zipSrc = "/tmp/app.zip"
    const mockSsh = createMockSsh({
      [`unzip -o '${zipSrc}' -d '${destination}'`]: { code: 0 },
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
      [`tar xzf '${tgzSrc}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(tgzSrc, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`tar xzf '${tgzSrc}' -C '${destination}'`)
  })

  it("runs chown when owner is specified", async () => {
    const mockSsh = createMockSsh({
      [`tar xzf '${src}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(archiveSha)
    vi.spyOn(mockSsh, "writeFile").mockResolvedValue()

    const mod = archive.extract(src, destination, { owner: "www-data:www-data" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
    expect(mockSsh.calls).toContain(`chown -R 'www-data:www-data' '${destination}'`)
  })

  it("uploads file and cleans up when upload is true", async () => {
    const localFile = "/local/app.tar.gz"
    const uploadHash = "113329b21446a20ca2e8304294da20dc3aa7668c5cc4a803ffb59e377bb80f4f"
    const remoteTmp = `/tmp/paratix-upload-${uploadHash}`

    const mockSsh = createMockSsh({
      [`tar xzf '${remoteTmp}' -C '${destination}'`]: { code: 0 },
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

  it("returns failed when extraction fails", async () => {
    const mockSsh = createMockSsh({
      [`tar xzf '${src}' -C '${destination}'`]: { code: 1, stderr: "tar: unexpected EOF" },
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
    const uploadHash = "113329b21446a20ca2e8304294da20dc3aa7668c5cc4a803ffb59e377bb80f4f"
    const remoteTmp = `/tmp/paratix-upload-${uploadHash}`

    const mockSsh = createMockSsh({
      [`tar xzf '${remoteTmp}' -C '${destination}'`]: { code: 1 },
    })
    vi.spyOn(mockSsh, "uploadFile").mockResolvedValue()

    const mod = archive.extract(localFile, destination, { upload: true })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(mockSsh.calls).toContain(`rm -f '${remoteTmp}'`)
  })

  it("returns failed when sha256 of remote archive is null", async () => {
    const mockSsh = createMockSsh({
      [`tar xzf '${src}' -C '${destination}'`]: { code: 0 },
    })
    vi.spyOn(mockSsh, "sha256").mockResolvedValue(null)

    const mod = archive.extract(src, destination)
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("has correct module name", () => {
    const mod = archive.extract(src, destination)
    expect(mod.name).toBe(`archive.extract: ${destination}`)
  })
})
