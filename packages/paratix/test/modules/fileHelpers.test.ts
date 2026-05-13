import { createHash } from "node:crypto"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Readable } from "node:stream"
import { afterEach, describe, expect, it, vi } from "vitest"

import { hexHashesEqual, localSha256 } from "../../src/modules/fileHelpers.js"

const tempDirectories: string[] = []

describe("hexHashesEqual", () => {
  it("returns true when both hashes are identical", () => {
    const hash = "a".repeat(64)
    expect(hexHashesEqual(hash, hash)).toBe(true)
  })

  it("returns true for two equal SHA-256 hex hashes", () => {
    const hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    expect(hexHashesEqual(hash, hash)).toBe(true)
  })

  it("returns false when hashes differ", () => {
    const hashA = "a".repeat(64)
    const hashB = "b".repeat(64)
    expect(hexHashesEqual(hashA, hashB)).toBe(false)
  })

  it("returns false when only one character differs", () => {
    const hashA = `${"a".repeat(63)}b`
    const hashB = "a".repeat(64)
    expect(hexHashesEqual(hashA, hashB)).toBe(false)
  })

  it("returns false when first parameter is null", () => {
    const hash = "a".repeat(64)
    expect(hexHashesEqual(null, hash)).toBe(false)
  })
})

describe("localSha256", () => {
  afterEach(async () => {
    vi.doUnmock("node:fs")
    vi.resetModules()
    await Promise.all(
      tempDirectories.splice(0).map(async (path) => rm(path, { force: true, recursive: true }))
    )
  })

  it("returns the SHA-256 hash of a local file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "paratix-local-sha256-"))
    tempDirectories.push(directory)
    const filePath = join(directory, "payload.txt")
    const content = "hello world"
    await writeFile(filePath, content)

    await expect(localSha256(filePath)).resolves.toBe(
      createHash("sha256").update(content).digest("hex")
    )
  })

  it("hashes local files through createReadStream", async () => {
    const createReadStream = vi.fn(() =>
      Readable.from([Buffer.from("hello "), Buffer.from("world")])
    )
    vi.doMock("node:fs", () => ({ createReadStream }))
    const { localSha256: streamedLocalSha256 } = await import("../../src/modules/fileHelpers.js")

    await expect(streamedLocalSha256("/tmp/payload.txt")).resolves.toBe(
      createHash("sha256").update("hello world").digest("hex")
    )
    expect(createReadStream).toHaveBeenCalledWith("/tmp/payload.txt")
  })
})
