import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it } from "vitest"

import { writeProjectFiles } from "../src/index.js"

const TEST_DIR = resolve("/tmp/create-paratix-test")

describe("writeProjectFiles", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true })
  })

  afterEach(() => {
    rmSync(TEST_DIR, { force: true, recursive: true })
  })

  it("creates a package.json in the target directory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "package.json"))).toBe(true)
  })

  it("generated package.json contains an engines field with node >=24.0.0", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      engines: { node: ">=24.0.0" },
    })
  })

  it("generated package.json has type module", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({ type: "module" })
  })

  it("generated package.json contains the paratix dependency", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      dependencies: { paratix: expect.stringMatching(/^\^/v) },
    })
  })

  it("creates a server.ts file", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(true)
  })

  it("creates a files subdirectory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "files"))).toBe(true)
  })
})
