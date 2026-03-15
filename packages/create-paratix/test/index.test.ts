import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it } from "vitest"

import { isDirectExecution, writeProjectFiles } from "../src/index.js"

describe("isDirectExecution (process.argv[1] regression)", () => {
  it("returns false when argv1 is null without throwing", () => {
    // Regression: previously index.ts called process.argv[1].replaceAll() without a null-check,
    // causing a TypeError when argv[1] is undefined (e.g. in a REPL or certain test runners).
    // null and undefined are both guarded by the != null check.
    expect(isDirectExecution("file:///some/module.js", null)).toBe(false)
  })

  it("returns false when the module URL does not match argv1", () => {
    expect(isDirectExecution("file:///project/src/index.js", "/other/script.js")).toBe(false)
  })

  it("returns true when the module URL ends with the normalised argv1 path", () => {
    expect(isDirectExecution("file:///project/src/index.js", "/project/src/index.js")).toBe(true)
  })

  it("normalises Windows backslashes in argv1 before comparing", () => {
    expect(isDirectExecution("file:///project/src/index.js", "\\project\\src\\index.js")).toBe(true)
  })
})

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

  it("generated server.ts uses pkg.upgrade and pkg.installed (not apt.*)", () => {
    // Regression: SERVER_TEMPLATE previously used the deprecated apt module
    // (apt.upgrade / apt.installed). After Plan-0013 refactoring the correct
    // module is `package as pkg` with pkg.upgrade / pkg.installed.
    // TypeScript cannot catch this because the template is a plain string.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("pkg.upgrade(")
    expect(content).toContain("pkg.installed(")
    expect(content).not.toContain("apt.upgrade(")
    expect(content).not.toContain("apt.installed(")
  })

  it("generated server.ts imports package as pkg from paratix/modules", () => {
    // Regression: import must use `package as pkg`, not the old `apt` import.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("package as pkg")
    expect(content).not.toMatch(/\bapt\b/)
  })

  it("creates a files subdirectory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "files"))).toBe(true)
  })
})
