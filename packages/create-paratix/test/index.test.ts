import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it } from "vitest"

import { isDirectExecution, isValidProjectName, writeProjectFiles } from "../src/index.js"

describe("isValidProjectName", () => {
  // These tests document that invalid project names must be rejected.
  // Currently no validation exists in main() beyond a falsy-check, so
  // isValidProjectName is not yet exported. All tests in this block will
  // fail until the validation function is implemented and exported.

  it("accepts a simple lowercase name", () => {
    expect(isValidProjectName("my-project")).toBe(true)
  })

  it("accepts a name with numbers and hyphens", () => {
    expect(isValidProjectName("project-42")).toBe(true)
  })

  it("rejects a name containing spaces", () => {
    // Spaces are invalid in directory names used as npm package names and
    // would silently produce a broken package.json "name" field.
    expect(isValidProjectName("my project")).toBe(false)
  })

  it("rejects a name containing special characters", () => {
    // Characters like @ and ! are invalid in npm package names (unless
    // scoped with a leading @) and as unquoted directory names.
    expect(isValidProjectName("my@project!")).toBe(false)
  })

  it("rejects path traversal sequences", () => {
    // "../../etc" would resolve to an arbitrary directory outside the
    // current working directory, allowing an attacker to overwrite files.
    expect(isValidProjectName("../../etc")).toBe(false)
  })

  it("rejects names containing uppercase letters", () => {
    // npm package names must be lowercase. An uppercase name would be
    // written into package.json and cause npm publish/install errors.
    expect(isValidProjectName("MyProject")).toBe(false)
  })

  it("rejects a string that is blank after trimming", () => {
    // A name consisting only of whitespace passes the current falsy-check
    // in main() and would create a directory with a whitespace name.
    expect(isValidProjectName("   ")).toBe(false)
  })
})

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
    expect(content).not.toMatch(/\bapt\b/v)
  })

  it("creates a files subdirectory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "files"))).toBe(true)
  })
})
