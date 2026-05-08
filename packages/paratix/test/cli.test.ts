import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest"

import {
  applyCliEnvironmentOverrides,
  applyCliProcessEnvironment,
  collectDefinitionErrors,
  collectEnvironment,
  exitAfterApplyError,
  handleTsxLoadFailure,
  isDirectCliExecution,
  isServerDefinitionLike,
  loadServerDefinitionFromFile,
  parsePositiveNumber,
  parseReconnectTimeoutSeconds,
  printExceptionError,
  resetTsxRegistrationForTests,
  runApplyCommand,
} from "../src/cli.js"
import { printCliHeader } from "../src/output.js"
import { clearRegisteredSecrets, registerSecret } from "../src/secretSink.js"

declare const PACKAGE_VERSION: string
declare const PACKAGE_DISPLAY_VERSION: string

const CLI_COMMAND_TIMEOUT_MS = 30_000
const CLI_COMMAND_MAX_BUFFER = 10 * 1024 * 1024

type ExecFailure = {
  status?: null | number
  stderr?: Buffer | string
} & Error

function captureExecFailure(callback: () => void): ExecFailure {
  try {
    callback()
  } catch (error) {
    return error as ExecFailure
  }

  throw new Error("Expected command to fail")
}

async function captureAsyncError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    if (error instanceof Error) return error
    throw new Error(`Expected Error rejection, received ${String(error)}`, { cause: error })
  }

  throw new Error("Expected promise to fail")
}

describe("PACKAGE_VERSION", () => {
  it("matches the version in package.json", () => {
    const packageJsonPath = resolve(new URL("../package.json", import.meta.url).pathname)
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { version: string }
    expect(PACKAGE_VERSION).toBe(packageJson.version)
  })
})

describe("PACKAGE_DISPLAY_VERSION", () => {
  it("starts with the package version and may append the short git hash", () => {
    const versionParts = PACKAGE_DISPLAY_VERSION.split("-")
    const hashPart = [...versionParts, "0"][1]

    expect(versionParts[0]).toBe(PACKAGE_VERSION)
    expect(versionParts.length).toBeGreaterThanOrEqual(1)
    expect(versionParts.length).toBeLessThanOrEqual(2)
    expect(hashPart).toMatch(/^[0-9a-f]+$/v)
  })
})

describe("isDirectCliExecution", () => {
  it("returns false when no entry script exists", () => {
    expect(isDirectCliExecution(import.meta.url)).toBe(false)
  })

  it("returns true when entry script points to the same file through a symlink", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-entry-"))
    const targetPath = join(tempDirectory, "cli-target.mjs")
    const symlinkPath = join(tempDirectory, "cli-link.mjs")

    try {
      writeFileSync(targetPath, "export {}\n")
      symlinkSync(targetPath, symlinkPath)

      expect(isDirectCliExecution(pathToFileURL(targetPath).href, symlinkPath)).toBe(true)
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("returns false when entry script points to a different file", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-entry-"))
    const firstPath = join(tempDirectory, "first.mjs")
    const secondPath = join(tempDirectory, "second.mjs")

    try {
      writeFileSync(firstPath, "export {}\n")
      writeFileSync(secondPath, "export {}\n")

      expect(isDirectCliExecution(pathToFileURL(firstPath).href, secondPath)).toBe(false)
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("returns false when realpathSync throws (e.g. symlink loop or EACCES)", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-entry-"))
    const targetPath = join(tempDirectory, "cli-target.mjs")
    const loopingSymlink = join(tempDirectory, "cli-loop.mjs")
    const innerLoopSymlink = join(tempDirectory, "cli-loop-inner.mjs")

    try {
      writeFileSync(targetPath, "export {}\n")
      // Create a symlink loop: cli-loop -> cli-loop-inner -> cli-loop
      symlinkSync(innerLoopSymlink, loopingSymlink)
      symlinkSync(loopingSymlink, innerLoopSymlink)

      expect(() =>
        isDirectCliExecution(pathToFileURL(targetPath).href, loopingSymlink)
      ).not.toThrow()
      expect(isDirectCliExecution(pathToFileURL(targetPath).href, loopingSymlink)).toBe(false)
    } finally {
      // Unlink the symlink loop before rmSync so that Node/macOS does not
      // encounter ELOOP when recursively deleting the directory.
      try {
        unlinkSync(loopingSymlink)
      } catch {
        /* already gone */
      }
      try {
        unlinkSync(innerLoopSymlink)
      } catch {
        /* already gone */
      }
      try {
        rmSync(tempDirectory, { force: true, recursive: true })
      } catch {
        /* best-effort cleanup */
      }
    }
  })
})

describe("collectEnvironment", () => {
  let exitSpy: MockInstance<typeof process.exit>
  let errorSpy: MockInstance<typeof console.error>

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
    })
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("parses a simple KEY=value pair", () => {
    const result = collectEnvironment("KEY=value", {})
    expect(result).toStrictEqual({ KEY: "value" })
  })

  it("splits only at the first equals sign when value contains equals signs", () => {
    const result = collectEnvironment("KEY=val=with=equals", {})
    expect(result).toStrictEqual({ KEY: "val=with=equals" })
  })

  it("accepts an empty value after the equals sign", () => {
    const result = collectEnvironment("KEY=", {})
    expect(result).toStrictEqual({ KEY: "" })
  })

  it("calls process.exit(2) when input has no equals sign", () => {
    let exitCalled = false
    try {
      collectEnvironment("NOEQUALS", {})
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
  })

  it("calls process.exit(2) when the env name is empty", () => {
    let exitCalled = false
    try {
      collectEnvironment("=value", {})
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledWith(
      "Invalid --env name: (empty) (expected [A-Za-z_][A-Za-z0-9_]*)"
    )
  })

  it("calls process.exit(2) when the env name contains invalid characters", () => {
    let exitCalled = false
    try {
      collectEnvironment("BAD-NAME=value", {})
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledWith(
      "Invalid --env name: BAD-NAME (expected [A-Za-z_][A-Za-z0-9_]*)"
    )
  })

  it("calls process.exit(2) when the env name contains leading whitespace", () => {
    let exitCalled = false
    try {
      collectEnvironment(" BAD=value", {})
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledWith(
      "Invalid --env name:  BAD (expected [A-Za-z_][A-Za-z0-9_]*)"
    )
  })

  it("calls process.exit(2) when the env name contains internal whitespace", () => {
    let exitCalled = false
    try {
      collectEnvironment("BAD NAME=value", {})
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledWith(
      "Invalid --env name: BAD NAME (expected [A-Za-z_][A-Za-z0-9_]*)"
    )
  })

  it.each(["__proto__", "constructor", "prototype"])(
    "calls process.exit(2) when the env name is reserved: %s",
    (key) => {
      let exitCalled = false
      try {
        collectEnvironment(`${key}=value`, {})
      } catch {
        exitCalled = true
      }
      expect(exitCalled).toBe(true)
      expect(exitSpy).toHaveBeenCalledWith(2)
      expect(errorSpy).toHaveBeenCalledWith(
        `Forbidden --env name: ${key} (reserved JavaScript identifier)`
      )
    }
  )

  it("accumulates multiple entries into the previous object", () => {
    const first = collectEnvironment("FOO=bar", {})
    const second = collectEnvironment("BAZ=qux", first)
    expect(second).toStrictEqual({ BAZ: "qux", FOO: "bar" })
  })

  it("overwrites an existing key when the same key is provided again", () => {
    const first = collectEnvironment("KEY=original", {})
    const second = collectEnvironment("KEY=updated", first)
    expect(second).toStrictEqual({ KEY: "updated" })
  })
})

describe("applyCliEnvironmentOverrides", () => {
  it("returns the existing environment unchanged without --first-run", () => {
    expect(applyCliEnvironmentOverrides({ EXISTING: "value" }, { firstRun: false })).toStrictEqual({
      EXISTING: "value",
    })
  })

  it("adds PARATIX_FIRST_RUN=true when --first-run is enabled", () => {
    expect(applyCliEnvironmentOverrides({ EXISTING: "value" }, { firstRun: true })).toStrictEqual({
      EXISTING: "value",
      PARATIX_FIRST_RUN: "true",
    })
  })
})

describe("applyCliProcessEnvironment", () => {
  afterEach(() => {
    delete process.env.PARATIX_FIRST_RUN
  })

  it("leaves process.env unchanged without --first-run", () => {
    const restore = applyCliProcessEnvironment({ firstRun: false })

    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
    restore()
    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
  })

  it("sets process.env.PARATIX_FIRST_RUN before playbook loading when --first-run is enabled", () => {
    const restore = applyCliProcessEnvironment({ firstRun: true })

    expect(process.env.PARATIX_FIRST_RUN).toBe("true")
    restore()
    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
  })

  it("restores an existing PARATIX_FIRST_RUN value", () => {
    process.env.PARATIX_FIRST_RUN = "external"

    const restore = applyCliProcessEnvironment({ firstRun: true })

    expect(process.env.PARATIX_FIRST_RUN).toBe("true")
    restore()
    expect(process.env.PARATIX_FIRST_RUN).toBe("external")
  })

  it("deletes PARATIX_FIRST_RUN on restore when no previous value was set (firstRun=true)", () => {
    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()

    const restore = applyCliProcessEnvironment({ firstRun: true })

    expect(process.env.PARATIX_FIRST_RUN).toBe("true")
    restore()

    // The key must be removed entirely, not assigned the literal string "undefined".
    expect(Object.hasOwn(process.env, "PARATIX_FIRST_RUN")).toBe(false)
    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
  })

  it("restores process.env to the pre-CLI value across nested reentrant calls", () => {
    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()

    const restoreOuter = applyCliProcessEnvironment({ firstRun: true })
    expect(process.env.PARATIX_FIRST_RUN).toBe("true")

    // A reentrant call must not capture the synthetic "true" set by the
    // outer call as its restore target.
    const restoreInner = applyCliProcessEnvironment({ firstRun: true })
    expect(process.env.PARATIX_FIRST_RUN).toBe("true")

    restoreInner()
    // The outer frame still depends on the synthetic value, so the key must
    // remain "true" until the outer frame restores.
    expect(process.env.PARATIX_FIRST_RUN).toBe("true")

    restoreOuter()
    // After the outermost frame restores, the original (absent) state is
    // recovered — not the synthetic "true" the inner call observed.
    expect(Object.hasOwn(process.env, "PARATIX_FIRST_RUN")).toBe(false)
    expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
  })

  it("preserves an externally set value when reentrant calls layer firstRun", () => {
    process.env.PARATIX_FIRST_RUN = "external"

    const restoreOuter = applyCliProcessEnvironment({ firstRun: true })
    expect(process.env.PARATIX_FIRST_RUN).toBe("true")

    const restoreInner = applyCliProcessEnvironment({ firstRun: true })
    expect(process.env.PARATIX_FIRST_RUN).toBe("true")

    restoreInner()
    expect(process.env.PARATIX_FIRST_RUN).toBe("true")

    restoreOuter()
    expect(process.env.PARATIX_FIRST_RUN).toBe("external")
  })

  it("does not assign the literal string 'undefined' when restoring", () => {
    // Capture every assignment of process.env's PARATIX_FIRST_RUN. A
    // regression would write the literal string "undefined" via
    // `process.env[KEY] = previousValue` when previousValue is undefined.
    const seenAssignments: Array<[PropertyKey, unknown]> = []
    const proxy = new Proxy(process.env, {
      deleteProperty(target, property): boolean {
        return Reflect.deleteProperty(target, property)
      },
      set(target, property, value): boolean {
        seenAssignments.push([property, value])
        return Reflect.set(target, property, value)
      },
    })

    const previousEnvironment = process.env
    Reflect.set(process, "env", proxy)
    try {
      const restore = applyCliProcessEnvironment({ firstRun: true })
      expect(process.env.PARATIX_FIRST_RUN).toBe("true")
      restore()

      const firstRunAssignments = seenAssignments
        .filter(([key]) => key === "PARATIX_FIRST_RUN")
        .map(([, value]) => value)

      // The literal string "undefined" must never have been assigned.
      expect(firstRunAssignments).not.toContain("undefined")
      // After restore the key is gone.
      expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
    } finally {
      Reflect.set(process, "env", previousEnvironment)
      delete process.env.PARATIX_FIRST_RUN
    }
  })
})

describe("isServerDefinitionLike", () => {
  it("returns false for null", () => {
    expect(isServerDefinitionLike(null)).toBe(false)
  })

  it("returns false for undefined", () => {
    const value: unknown = undefined
    expect(isServerDefinitionLike(value)).toBe(false)
  })

  it("returns false for a number", () => {
    expect(isServerDefinitionLike(42)).toBe(false)
  })

  it("returns false for a string", () => {
    expect(isServerDefinitionLike("hello")).toBe(false)
  })

  it("returns false for an empty object", () => {
    expect(isServerDefinitionLike({})).toBe(false)
  })

  const validSsh = { ports: [22], privateKey: "/home/user/.ssh/id_ed25519", user: "root" }

  it("returns false for an object with only host", () => {
    expect(isServerDefinitionLike({ host: "example.com" })).toBe(false)
  })

  it("returns false for an object with only run", () => {
    expect(isServerDefinitionLike({ run: [] })).toBe(false)
  })

  it("returns false for an object with string host and empty array run", () => {
    expect(isServerDefinitionLike({ host: "example.com", run: [] })).toBe(false)
  })

  it("returns true for a complete valid definition", () => {
    expect(
      isServerDefinitionLike({
        host: "example.com",
        name: "test",
        run: [["echo", "hello"]],
        ssh: validSsh,
      })
    ).toBe(true)
  })

  it("returns false when host is not a string", () => {
    expect(isServerDefinitionLike({ host: 123, run: [] })).toBe(false)
  })
})

describe("collectDefinitionErrors", () => {
  it("returns a single error when value is null", () => {
    const errors = collectDefinitionErrors(null)
    expect(errors).toStrictEqual(["Export is not an object"])
  })

  it("returns a single error when value is a number", () => {
    const errors = collectDefinitionErrors(42)
    expect(errors).toStrictEqual(["Export is not an object"])
  })

  it("returns a single error when value is a string", () => {
    const errors = collectDefinitionErrors("hello")
    expect(errors).toStrictEqual(["Export is not an object"])
  })

  const validSsh = { ports: [22], privateKey: "/home/user/.ssh/id_ed25519", user: "root" }

  it("returns errors for all missing properties on an empty object", () => {
    const errors = collectDefinitionErrors({})
    expect(errors).toContain("Missing property 'name' (expected string)")
    expect(errors).toContain("Missing property 'host' (expected string)")
    expect(errors).toContain("Missing property 'ssh' (expected object)")
    expect(errors).toContain("Missing property 'run' (expected array)")
    expect(errors).toHaveLength(4)
  })

  it("returns errors for missing properties when only host is present", () => {
    const errors = collectDefinitionErrors({ host: "example.com" })
    expect(errors).toContain("Missing property 'name' (expected string)")
    expect(errors).toContain("Missing property 'ssh' (expected object)")
    expect(errors).toContain("Missing property 'run' (expected array)")
    expect(errors).toHaveLength(3)
  })

  it("returns errors for missing properties when only an empty run is present", () => {
    const errors = collectDefinitionErrors({ run: [] })
    expect(errors).toContain("Missing property 'name' (expected string)")
    expect(errors).toContain("Missing property 'host' (expected string)")
    expect(errors).toContain("Missing property 'ssh' (expected object)")
    expect(errors).toContain("Property 'run' must not be empty")
    expect(errors).toHaveLength(4)
  })

  it("returns errors when host has the wrong type and run is empty", () => {
    const errors = collectDefinitionErrors({ host: 123, name: "test", run: [], ssh: validSsh })
    expect(errors).toContain("Invalid property 'host' (expected string, got number)")
    expect(errors).toContain("Property 'run' must not be empty")
    expect(errors).toHaveLength(2)
  })

  it("returns an error mentioning the actual type when run is not an array", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: "not-an-array",
      ssh: validSsh,
    })
    expect(errors).toStrictEqual(["Invalid property 'run' (expected array, got string)"])
  })

  it("returns an error when run is an empty array", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: [],
      ssh: validSsh,
    })
    expect(errors).toStrictEqual(["Property 'run' must not be empty"])
  })

  it("returns an error when host is an empty string", () => {
    const errors = collectDefinitionErrors({
      host: "",
      name: "test",
      run: ["echo hello"],
      ssh: validSsh,
    })
    expect(errors).toStrictEqual(["Property 'host' must not be empty"])
  })

  it("returns errors for both empty host and empty run", () => {
    const errors = collectDefinitionErrors({ host: "", name: "test", run: [], ssh: validSsh })
    expect(errors).toContain("Property 'host' must not be empty")
    expect(errors).toContain("Property 'run' must not be empty")
    expect(errors).toHaveLength(2)
  })

  it("returns an empty array for a valid ServerDefinition shape", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: validSsh,
    })
    expect(errors).toStrictEqual([])
  })

  it("returns an error when name is missing", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      run: ["echo hello"],
      ssh: validSsh,
    })
    expect(errors).toStrictEqual(["Missing property 'name' (expected string)"])
  })

  it("returns an error when name has the wrong type", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: 42,
      run: ["echo hello"],
      ssh: validSsh,
    })
    expect(errors).toStrictEqual(["Invalid property 'name' (expected string, got number)"])
  })

  it("returns an error when name is an empty string", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "",
      run: ["echo hello"],
      ssh: validSsh,
    })
    expect(errors).toStrictEqual(["Property 'name' must not be empty"])
  })

  it("returns an error when ssh is missing", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
    })
    expect(errors).toStrictEqual(["Missing property 'ssh' (expected object)"])
  })

  it("returns an error when ssh has the wrong type", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: "not-an-object",
    })
    expect(errors).toStrictEqual(["Invalid property 'ssh' (expected object, got string)"])
  })

  it("returns an error when ssh is null", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: null,
    })
    expect(errors).toStrictEqual(["Invalid property 'ssh' (expected object, got null)"])
  })

  it("returns errors for all missing ssh subfields when ssh is an empty object", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: {},
    })
    expect(errors).toContain("Missing property 'ssh.ports' (expected array)")
    expect(errors).toContain("Missing property 'ssh.user' (expected string)")
    expect(errors).toHaveLength(2)
  })

  it("returns an error when ssh.ports has the wrong type", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: "not-an-array", privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual(["Invalid property 'ssh.ports' (expected array, got string)"])
  })

  it("returns an error when ssh.ports is an empty array", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.ports' must not be empty"])
  })

  it("returns an error when ssh.ports contains zero in an untyped JS definition", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [0], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.ports[0]' must be an integer between 1 and 65535"])
  })

  it("returns an error when ssh.ports contains 65536 in an untyped JS definition", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [65_536], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.ports[0]' must be an integer between 1 and 65535"])
  })

  it("returns an error when ssh.ports contains a string in an untyped JS definition", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: ["22"], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.ports[0]' must be an integer between 1 and 65535"])
  })

  it("returns an error when ssh.privateKey has the wrong type", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: 123, user: "root" },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.privateKey' (expected string, got number)",
    ])
  })

  it("returns an error when ssh.privateKey is an empty string", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "", user: "root" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.privateKey' must not be an empty string"])
  })

  it("returns an error when ssh.user has the wrong type", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", user: 42 },
    })
    expect(errors).toStrictEqual(["Invalid property 'ssh.user' (expected string, got number)"])
  })

  it("returns an error when ssh.user is an empty string", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", user: "" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.user' must not be an empty string"])
  })

  it("returns no error when ssh.strictHostKeyChecking is 'accept-new'", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", strictHostKeyChecking: "accept-new", user: "root" },
    })
    expect(errors).toStrictEqual([])
  })

  it("returns no error when ssh.strictHostKeyChecking is 'no'", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", strictHostKeyChecking: "no", user: "root" },
    })
    expect(errors).toStrictEqual([])
  })

  it("returns no error when ssh.strictHostKeyChecking is 'yes'", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", strictHostKeyChecking: "yes", user: "root" },
    })
    expect(errors).toStrictEqual([])
  })

  it("returns an error when ssh.strictHostKeyChecking has an invalid value", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: {
        ports: [22],
        privateKey: "/key",
        strictHostKeyChecking: "invalid-value",
        user: "root",
      },
    })
    expect(errors).toStrictEqual([
      `Invalid property 'ssh.strictHostKeyChecking' (expected "accept-new", "no", or "yes")`,
    ])
  })

  it("returns an error when ssh.strictHostKeyChecking is a non-string value", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", strictHostKeyChecking: 42, user: "root" },
    })
    expect(errors).toStrictEqual([
      `Invalid property 'ssh.strictHostKeyChecking' (expected "accept-new", "no", or "yes")`,
    ])
  })

  it("returns no error when ssh.strictHostKeyChecking is undefined (optional field)", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual([])
  })

  it("returns no error when ssh.expectedHostFingerprint and ssh.expectedHostPublicKey are strings", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: {
        expectedHostFingerprint: "SHA256:trusted-fingerprint",
        expectedHostPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItrusted",
        ports: [22],
        privateKey: "/key",
        user: "root",
      },
    })
    expect(errors).toStrictEqual([])
  })

  it("returns an error when ssh.expectedHostPublicKey has no key material", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: {
        expectedHostPublicKey: "ssh-ed25519",
        ports: [22],
        privateKey: "/key",
        user: "root",
      },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.expectedHostPublicKey': Expected host public key must use the format '<algorithm> <base64>'",
    ])
  })

  it("returns an error when ssh.expectedHostFingerprint is a non-string value", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { expectedHostFingerprint: 42, ports: [22], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.expectedHostFingerprint' (expected string, got number)",
    ])
  })

  it("returns an error when ssh.agentForward is not a boolean", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { agentForward: "yes", ports: [22], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.agentForward' (expected boolean, got string)",
    ])
  })

  it("returns an error when ssh.passwordFallback is not a boolean", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { passwordFallback: "no", ports: [22], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.passwordFallback' (expected boolean, got string)",
    ])
  })

  it("returns an error when ssh.sudoPassword is not a string", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", sudoPassword: 123, user: "root" },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.sudoPassword' (expected string, got number)",
    ])
  })

  it("returns an error when ssh.reconnectTimeout is not a number", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", reconnectTimeout: "5000", user: "root" },
    })
    expect(errors).toStrictEqual([
      "Invalid property 'ssh.reconnectTimeout' (expected number, got string)",
    ])
  })

  it("returns an error when ssh.maxReconnectAttempts is not an integer", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { maxReconnectAttempts: 1.5, ports: [22], privateKey: "/key", user: "root" },
    })
    expect(errors).toStrictEqual(["Property 'ssh.maxReconnectAttempts' must be an integer"])
  })

  it("returns no error when ssh.strictHostKeyChecking is null (treated as absent)", () => {
    const errors = collectDefinitionErrors({
      host: "example.com",
      name: "test",
      run: ["echo hello"],
      ssh: { ports: [22], privateKey: "/key", strictHostKeyChecking: null, user: "root" },
    })
    expect(errors).toStrictEqual([])
  })
})

describe("parsePositiveNumber", () => {
  // Tests for parsePositiveNumber which validates --reconnect-timeout
  // (and any future option that needs a positive finite number).

  let exitSpy: MockInstance<typeof process.exit>
  let errorSpy: MockInstance<typeof console.error>

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
    })
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      // noop: suppress console.error output during tests
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    clearRegisteredSecrets()
  })

  it("returns the numeric value for a valid positive integer string", () => {
    const result = parsePositiveNumber("300")
    expect(result).toBe(300)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("returns the numeric value for a positive decimal string", () => {
    const result = parsePositiveNumber("1.5")
    expect(result).toBe(1.5)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("returns the numeric value for the minimum accepted value '1'", () => {
    const result = parsePositiveNumber("1")
    expect(result).toBe(1)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("calls process.exit(2) and prints an error for a non-numeric string", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("foo")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledOnce()
  })

  it("calls process.exit(2) and prints an error for a negative number string", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("-5")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledOnce()
  })

  it("calls process.exit(2) and prints an error for zero", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("0")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledOnce()
  })

  it("calls process.exit(2) and prints an error for an empty string", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledOnce()
  })

  it("calls process.exit(2) and prints an error for a string that is only whitespace", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("   ")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledOnce()
  })

  it("calls process.exit(2) and prints an error for 'Infinity'", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("Infinity")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    expect(errorSpy).toHaveBeenCalledOnce()
  })

  it("includes the invalid value in the error message so users know what was rejected", () => {
    try {
      parsePositiveNumber("notanumber")
    } catch {
      // expected
    }
    const errorMessage = errorSpy.mock.calls[0]?.[0] as string
    expect(errorMessage).toContain("notanumber")
  })

  it("accepts values within an optional max bound", () => {
    expect(parsePositiveNumber("60", { max: 86_400 })).toBe(60)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("rejects values exceeding the max bound", () => {
    let exitCalled = false
    try {
      parsePositiveNumber("100000", { max: 86_400 })
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    const errorMessage = errorSpy.mock.calls[0]?.[0] as string
    expect(errorMessage).toContain("at most 86400")
  })
})

describe("parseReconnectTimeoutSeconds", () => {
  // Rejects huge or scientific-notation values that would overflow
  // `Date.now() + timeout`-style deadline checks after seconds-to-ms scaling.

  let exitSpy: MockInstance<typeof process.exit>
  let errorSpy: MockInstance<typeof console.error>

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
    })
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      // noop: suppress console.error output during tests
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    clearRegisteredSecrets()
  })

  it("accepts the maximum allowed value (86400 seconds)", () => {
    expect(parseReconnectTimeoutSeconds("86400")).toBe(86_400)
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("rejects values above 86400 seconds", () => {
    let exitCalled = false
    try {
      parseReconnectTimeoutSeconds("86401")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
  })

  it("rejects scientific notation that exceeds the max bound (1e10)", () => {
    let exitCalled = false
    try {
      parseReconnectTimeoutSeconds("1e10")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
    const errorMessage = errorSpy.mock.calls[0]?.[0] as string
    expect(errorMessage).toContain("1e10")
  })

  it("still rejects non-positive numbers", () => {
    let exitCalled = false
    try {
      parseReconnectTimeoutSeconds("0")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
  })
})

describe("handleTsxLoadFailure", () => {
  let exitSpy: MockInstance<typeof process.exit>
  let errorSpy: MockInstance<typeof console.error>

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
    })
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      // noop: suppress console.error output during tests
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("calls process.exit(2) when the file has a .ts extension", () => {
    let exitCalled = false
    try {
      handleTsxLoadFailure("/home/user/playbook.ts")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
  })

  it("calls process.exit(2) when the file has a .mts extension", () => {
    let exitCalled = false
    try {
      handleTsxLoadFailure("/home/user/playbook.mts")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
  })

  it("calls process.exit(2) when the file has a .cts extension", () => {
    let exitCalled = false
    try {
      handleTsxLoadFailure("/home/user/playbook.cts")
    } catch {
      exitCalled = true
    }
    expect(exitCalled).toBe(true)
    expect(exitSpy).toHaveBeenCalledWith(2)
  })

  it("prints an error mentioning tsx to stderr for a TypeScript file", () => {
    try {
      handleTsxLoadFailure("/home/user/playbook.ts")
    } catch {
      // expected: process.exit throws in test environment
    }
    expect(errorSpy).toHaveBeenCalledOnce()
    const message = errorSpy.mock.calls[0]?.[0] as string
    expect(message).toContain("tsx")
  })

  it("does not call process.exit for a .js file", () => {
    handleTsxLoadFailure("/home/user/playbook.js")
    expect(exitSpy).not.toHaveBeenCalled()
    expect(errorSpy).not.toHaveBeenCalled()
  })

  it("does not call process.exit for a .mjs file", () => {
    handleTsxLoadFailure("/home/user/playbook.mjs")
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("does not call process.exit for a .cjs file", () => {
    handleTsxLoadFailure("/home/user/playbook.cjs")
    expect(exitSpy).not.toHaveBeenCalled()
  })

  it("does not call process.exit for a file with no extension", () => {
    handleTsxLoadFailure("/home/user/playbook")
    expect(exitSpy).not.toHaveBeenCalled()
  })
})

describe("printExceptionError", () => {
  let errorSpy: MockInstance<typeof console.error>

  beforeEach(() => {
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      // noop: suppress console.error output during tests
    })
  })

  afterEach(() => {
    clearRegisteredSecrets()
    vi.restoreAllMocks()
  })

  it("prints the error message for a plain Error", () => {
    printExceptionError(new Error("something went wrong"), false)
    expect(errorSpy).toHaveBeenCalledWith("Error: something went wrong")
  })

  it("prints the string representation for a non-Error string value", () => {
    printExceptionError("oops", false)
    expect(errorSpy).toHaveBeenCalledWith("Error: oops")
  })

  it("prints the string representation for a non-Error number value", () => {
    printExceptionError(42, false)
    expect(errorSpy).toHaveBeenCalledWith("Error: 42")
  })

  it("prints the JSON representation for a plain object to avoid [object Object]", () => {
    printExceptionError({ code: 404 }, false)
    expect(errorSpy).toHaveBeenCalledWith('Error: {"code":404}')
  })

  it("does not crash on circular non-Error objects and falls back to a safe representation", () => {
    const circular = { label: "loop" } as { label: string; self?: unknown }
    circular.self = circular

    expect(() => {
      printExceptionError(circular, false)
    }).not.toThrow()

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("Error:")
    expect(output).toContain("loop")
    expect(output).toContain("Circular")
  })

  it("does not crash on non-Error objects containing BigInt and falls back to a safe representation", () => {
    expect(() => {
      printExceptionError({ count: 1n }, false)
    }).not.toThrow()

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("Error:")
    expect(output).toContain("count")
    expect(output).toContain("1n")
  })

  it("bounds the inspect fallback so huge arrays and strings are truncated", () => {
    const hugeArray = Array.from({ length: 5000 }, (_, index) => index)
    const hugeString = "A".repeat(50_000)
    // Force the JSON path to throw (BigInt) so the inspect fallback runs.
    const huge = { array: hugeArray, marker: 1n, text: hugeString }

    printExceptionError(huge, false)

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    // Even the most permissive expansion stays well below the raw size.
    expect(output.length).toBeLessThan(10_000)
    // util.inspect emits "... N more items" / "... N more characters" markers
    // when bounded by maxArrayLength / maxStringLength.
    expect(output).toMatch(/more (?:items|characters)/v)
  })

  it("truncates Buffer payloads so private key bytes never leak into stderr", () => {
    // Force the JSON path to throw (BigInt) so the inspect fallback runs.
    const sensitive = {
      key: Buffer.from("A".repeat(8192)),
      marker: 1n,
    }

    printExceptionError(sensitive, false)

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).not.toContain("A".repeat(2048))
  })

  it("prints a single cause when the error has one cause", () => {
    const cause = new Error("root cause")
    const error = new Error("top-level error", { cause })
    printExceptionError(error, false)
    expect(errorSpy).toHaveBeenCalledWith("Error: top-level error")
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: root cause")
  })

  it("prints the full cause chain for nested causes", () => {
    const root = new Error("database unavailable")
    const mid = new Error("query failed", { cause: root })
    const top = new Error("request failed", { cause: mid })
    printExceptionError(top, false)
    expect(errorSpy).toHaveBeenCalledWith("Error: request failed")
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: query failed")
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: database unavailable")
  })

  it("prints a non-Error cause using its string representation", () => {
    const error = new Error("top-level error")
    error.cause = "string cause"
    printExceptionError(error, false)
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: string cause")
  })

  it("does not crash on circular object causes and prints a safe fallback", () => {
    const cause = { kind: "cycle" } as { kind: string; self?: unknown }
    cause.self = cause
    const error = new Error("top-level error")
    error.cause = cause

    expect(() => {
      printExceptionError(error, false)
    }).not.toThrow()

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("  Caused by:")
    expect(output).toContain("cycle")
    expect(output).toContain("Circular")
  })

  it("does not print a stack trace without --verbose", () => {
    const error = new Error("something went wrong")
    printExceptionError(error, false)
    const calls = errorSpy.mock.calls.map((args) => String(args[0]))
    expect(calls.some((msg) => msg.includes("at "))).toBe(false)
  })

  it("prints the stack trace when verbose is true", () => {
    const error = new Error("something went wrong")
    // Ensure the stack is defined so the assertion is meaningful
    expect(error.stack).toBeDefined()
    printExceptionError(error, true)
    // The stack is printed as the second console.error call (after "Error: …")
    const stackCall = errorSpy.mock.calls[1]?.[0] as string
    expect(stackCall).toContain("something went wrong")
    expect(stackCall).toContain("at ")
  })

  it("does not print cause output when there is no cause", () => {
    printExceptionError(new Error("lone error"), false)
    expect(errorSpy).toHaveBeenCalledTimes(1)
    expect(errorSpy).toHaveBeenCalledWith("Error: lone error")
  })

  it("breaks out of a cyclic cause chain instead of hanging", () => {
    const first = new Error("first")
    const second = new Error("second")
    first.cause = second
    second.cause = first

    expect(() => {
      printExceptionError(first, false)
    }).not.toThrow()

    const calls = errorSpy.mock.calls.map((args) => String(args[0]))
    expect(calls.some((line) => line.includes("Caused by: second"))).toBe(true)
    expect(calls.some((line) => line.includes("<cycle detected>"))).toBe(true)
  })

  it("breaks out of a self-referential cause without recursing", () => {
    const error = new Error("self")
    error.cause = error

    expect(() => {
      printExceptionError(error, false)
    }).not.toThrow()

    const calls = errorSpy.mock.calls.map((args) => String(args[0]))
    expect(calls.some((line) => line.includes("<cycle detected>"))).toBe(true)
  })

  it("does not attempt to walk the cause chain for non-Error values", () => {
    printExceptionError("plain string error", true)
    expect(errorSpy).toHaveBeenCalledTimes(1)
  })

  it("redacts registered secrets in error messages", () => {
    registerSecret("cli-message-secret")
    printExceptionError(new Error("failed with cli-message-secret"), false)

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("[REDACTED]")
    expect(output).not.toContain("cli-message-secret")
  })

  it("redacts registered secrets in error causes", () => {
    registerSecret("cli-cause-secret")
    const error = new Error("top-level", { cause: new Error("nested cli-cause-secret") })
    printExceptionError(error, false)

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("  Caused by: nested [REDACTED]")
    expect(output).not.toContain("cli-cause-secret")
  })

  it("redacts registered secrets in non-Error object output", () => {
    registerSecret("cli-object-secret")
    printExceptionError({ token: "cli-object-secret" }, false)

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("[REDACTED]")
    expect(output).not.toContain("cli-object-secret")
  })

  it("redacts registered secrets in verbose stack traces", () => {
    registerSecret("cli-stack-secret")
    const error = new Error("top-level")
    error.stack = "Error: top-level\n    at run (/tmp/file.ts:1) // cli-stack-secret"
    printExceptionError(error, true)

    const output = errorSpy.mock.calls.map((args) => String(args[0])).join("\n")
    expect(output).toContain("[REDACTED]")
    expect(output).not.toContain("cli-stack-secret")
  })
})

describe("CLI entrypoint", () => {
  beforeEach(() => {
    // Reset the tsx registration guard so each test exercises the loader
    // path against a clean state, regardless of which earlier test ran.
    resetTsxRegistrationForTests()
  })

  it("registers the tsx loader at most once across multiple TypeScript playbook loads", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-tsx-once-"))
    const firstPlaybookPath = join(tempDirectory, "first.ts")
    const secondPlaybookPath = join(tempDirectory, "second.ts")
    let registerCalls = 0

    try {
      for (const playbookPath of [firstPlaybookPath, secondPlaybookPath]) {
        writeFileSync(
          playbookPath,
          [
            "export default {",
            "  name: 'tsx-once-server',",
            "  host: '1.2.3.4',",
            "  ssh: { user: 'root', ports: [22] },",
            "  run: ['noop'],",
            "}",
          ].join("\n")
        )
      }

      vi.doMock("tsx/esm/api", () => ({
        register() {
          registerCalls += 1
        },
      }))

      await loadServerDefinitionFromFile(firstPlaybookPath, { firstRun: false })
      await loadServerDefinitionFromFile(secondPlaybookPath, { firstRun: false })

      expect(registerCalls).toBe(1)
    } finally {
      vi.doUnmock("tsx/esm/api")
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("prints the ASCII header with the current version", () => {
    const logs: string[] = []
    const logSpy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "))
    })

    try {
      printCliHeader(PACKAGE_VERSION)
    } finally {
      logSpy.mockRestore()
    }

    const output = logs.join("\n")
    expect(output).toContain("_ __   __ _ _ __ __ _| |_ ___  __")
    expect(output).toContain(PACKAGE_VERSION)
  })

  it("awaits the async apply action and prints validation errors for invalid playbooks", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-"))
    const playbookPath = join(tempDirectory, "invalid-server.mjs")
    const definePath = join(tempDirectory, "package-display-version.mjs")
    const packageDirectory = resolve(new URL("..", import.meta.url).pathname)
    const cliPath = resolve(new URL("../src/cli.ts", import.meta.url).pathname)

    try {
      writeFileSync(playbookPath, "export default {}\n")
      writeFileSync(
        definePath,
        `globalThis.PACKAGE_DISPLAY_VERSION = ${JSON.stringify(PACKAGE_DISPLAY_VERSION)};\n`
      )

      const error = captureExecFailure(() => {
        execFileSync(
          process.execPath,
          ["--import", "tsx", "--import", definePath, cliPath, "apply", playbookPath, "--dry-run"],
          {
            cwd: packageDirectory,
            encoding: "utf8",
            killSignal: "SIGTERM",
            maxBuffer: CLI_COMMAND_MAX_BUFFER,
            stdio: "pipe",
            timeout: CLI_COMMAND_TIMEOUT_MS,
          }
        )
      })

      expect(error).toBeInstanceOf(Error)
      expect(error.status).toBe(2)
      expect(String(error.stderr)).toContain("does not export a valid ServerDefinition")
      expect(String(error.stderr)).toContain("Missing property 'name'")
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  // R-0000071 regression: when the dynamic `import("tsx/esm/api")` throws
  // a non-MODULE_NOT_FOUND error (e.g. an incompatible Node, broken
  // install, OOM, transitive dep missing), the CLI must NOT silently fall
  // back to handleTsxLoadFailure (which only exits for .ts files and
  // would otherwise mask the real cause). Instead the original error must
  // surface so the operator can act on it.
  it("rethrows non-MODULE_NOT_FOUND tsx loader errors with the original cause", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-tsx-rethrow-"))
    const playbookPath = join(tempDirectory, "playbook.ts")

    try {
      writeFileSync(playbookPath, "export default {}")

      const realCause = new Error("incompatible Node version: tsx requires Node >=20")
      vi.doMock("tsx/esm/api", () => ({
        register() {
          throw realCause
        },
      }))

      const error = await captureAsyncError(
        loadServerDefinitionFromFile(playbookPath, { firstRun: false })
      )

      expect(error).toMatchObject({
        message: expect.stringMatching(/Failed to load tsx\/esm\/api/v),
      })
      expect(error.cause).toBe(realCause)
    } finally {
      vi.doUnmock("tsx/esm/api")
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("rethrows transitive MODULE_NOT_FOUND errors from the tsx loader", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-tsx-transitive-"))
    const playbookPath = join(tempDirectory, "playbook.ts")

    try {
      writeFileSync(playbookPath, "export default {}")

      const realCause = Object.assign(
        new Error(
          "Cannot find module 'tsx-transitive-helper'\nRequire stack:\n- /repo/node_modules/tsx/dist/index.cjs"
        ),
        { code: "MODULE_NOT_FOUND" }
      )
      vi.doMock("tsx/esm/api", () => ({
        register() {
          throw realCause
        },
      }))

      const error = await captureAsyncError(
        loadServerDefinitionFromFile(playbookPath, { firstRun: false })
      )

      expect(error).toMatchObject({
        message: expect.stringMatching(/Failed to load tsx\/esm\/api/v),
      })
      expect(error.cause).toBe(realCause)
    } finally {
      vi.doUnmock("tsx/esm/api")
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it.each([
    [".js", "export default"],
    [".mjs", "export default"],
    [".cjs", "module.exports ="],
  ])("loads native %s playbooks without registering tsx", async (extension, exportSyntax) => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-native-js-"))
    const playbookPath = join(tempDirectory, `playbook${extension}`)

    try {
      writeFileSync(
        playbookPath,
        [
          `${exportSyntax} {`,
          "  name: 'native-js-server',",
          "  host: '1.2.3.4',",
          "  ssh: { user: 'root', ports: [22] },",
          "  run: ['noop'],",
          "}",
        ].join("\n")
      )

      vi.doMock("tsx/esm/api", () => ({
        register() {
          throw new Error("tsx should not be loaded for native JavaScript playbooks")
        },
      }))

      const definition = await loadServerDefinitionFromFile(playbookPath, { firstRun: false })

      expect(definition.name).toBe("native-js-server")
    } finally {
      vi.doUnmock("tsx/esm/api")
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("sets PARATIX_FIRST_RUN before importing the playbook when --first-run is passed", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-first-run-"))
    const playbookPath = join(tempDirectory, "capture-first-run.mjs")

    try {
      writeFileSync(
        playbookPath,
        [
          "export default {",
          "  name: 'test-server',",
          "  host: '1.2.3.4',",
          "  ssh: { user: 'root', ports: [22] },",
          "  run: [process.env['PARATIX_FIRST_RUN'] ?? 'missing'],",
          "}",
        ].join("\n")
      )

      const definition = await loadServerDefinitionFromFile(playbookPath, { firstRun: true })

      expect(definition.run).toStrictEqual(["true"])
      expect(process.env.PARATIX_FIRST_RUN).toBeUndefined()
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
      delete process.env.PARATIX_FIRST_RUN
    }
  })

  it("does not leak PARATIX_FIRST_RUN into a later playbook load", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-first-run-leak-"))
    const firstRunPlaybookPath = join(tempDirectory, "first-run.mjs")
    const regularPlaybookPath = join(tempDirectory, "regular.mjs")

    try {
      for (const playbookPath of [firstRunPlaybookPath, regularPlaybookPath]) {
        writeFileSync(
          playbookPath,
          [
            "export default {",
            "  name: 'test-server',",
            "  host: '1.2.3.4',",
            "  ssh: { user: 'root', ports: [22] },",
            "  run: [process.env['PARATIX_FIRST_RUN'] ?? 'missing'],",
            "}",
          ].join("\n")
        )
      }

      const firstDefinition = await loadServerDefinitionFromFile(firstRunPlaybookPath, {
        firstRun: true,
      })
      const regularDefinition = await loadServerDefinitionFromFile(regularPlaybookPath, {
        firstRun: false,
      })

      expect(firstDefinition.run).toStrictEqual(["true"])
      expect(regularDefinition.run).toStrictEqual(["missing"])
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
      delete process.env.PARATIX_FIRST_RUN
    }
  })

  it("wires apply options through to runPlaybook on the successful path", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-apply-options-"))
    const playbookPath = join(tempDirectory, "capture-apply-options.mjs")
    const envFilePath = join(tempDirectory, ".env")
    const calls: Array<{
      definition: unknown
      options: unknown
    }> = []
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {
      /* suppress CLI header */
    })

    try {
      writeFileSync(
        playbookPath,
        [
          "export default {",
          "  name: 'test-server',",
          "  host: '1.2.3.4',",
          "  ssh: { user: 'root', ports: [22] },",
          "  run: [process.env['PARATIX_FIRST_RUN'] ?? 'missing'],",
          "}",
        ].join("\n")
      )
      writeFileSync(envFilePath, "FROM_FILE=yes\n")

      await runApplyCommand(
        playbookPath,
        {
          dryRun: true,
          env: { INLINE_ENV: "inline" },
          envFile: envFilePath,
          firstRun: true,
          reconnectTimeout: 12.5,
          verbose: true,
        },
        async (definition, options) => {
          await Promise.resolve()
          calls.push({ definition, options })
        }
      )

      expect(calls).toHaveLength(1)
      expect(calls[0]?.definition).toMatchObject({
        host: "1.2.3.4",
        name: "test-server",
        run: ["true"],
      })
      expect(calls[0]?.options).toStrictEqual({
        dryRun: true,
        envFile: envFilePath,
        envOverrides: { INLINE_ENV: "inline", PARATIX_FIRST_RUN: "true" },
        reconnectTimeout: 12_500,
        verbose: true,
      })
    } finally {
      logSpy.mockRestore()
      rmSync(tempDirectory, { force: true, recursive: true })
      delete process.env.PARATIX_FIRST_RUN
    }
  })

  it("omits reconnectTimeout when the apply option is not provided", async () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-apply-options-"))
    const playbookPath = join(tempDirectory, "capture-default-options.mjs")
    const calls: Array<{ options: unknown }> = []
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {
      /* suppress CLI header */
    })

    try {
      writeFileSync(
        playbookPath,
        [
          "export default {",
          "  name: 'test-server',",
          "  host: '1.2.3.4',",
          "  ssh: { user: 'root', ports: [22], reconnectTimeout: 45000 },",
          "  run: ['noop'],",
          "}",
        ].join("\n")
      )

      await runApplyCommand(
        playbookPath,
        {
          dryRun: true,
          env: {},
          firstRun: false,
          verbose: false,
        },
        async (_definition, options) => {
          await Promise.resolve()
          calls.push({ options })
        }
      )

      expect(calls).toHaveLength(1)
      expect(calls[0]?.options).not.toHaveProperty("reconnectTimeout")
    } finally {
      logSpy.mockRestore()
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("preserves an exit code set by the runner when the apply action fails", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
    })
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      /* suppress expected error */
    })
    const previousExitCode = process.exitCode

    try {
      process.exitCode = 1
      expect(() => exitAfterApplyError(new Error("module failed"), false)).toThrow("process.exit")
      expect(exitSpy).toHaveBeenCalledWith(1)
    } finally {
      process.exitCode = previousExitCode
      exitSpy.mockRestore()
      errorSpy.mockRestore()
    }
  })

  it("falls back to exit code 2 when the apply failure did not set an exit code", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
    })
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      /* suppress expected error */
    })
    const previousExitCode = process.exitCode

    try {
      process.exitCode = undefined
      expect(() => exitAfterApplyError(new Error("loader failed"), false)).toThrow("process.exit")
      expect(exitSpy).toHaveBeenCalledWith(2)
    } finally {
      process.exitCode = previousExitCode
      exitSpy.mockRestore()
      errorSpy.mockRestore()
    }
  })
})
