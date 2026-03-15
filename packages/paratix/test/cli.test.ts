import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest"

import {
  collectDefinitionErrors,
  collectEnvironment,
  isServerDefinitionLike,
  printError,
} from "../src/cli.js"

declare const PACKAGE_VERSION: string

describe("PACKAGE_VERSION", () => {
  it("matches the version in package.json", () => {
    const packageJsonPath = resolve(new URL("../package.json", import.meta.url).pathname)
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { version: string }
    expect(PACKAGE_VERSION).toBe(packageJson.version)
  })
})

describe("collectEnvironment", () => {
  let exitSpy: MockInstance<typeof process.exit>

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit")
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

describe("isServerDefinitionLike", () => {
  it("returns false for null", () => {
    expect(isServerDefinitionLike(null)).toBe(false)
  })

  it("returns false for undefined", () => {
    const value: unknown = void 0 as unknown
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

  it("returns false for an object with only host", () => {
    expect(isServerDefinitionLike({ host: "example.com" })).toBe(false)
  })

  it("returns false for an object with only run", () => {
    expect(isServerDefinitionLike({ run: [] })).toBe(false)
  })

  it("returns false for an object with string host and empty array run", () => {
    expect(isServerDefinitionLike({ host: "example.com", run: [] })).toBe(false)
  })

  it("returns true for an object with string host and non-empty array run", () => {
    expect(isServerDefinitionLike({ host: "example.com", run: [["echo", "hello"]] })).toBe(true)
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

  it("returns errors for both missing host and run on an empty object", () => {
    const errors = collectDefinitionErrors({})
    expect(errors).toContain("Missing property 'host' (expected string)")
    expect(errors).toContain("Missing property 'run' (expected array)")
    expect(errors).toHaveLength(2)
  })

  it("returns an error for missing run when only host is present", () => {
    const errors = collectDefinitionErrors({ host: "example.com" })
    expect(errors).toStrictEqual(["Missing property 'run' (expected array)"])
  })

  it("returns errors for missing host and empty run when only an empty run is present", () => {
    const errors = collectDefinitionErrors({ run: [] })
    expect(errors).toContain("Missing property 'host' (expected string)")
    expect(errors).toContain("Property 'run' must not be empty")
    expect(errors).toHaveLength(2)
  })

  it("returns errors when host has the wrong type and run is empty", () => {
    const errors = collectDefinitionErrors({ host: 123, run: [] })
    expect(errors).toContain("Invalid property 'host' (expected string, got number)")
    expect(errors).toContain("Property 'run' must not be empty")
    expect(errors).toHaveLength(2)
  })

  it("returns an error mentioning the actual type when run is not an array", () => {
    const errors = collectDefinitionErrors({ host: "example.com", run: "not-an-array" })
    expect(errors).toStrictEqual(["Invalid property 'run' (expected array, got string)"])
  })

  it("returns an error when run is an empty array", () => {
    const errors = collectDefinitionErrors({ host: "example.com", run: [] })
    expect(errors).toStrictEqual(["Property 'run' must not be empty"])
  })

  it("returns an error when host is an empty string", () => {
    const errors = collectDefinitionErrors({ host: "", run: ["echo hello"] })
    expect(errors).toStrictEqual(["Property 'host' must not be empty"])
  })

  it("returns errors for both empty host and empty run", () => {
    const errors = collectDefinitionErrors({ host: "", run: [] })
    expect(errors).toContain("Property 'host' must not be empty")
    expect(errors).toContain("Property 'run' must not be empty")
    expect(errors).toHaveLength(2)
  })

  it("returns an empty array for a valid ServerDefinition shape", () => {
    const errors = collectDefinitionErrors({ host: "example.com", run: ["echo hello"] })
    expect(errors).toStrictEqual([])
  })
})

describe("printError", () => {
  let errorSpy: MockInstance<typeof console.error>

  beforeEach(() => {
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {
      // noop: suppress console.error output during tests
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("prints the error message for a plain Error", () => {
    printError(new Error("something went wrong"), false)
    expect(errorSpy).toHaveBeenCalledWith("Error: something went wrong")
  })

  it("prints the string representation for a non-Error string value", () => {
    printError("oops", false)
    expect(errorSpy).toHaveBeenCalledWith("Error: oops")
  })

  it("prints the string representation for a non-Error number value", () => {
    printError(42, false)
    expect(errorSpy).toHaveBeenCalledWith("Error: 42")
  })

  it("prints the JSON representation for a plain object to avoid [object Object]", () => {
    printError({ code: 404 }, false)
    expect(errorSpy).toHaveBeenCalledWith('Error: {"code":404}')
  })

  it("prints a single cause when the error has one cause", () => {
    const cause = new Error("root cause")
    const error = new Error("top-level error", { cause })
    printError(error, false)
    expect(errorSpy).toHaveBeenCalledWith("Error: top-level error")
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: root cause")
  })

  it("prints the full cause chain for nested causes", () => {
    const root = new Error("database unavailable")
    const mid = new Error("query failed", { cause: root })
    const top = new Error("request failed", { cause: mid })
    printError(top, false)
    expect(errorSpy).toHaveBeenCalledWith("Error: request failed")
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: query failed")
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: database unavailable")
  })

  it("prints a non-Error cause using its string representation", () => {
    const error = new Error("top-level error")
    error.cause = "string cause"
    printError(error, false)
    expect(errorSpy).toHaveBeenCalledWith("  Caused by: string cause")
  })

  it("does not print a stack trace without --verbose", () => {
    const error = new Error("something went wrong")
    printError(error, false)
    const calls = errorSpy.mock.calls.map((args) => String(args[0]))
    expect(calls.some((msg) => msg.includes("at "))).toBe(false)
  })

  it("prints the stack trace when verbose is true", () => {
    const error = new Error("something went wrong")
    // Ensure the stack is defined so the assertion is meaningful
    expect(error.stack).toBeDefined()
    printError(error, true)
    // The stack is printed as the second console.error call (after "Error: …")
    const stackCall = errorSpy.mock.calls[1]?.[0] as string
    expect(stackCall).toContain("something went wrong")
    expect(stackCall).toContain("at ")
  })

  it("does not print cause output when there is no cause", () => {
    printError(new Error("lone error"), false)
    expect(errorSpy).toHaveBeenCalledTimes(1)
    expect(errorSpy).toHaveBeenCalledWith("Error: lone error")
  })

  it("does not attempt to walk the cause chain for non-Error values", () => {
    printError("plain string error", true)
    expect(errorSpy).toHaveBeenCalledTimes(1)
  })
})
