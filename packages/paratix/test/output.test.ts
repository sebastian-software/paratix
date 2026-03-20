import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { printCommandFailure, printVerboseCommandError } from "../src/output.js"
import { CommandError } from "../src/sshHelpers.js"

// ---------------------------------------------------------------------------
// printVerboseCommandError
// ---------------------------------------------------------------------------

describe("printVerboseCommandError", () => {
  let consoleErrors: string[]

  beforeEach(() => {
    consoleErrors = []
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("prints 'Full stderr:' label when stderr is non-empty", () => {
    printVerboseCommandError("", "error line one")

    const output = consoleErrors.join("\n")
    expect(output).toContain("Full stderr:")
  })

  it("prints 'Full stdout:' label when stdout is non-empty", () => {
    printVerboseCommandError("output line one", "")

    const output = consoleErrors.join("\n")
    expect(output).toContain("Full stdout:")
  })

  it("prints stderr content lines after the 'Full stderr:' label", () => {
    printVerboseCommandError("", "the full error message")

    const output = consoleErrors.join("\n")
    expect(output).toContain("the full error message")
  })

  it("prints stdout content lines after the 'Full stdout:' label", () => {
    printVerboseCommandError("the full output message", "")

    const output = consoleErrors.join("\n")
    expect(output).toContain("the full output message")
  })

  it("prints both 'Full stderr:' and 'Full stdout:' labels when both streams are non-empty", () => {
    printVerboseCommandError("full output", "full error")

    const output = consoleErrors.join("\n")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("Full stdout:")
  })

  it("prints nothing when both stdout and stderr are empty strings", () => {
    printVerboseCommandError("", "")

    expect(consoleErrors).toHaveLength(0)
  })

  it("prints nothing when both stdout and stderr contain only whitespace", () => {
    printVerboseCommandError("   ", "\n\t")

    expect(consoleErrors).toHaveLength(0)
  })

  it("prints each line of multiline stderr as a separate log call", () => {
    printVerboseCommandError("", "line one\nline two\nline three")

    const output = consoleErrors.join("\n")
    expect(output).toContain("line one")
    expect(output).toContain("line two")
    expect(output).toContain("line three")
  })
})

// ---------------------------------------------------------------------------
// printCommandFailure
// ---------------------------------------------------------------------------

describe("printCommandFailure", () => {
  let consoleErrors: string[]

  beforeEach(() => {
    consoleErrors = []
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("prints the error message in non-verbose mode", () => {
    const error = new Error("command failed badly")

    printCommandFailure(error, false)

    const output = consoleErrors.join("\n")
    expect(output).toContain("command failed badly")
  })

  it("does not print verbose output for a plain Error in non-verbose mode", () => {
    const error = new Error("plain error")

    printCommandFailure(error, false)

    const output = consoleErrors.join("\n")
    expect(output).not.toContain("Full stderr:")
    expect(output).not.toContain("Full stdout:")
  })

  it("does not print verbose output for a CommandError in non-verbose mode", () => {
    const error = new CommandError(
      "Command failed with exit code 1: false\nstdout: short\nstderr: short",
      "full stdout content",
      "full stderr content"
    )

    printCommandFailure(error, false)

    const output = consoleErrors.join("\n")
    expect(output).not.toContain("full stdout content")
    expect(output).not.toContain("full stderr content")
    expect(output).not.toContain("Full stderr:")
    expect(output).not.toContain("Full stdout:")
  })

  it("prints the error message in verbose mode", () => {
    const error = new Error("verbose error message")
    error.stack = "Error: verbose error message\n    at output.test.ts:1:1"

    printCommandFailure(error, true)

    const output = consoleErrors.join("\n")
    expect(output).toContain("verbose error message")
  })

  it("prints the full stack for a plain Error in verbose mode", () => {
    const error = new Error("just a regular error")
    error.stack = "Error: just a regular error\n    at output.test.ts:2:2"

    printCommandFailure(error, true)

    const output = consoleErrors.join("\n")
    expect(output).toContain("Full stack:")
    expect(output).toContain("at output.test.ts:2:2")
    expect(output).not.toContain("Full stderr:")
    expect(output).not.toContain("Full stdout:")
  })

  it("prints the full cause chain for a plain Error in verbose mode", () => {
    const rootCause = new Error("root cause")
    rootCause.stack = "Error: root cause\n    at root.ts:3:3"
    const cause = new Error("inner cause", { cause: rootCause })
    cause.stack = "Error: inner cause\n    at inner.ts:2:2"
    const error = new Error("outer failure", { cause })
    error.stack = "Error: outer failure\n    at outer.ts:1:1"

    printCommandFailure(error, true)

    const output = consoleErrors.join("\n")
    expect(output).toContain("Full stack:")
    expect(output).toContain("outer failure")
    expect(output).toContain("Cause 1:")
    expect(output).toContain("inner cause")
    expect(output).toContain("Cause 2:")
    expect(output).toContain("root cause")
  })

  it("prints full stdout and stderr via verbose output when verbose is true and error is a CommandError", () => {
    const error = new CommandError(
      "Command failed with exit code 1: false\nstdout: short\nstderr: short",
      "the complete stdout output",
      "the complete stderr output"
    )

    printCommandFailure(error, true)

    const output = consoleErrors.join("\n")
    expect(output).toContain("the complete stdout output")
    expect(output).toContain("the complete stderr output")
  })

  it("prints 'Full stderr:' and 'Full stdout:' labels when verbose is true and error is a CommandError with non-empty streams", () => {
    const error = new CommandError(
      "Command failed with exit code 1: false\nstdout: s\nstderr: e",
      "stdout data",
      "stderr data"
    )

    printCommandFailure(error, true)

    const output = consoleErrors.join("\n")
    expect(output).toContain("Full stderr:")
    expect(output).toContain("Full stdout:")
  })

  it("does not print verbose headers when CommandError has empty fullStdout and fullStderr", () => {
    const error = new CommandError(
      "Command failed with exit code 1: false\nstdout: \nstderr: ",
      "",
      ""
    )

    printCommandFailure(error, true)

    const output = consoleErrors.join("\n")
    expect(output).not.toContain("Full stderr:")
    expect(output).not.toContain("Full stdout:")
  })

  it("handles a non-Error thrown value (string) without crashing", () => {
    printCommandFailure("something went wrong", false)

    const output = consoleErrors.join("\n")
    expect(output).toContain("something went wrong")
  })
})
