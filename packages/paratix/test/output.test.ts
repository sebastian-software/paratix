import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  printCommandFailure,
  printModuleResult,
  printRecipeHeader,
  printVerboseCommandError,
  renderCliHeader,
  resetLiveOutputForTests,
  startModuleSpinner,
  stopLiveModuleOutput,
  withRecipeOutputScope,
} from "../src/output.js"
import { clearRegisteredSecrets, registerSecret } from "../src/secretSink.js"
import { CommandError } from "../src/sshHelpers.js"

function bindOptionalStdoutMethod(name: "clearLine" | "cursorTo") {
  const method = process.stdout[name] as ((...args: never[]) => unknown) | undefined
  return method == null ? undefined : method.bind(process.stdout)
}

describe("renderCliHeader", () => {
  it("includes the paratix name and display version", () => {
    expect(renderCliHeader("0.1.0-af172d6")).toContain("_ __   __ _ _ __ __ _| |_ ___  __")
    expect(renderCliHeader("0.1.0-af172d6")).toContain("v0.1.0-af172d6")
  })
})

describe("printModuleResult", () => {
  let consoleLogs: string[]

  beforeEach(() => {
    consoleLogs = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    resetLiveOutputForTests()
    clearRegisteredSecrets()
    vi.restoreAllMocks()
  })

  it("keeps a separator between exact-width names and the status", () => {
    printModuleResult("package.installed: nginx, curl, htop", "changed", "(dry-run)")

    expect(consoleLogs).toHaveLength(2)
    expect(consoleLogs[0]).toContain("package.installed")
    expect(consoleLogs[0]).toContain("changed")
    expect(consoleLogs[0]).toContain("3 packages")
    expect(consoleLogs[0]).toContain("(dry-run)")
    expect(consoleLogs[1]).toContain("nginx")
    expect(consoleLogs[1]).toContain("curl")
    expect(consoleLogs[1]).toContain("htop")
  })

  it("renders detail text for regular changed results", () => {
    printModuleResult("quadlet.updateImage: traefik", "changed", "(sha256:new-traefik-id)")

    expect(consoleLogs).toHaveLength(1)
    expect(consoleLogs[0]).toContain("changed")
    expect(consoleLogs[0]).toContain("(sha256:new-traefik-id)")
  })

  it("masks registered secrets in module names and details before rendering results", () => {
    const secret = "module-result-secret-XYZ123"
    registerSecret(secret)

    printModuleResult(`command.shell: deploy --token ${secret}`, "changed", `rotated ${secret}`)

    const output = consoleLogs.join("\n")
    expect(output).not.toContain(secret)
    expect(output).toContain("[REDACTED]")
  })

  it("renders a live running line on TTY and replaces it with the final result", () => {
    const writes: string[] = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: vi.fn(() => true),
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: vi.fn(() => true),
    })

    try {
      startModuleSpinner("hostname.set: my-server")
      printModuleResult("hostname.set: my-server", "changed")

      expect(consoleLogs).toHaveLength(0)
      expect(writes.some((entry) => entry.includes("running"))).toBe(true)
      expect(writes.some((entry) => entry.includes("changed"))).toBe(true)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
      Object.defineProperty(process.stdout, "clearLine", {
        configurable: true,
        value: originalClearLine,
      })
      Object.defineProperty(process.stdout, "cursorTo", {
        configurable: true,
        value: originalCursorTo,
      })
    }
  })

  it("masks registered secrets before writing live spinner output", () => {
    const writes: string[] = []
    const secret = "spinner-secret-XYZ123"
    registerSecret(secret)
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")
    const originalColumns = process.stdout.columns

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: vi.fn(() => true),
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: vi.fn(() => true),
    })
    Object.defineProperty(process.stdout, "columns", {
      configurable: true,
      value: 120,
    })

    try {
      startModuleSpinner(`command.shell: deploy --token ${secret}`, `waiting for ${secret}`)

      const output = writes.join("\n")
      expect(output).not.toContain(secret)
      expect(output).toContain("[REDACTED]")
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
      Object.defineProperty(process.stdout, "clearLine", {
        configurable: true,
        value: originalClearLine,
      })
      Object.defineProperty(process.stdout, "cursorTo", {
        configurable: true,
        value: originalCursorTo,
      })
      Object.defineProperty(process.stdout, "columns", {
        configurable: true,
        value: originalColumns,
      })
    }
  })

  it("keeps the status column aligned across nested recipe depths", async () => {
    printModuleResult("top-level", "ok")

    await withRecipeOutputScope(() => {
      printModuleResult("nested-child", "changed")
    })

    expect(consoleLogs).toHaveLength(2)
    const topLevelStatusColumn = consoleLogs[0].indexOf("ok")
    const nestedStatusColumn = consoleLogs[1].indexOf("changed")
    expect(topLevelStatusColumn).toBe(nestedStatusColumn)
  })

  it("renders package modules compactly while the spinner is active", () => {
    const writes: string[] = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")
    const originalColumns = process.stdout.columns

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: vi.fn(() => true),
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: vi.fn(() => true),
    })
    Object.defineProperty(process.stdout, "columns", {
      configurable: true,
      value: 120,
    })

    try {
      startModuleSpinner(
        "package.installed: ca-certificates, podman, podman-compose, docker-ce, docker-ce-cli"
      )
      printModuleResult(
        "package.installed: ca-certificates, podman, podman-compose, docker-ce, docker-ce-cli",
        "ok"
      )

      expect(writes.some((entry) => entry.includes("package.installed"))).toBe(true)
      expect(writes.some((entry) => entry.includes("5 packages"))).toBe(true)
      expect(writes.some((entry) => entry.includes("docker-compose-plugin"))).toBe(false)
      expect(writes.some((entry) => entry.includes("ca-certificates, podman"))).toBe(false)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
      Object.defineProperty(process.stdout, "clearLine", {
        configurable: true,
        value: originalClearLine,
      })
      Object.defineProperty(process.stdout, "cursorTo", {
        configurable: true,
        value: originalCursorTo,
      })
      Object.defineProperty(process.stdout, "columns", {
        configurable: true,
        value: originalColumns,
      })
    }
  })

  it("unrefs the spinner timer so a missed stop call cannot keep the event loop alive", () => {
    const unrefSpy = vi.fn()
    const setIntervalSpy = vi.spyOn(globalThis, "setInterval").mockImplementation(((
      handler: (...args: unknown[]) => void,
      _ms?: number
    ) => {
      // Return an opaque object with the same surface the spinner relies on
      // (clearInterval + unref). Using a fake timer here lets the test assert
      // that the production code calls unref() on whatever setInterval
      // returned, regardless of the host runtime's Timeout shape.
      void handler
      return { unref: unrefSpy } as unknown as NodeJS.Timeout
    }) as typeof setInterval)
    vi.spyOn(globalThis, "clearInterval").mockImplementation(() => {
      // noop: the matching mocked setInterval returns a fake timer that
      // clearInterval cannot consume. Suppressing the call here keeps the
      // test from throwing while still allowing the spinner to invoke it.
    })
    vi.spyOn(process.stdout, "write").mockImplementation(() => true)
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: vi.fn(() => true),
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: vi.fn(() => true),
    })

    try {
      startModuleSpinner("service.restart: app")

      // The spinner must call setInterval and immediately unref the returned
      // timer so an uncaughtException-path that misses stopAnimatedModuleLine
      // does not keep the Node event loop alive.
      expect(setIntervalSpy).toHaveBeenCalled()
      expect(unrefSpy).toHaveBeenCalledTimes(1)
    } finally {
      stopLiveModuleOutput(true)
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
      Object.defineProperty(process.stdout, "clearLine", {
        configurable: true,
        value: originalClearLine,
      })
      Object.defineProperty(process.stdout, "cursorTo", {
        configurable: true,
        value: originalCursorTo,
      })
    }
  })

  it("stops and clears live output on request", () => {
    const clearLine = vi.fn(() => true)
    const cursorTo = vi.fn(() => true)
    vi.spyOn(process.stdout, "write").mockImplementation(() => true)
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: clearLine,
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: cursorTo,
    })

    try {
      startModuleSpinner("service.restart: app")
      stopLiveModuleOutput(true)
      printModuleResult("service.restart: app", "ok")

      expect(clearLine).toHaveBeenCalledTimes(2)
      expect(cursorTo).toHaveBeenCalledTimes(2)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
      Object.defineProperty(process.stdout, "clearLine", {
        configurable: true,
        value: originalClearLine,
      })
      Object.defineProperty(process.stdout, "cursorTo", {
        configurable: true,
        value: originalCursorTo,
      })
    }
  })
})

describe("printRecipeHeader", () => {
  let consoleLogs: string[]

  beforeEach(() => {
    consoleLogs = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    resetLiveOutputForTests()
    vi.restoreAllMocks()
  })

  it("stops an active spinner before printing the recipe header", () => {
    const writes: string[] = []
    const clearLine = vi.fn(() => true)
    const cursorTo = vi.fn(() => true)
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: clearLine,
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: cursorTo,
    })

    try {
      startModuleSpinner("firewall")
      printRecipeHeader("firewall")
      printModuleResult("firewall", "ok")

      expect(consoleLogs.join("\n")).toContain("[firewall]")
      expect(writes.some((entry) => entry.includes("running"))).toBe(true)
      expect(writes.some((entry) => entry.includes("ok"))).toBe(false)
      expect(clearLine).toHaveBeenCalledTimes(2)
      expect(cursorTo).toHaveBeenCalledTimes(2)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
      Object.defineProperty(process.stdout, "clearLine", {
        configurable: true,
        value: originalClearLine,
      })
      Object.defineProperty(process.stdout, "cursorTo", {
        configurable: true,
        value: originalCursorTo,
      })
    }
  })

  it("indents nested recipe headers one level deeper than the parent scope", async () => {
    await withRecipeOutputScope(() => {
      printRecipeHeader("service-layer")
    })

    expect(consoleLogs).toHaveLength(1)
    expect(consoleLogs[0]).toContain("  [service-layer]")
  })
})

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

  it("breaks out of a cyclic cause chain in verbose mode without recursing forever", () => {
    const inner = new Error("inner cause")
    inner.stack = "Error: inner cause\n    at inner.ts:2:2"
    const outer = new Error("outer failure", { cause: inner })
    outer.stack = "Error: outer failure\n    at outer.ts:1:1"
    inner.cause = outer

    expect(() => {
      printCommandFailure(outer, true)
    }).not.toThrow()

    const output = consoleErrors.join("\n")
    expect(output).toContain("Cause 1:")
    expect(output).toContain("inner cause")
    expect(output).toContain("<cycle detected>")
  })

  it("breaks out of a self-referential cause in verbose mode", () => {
    const error = new Error("self")
    error.stack = "Error: self\n    at self.ts:1:1"
    error.cause = error

    expect(() => {
      printCommandFailure(error, true)
    }).not.toThrow()

    const output = consoleErrors.join("\n")
    expect(output).toContain("<cycle detected>")
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
