import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  printCommandError,
  printCommandFailure,
  printInfoLine,
  printModuleResult,
  printRecipeHeader,
  printSummary,
  printVerboseCommandError,
  printWarningLine,
  renderCliHeader,
  resetLiveOutputForTests,
  startModuleSpinner,
  stopLiveModuleOutput,
  withRecipeOutputScope,
} from "../src/output.js"
import { formatModuleElapsed } from "../src/outputFormatting.js"
import { clearRegisteredSecrets, registerSecret } from "../src/secretSink.js"
import { CommandError } from "../src/sshHelpers.js"

function bindOptionalStdoutMethod(name: "clearLine" | "cursorTo") {
  const method = process.stdout[name] as ((...args: never[]) => unknown) | undefined
  return method == null ? undefined : method.bind(process.stdout)
}

function setTTY(): {
  originalClearLine: ReturnType<typeof bindOptionalStdoutMethod>
  originalCursorTo: ReturnType<typeof bindOptionalStdoutMethod>
  originalIsTTY: boolean | undefined
} {
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

  return { originalClearLine, originalCursorTo, originalIsTTY }
}

function restoreTTY(saved: ReturnType<typeof setTTY>): void {
  Object.defineProperty(process.stdout, "isTTY", {
    configurable: true,
    value: saved.originalIsTTY,
  })
  Object.defineProperty(process.stdout, "clearLine", {
    configurable: true,
    value: saved.originalClearLine,
  })
  Object.defineProperty(process.stdout, "cursorTo", {
    configurable: true,
    value: saved.originalCursorTo,
  })
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

  it("renders unified-diff lines below the status when a diff is provided", () => {
    const diff = ["--- /etc/foo", "+++ desired", "-old", "+new"].join("\n")
    printModuleResult("file.copy: /etc/foo", "changed", "(dry-run)", diff)

    // 1 status line + 4 diff lines.
    expect(consoleLogs).toHaveLength(5)
    expect(consoleLogs[0]).toContain("file.copy: /etc/foo")
    expect(consoleLogs[1]).toContain("--- /etc/foo")
    expect(consoleLogs[2]).toContain("+++ desired")
    expect(consoleLogs[3]).toContain("-old")
    expect(consoleLogs[4]).toContain("+new")
  })

  it("masks registered secrets that appear inside the diff", () => {
    const secret = "diff-secret-ABCXYZ"
    registerSecret(secret)
    const diff = ["--- /etc/foo", "+++ desired", `-token = ${secret}`, "+token = rotated"].join(
      "\n"
    )

    printModuleResult("file.copy: /etc/foo", "changed", "(dry-run)", diff)

    const combined = consoleLogs.join("\n")
    expect(combined).not.toContain(secret)
    expect(combined).toContain("[REDACTED]")
  })

  it("omits diff output when the diff string is empty", () => {
    printModuleResult("noop", "changed", "(dry-run)", "")

    expect(consoleLogs).toHaveLength(1)
    expect(consoleLogs[0]).toContain("noop")
  })

  // ---------------------------------------------------------------------------
  // Cursor-visibility regression tests (fix: hide/show cursor during spinner)
  // ---------------------------------------------------------------------------

  it("hides the terminal cursor when the spinner starts and restores it after live output stops", () => {
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
      startModuleSpinner("service.start: nginx")

      // The hide-cursor sequence must have been written synchronously on frame 0.
      expect(writes.some((w) => w.includes("\x1b[?25l"))).toBe(true)

      stopLiveModuleOutput(true)

      // After stopping, the last cursor-related sequence must be show-cursor,
      // not hide-cursor — the cursor must be visible again when the run ends.
      const cursorWrites = writes.filter((w) => w.includes("\x1b[?25"))
      expect(cursorWrites.length).toBeGreaterThan(0)
      expect(cursorWrites.at(-1)).toContain("\x1b[?25h")
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

  it("restores the terminal cursor via printSummary even when printModuleResult already cleared the active spinner", () => {
    // Regression: printModuleResult stops the spinner (activeSpinner → null) but
    // re-hides the cursor while writing the final animated result line.
    // printSummary must then emit the show-cursor sequence even though
    // activeSpinner is null at that point — before the fix, showCursor() was
    // guarded behind the activeSpinner null-check and was never reached.
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
      startModuleSpinner("file.copy: /etc/nginx/nginx.conf")
      // printModuleResult internally stops the spinner (activeSpinner → null)
      // and then re-hides the cursor while writing the final result line via
      // writeAnimatedModuleLine, leaving cursorHidden=true and activeSpinner=null.
      printModuleResult("file.copy: /etc/nginx/nginx.conf", "changed")
      // printSummary must emit show-cursor even though activeSpinner is null.
      printSummary({ changed: 1, failed: 0, ok: 0, signals: 0, skipped: 0 })

      const cursorWrites = writes.filter((w) => w.includes("\x1b[?25"))
      expect(cursorWrites.length).toBeGreaterThan(0)
      expect(cursorWrites.at(-1)).toContain("\x1b[?25h")
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

  it("does not write cursor hide or show sequences when stdout is not a TTY", () => {
    // Redirected or piped output must stay byte-for-byte clean: no ANSI cursor
    // control sequences when supportsAnimatedModuleOutput() returns false.
    const writes: string[] = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")

    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })
    Object.defineProperty(process.stdout, "clearLine", {
      configurable: true,
      value: undefined,
    })
    Object.defineProperty(process.stdout, "cursorTo", {
      configurable: true,
      value: undefined,
    })

    try {
      startModuleSpinner("file.copy: /etc/hosts")
      printModuleResult("file.copy: /etc/hosts", "ok")
      stopLiveModuleOutput(true)

      expect(writes.every((w) => !w.includes("\x1b[?25l"))).toBe(true)
      expect(writes.every((w) => !w.includes("\x1b[?25h"))).toBe(true)
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

  it("keeps the live-output state on a globalThis singleton so duplicate module bundles share one spinner", () => {
    // The CLI bundle (cli.js) and the library bundle (index.js) each contain a
    // copy of this module. Sharing the spinner/cursor/indent state through a
    // Symbol.for-keyed globalThis slot is what stops the two copies from
    // running concurrent spinner intervals on the same terminal line.
    const stateKey = Symbol.for("paratix.output.liveState")
    const shared = (globalThis as Record<symbol, { activeSpinner: unknown } | undefined>)[stateKey]
    expect(shared).toBeDefined()

    const originalIsTTY = process.stdout.isTTY
    const originalClearLine = bindOptionalStdoutMethod("clearLine")
    const originalCursorTo = bindOptionalStdoutMethod("cursorTo")
    vi.spyOn(process.stdout, "write").mockImplementation(() => true)

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
      // The running spinner is visible through the shared globalThis slot, so a
      // second module copy would observe (and clear) the same spinner.
      expect(shared?.activeSpinner).not.toBeNull()
      stopLiveModuleOutput(true)
      expect(shared?.activeSpinner).toBeNull()
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

  it("indents nested recipe headers one level deeper than the parent scope", async () => {
    await withRecipeOutputScope(() => {
      printRecipeHeader("service-layer")
    })

    expect(consoleLogs).toHaveLength(1)
    expect(consoleLogs[0]).toContain("  [service-layer]")
  })
})

// ---------------------------------------------------------------------------
// printInfoLine
// ---------------------------------------------------------------------------

describe("printInfoLine", () => {
  let consoleLogs: string[]

  beforeEach(() => {
    consoleLogs = []
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    clearRegisteredSecrets()
    vi.restoreAllMocks()
  })

  it("prints a single line with the given text", () => {
    printInfoLine("Resolving secrets before connecting …")

    expect(consoleLogs).toHaveLength(1)
    expect(consoleLogs[0]).toContain("Resolving secrets before connecting")
  })

  it("masks a registered secret before printing", () => {
    const secret = "info-line-secret-XYZ123"
    registerSecret(secret)

    printInfoLine(`status for ${secret}`)

    const output = consoleLogs.join("\n")
    expect(output).not.toContain(secret)
    expect(output).toContain("[REDACTED]")
  })
})

// ---------------------------------------------------------------------------
// printWarningLine
// ---------------------------------------------------------------------------

describe("printWarningLine", () => {
  let consoleErrors: string[]

  beforeEach(() => {
    consoleErrors = []
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    clearRegisteredSecrets()
    vi.restoreAllMocks()
  })

  it("prints a single line prefixed with 'Warning:'", () => {
    printWarningLine('--filter excluded "op.resolve: SECRET"')

    expect(consoleErrors).toHaveLength(1)
    expect(consoleErrors[0]).toContain("Warning:")
    expect(consoleErrors[0]).toContain("op.resolve: SECRET")
  })

  it("masks a registered secret before printing", () => {
    const secret = "warning-line-secret-XYZ123"
    registerSecret(secret)

    printWarningLine(`leaked ${secret}`)

    const output = consoleErrors.join("\n")
    expect(output).not.toContain(secret)
    expect(output).toContain("[REDACTED]")
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

  it("sanitizes remote control sequences after masking secrets", () => {
    const secret = "verbose-secret"
    registerSecret(secret)

    printVerboseCommandError(
      `stdout ${secret}\u001B[31m ok`,
      "stderr \u001B]0;bad-title\u0007line\rnext"
    )

    const output = consoleErrors.join("\n")
    expect(output).toContain("[REDACTED] ok")
    expect(output).toContain("stderr linenext")
    expect(output).not.toContain(secret)
    expect(output).not.toContain("\u001B")
    expect(output).not.toContain("\u0007")
    expect(output).not.toContain("\r")
    expect(output).not.toContain("bad-title")
  })
})

// ---------------------------------------------------------------------------
// printCommandError
// ---------------------------------------------------------------------------

describe("printCommandError", () => {
  let consoleErrors: string[]

  beforeEach(() => {
    consoleErrors = []
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(" "))
    })
  })

  afterEach(() => {
    clearRegisteredSecrets()
    vi.restoreAllMocks()
  })

  it("sanitizes captured command output before local formatting", () => {
    const secret = "command-error-secret"
    registerSecret(secret)

    printCommandError(`stdout ${secret}\u001B[2K`, "stderr \u001B]0;bad-title\u0007ok\u0000")

    const output = consoleErrors.join("\n")
    expect(output).toContain("Error output:")
    expect(output).toContain(`stdout [REDACTED]`)
    expect(output).toContain("stderr ok")
    expect(output).not.toContain(secret)
    expect(output).not.toContain("\u0000")
    expect(output).not.toContain("bad-title")
    expect(output).not.toContain("\u001B]0")
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

  it("redacts credential-named fields in plain object causes", () => {
    const error = new Error("outer failure", {
      cause: {
        authorization: "Bearer unregistered-authorization",
        headers: {
          cookie: "session=unregistered-cookie",
        },
        safe: "visible-diagnostic",
      },
    })

    printCommandFailure(error, false)

    const output = consoleErrors.join("\n")
    expect(output).toContain("visible-diagnostic")
    expect(output).toContain("[REDACTED]")
    expect(output).not.toContain("unregistered-authorization")
    expect(output).not.toContain("unregistered-cookie")
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

// ---------------------------------------------------------------------------
// formatModuleElapsed
// ---------------------------------------------------------------------------

describe("formatModuleElapsed", () => {
  it("returns undefined just below the 1-second threshold", () => {
    expect(formatModuleElapsed(999)).toBeUndefined()
  })

  it("returns '1.0s' at exactly the 1-second threshold", () => {
    expect(formatModuleElapsed(1000)).toBe("1.0s")
  })

  it("formats a mid-range value with one decimal place", () => {
    expect(formatModuleElapsed(3200)).toBe("3.2s")
  })

  it("formats a value just under 60 seconds in seconds", () => {
    expect(formatModuleElapsed(59_900)).toBe("59.9s")
  })

  it("switches to minutes-and-seconds format at exactly 60 seconds", () => {
    expect(formatModuleElapsed(60_000)).toBe("1m 00s")
  })

  it("zero-pads the seconds field in minutes-and-seconds format", () => {
    expect(formatModuleElapsed(65_300)).toBe("1m 05s")
  })

  it("returns undefined for a negative elapsed value", () => {
    expect(formatModuleElapsed(-5)).toBeUndefined()
  })

  it("returns undefined for NaN", () => {
    expect(formatModuleElapsed(Number.NaN)).toBeUndefined()
  })

  it("returns undefined for Infinity", () => {
    expect(formatModuleElapsed(Number.POSITIVE_INFINITY)).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Module elapsed-time display (live spinner counter + static result suffix)
// ---------------------------------------------------------------------------

describe("module elapsed-time display", () => {
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
    vi.useRealTimers()
  })

  it("shows a live elapsed counter on a spinner frame once past the 1-second threshold (TTY)", () => {
    vi.useFakeTimers()
    const writes: string[] = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const saved = setTTY()

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(3200)
      // Trigger the next spinner frame (interval fires every 80ms).
      vi.advanceTimersByTime(80)

      const runningWrite = writes.findLast((entry) => entry.includes("running"))
      expect(runningWrite).toBeDefined()
      expect(runningWrite).toMatch(/\d{1,3}\.\ds/v)
    } finally {
      stopLiveModuleOutput(true)
      restoreTTY(saved)
    }
  })

  it("does not show an elapsed suffix on a spinner frame below the 1-second threshold (TTY)", () => {
    vi.useFakeTimers()
    const writes: string[] = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const saved = setTTY()

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(400)
      // Trigger a spinner frame while still below the threshold.
      vi.advanceTimersByTime(80)

      const runningWrite = writes.find((entry) => entry.includes("running"))
      expect(runningWrite).toBeDefined()
      expect(runningWrite).not.toMatch(/\d{1,3}\.\ds/v)
    } finally {
      stopLiveModuleOutput(true)
      restoreTTY(saved)
    }
  })

  it("renders a static elapsed suffix on the final result line (TTY)", () => {
    vi.useFakeTimers()
    const writes: string[] = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      writes.push(String(chunk))
      return true
    })
    const saved = setTTY()

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(3200)
      printModuleResult("service.restart: app", "changed")

      const changedWrite = writes.find((entry) => entry.includes("changed"))
      expect(changedWrite).toBeDefined()
      expect(changedWrite).toMatch(/\d{1,3}\.\ds/v)
    } finally {
      stopLiveModuleOutput(true)
      restoreTTY(saved)
    }
  })

  it("renders the static elapsed suffix on the final result line in non-TTY output", () => {
    vi.useFakeTimers()
    const originalIsTTY = process.stdout.isTTY
    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(3200)
      printModuleResult("service.restart: app", "changed")

      expect(consoleLogs).toHaveLength(1)
      expect(consoleLogs[0]).toContain("changed")
      expect(consoleLogs[0]).toMatch(/\d{1,3}\.\ds/v)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
    }
  })

  it("formats the elapsed suffix in minutes-and-seconds once past the 60-second mark", () => {
    vi.useFakeTimers()
    const originalIsTTY = process.stdout.isTTY
    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(65_300)
      printModuleResult("service.restart: app", "changed")

      expect(consoleLogs).toHaveLength(1)
      expect(consoleLogs[0]).toContain("1m 05s")
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
    }
  })

  it("consumes the recorded start time exactly once so a second result line has no elapsed suffix", () => {
    vi.useFakeTimers()
    const originalIsTTY = process.stdout.isTTY
    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(3200)
      printModuleResult("service.restart: app", "changed")
      printModuleResult("service.restart: app", "ok")

      expect(consoleLogs).toHaveLength(2)
      expect(consoleLogs[0]).toMatch(/\d{1,3}\.\ds/v)
      expect(consoleLogs[1]).not.toMatch(/\d{1,3}\.\ds/v)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
    }
  })

  it("clears the recorded start time via resetLiveOutputForTests", () => {
    vi.useFakeTimers()
    const originalIsTTY = process.stdout.isTTY
    Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })

    try {
      startModuleSpinner("service.restart: app")
      vi.advanceTimersByTime(3200)
      resetLiveOutputForTests()
      printModuleResult("service.restart: app", "ok")

      expect(consoleLogs).toHaveLength(1)
      expect(consoleLogs[0]).not.toMatch(/\d{1,3}\.\ds/v)
    } finally {
      Object.defineProperty(process.stdout, "isTTY", {
        configurable: true,
        value: originalIsTTY,
      })
    }
  })
})
