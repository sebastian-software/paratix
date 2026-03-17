import { describe, expect, it, vi } from "vitest"

import { command } from "../../src/modules/command.js"
import { printCommandError } from "../../src/output.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const emptyEnv = {}

vi.mock("../../src/output.js", () => ({
  printCommandError: vi.fn(),
}))

// ---------------------------------------------------------------------------
// apply — null ssh
// ---------------------------------------------------------------------------

describe("command.shell — apply with null ssh", () => {
  it("returns failed when ssh is null", async () => {
    const mod = command.shell("echo hello")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })
})

// ---------------------------------------------------------------------------
// apply — successful command
// ---------------------------------------------------------------------------

describe("command.shell — apply with exit code 0", () => {
  it("returns changed when command exits with code 0", async () => {
    const mockSsh = createMockSsh({ "echo hello": { code: 0 } })
    const mod = command.shell("echo hello")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })
})

// ---------------------------------------------------------------------------
// apply — failed command
// ---------------------------------------------------------------------------

describe("command.shell — apply with non-zero exit code", () => {
  it("returns failed when command exits with non-zero code", async () => {
    const mockSsh = createMockSsh({ "exit 1": { code: 1 } })
    const mod = command.shell("exit 1")
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("calls printCommandError with stdout and stderr when command exits non-zero", async () => {
    vi.mocked(printCommandError).mockClear()

    const mockSsh = createMockSsh({
      "exit 1": { code: 1, stderr: "some error", stdout: "some output" },
    })
    const mod = command.shell("exit 1")
    await mod.apply(mockSsh, emptyEnv)

    expect(printCommandError).toHaveBeenCalledOnce()
    expect(printCommandError).toHaveBeenCalledWith("some output", "some error")
  })
})

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("command.shell — check", () => {
  it("returns needs-apply when no check option is provided", async () => {
    const mockSsh = createMockSsh()
    const mod = command.shell("echo hello")
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = command.shell("echo hello", { check: "which tool" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when check command exits with code 0", async () => {
    const mockSsh = createMockSsh({ "which tool": { code: 0 } })
    const mod = command.shell("install-tool", { check: "which tool" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns needs-apply when check command exits with non-zero code", async () => {
    const mockSsh = createMockSsh({ "which tool": { code: 1 } })
    const mod = command.shell("install-tool", { check: "which tool" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("command.shell — name", () => {
  it("uses custom name when provided", () => {
    const mod = command.shell("echo hello", { name: "greet" })
    expect(mod.name).toBe("greet")
  })

  it("uses truncated command as default name", () => {
    const mod = command.shell("echo hello")
    expect(mod.name).toBe("command.shell: echo hello")
  })

  it("truncates long commands to 50 characters in default name", () => {
    const longCmd = "a".repeat(60)
    const mod = command.shell(longCmd)
    expect(mod.name).toBe(`command.shell: ${"a".repeat(50)}`)
  })
})
