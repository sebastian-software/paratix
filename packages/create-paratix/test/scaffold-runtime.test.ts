import { spawnSync } from "node:child_process"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { detectPackageManager, installDependencies } from "../src/scaffoldRuntime.js"

vi.mock("node:child_process", () => ({
  spawnSync: vi.fn(),
}))

const spawnSyncMock = vi.mocked(spawnSync)

// R-0000663: shorthand for the SpawnSyncReturns shape used by the mock —
// only the fields installDependencies inspects are populated.
function buildSpawnResult(overrides: Partial<ReturnType<typeof spawnSync>> = {}) {
  return {
    output: [null, null, null] as ReturnType<typeof spawnSync>["output"],
    pid: 0,
    signal: null,
    status: 0,
    stderr: Buffer.from(""),
    stdout: Buffer.from(""),
    ...overrides,
  }
}

const PNPM_INSTALL = { args: ["install"] as readonly string[], executable: "pnpm" }
const NPM_INSTALL = { args: ["install"] as readonly string[], executable: "npm" }

describe("scaffoldRuntime", () => {
  const originalUserAgent = process.env.npm_config_user_agent

  beforeEach(() => {
    spawnSyncMock.mockReset()
    vi.spyOn(console, "log").mockImplementation((...args) => {
      void args
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
    delete process.env.npm_config_user_agent
  })

  afterEach(() => {
    vi.restoreAllMocks()
    if (originalUserAgent === undefined) {
      delete process.env.npm_config_user_agent
    } else {
      process.env.npm_config_user_agent = originalUserAgent
    }
  })

  it.each([
    [
      "pnpm/10.30.3 npm/? node/v25.6.1 darwin arm64",
      { command: { args: ["install"], executable: "pnpm" }, name: "pnpm" },
    ],
    [
      "yarn/1.22.22 npm/? node/v25.6.1 darwin arm64",
      { command: { args: ["install"], executable: "yarn" }, name: "yarn" },
    ],
    [
      "bun/1.3.0 npm/? node/v25.6.1 darwin arm64",
      { command: { args: ["install"], executable: "bun" }, name: "bun" },
    ],
  ])("detects the package manager for user agent %s", (userAgent, expected) => {
    process.env.npm_config_user_agent = userAgent

    expect(detectPackageManager()).toStrictEqual(expected)
  })

  it("defaults to npm when no package-manager user agent is present", () => {
    expect(detectPackageManager()).toStrictEqual({
      command: { args: ["install"], executable: "npm" },
      name: "npm",
    })
  })

  // R-0000663: spawnSync must be invoked with the executable and its argv
  // array separated, and `shell: false` must be set so no `/bin/sh -c`
  // layer can re-parse either side. Future command construction therefore
  // cannot be re-routed through a shell injection.
  it("R-0000663: spawns the install command with shell: false and an argv array", () => {
    spawnSyncMock.mockReturnValue(buildSpawnResult())

    const result = installDependencies("/tmp/generated-project", {
      command: PNPM_INSTALL,
      name: "pnpm",
    })

    expect(result).toBe(true)
    expect(spawnSyncMock).toHaveBeenCalledWith("pnpm", ["install"], {
      cwd: "/tmp/generated-project",
      shell: false,
      stdio: "inherit",
      timeout: 120_000,
    })
    expect(console.log).toHaveBeenCalledWith("Installing dependencies with pnpm...")
  })

  it("returns false and prints the install error when spawnSync reports error", () => {
    spawnSyncMock.mockReturnValue(buildSpawnResult({ error: new Error("install failed") }))

    const result = installDependencies("/tmp/generated-project", {
      command: NPM_INSTALL,
      name: "npm",
    })

    expect(result).toBe(false)
    expect(console.error).toHaveBeenCalledWith("Failed to install dependencies: install failed")
    expect(console.error).toHaveBeenCalledWith("Run install manually.")
  })

  it("returns false and prints a timeout message when the install is terminated", () => {
    spawnSyncMock.mockReturnValue(buildSpawnResult({ signal: "SIGTERM", status: null }))

    const result = installDependencies("/tmp/generated-project", {
      command: PNPM_INSTALL,
      name: "pnpm",
    })

    expect(result).toBe(false)
    expect(console.error).toHaveBeenCalledWith("Installation timed out after 2 minutes.")
    expect(console.error).toHaveBeenCalledWith("Run install manually.")
  })

  it("returns false when the install command exits non-zero", () => {
    spawnSyncMock.mockReturnValue(buildSpawnResult({ status: 1 }))

    const result = installDependencies("/tmp/generated-project", {
      command: NPM_INSTALL,
      name: "npm",
    })

    expect(result).toBe(false)
    expect(console.error).toHaveBeenCalledWith(
      "Failed to install dependencies: npm exited with status 1"
    )
    expect(console.error).toHaveBeenCalledWith("Run install manually.")
  })
})
