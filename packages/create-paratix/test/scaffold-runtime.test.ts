import { execSync } from "node:child_process"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { detectPackageManager, installDependencies } from "../src/scaffoldRuntime.js"

vi.mock("node:child_process", () => ({
  execSync: vi.fn(),
}))

const execSyncMock = vi.mocked(execSync)

describe("scaffoldRuntime", () => {
  const originalUserAgent = process.env.npm_config_user_agent

  beforeEach(() => {
    execSyncMock.mockReset()
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
    ["pnpm/10.30.3 npm/? node/v25.6.1 darwin arm64", { command: "pnpm install", name: "pnpm" }],
    ["yarn/1.22.22 npm/? node/v25.6.1 darwin arm64", { command: "yarn install", name: "yarn" }],
    ["bun/1.3.0 npm/? node/v25.6.1 darwin arm64", { command: "bun install", name: "bun" }],
    [undefined, { command: "npm install", name: "npm" }],
  ])("detects the package manager for user agent %s", (userAgent, expected) => {
    if (userAgent !== undefined) process.env.npm_config_user_agent = userAgent

    expect(detectPackageManager()).toStrictEqual(expected)
  })

  it("runs the selected install command in the generated project directory", () => {
    execSyncMock.mockReturnValue(Buffer.from(""))

    const result = installDependencies("/tmp/generated-project", {
      command: "pnpm install",
      name: "pnpm",
    })

    expect(result).toBe(true)
    expect(execSyncMock).toHaveBeenCalledWith("pnpm install", {
      cwd: "/tmp/generated-project",
      stdio: "inherit",
      timeout: 120_000,
    })
    expect(console.log).toHaveBeenCalledWith("Installing dependencies with pnpm...")
  })

  it("returns false and prints the install error when the command fails", () => {
    execSyncMock.mockImplementation(() => {
      throw new Error("install failed")
    })

    const result = installDependencies("/tmp/generated-project", {
      command: "npm install",
      name: "npm",
    })

    expect(result).toBe(false)
    expect(console.error).toHaveBeenCalledWith("Failed to install dependencies: install failed")
    expect(console.error).toHaveBeenCalledWith("Run install manually.")
  })

  it("returns false and prints a timeout message when the install is terminated", () => {
    execSyncMock.mockImplementation(() => {
      throw Object.assign(new Error("spawn killed"), { signal: "SIGTERM" })
    })

    const result = installDependencies("/tmp/generated-project", {
      command: "pnpm install",
      name: "pnpm",
    })

    expect(result).toBe(false)
    expect(console.error).toHaveBeenCalledWith("Installation timed out after 2 minutes.")
    expect(console.error).toHaveBeenCalledWith("Run install manually.")
  })
})
