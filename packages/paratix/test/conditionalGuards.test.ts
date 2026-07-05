import { beforeEach, describe, expect, it, vi } from "vitest"

import {
  createCommandGuard,
  createFilesystemGuard,
  createPackageGuard,
} from "../src/conditionalGuards.js"
import { createNullPrototypeEnvironment } from "../src/environment.js"
import { createMockSsh } from "./helpers/mockSsh.js"

vi.mock("../src/modules/package.js", () => ({
  detectPackageManager: vi.fn(),
  isPackageInstalled: vi.fn(),
}))

const packageModule = await import("../src/modules/package.js")
const detectPackageManager = vi.mocked(packageModule.detectPackageManager)
const isPackageInstalled = vi.mocked(packageModule.isPackageInstalled)

const env = createNullPrototypeEnvironment()

const TEST_FLAGS = [
  { flag: "-d", type: "path" },
  { flag: "-f", type: "file" },
  { flag: "-L", type: "symlink" },
  { flag: "-S", type: "socket" },
] as const

describe("createFilesystemGuard", () => {
  it("derives the module name from the test flag and inversion", () => {
    for (const { flag, type } of TEST_FLAGS) {
      expect(
        createFilesystemGuard({ invert: false, modules: [], path: "/srv/app", testFlag: flag }).name
      ).toBe(`when.${type}Exists: /srv/app`)
      expect(
        createFilesystemGuard({ invert: true, modules: [], path: "/srv/app", testFlag: flag }).name
      ).toBe(`when.${type}Missing: /srv/app`)
    }
  })

  it("skips when the connection is unavailable", async () => {
    const guard = createFilesystemGuard({
      invert: false,
      modules: [],
      path: "/srv/app",
      testFlag: "-f",
    })
    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await guard.apply(null, env)
    expect(result.status).toBe("skipped")
  })

  it("runs the children when the path exists and is not inverted", async () => {
    const ssh = createMockSsh({ "test -f '/srv/app'": { code: 0 } })
    const guard = createFilesystemGuard({
      invert: false,
      modules: [],
      path: "/srv/app",
      testFlag: "-f",
    })
    const result = await guard.apply(ssh, env)
    expect(result.status).not.toBe("skipped")
    expect(ssh.calls).toContain("test -f '/srv/app'")
  })

  it("skips when the path exists but the guard is inverted", async () => {
    const ssh = createMockSsh({ "test -f '/srv/app'": { code: 0 } })
    const guard = createFilesystemGuard({
      invert: true,
      modules: [],
      path: "/srv/app",
      testFlag: "-f",
    })
    const result = await guard.apply(ssh, env)
    expect(result.status).toBe("skipped")
  })

  it("runs the children when an inverted guard finds the path missing", async () => {
    const ssh = createMockSsh({ "test -d '/data'": { code: 1 } })
    const guard = createFilesystemGuard({
      invert: true,
      modules: [],
      path: "/data",
      testFlag: "-d",
    })
    const result = await guard.apply(ssh, env)
    expect(result.status).not.toBe("skipped")
  })
})

describe("createCommandGuard", () => {
  it("names the guard after the command and inversion", () => {
    expect(createCommandGuard("git", false, []).name).toBe("when.commandExists: git")
    expect(createCommandGuard("git", true, []).name).toBe("when.commandMissing: git")
  })

  it("skips when the connection is unavailable", async () => {
    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await createCommandGuard("git", false, []).apply(null, env)
    expect(result.status).toBe("skipped")
  })

  it("runs the children when the command is present", async () => {
    const ssh = createMockSsh({ "command -v 'git' >/dev/null 2>&1": { code: 0 } })
    const result = await createCommandGuard("git", false, []).apply(ssh, env)
    expect(result.status).not.toBe("skipped")
    expect(ssh.calls).toContain("command -v 'git' >/dev/null 2>&1")
  })

  it("runs the children when an inverted guard finds the command missing", async () => {
    const ssh = createMockSsh({ "command -v 'git' >/dev/null 2>&1": { code: 1 } })
    const result = await createCommandGuard("git", true, []).apply(ssh, env)
    expect(result.status).not.toBe("skipped")
  })
})

describe("createPackageGuard", () => {
  beforeEach(() => {
    detectPackageManager.mockReset()
    isPackageInstalled.mockReset()
  })

  it("names the guard after the package and inversion", () => {
    expect(createPackageGuard("nginx", false, []).name).toBe("when.packageInstalled: nginx")
    expect(createPackageGuard("nginx", true, []).name).toBe("when.packageAbsent: nginx")
  })

  it("skips when the connection is unavailable", async () => {
    // eslint-disable-next-line prefer-spread -- Module.apply is the module lifecycle hook, not Function.prototype.apply
    const result = await createPackageGuard("nginx", false, []).apply(null, env)
    expect(result.status).toBe("skipped")
  })

  it("skips when no package manager can be detected", async () => {
    detectPackageManager.mockResolvedValue(null)
    const ssh = createMockSsh()
    const result = await createPackageGuard("nginx", false, []).apply(ssh, env)
    expect(result.status).toBe("skipped")
    expect(isPackageInstalled).not.toHaveBeenCalled()
  })

  it("runs the children when the package is installed", async () => {
    detectPackageManager.mockResolvedValue("apt")
    isPackageInstalled.mockResolvedValue(true)
    const ssh = createMockSsh()
    const result = await createPackageGuard("nginx", false, []).apply(ssh, env)
    expect(result.status).not.toBe("skipped")
    expect(isPackageInstalled).toHaveBeenCalledWith(ssh, "apt", "nginx")
  })

  it("runs the children when an inverted guard finds the package absent", async () => {
    detectPackageManager.mockResolvedValue("apt")
    isPackageInstalled.mockResolvedValue(false)
    const ssh = createMockSsh()
    const result = await createPackageGuard("nginx", true, []).apply(ssh, env)
    expect(result.status).not.toBe("skipped")
  })

  it("skips when the package is installed but the guard is inverted", async () => {
    detectPackageManager.mockResolvedValue("apt")
    isPackageInstalled.mockResolvedValue(true)
    const ssh = createMockSsh()
    const result = await createPackageGuard("nginx", true, []).apply(ssh, env)
    expect(result.status).toBe("skipped")
  })
})
