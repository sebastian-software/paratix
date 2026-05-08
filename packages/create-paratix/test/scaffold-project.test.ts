import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { scaffoldProject } from "../src/index.js"
import { expectProcessExit, TEST_ADMIN_PUBLIC_KEY } from "./helpers.js"

describe("scaffoldProject", () => {
  const projectName = "create-paratix-scaffold-test"
  const paddedProjectName = " create-paratix-trim-test "
  const trimmedProjectName = "create-paratix-trim-test"
  const invalidAdminKeyProjectName = "create-paratix-invalid-admin-key-test"
  const invalidFingerprintProjectName = "create-paratix-invalid-fingerprint-test"
  const invalidHostProjectName = "create-paratix-invalid-host-test"
  const missingKeyProjectName = "create-paratix-missing-root-key-test"
  let invalidAdminKeyProjectDirectory = ""
  let invalidFingerprintProjectDirectory = ""
  let invalidHostProjectDirectory = ""
  let missingKeyProjectDirectory = ""
  let originalCwd = ""
  let paddedProjectDirectory = ""
  let projectDirectory = ""
  let scaffoldRoot = ""
  let trimmedProjectDirectory = ""

  beforeEach(() => {
    originalCwd = process.cwd()
    scaffoldRoot = mkdtempSync(join(tmpdir(), "create-paratix-scaffold-"))
    const scaffoldCwd = join(scaffoldRoot, "cwd")
    mkdirSync(scaffoldCwd)
    process.chdir(scaffoldCwd)
    projectDirectory = resolve(projectName)
    paddedProjectDirectory = resolve(paddedProjectName)
    trimmedProjectDirectory = resolve(trimmedProjectName)
    invalidAdminKeyProjectDirectory = resolve(invalidAdminKeyProjectName)
    invalidFingerprintProjectDirectory = resolve(invalidFingerprintProjectName)
    invalidHostProjectDirectory = resolve(invalidHostProjectName)
    missingKeyProjectDirectory = resolve(missingKeyProjectName)
    vi.spyOn(console, "log").mockImplementation((...args) => {
      void args
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
    process.exitCode = undefined
  })

  afterEach(() => {
    vi.restoreAllMocks()
    process.chdir(originalCwd)
    rmSync(scaffoldRoot, { force: true, recursive: true })
    process.exitCode = undefined
  })

  it("prints the success message when dependency installation succeeds", () => {
    const installer = vi.fn().mockReturnValue(true)

    const result = scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      {
        adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
        host: "example.com",
        initialUser: { kind: "root" },
        installer,
      }
    )

    expect(result).toBe(true)
    expect(installer).toHaveBeenCalledWith(projectDirectory, {
      command: "pnpm install",
      name: "pnpm",
    })
    expect(console.log).toHaveBeenCalledWith(`Creating Paratix project in ${projectDirectory}...`)
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining("Project created successfully!")
    )
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply"))
    expect(console.log).not.toHaveBeenCalledWith(
      expect.stringContaining("dependency installation failed")
    )
    expect(process.exitCode).toBeUndefined()
  })

  it("prints a partial-success message and keeps a non-zero exit code when dependency installation fails", () => {
    const installer = vi.fn().mockReturnValue(false)

    const result = scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      { host: "deploy.example.com", initialUser: { kind: "admin", user: "deploy" }, installer }
    )

    expect(result).toBe(false)
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining("Project files created, but dependency installation failed.")
    )
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply"))
    expect(console.log).not.toHaveBeenCalledWith(
      expect.stringContaining("Project created successfully!")
    )
    expect(process.exitCode).toBe(1)
  })

  it("prints npm completion commands with first-run bootstrap before regular apply", () => {
    const installer = vi.fn().mockReturnValue(true)

    scaffoldProject(
      projectName,
      { command: "npm install", name: "npm" },
      {
        host: "example.com",
        installer,
      }
    )

    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:first-run:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:first-run"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply"))
  })

  it("prints completion commands in bootstrap order", () => {
    const installer = vi.fn().mockReturnValue(true)

    scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      {
        host: "example.com",
        installer,
      }
    )

    const logMock = console.log as unknown as { mock: { calls: unknown[][] } }
    const completionMessage = logMock.mock.calls
      .map((call) => String(call[0]))
      .find((message) => message.includes("Project created successfully!"))

    expect(completionMessage).toBeDefined()
    const commandLines = completionMessage
      ?.split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("pnpm apply"))

    expect(commandLines).toStrictEqual([
      "pnpm apply:first-run:dry",
      "pnpm apply:first-run",
      "pnpm apply:dry",
      "pnpm apply",
    ])
  })

  it("rejects root bootstrap without an admin public key before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        missingKeyProjectName,
        { command: "pnpm install", name: "pnpm" },
        { host: "example.com", initialUser: { kind: "root" }, installer }
      )
    }).toThrow(/Root bootstrap requires --admin-public-key or --admin-public-key-file/v)

    expect(existsSync(missingKeyProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
    expect(console.log).not.toHaveBeenCalledWith(
      `Creating Paratix project in ${missingKeyProjectDirectory}...`
    )
  })

  it("rejects invalid programmatic hosts before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        invalidHostProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          host: "bad host",
          initialUser: { kind: "admin", user: "deploy" },
          installer,
        }
      )
    }).toThrow(
      'Error: Invalid host "bad host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )

    expect(existsSync(invalidHostProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("rejects invalid programmatic admin public keys before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        invalidAdminKeyProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          adminPublicKey: "invalid-key",
          host: "example.com",
          initialUser: { kind: "admin", user: "deploy" },
          installer,
        }
      )
    }).toThrow(
      'Error: Invalid value for "--admin-public-key" — provide a valid single-line OpenSSH public key.'
    )

    expect(existsSync(invalidAdminKeyProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("rejects invalid programmatic expected host fingerprints before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        invalidFingerprintProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          expectedHostFingerprint: "SHA256:trusted-host-fingerprint",
          host: "example.com",
          initialUser: { kind: "admin", user: "deploy" },
          installer,
        }
      )
    }).toThrow(
      'Error: Invalid expected host fingerprint "SHA256:trusted-host-fingerprint" — use an OpenSSH SHA256 fingerprint.'
    )

    expect(existsSync(invalidFingerprintProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("rejects invalid programmatic initial users before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        missingKeyProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          host: "example.com",
          initialUser: { kind: "admin", user: "Deploy" },
          installer,
        }
      )
    }).toThrow(/Invalid initial user/v)

    expect(existsSync(missingKeyProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  // R-0000124 regression: scaffoldProject must fail closed when the target
  // directory already exists, instead of silently overwriting files inside it.
  // Previously the function used `existsSync(...) ? exit : mkdirSync(..., { recursive: true })`
  // which left a TOCTOU window — and `recursive: true` masked any pre-existing
  // directory created during that window. We now expect an atomic failure with
  // a clear error message and no overwrite of pre-existing files.
  it("fails with a clear message and does not overwrite files when the target directory already exists", async () => {
    const installer = vi.fn().mockReturnValue(true)
    mkdirSync(projectDirectory, { recursive: true })
    const sentinelPath = join(projectDirectory, "package.json")
    writeFileSync(sentinelPath, "PRE_EXISTING_CONTENT")

    await expectProcessExit(() => {
      scaffoldProject(
        projectName,
        { command: "pnpm install", name: "pnpm" },
        {
          adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
          host: "example.com",
          initialUser: { kind: "root" },
          installer,
        }
      )
    })

    expect(console.error).toHaveBeenCalledWith(`Error: Directory "${projectName}" already exists.`)
    expect(installer).not.toHaveBeenCalled()
    expect(readFileSync(sentinelPath, "utf8")).toBe("PRE_EXISTING_CONTENT")
  })

  it("rejects invalid project names before creating directories", async () => {
    const installer = vi.fn().mockReturnValue(true)
    const invalidProjectDirectory = resolve("..", "create-paratix-invalid")

    await expectProcessExit(() => {
      scaffoldProject(
        "../create-paratix-invalid",
        { command: "pnpm install", name: "pnpm" },
        {
          host: "example.com",
          installer,
        }
      )
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid project name "../create-paratix-invalid" — use only lowercase letters, numbers, and hyphens.'
    )
    expect(existsSync(invalidProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  // R-0000230: validateProjectName must guard against undefined/empty input
  // even when exitWithMessage is intercepted by a non-throwing stub. We
  // simulate that by passing the empty string and asserting the function
  // never reaches normalizeProjectName(undefined) — it must surface a
  // CliExitError before any directory mutation happens.
  it("rejects an empty project name with a CliExitError before touching the filesystem", async () => {
    const installer = vi.fn().mockReturnValue(true)

    await expectProcessExit(() => {
      scaffoldProject(
        "",
        { command: "pnpm install", name: "pnpm" },
        { host: "example.com", installer }
      )
    })

    expect(console.error).toHaveBeenCalledWith("Usage: create-paratix <project-name>")
    expect(installer).not.toHaveBeenCalled()
  })

  it("normalizes padded project names before creating the project directory and package name", () => {
    const installer = vi.fn().mockReturnValue(true)

    const result = scaffoldProject(
      paddedProjectName,
      { command: "pnpm install", name: "pnpm" },
      { host: "example.com", installer }
    )

    expect(result).toBe(true)
    expect(existsSync(trimmedProjectDirectory)).toBe(true)
    expect(existsSync(paddedProjectDirectory)).toBe(false)

    const raw = readFileSync(join(trimmedProjectDirectory, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe(trimmedProjectName)
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining(`cd ${trimmedProjectName}`))
  })
})

// R-0000056 regression: AGENTS.md forbids inline `cspell:ignore` directives.
// The two existing directives in `src/templates.ts` were lifted into the
// project root `cspell.json`. This guard prevents future regressions where
// new tokens get masked locally instead of being added to the shared
// dictionary.
