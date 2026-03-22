import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  isDirectExecution,
  isValidInitialUserName,
  isValidProjectName,
  normalizeProjectName,
  parseCliArguments,
  parseInitialUserConfig,
  promptForInitialUserConfig,
  scaffoldProject,
  writeProjectFiles,
} from "../src/index.js"

async function expectProcessExit(
  callback: () => Promise<void> | void,
  expectedCode = 1
): Promise<void> {
  const exitError = new Error(`process.exit:${expectedCode}`)
  const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw code === expectedCode ? exitError : new Error(`process.exit:${String(code)}`)
  }) as typeof process.exit)

  await expect(Promise.resolve().then(callback)).rejects.toThrow(exitError.message)
  expect(exitSpy).toHaveBeenCalledWith(expectedCode)
}

describe("isValidProjectName", () => {
  // These tests document that invalid project names must be rejected.
  // Currently no validation exists in main() beyond a falsy-check, so
  // isValidProjectName is not yet exported. All tests in this block will
  // fail until the validation function is implemented and exported.

  it("accepts a simple lowercase name", () => {
    expect(isValidProjectName("my-project")).toBe(true)
  })

  it("accepts a name with numbers and hyphens", () => {
    expect(isValidProjectName("project-42")).toBe(true)
  })

  it("rejects a name containing spaces", () => {
    // Spaces are invalid in directory names used as npm package names and
    // would silently produce a broken package.json "name" field.
    expect(isValidProjectName("my project")).toBe(false)
  })

  it("rejects a name containing special characters", () => {
    // Characters like @ and ! are invalid in npm package names (unless
    // scoped with a leading @) and as unquoted directory names.
    expect(isValidProjectName("my@project!")).toBe(false)
  })

  it("rejects path traversal sequences", () => {
    // "../../etc" would resolve to an arbitrary directory outside the
    // current working directory, allowing an attacker to overwrite files.
    expect(isValidProjectName("../../etc")).toBe(false)
  })

  it("rejects names containing uppercase letters", () => {
    // npm package names must be lowercase. An uppercase name would be
    // written into package.json and cause npm publish/install errors.
    expect(isValidProjectName("MyProject")).toBe(false)
  })

  it("rejects a string that is blank after trimming", () => {
    // A name consisting only of whitespace passes the current falsy-check
    // in main() and would create a directory with a whitespace name.
    expect(isValidProjectName("   ")).toBe(false)
  })
})

describe("normalizeProjectName", () => {
  it("trims padded input before scaffolding uses it", () => {
    expect(normalizeProjectName(" my-server ")).toBe("my-server")
  })
})

describe("isDirectExecution (process.argv[1] regression)", () => {
  it("returns false when argv1 is null without throwing", () => {
    // Regression: previously index.ts called process.argv[1].replaceAll() without a null-check,
    // causing a TypeError when argv[1] is undefined (e.g. in a REPL or certain test runners).
    // null and undefined are both guarded by the != null check.
    expect(isDirectExecution("file:///some/module.js", null)).toBe(false)
  })

  it("returns false when the module URL does not match argv1", () => {
    expect(isDirectExecution("file:///project/src/index.js", "/other/script.js")).toBe(false)
  })

  it("returns true when the module URL ends with the normalised argv1 path", () => {
    expect(isDirectExecution("file:///project/src/index.js", "/project/src/index.js")).toBe(true)
  })

  it("normalises Windows backslashes in argv1 before comparing", () => {
    expect(isDirectExecution("file:///project/src/index.js", "\\project\\src\\index.js")).toBe(true)
  })
})

describe("parseCliArguments", () => {
  it("uses interactive initial-user selection by default", () => {
    expect(parseCliArguments(["my-server"])).toStrictEqual({
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit root initial user", () => {
    expect(parseCliArguments(["my-server", "--initial-user", "root"])).toStrictEqual({
      initialUser: "root",
      projectName: "my-server",
    })
  })

  it("supports an explicit admin initial user", () => {
    expect(parseCliArguments(["my-server", "--initial-user", "deploy"])).toStrictEqual({
      initialUser: "deploy",
      projectName: "my-server",
    })
  })

  it("rejects the removed bootstrap-root flag with a migration hint", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--bootstrap-root"])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: "--bootstrap-root" was removed. Use "--initial-user root" instead.'
    )
  })
})

describe("initial user parsing", () => {
  it("accepts valid lowercase Linux usernames", () => {
    expect(isValidInitialUserName("deploy")).toBe(true)
    expect(isValidInitialUserName("admin_user")).toBe(true)
    expect(isValidInitialUserName("root")).toBe(true)
  })

  it("rejects invalid initial usernames", () => {
    expect(isValidInitialUserName("Admin")).toBe(false)
    expect(isValidInitialUserName("bad name")).toBe(false)
    expect(isValidInitialUserName("")).toBe(false)
  })

  it("maps root to the explicit root config", () => {
    expect(parseInitialUserConfig(" root ")).toStrictEqual({ kind: "root" })
  })

  it("maps other valid users to the admin config", () => {
    expect(parseInitialUserConfig(" deploy ")).toStrictEqual({ kind: "admin", user: "deploy" })
  })
})

describe("promptForInitialUserConfig", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("supports the interactive root flow", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("root")

    await expect(promptForInitialUserConfig(prompt)).resolves.toStrictEqual({ kind: "root" })
    expect(prompt).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenCalledWith("Initial SSH user? [root/admin]: ")
  })

  it("supports the interactive admin flow with a concrete username", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("admin").mockResolvedValueOnce("deploy")

    await expect(promptForInitialUserConfig(prompt)).resolves.toStrictEqual({
      kind: "admin",
      user: "deploy",
    })
    expect(prompt).toHaveBeenNthCalledWith(1, "Initial SSH user? [root/admin]: ")
    expect(prompt).toHaveBeenNthCalledWith(2, "Admin username: ")
  })
})

const TEST_DIR = resolve("/tmp/create-paratix-test")

describe("writeProjectFiles", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true })
  })

  afterEach(() => {
    rmSync(TEST_DIR, { force: true, recursive: true })
  })

  it("creates a package.json in the target directory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "package.json"))).toBe(true)
  })

  it("generated package.json contains an engines field with node >=24.0.0", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      engines: { node: ">=24.0.0" },
    })
  })

  it("generated package.json has type module", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({ type: "module" })
  })

  it("generated package.json contains the paratix dependency", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      dependencies: { paratix: expect.stringMatching(/^\^/v) },
    })
  })

  it("generated package.json includes tsx so apply scripts can run server.ts immediately", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      devDependencies: { tsx: expect.stringMatching(/^\^/v) },
      scripts: {
        apply: "paratix apply server.ts",
        "apply:dry": "paratix apply server.ts --dry-run",
      },
    })
  })

  it("derives package.json name correctly from a Windows-style absolute path", () => {
    const windowsPath = join(TEST_DIR, "windows", "C:\\tmp\\windows-project")
    writeProjectFiles(windowsPath)

    const raw = readFileSync(join(windowsPath, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe("windows-project")
  })

  it("derives package.json name correctly from a backslash-separated relative path", () => {
    const windowsRelativePath = join(TEST_DIR, "windows", "tmp\\nested\\mixed-project")
    writeProjectFiles(windowsRelativePath)

    const raw = readFileSync(join(windowsRelativePath, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe("mixed-project")
  })

  it("creates a server.ts file", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(true)
  })

  it("generated server.ts uses pkg.upgrade and pkg.installed (not apt.*)", () => {
    // Regression: SERVER_TEMPLATE previously used the deprecated apt module
    // (apt.upgrade / apt.installed). After Plan-0013 refactoring the correct
    // module is `package as pkg` with pkg.upgrade / pkg.installed.
    // TypeScript cannot catch this because the template is a plain string.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("pkg.upgrade(")
    expect(content).toContain("pkg.installed(")
    expect(content).not.toContain("apt.upgrade(")
    expect(content).not.toContain("apt.installed(")
  })

  it("generated server.ts imports package as pkg from paratix/modules", () => {
    // Regression: import must use `package as pkg`, not the old `apt` import.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("package as pkg")
    expect(content).not.toMatch(/\bapt\b/v)
  })

  it("generated server.ts uses the hardened admin mode by default", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "admin";')
    expect(content).toContain("user: adminUser")
    expect(content).toContain("ssh.authorizedKeys(adminUser, adminPublicKey)")
    expect(content).toContain('PermitRootLogin: "no"')
    expect(content).not.toContain('user: "root"')
    expect(content).not.toContain('PermitRootLogin: "prohibit-password"')
    expect(content).toContain('PasswordAuthentication: "no"')
  })

  it("generated server.ts uses an explicitly provided admin username", () => {
    writeProjectFiles(TEST_DIR, { initialUser: { kind: "admin", user: "deploy" } })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "deploy";')
    expect(content).toContain("user: adminUser")
    expect(content).toContain('recipe("admin-access"')
    expect(content).not.toContain('user: "root"')
  })

  it("generated server.ts includes an explicit host-key bootstrap for the first apply:dry", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('strictHostKeyChecking: "accept-new"')
    expect(content).toContain("Initial host-key bootstrap for fresh servers:")
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).toContain(
      'expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY"'
    )
  })

  it("generated server.ts keeps the ~/.ssh privateKey default that Paratix expands at runtime", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('privateKey: "~/.ssh/id_ed25519"')
    expect(content).toContain('"~" is expanded by Paratix')
  })

  it("generated server.ts does not leave SSH port 22 open in the final firewall default", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('ufw.rule("allow", [2222, 80, 443])')
    expect(content).not.toContain('ufw.rule("allow", [22, 2222, 80, 443])')
  })

  it("generated server.ts opens firewall port 2222 before applying sshd.port(2222)", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firewallIndex = content.indexOf('recipe("firewall"')
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening"')

    expect(firewallIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(firewallIndex).toBeLessThan(sshHardeningIndex)
  })

  it("generated server.ts supports an explicit root bootstrap transition mode", () => {
    writeProjectFiles(TEST_DIR, { initialUser: { kind: "root" } })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('user: "root"')
    expect(content).toContain('const adminUser = "admin";')
    expect(content).toContain("Transitional bootstrap mode:")
    expect(content).toContain('PermitRootLogin: "prohibit-password"')
    expect(content).not.toContain('PermitRootLogin: "no"')
    expect(content).toContain('strictHostKeyChecking: "accept-new"')
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).not.toContain("--bootstrap-root")
  })

  it("generated root-bootstrap server.ts also opens firewall port 2222 before ssh-hardening-transition", () => {
    writeProjectFiles(TEST_DIR, { initialUser: { kind: "root" } })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firewallIndex = content.indexOf('recipe("firewall"')
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening-transition"')

    expect(firewallIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(firewallIndex).toBeLessThan(sshHardeningIndex)
  })

  it("creates a files subdirectory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "files"))).toBe(true)
  })
})

describe("scaffoldProject", () => {
  const projectName = "create-paratix-scaffold-test"
  const projectDirectory = resolve(projectName)
  const paddedProjectName = " create-paratix-trim-test "
  const trimmedProjectName = "create-paratix-trim-test"
  const paddedProjectDirectory = resolve(paddedProjectName)
  const trimmedProjectDirectory = resolve(trimmedProjectName)

  beforeEach(() => {
    rmSync(projectDirectory, { force: true, recursive: true })
    rmSync(paddedProjectDirectory, { force: true, recursive: true })
    rmSync(trimmedProjectDirectory, { force: true, recursive: true })
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
    rmSync(projectDirectory, { force: true, recursive: true })
    rmSync(paddedProjectDirectory, { force: true, recursive: true })
    rmSync(trimmedProjectDirectory, { force: true, recursive: true })
    process.exitCode = undefined
  })

  it("prints the success message when dependency installation succeeds", () => {
    const installer = vi.fn().mockReturnValue(true)

    const result = scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      { initialUser: { kind: "root" }, installer }
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
      { initialUser: { kind: "admin", user: "deploy" }, installer }
    )

    expect(result).toBe(false)
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining("Project files created, but dependency installation failed.")
    )
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply"))
    expect(console.log).not.toHaveBeenCalledWith(
      expect.stringContaining("Project created successfully!")
    )
    expect(process.exitCode).toBe(1)
  })

  it("prints npm completion commands with apply:dry before apply", () => {
    const installer = vi.fn().mockReturnValue(true)

    scaffoldProject(projectName, { command: "npm install", name: "npm" }, { installer })

    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply"))
  })

  it("normalizes padded project names before creating the project directory and package name", () => {
    const installer = vi.fn().mockReturnValue(true)

    const result = scaffoldProject(
      paddedProjectName,
      { command: "pnpm install", name: "pnpm" },
      { installer }
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
