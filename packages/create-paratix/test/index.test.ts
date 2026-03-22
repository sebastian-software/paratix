import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  isDirectExecution,
  isValidHost,
  isValidInitialUserName,
  isValidProjectName,
  normalizeHost,
  normalizeProjectName,
  parseCliArguments,
  parseInitialUserConfig,
  promptForAdminPublicKey,
  promptForHost,
  promptForInitialUserConfig,
  scaffoldProject,
  validateHost,
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
      host: undefined,
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit host value", () => {
    expect(parseCliArguments(["my-server", "--host", "example.com"])).toStrictEqual({
      host: "example.com",
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit root initial user", () => {
    expect(parseCliArguments(["my-server", "--initial-user", "root"])).toStrictEqual({
      host: undefined,
      initialUser: "root",
      projectName: "my-server",
    })
  })

  it("supports an explicit admin initial user", () => {
    expect(parseCliArguments(["my-server", "--initial-user", "deploy"])).toStrictEqual({
      host: undefined,
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

describe("host parsing", () => {
  it("trims padded hosts", () => {
    expect(normalizeHost(" example.com ")).toBe("example.com")
  })

  it("accepts a domain, IPv4, and IPv6 literal", () => {
    expect(isValidHost("example.com")).toBe(true)
    expect(isValidHost("203.0.113.10")).toBe(true)
    expect(isValidHost("2001:db8::10")).toBe(true)
  })

  it("rejects empty or whitespace-containing hosts", () => {
    expect(isValidHost("")).toBe(false)
    expect(isValidHost("bad host")).toBe(false)
  })

  it("validates a trimmed host", () => {
    expect(validateHost(" example.com ")).toBe("example.com")
  })

  it("exits for invalid hosts", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      validateHost("bad host")
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid host "bad host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )
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
    const prompt = vi.fn()
    const select = vi.fn().mockResolvedValueOnce("root")

    await expect(promptForInitialUserConfig(prompt, select)).resolves.toStrictEqual({
      kind: "root",
    })
    expect(prompt).not.toHaveBeenCalled()
    expect(select).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenCalledWith(
      "Which SSH user already works for the first connection to this server?",
      [
        {
          description:
            "Fresh server with SSH access only as root. Paratix bootstraps a dedicated admin user first.",
          label: "Root user",
          value: "root",
        },
        {
          description:
            "A named admin user already exists. Paratix connects directly as that user and skips root bootstrap.",
          label: "Admin user",
          value: "admin",
        },
      ]
    )
  })

  it("supports the interactive admin flow with a concrete username", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("deploy")
    const select = vi.fn().mockResolvedValueOnce("admin")

    await expect(promptForInitialUserConfig(prompt, select)).resolves.toStrictEqual({
      kind: "admin",
      user: "deploy",
    })
    expect(select).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenNthCalledWith(1, "Admin username: ")
  })
})

describe("promptForHost", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("accepts a valid interactive host", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("example.com")

    await expect(promptForHost(prompt)).resolves.toBe("example.com")
    expect(prompt).toHaveBeenCalledWith("Server host (domain or IP): ")
  })

  it("retries until a valid host is entered", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("bad host").mockResolvedValueOnce("203.0.113.10")

    await expect(promptForHost(prompt)).resolves.toBe("203.0.113.10")
    expect(console.error).toHaveBeenCalledWith(
      "Error: Please enter a domain name, IPv4, or IPv6 address without spaces."
    )
  })
})

describe("promptForAdminPublicKey", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("keeps the placeholder when the user declines local key reuse", async () => {
    const select = vi.fn().mockResolvedValueOnce("placeholder")

    await expect(promptForAdminPublicKey(select)).resolves.toBeUndefined()
    expect(select).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenNthCalledWith(
      1,
      "How should create-paratix configure the admin SSH public key?",
      [
        {
          description:
            "Read a public key from ~/.ssh and embed it directly into server.ts for the bootstrap admin user.",
          label: "Use local public key",
          value: "local",
        },
        {
          description:
            "Keep the placeholder in server.ts and paste your public key manually before the first apply.",
          label: "Keep placeholder",
          value: "placeholder",
        },
      ]
    )
  })

  it("selects from multiple local public keys via the cursor flow", async () => {
    const select = vi
      .fn()
      .mockResolvedValueOnce("local")
      .mockResolvedValueOnce("/tmp/id_ed25519.pub")

    await expect(
      promptForAdminPublicKey(select, [
        {
          key: "ssh-rsa AAAA example-rsa",
          label: "id_rsa.pub",
          path: "/tmp/id_rsa.pub",
        },
        {
          key: "ssh-ed25519 AAAA example-ed25519",
          label: "id_ed25519.pub",
          path: "/tmp/id_ed25519.pub",
        },
      ])
    ).resolves.toBe("ssh-ed25519 AAAA example-ed25519")
    expect(select).toHaveBeenCalledTimes(2)
  })

  it("falls back to the placeholder when no readable local public keys exist", async () => {
    const select = vi.fn().mockResolvedValueOnce("local")

    await expect(promptForAdminPublicKey(select, [])).resolves.toBeUndefined()
    expect(console.error).toHaveBeenCalledWith(
      "No readable public keys were found in ~/.ssh. Keeping the placeholder in server.ts."
    )
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

  it("generated server.ts uses packages.upgrade and packages.installed (not apt.*)", () => {
    // Regression: SERVER_TEMPLATE previously used the deprecated apt module
    // (apt.upgrade / apt.installed). After Plan-0013 refactoring the correct
    // module is `package as packages` with packages.upgrade / packages.installed.
    // TypeScript cannot catch this because the template is a plain string.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("packages.upgrade(")
    expect(content).toContain("packages.installed(")
    expect(content).not.toContain("apt.upgrade(")
    expect(content).not.toContain("apt.installed(")
  })

  it("generated server.ts imports package as packages from paratix/modules", () => {
    // Regression: import must use `package as packages`, not the old `apt` import.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("package as packages")
    expect(content).not.toMatch(/\bapt\b/v)
  })

  it("generated server.ts uses the hardened admin mode by default", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "admin";')
    expect(content).toContain(
      'const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY";'
    )
    expect(content).toContain('const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";')
    expect(content).toContain('host: "1.2.3.4"')
    expect(content).toContain("user: adminUser")
    expect(content).toContain("ssh.authorizedKeys(adminUser, adminPublicKey)")
    expect(content).toContain('PasswordAuthentication: "no"')
    expect(content).toContain('PermitRootLogin: "no"')
    expect(content).not.toContain('user: "root"')
    expect(content).not.toContain('PermitRootLogin: "prohibit-password"')
  })

  it("generated server.ts uses an explicitly provided admin username", () => {
    writeProjectFiles(TEST_DIR, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "deploy";')
    expect(content).toContain('host: "deploy.example.com"')
    expect(content).toContain("user: adminUser")
    expect(content).toContain('recipe("admin-access"')
    expect(content).not.toContain('user: "root"')
  })

  it("generated server.ts embeds a selected local public key directly", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBExample generated@test",
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(
      'const adminPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBExample generated@test";'
    )
    expect(content).not.toContain("REPLACE_ME_WITH_YOUR_PUBLIC_KEY")
  })

  it("generated server.ts includes an explicit host-key bootstrap for the first apply:dry", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const strictHostKeyChecking = FIRST_RUN ? "accept-new" : "yes";')
    expect(content).toContain('pass "paratix apply ... --first-run" for the bootstrap run')
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

  it("generated server.ts gates firewall and ssh ports behind FIRST_RUN", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";')
    expect(content).toContain("const sshPorts = FIRST_RUN ? [22] : [2222];")
    expect(content).toContain(
      "const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443];"
    )
    expect(content).toContain("ports: sshPorts")
    expect(content).toContain('ufw.rule("allow", firewallTcpPorts)')
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
    writeProjectFiles(TEST_DIR, { host: "203.0.113.10", initialUser: { kind: "root" } })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('host: "203.0.113.10"')
    expect(content).toContain('user: "root"')
    expect(content).toContain('const adminUser = "admin";')
    expect(content).toContain('const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";')
    expect(content).toContain("Transitional bootstrap mode:")
    expect(content).toContain('PasswordAuthentication: "no"')
    expect(content).toContain('PermitRootLogin: "prohibit-password"')
    expect(content).not.toContain('PermitRootLogin: "no"')
    expect(content).toContain('const strictHostKeyChecking = FIRST_RUN ? "accept-new" : "yes";')
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).not.toContain("--bootstrap-root")
  })

  it("generated server.ts exposes FIRST_RUN through env for template logic and operator visibility", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("env: {")
    expect(content).toContain("FIRST_RUN,")
    expect(content).toContain("SSH_PORT: 2222,")
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
      { host: "example.com", initialUser: { kind: "root" }, installer }
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
      { host: "deploy.example.com", initialUser: { kind: "admin", user: "deploy" }, installer }
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

    scaffoldProject(
      projectName,
      { command: "npm install", name: "npm" },
      {
        host: "example.com",
        installer,
      }
    )

    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply"))
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
