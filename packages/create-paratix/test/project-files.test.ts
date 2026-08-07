import { spawnSync } from "node:child_process"
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { afterEach, beforeEach, describe, expect, it } from "vitest"

import { deriveParatixDependencyRange, writeProjectFiles } from "../src/index.js"
import { createServerTemplate } from "../src/serverTemplate.js"
import {
  AUTO_UPGRADES_20_TEMPLATE,
  createAdminNopasswdSudoersContent,
  UNATTENDED_UPGRADES_50_TEMPLATE,
} from "../src/templates.js"
import {
  readCreateParatixPackageVersion,
  TEST_ADMIN_PUBLIC_KEY,
  TEST_HOST_FINGERPRINT,
} from "./helpers.js"

let TEST_DIR = ""

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)))
const paratixIndexPath = resolve(
  fileURLToPath(new URL("../../paratix/src/index.ts", import.meta.url))
)
const paratixModulesPath = resolve(
  fileURLToPath(new URL("../../paratix/src/modules/index.ts", import.meta.url))
)
const paratixCliPath = resolve(fileURLToPath(new URL("../../paratix/src/cli.ts", import.meta.url)))
// The workspace aliases `typescript` to @typescript/typescript6, which ships
// its binary as `tsc6` so it does not collide with the TypeScript 7 `tsc`.
// This check deliberately stays on the 6.x compiler: a scaffolded project
// pins typescript ^5.9, and the typecheck config below relies on `baseUrl`,
// which TypeScript 7 no longer supports.
const tscBinaryPath = resolve(
  fileURLToPath(new URL("../../../node_modules/typescript/bin/tsc6", import.meta.url))
)
const eslintBinaryPath = resolve(
  fileURLToPath(new URL("../../../node_modules/eslint/bin/eslint.js", import.meta.url))
)

function linkGeneratedProjectDependency(projectDirectory: string, dependencyName: string): void {
  const nodeModulesDirectory = join(projectDirectory, "node_modules")
  const dependencyTarget = resolve(packageRoot, "../../node_modules", dependencyName)
  const dependencyLink = join(nodeModulesDirectory, dependencyName)
  mkdirSync(nodeModulesDirectory, { recursive: true })
  symlinkSync(dependencyTarget, dependencyLink)
}

function linkGeneratedProjectParatixRuntime(projectDirectory: string): void {
  const paratixShimDirectory = join(projectDirectory, "node_modules", "paratix")
  mkdirSync(join(paratixShimDirectory, "modules"), { recursive: true })
  writeFileSync(
    join(paratixShimDirectory, "package.json"),
    `${JSON.stringify(
      {
        exports: {
          ".": "./index.ts",
          "./modules": "./modules/index.ts",
        },
        type: "module",
      },
      null,
      2
    )}\n`
  )
  writeFileSync(
    join(paratixShimDirectory, "index.ts"),
    `export * from ${JSON.stringify(pathToFileURL(paratixIndexPath).href)}\n`
  )
  writeFileSync(
    join(paratixShimDirectory, "modules", "index.ts"),
    `export * from ${JSON.stringify(pathToFileURL(paratixModulesPath).href)}\n`
  )
}

async function loadGeneratedServerDefinition(
  projectDirectory: string,
  options: { firstRun: boolean }
) {
  const { loadServerDefinitionFromFile } = (await import(pathToFileURL(paratixCliPath).href)) as {
    loadServerDefinitionFromFile: (
      file: string,
      options: { firstRun: boolean }
    ) => Promise<{
      env?: Record<string, unknown>
      ssh: {
        ports: number[]
        strictHostKeyChecking?: string
        user: string
      }
    }>
  }
  linkGeneratedProjectParatixRuntime(projectDirectory)
  return loadServerDefinitionFromFile(join(projectDirectory, "server.ts"), options)
}

function expectGeneratedServerToTypecheck(projectDirectory: string): void {
  writeFileSync(
    join(projectDirectory, "tsconfig.typecheck.json"),
    `${JSON.stringify(
      {
        compilerOptions: {
          baseUrl: ".",
          ignoreDeprecations: "6.0",
          paths: {
            paratix: [paratixIndexPath],
            "paratix/modules": [paratixModulesPath],
          },
          typeRoots: [join(packageRoot, "node_modules", "@types")],
        },
        extends: "./tsconfig.json",
        include: ["server.ts"],
      },
      null,
      2
    )}\n`
  )

  const typecheck = spawnSync(tscBinaryPath, ["--noEmit", "--project", "tsconfig.typecheck.json"], {
    cwd: projectDirectory,
    encoding: "utf8",
  })
  expect(typecheck.status, `${typecheck.stdout}\n${typecheck.stderr}`).toBe(0)
}

describe("writeProjectFiles", () => {
  beforeEach(() => {
    TEST_DIR = mkdtempSync(join(tmpdir(), "create-paratix-test-"))
  })

  afterEach(() => {
    rmSync(TEST_DIR, { force: true, recursive: true })
    TEST_DIR = ""
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
    const expectedRange = `^${readCreateParatixPackageVersion()}`

    expect(parsed).toMatchObject({
      dependencies: { paratix: expectedRange },
    })
  })

  it("derives the paratix dependency range from the create-paratix package version", () => {
    expect(deriveParatixDependencyRange()).toBe(`^${readCreateParatixPackageVersion()}`)
  })

  it("generated package.json includes TypeScript tooling so apply and lint scripts work immediately", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      devDependencies: {
        "@types/node": expect.stringMatching(/^\^/v),
        // The scaffold runs TypeScript 7 for tsc next to the 6.x compatibility
        // package that typescript-eslint needs, so both entries are npm
        // aliases rather than plain ranges.
        "@typescript/native": expect.stringMatching(/^npm:typescript@\^/v),
        eslint: expect.stringMatching(/^\^/v),
        "eslint-config-setup": expect.stringMatching(/^\^/v),
        jiti: expect.stringMatching(/^\^/v),
        prettier: expect.stringMatching(/^\^/v),
        tsx: expect.stringMatching(/^\^/v),
        typescript: expect.stringMatching(/^npm:@typescript\/typescript6@\^/v),
      },
      scripts: {
        apply: "paratix apply server.ts",
        "apply:dry": "paratix apply server.ts --dry-run",
        "apply:first-run": "paratix apply server.ts --first-run",
        "apply:first-run:dry": "paratix apply server.ts --dry-run --first-run",
        "format:check": "prettier --check .",
        "format:fix": "prettier --write .",
        lint: "eslint .",
        typecheck: "tsc --noEmit",
      },
    })
  })

  // R-0000738: the previous implementation replaced `\\` with `/`
  // unconditionally and called the platform default `basename`,
  // which mangled POSIX paths containing legitimate backslash
  // characters in a directory name. The new implementation selects
  // the platform-specific `basename` so on POSIX, backslashes stay
  // literal and the entire directory name is the basename. These
  // tests pin the POSIX behaviour because the test suite runs on
  // POSIX; the Windows code path is exercised via `path.win32`
  // directly in the unit test below.
  it("treats backslashes as literal characters on POSIX when deriving the package name", () => {
    // R-0000498 hardened assertWritableScaffoldDirectory to mkdir { recursive: false },
    // so the intermediate parent must be created explicitly first.
    mkdirSync(join(TEST_DIR, "windows"), { recursive: true })
    const windowsPath = join(TEST_DIR, "windows", "C:\\tmp\\windows-project")
    writeProjectFiles(windowsPath)

    const raw = readFileSync(join(windowsPath, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe("C:\\tmp\\windows-project")
  })

  it("treats backslashes in a relative path as literal characters on POSIX", () => {
    mkdirSync(join(TEST_DIR, "windows"), { recursive: true })
    const windowsRelativePath = join(TEST_DIR, "windows", "tmp\\nested\\mixed-project")
    writeProjectFiles(windowsRelativePath)

    const raw = readFileSync(join(windowsRelativePath, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe("tmp\\nested\\mixed-project")
  })

  // R-0000234: writeProjectFiles is exported, so a programmatic caller can
  // bypass scaffoldProject's project-name validation. The derived basename
  // must be rejected when it contains control characters / bidi formatting
  // codepoints before any file is created — otherwise the unvalidated name
  // would be embedded into package.json.
  it("rejects a project directory whose basename contains a newline", () => {
    const dangerousBasename = "evil\nname"
    const dangerousPath = join(TEST_DIR, dangerousBasename)

    expect(() => {
      writeProjectFiles(dangerousPath)
    }).toThrow(/derived package name contains control or bidi codepoints/v)

    expect(existsSync(join(dangerousPath, "package.json"))).toBe(false)
  })

  it("rejects a project directory whose basename contains a bidi codepoint", () => {
    const bidiOverride = String.fromCodePoint(0x20_2e)
    const dangerousBasename = `evil${bidiOverride}name`
    const dangerousPath = join(TEST_DIR, dangerousBasename)

    expect(() => {
      writeProjectFiles(dangerousPath)
    }).toThrow(/derived package name contains control or bidi codepoints/v)

    expect(existsSync(join(dangerousPath, "package.json"))).toBe(false)
  })

  it("creates a server.ts file", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(true)
  })

  it("does not overwrite an existing managed project file", () => {
    const existingPackageJson = '{"name":"keep-me"}\n'
    writeFileSync(join(TEST_DIR, "package.json"), existingPackageJson)

    expect(() => {
      writeProjectFiles(TEST_DIR)
    }).toThrow(/already exists/v)

    expect(readFileSync(join(TEST_DIR, "package.json"), "utf8")).toBe(existingPackageJson)
    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects a dangling symlink at a managed project file path", () => {
    const symlinkTarget = join(TEST_DIR, "outside-target")
    const symlinkPath = join(TEST_DIR, "server.ts")
    symlinkSync(symlinkTarget, symlinkPath)

    expect(() => {
      writeProjectFiles(TEST_DIR)
    }).toThrow(/already exists/v)

    expect(existsSync(symlinkTarget)).toBe(false)
  })

  it("rejects a symlinked files directory before writing support files", () => {
    const symlinkTarget = join(TEST_DIR, "outside-files")
    const symlinkPath = join(TEST_DIR, "files")
    mkdirSync(symlinkTarget)
    symlinkSync(symlinkTarget, symlinkPath, "dir")

    expect(() => {
      writeProjectFiles(TEST_DIR)
    }).toThrow(/already exists/v)

    expect(existsSync(join(symlinkTarget, ".gitkeep"))).toBe(false)
    expect(existsSync(join(symlinkTarget, "20auto-upgrades"))).toBe(false)
  })

  it("generated tsconfig.json uses the DX-oriented ESNext/Bundler defaults", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "tsconfig.json"), "utf8")
    const parsed = JSON.parse(raw) as {
      compilerOptions: { module: string; moduleResolution: string; types: string[] }
      include: string[]
    }

    expect(parsed.compilerOptions).toMatchObject({
      module: "ESNext",
      moduleResolution: "Bundler",
      types: ["node"],
    })
    expect(parsed.include).toStrictEqual(["**/*.ts"])
  })

  it("generated server.ts typechecks against the local paratix package types", () => {
    writeProjectFiles(TEST_DIR)

    expectGeneratedServerToTypecheck(TEST_DIR)
  }, 30_000)

  it("generated root-bootstrap server.ts typechecks against the local paratix package types", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    expectGeneratedServerToTypecheck(TEST_DIR)
  }, 30_000)

  it("writes a Prettier config matching the scaffold default", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, ".prettierrc"), "utf8")
    const parsed = JSON.parse(raw) as Record<string, boolean | number | string>

    expect(parsed).toStrictEqual({
      arrowParens: "always",
      bracketSpacing: true,
      printWidth: 100,
      semi: false,
      singleQuote: false,
      tabWidth: 2,
      trailingComma: "es5",
    })
  })

  it("writes a .prettierignore that excludes package-manager lockfiles", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, ".prettierignore"), "utf8")

    expect(content).toContain("pnpm-lock.yaml")
    expect(content).toContain("package-lock.json")
    expect(content).toContain("yarn.lock")
    expect(content).toContain("bun.lockb")
  })

  it("writes an eslint.config.ts using eslint-config-setup for node projects", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "eslint.config.ts"), "utf8")

    expect(content).toContain('import { getEslintConfig } from "eslint-config-setup"')
    expect(content).toContain("...(await getEslintConfig({ node: true }))")
    // JSON files are excluded because the shared config registers JavaScript
    // rules that ESLint refuses to run against the json/json language, which
    // aborts the run instead of reporting findings.
    expect(content).toContain('"**/*.json"')
  })

  it("generated eslint config loads through the scaffolded lint toolchain", () => {
    writeProjectFiles(TEST_DIR)
    linkGeneratedProjectDependency(TEST_DIR, "eslint-config-setup")
    linkGeneratedProjectDependency(TEST_DIR, "jiti")

    const result = spawnSync(process.execPath, [eslintBinaryPath, "--print-config", "server.ts"], {
      cwd: TEST_DIR,
      encoding: "utf8",
      timeout: 30_000,
    })

    expect(result.status).toBe(0)
    expect(result.stdout).toContain('"languageOptions"')
  }, 30_000)

  it("generated server.ts uses packages.upgrade and packages.installed (not apt.*)", () => {
    // Regression: SERVER_TEMPLATE previously used the deprecated apt module
    // (apt.upgrade / apt.installed). After Plan-0013 refactoring the correct
    // module is `package as packages` with packages.upgrade / packages.installed.
    // TypeScript cannot catch this because the template is a plain string.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("packages.upgrade(")
    expect(content).toContain('packages.installed("curl", "htop", "ufw")')
    expect(content).not.toContain("apt.upgrade(")
    expect(content).not.toContain("apt.installed(")
  })

  it("generated server.ts imports package as packages from paratix/modules", () => {
    // Regression: import must use `package as packages`, not the old `apt` import.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("package as packages")
    expect(content).toContain("  package as packages,")
    expect(content).not.toContain("import { apt")
  })

  it("generated server.ts uses the hardened admin mode by default", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "paratix"')
    // Without a key neither the constant nor the ssh import is emitted; both
    // would sit unused and fail the lint config the scaffold ships.
    expect(content).not.toContain("const adminPublicKey")
    expect(content).not.toContain("  ssh,")
    expect(content).toContain("const FIRST_RUN = isFirstRun()")
    expect(content).toContain('host: "1.2.3.4"')
    expect(content).toContain("user: adminUser")
    expect(content).toContain("// To let the admin user log in, add ssh to the paratix/modules")
    expect(content).toContain(
      '// ssh.authorizedKeys(adminUser, "ssh-ed25519 AAAA... you@example.com"),'
    )
    expect(content).not.toContain("      ssh.authorizedKeys(adminUser, adminPublicKey),")
    expect(content).toContain('PasswordAuthentication: "no"')
    expect(content).toContain('PermitRootLogin: "no"')
    expect(content).not.toContain('user: "root"')
    expect(content).not.toContain('PermitRootLogin: "prohibit-password"')
  })

  it("generated server.ts installs the admin public key when one is provided", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("const adminPublicKey =")
    expect(content).toContain(JSON.stringify(TEST_ADMIN_PUBLIC_KEY))
    expect(content).toContain("      ssh.authorizedKeys(adminUser, adminPublicKey),")
    expect(content).not.toContain("// ssh.authorizedKeys(adminUser, adminPublicKey),")
  })

  it("generated server.ts uses an explicitly provided admin username", () => {
    writeProjectFiles(TEST_DIR, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "deploy"')
    expect(content).toContain('host: "deploy.example.com"')
    expect(content).toContain("user: adminUser")
    expect(content).toContain('recipe("admin-access"')
    expect(content).not.toContain('user: "root"')
  })

  it("normalizes a padded programmatic admin username before rendering server.ts", () => {
    writeProjectFiles(TEST_DIR, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: " deploy " },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "deploy"')
    expect(content).not.toContain('const adminUser = " deploy "')
  })

  it("rejects an invalid programmatic admin username before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        host: "deploy.example.com",
        initialUser: { kind: "admin", user: 'deploy";\nthrow new Error("owned")' },
      })
    }).toThrow(/Invalid initial user/v)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects programmatic admin mode with root as the username", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        host: "deploy.example.com",
        initialUser: { kind: "admin", user: "root" },
      })
    }).toThrow(/use a non-root lowercase Linux username for admin mode/v)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("server template safely serializes admin usernames when called directly", () => {
    const initialAdminUser = 'deploy";\nthrow new Error("owned")'
    const content = createServerTemplate({
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: initialAdminUser },
    })

    expect(content).toContain(`const adminUser = ${JSON.stringify(initialAdminUser)}`)
    expect(content).not.toContain(`const adminUser = "${initialAdminUser}"`)
  })

  it("generated server.ts safely serializes quote characters in the host", () => {
    const host = 'dangerous"host.example'
    writeProjectFiles(TEST_DIR, {
      host,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`host: ${JSON.stringify(host)}`)
    expect(content).not.toContain(`host: "${host}"`)
  })

  it("generated server.ts safely serializes backslashes in the host", () => {
    const host = String.raw`example\host`
    writeProjectFiles(TEST_DIR, {
      host,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`host: ${JSON.stringify(host)}`)
  })

  it("generated server.ts safely serializes other string-literal escape sequences in the host", () => {
    const host = String.raw`example\${template}\path`
    writeProjectFiles(TEST_DIR, {
      host,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`host: ${JSON.stringify(host)}`)
  })

  it("generated server.ts embeds a selected local public key directly", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("const adminPublicKey =")
    expect(content).toContain(JSON.stringify(TEST_ADMIN_PUBLIC_KEY))
    expect(content).not.toContain("REPLACE_ME_WITH_YOUR_PUBLIC_KEY")
  })

  it("generated server.ts also embeds a CLI-supplied public key directly", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("const adminPublicKey =")
    expect(content).toContain(JSON.stringify(TEST_ADMIN_PUBLIC_KEY))
  })

  it("generated server.ts keeps first-run host-key checking fail-closed", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const strictHostKeyChecking = "yes"')
    expect(content).toContain('pass "paratix apply ... --first-run" for the bootstrap run')
    expect(content).toContain("pin expectedHostFingerprint/PublicKey or pre-populate known_hosts")
    expect(content).not.toContain('"accept-new"')
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).toContain(
      'expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY"'
    )
  })

  it("generated server.ts embeds a scanned expectedHostFingerprint and keeps strict host-key checking enabled", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      expectedHostFingerprint: TEST_HOST_FINGERPRINT,
      host: "deploy.example.com",
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const strictHostKeyChecking = "yes"')
    expect(content).toContain(`expectedHostFingerprint: ${JSON.stringify(TEST_HOST_FINGERPRINT)}`)
    expect(content).not.toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).not.toContain('"accept-new"')
  })

  it("rejects invalid programmatic hosts before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        host: "bad host",
        initialUser: { kind: "admin", user: "deploy" },
      })
    }).toThrow(
      'Error: Invalid host "bad host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects invalid programmatic admin public keys before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        adminPublicKey: "invalid-key",
        initialUser: { kind: "admin", user: "deploy" },
      })
    }).toThrow(
      'Error: Invalid value for "--admin-public-key" — provide a valid single-line OpenSSH public key.'
    )

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects invalid programmatic expected host fingerprints before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        expectedHostFingerprint: "SHA256:trusted-host-fingerprint",
        initialUser: { kind: "admin", user: "deploy" },
      })
    }).toThrow(
      'Error: Invalid expected host fingerprint "SHA256:trusted-host-fingerprint" — use an OpenSSH SHA256 fingerprint.'
    )

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
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

    expect(content).toContain("const FIRST_RUN = isFirstRun()")
    expect(content).toContain("const sshPorts = FIRST_RUN ? [22] : [2222]")
    expect(content).toContain(
      "const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443]"
    )
    expect(content).toContain("ports: sshPorts")
    expect(content).toContain('ufw.rule("allow", firewallTcpPorts)')
    expect(content).toContain("(env) => env.FIRST_RUN !== true")
    expect(content).toContain("ufw --force delete allow 22 || true")
    expect(content).toContain("ufw --force delete allow 22/tcp || true")
    expect(content).toContain(
      "check: \"! ufw status | grep -Eq '^22(/tcp)?[[:space:]]+(\\\\(v6\\\\)[[:space:]]+)?ALLOW'\""
    )
  })

  it("generated admin server.ts resolves FIRST_RUN from loadServerDefinitionFromFile", async () => {
    const firstRunDirectory = join(TEST_DIR, "first-run")
    const regularRunDirectory = join(TEST_DIR, "regular-run")
    mkdirSync(firstRunDirectory)
    mkdirSync(regularRunDirectory)
    writeProjectFiles(firstRunDirectory, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })
    writeProjectFiles(regularRunDirectory, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const firstRunDefinition = await loadGeneratedServerDefinition(firstRunDirectory, {
      firstRun: true,
    })
    const regularRunDefinition = await loadGeneratedServerDefinition(regularRunDirectory, {
      firstRun: false,
    })

    expect(firstRunDefinition.ssh).toMatchObject({
      ports: [22],
      strictHostKeyChecking: "yes",
      user: "deploy",
    })
    expect(firstRunDefinition.env).toMatchObject({
      FIRST_RUN: true,
      SSH_PORT: 2222,
    })
    expect(regularRunDefinition.ssh).toMatchObject({
      ports: [2222],
      strictHostKeyChecking: "yes",
      user: "deploy",
    })
    expect(regularRunDefinition.env).toMatchObject({
      FIRST_RUN: false,
      SSH_PORT: 2222,
    })
  })

  it("generated server.ts recognizes protocol-specific port 22 ufw status lines", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("grep -Eq '^22(/tcp)?[[:space:]]+(\\\\(v6\\\\)[[:space:]]+)?ALLOW'")

    const cleanupPattern = "^22(/tcp)?[[:space:]]+(\\(v6\\)[[:space:]]+)?ALLOW"

    const grepResult1 = spawnSync("grep", ["-Eq", cleanupPattern], {
      input: "22 ALLOW IN Anywhere",
      timeout: 5000,
    })
    expect(grepResult1.error).toBeUndefined()
    expect(grepResult1.status).toBe(0)

    const grepResult2 = spawnSync("grep", ["-Eq", cleanupPattern], {
      input: "22 (v6) ALLOW IN Anywhere (v6)",
      timeout: 5000,
    })
    expect(grepResult2.error).toBeUndefined()
    expect(grepResult2.status).toBe(0)

    const grepResult3 = spawnSync("grep", ["-Eq", cleanupPattern], {
      input: "22/tcp ALLOW IN Anywhere",
      timeout: 5000,
    })
    expect(grepResult3.error).toBeUndefined()
    expect(grepResult3.status).toBe(0)

    const grepResult4 = spawnSync("grep", ["-Eq", cleanupPattern], {
      input: "22/tcp (v6) ALLOW IN Anywhere (v6)",
      timeout: 5000,
    })
    expect(grepResult4.error).toBeUndefined()
    expect(grepResult4.status).toBe(0)

    const grepResult5 = spawnSync("grep", ["-Eq", cleanupPattern], {
      input: "2222/tcp ALLOW IN Anywhere",
      timeout: 5000,
    })
    expect(grepResult5.error).toBeUndefined()
    expect(grepResult5.status).toBe(1)
  })

  it("generated server.ts keeps port 22 open during first run before removing it later", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firstRunPortsIndex = content.indexOf(
      "const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443]"
    )
    const removeBootstrapRuleIndex = content.indexOf('name: "remove bootstrap ssh firewall rule"')

    expect(firstRunPortsIndex).toBeGreaterThanOrEqual(0)
    expect(removeBootstrapRuleIndex).toBeGreaterThanOrEqual(0)
    expect(firstRunPortsIndex).toBeLessThan(removeBootstrapRuleIndex)
    expect(content).toContain("when(\n        (env) => env.FIRST_RUN !== true,")
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
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      host: "203.0.113.10",
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('host: "203.0.113.10"')
    expect(content).toContain('user: FIRST_RUN ? "root" : adminUser')
    expect(content).toContain('const adminUser = "paratix"')
    expect(content).toContain("const FIRST_RUN = isFirstRun()")
    expect(content).toContain("Transitional bootstrap mode:")
    expect(content).toContain('PasswordAuthentication: "no"')
    expect(content).toContain('PermitRootLogin: FIRST_RUN ? "prohibit-password" : "no"')
    expect(content).toContain('const strictHostKeyChecking = "yes"')
    expect(content).not.toContain('"accept-new"')
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).not.toContain("--bootstrap-root")
    expect(content).not.toContain('service.restart("sshd")')
  })

  it("rejects root bootstrap without an admin public key", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, { host: "203.0.113.10", initialUser: { kind: "root" } })
    }).toThrow(/Root bootstrap requires --admin-public-key or --admin-public-key-file/v)
  })

  it("generated server.ts does not scaffold a hardcoded sshd restart signal", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).not.toContain('service.restart("sshd")')
    expect(content).not.toContain('signals: [service.restart("sshd")]')
  })

  it("generated root-bootstrap server.ts switches to the admin user after FIRST_RUN", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('user: FIRST_RUN ? "root" : adminUser')
    expect(content).toContain('PermitRootLogin: FIRST_RUN ? "prohibit-password" : "no"')
    expect(content).not.toContain('user: "root"')
    expect(content).not.toContain('PermitRootLogin: "prohibit-password"')
  })

  it("generated root-bootstrap server.ts resolves ssh and env for first-run and regular loads", async () => {
    const firstRunDirectory = join(TEST_DIR, "root-first-run")
    const regularRunDirectory = join(TEST_DIR, "root-regular-run")
    mkdirSync(firstRunDirectory)
    mkdirSync(regularRunDirectory)
    writeProjectFiles(firstRunDirectory, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      host: "203.0.113.10",
      initialUser: { kind: "root" },
    })
    writeProjectFiles(regularRunDirectory, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      host: "203.0.113.10",
      initialUser: { kind: "root" },
    })

    const firstRunDefinition = await loadGeneratedServerDefinition(firstRunDirectory, {
      firstRun: true,
    })
    const regularRunDefinition = await loadGeneratedServerDefinition(regularRunDirectory, {
      firstRun: false,
    })

    expect(firstRunDefinition.ssh).toMatchObject({
      ports: [22],
      strictHostKeyChecking: "yes",
      user: "root",
    })
    expect(firstRunDefinition.env).toMatchObject({
      FIRST_RUN: true,
      SSH_PORT: 2222,
    })
    expect(regularRunDefinition.ssh).toMatchObject({
      ports: [2222],
      strictHostKeyChecking: "yes",
      user: "paratix",
    })
    expect(regularRunDefinition.env).toMatchObject({
      FIRST_RUN: false,
      SSH_PORT: 2222,
    })
  })

  it("generated root-bootstrap server.ts provisions passwordless sudo for the bootstrap admin user", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('recipe("bootstrap-admin-sudo"')
    expect(content).toContain("file.copy(")
    expect(content).toContain('"/etc/sudoers.d/90-paratix-admin-nopasswd"')
    expect(content).toContain('"./files/admin-nopasswd-sudoers"')
    expect(content).toContain('mode: "0440"')
    expect(content).toContain('owner: "root:root"')
    expect(content).toContain("NOPASSWD sudo")
  })

  it("generated root-bootstrap project writes the sudoers drop-in for the admin user", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const sudoersPath = join(TEST_DIR, "files", "admin-nopasswd-sudoers")

    expect(existsSync(sudoersPath)).toBe(true)
    expect(readFileSync(sudoersPath, "utf8")).toBe(createAdminNopasswdSudoersContent("paratix"))
  })

  it("generated direct-admin project does not add a bootstrap sudoers drop-in", () => {
    writeProjectFiles(TEST_DIR, { initialUser: { kind: "admin", user: "deploy" } })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).not.toContain('recipe("bootstrap-admin-sudo"')
    expect(existsSync(join(TEST_DIR, "files", "admin-nopasswd-sudoers"))).toBe(false)
  })

  it("generated server.ts exposes FIRST_RUN through env for template logic and operator visibility", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const serverName = "my-server"')
    expect(content).toContain("name: serverName")
    expect(content).toContain("env: {")
    expect(content).toContain("FIRST_RUN,")
    expect(content).toContain("SERVER_NAME: serverName,")
    expect(content).toContain("SSH_PORT: 2222,")
    expect(content).toContain("hostname.set(serverName)")
  })

  it("generated server.ts adds /etc/hosts before setting the hostname", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const hostsIndex = content.indexOf('net.hosts("127.0.1.1", [serverName])')
    const hostnameIndex = content.indexOf("hostname.set(serverName)")

    expect(hostsIndex).toBeGreaterThanOrEqual(0)
    expect(hostnameIndex).toBeGreaterThanOrEqual(0)
    expect(hostsIndex).toBeLessThan(hostnameIndex)
  })

  it("generated root-bootstrap server.ts also opens firewall port 2222 before ssh-hardening-transition", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firewallIndex = content.indexOf('recipe("firewall"')
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening-transition"')

    expect(firewallIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(firewallIndex).toBeLessThan(sshHardeningIndex)
  })

  it("generated server.ts includes the first-run stop after ssh hardening, kernel hardening and automatic security upgrades", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening-transition"')
    const kernelHardeningIndex = content.indexOf('recipe("kernel-hardening"')
    const automaticUpgradesIndex = content.indexOf('recipe("automatic-security-upgrades"')
    const firstRunStopIndex = content.indexOf(
      'firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue.")'
    )

    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(kernelHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(automaticUpgradesIndex).toBeGreaterThanOrEqual(0)
    expect(firstRunStopIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeLessThan(kernelHardeningIndex)
    expect(kernelHardeningIndex).toBeLessThan(automaticUpgradesIndex)
    expect(automaticUpgradesIndex).toBeLessThan(firstRunStopIndex)
    expect(content).toContain(
      'import { firstRun, isFirstRun, recipe, server, when } from "paratix"'
    )
    expect(content).toContain("// Add application and user-facing services below this line.")
  })

  it("generated server.ts configures unattended-upgrades via scaffolded files", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('recipe("automatic-security-upgrades"')
    expect(content).toContain('packages.installed("unattended-upgrades")')
    expect(content).toContain('"/etc/apt/apt.conf.d/20auto-upgrades"')
    expect(content).toContain('"/etc/apt/apt.conf.d/50unattended-upgrades"')
  })

  it("generated project writes unattended-upgrades scaffold files", () => {
    writeProjectFiles(TEST_DIR)

    expect(readFileSync(join(TEST_DIR, "files", "20auto-upgrades"), "utf8")).toBe(
      AUTO_UPGRADES_20_TEMPLATE
    )
    expect(readFileSync(join(TEST_DIR, "files", "50unattended-upgrades"), "utf8")).toBe(
      UNATTENDED_UPGRADES_50_TEMPLATE
    )
  })

  it("creates a files subdirectory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "files"))).toBe(true)
  })
})
