import { spawnSync } from "node:child_process"
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { createRequire } from "node:module"
import { tmpdir } from "node:os"
import { delimiter, dirname, join, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

import { TEST_ADMIN_PUBLIC_KEY, TEST_HOST_FINGERPRINT } from "../helpers.js"

const require = createRequire(import.meta.url)
const packageRootDirectory = resolve(import.meta.dirname, "../..")
const paratixIndexPath = resolve(
  fileURLToPath(new URL("../../../paratix/src/index.ts", import.meta.url))
)
const paratixModulesPath = resolve(
  fileURLToPath(new URL("../../../paratix/src/modules/index.ts", import.meta.url))
)
const paratixCliPath = resolve(
  fileURLToPath(new URL("../../../paratix/src/cli.ts", import.meta.url))
)
const CLI_COMMAND_TIMEOUT_MS = 30_000

describe("dist CLI", () => {
  let packedPackageRootDirectory: string
  let packedTarballEntries: string[]
  let packedTempDirectory: string

  beforeAll(() => {
    packedTempDirectory = mkdtempSync(join(tmpdir(), "create-paratix-packed-package-"))
    packedPackageRootDirectory = join(packedTempDirectory, "node_modules", "create-paratix")
    mkdirSync(packedPackageRootDirectory, { recursive: true })
    linkRuntimeDependencies(packedTempDirectory)

    const packResult = spawnSync(
      "npm",
      ["pack", "--pack-destination", packedTempDirectory, "--json"],
      {
        cwd: packageRootDirectory,
        encoding: "utf8",
        env: {
          ...process.env,
          npm_config_cache: join(packedTempDirectory, "npm-cache"),
          npm_config_logs_dir: join(packedTempDirectory, "npm-logs"),
        },
        killSignal: "SIGTERM",
        timeout: CLI_COMMAND_TIMEOUT_MS,
      }
    )
    if (packResult.status !== 0) {
      throw new Error(`npm pack failed:\n${packResult.stderr}`)
    }

    const packEntries = JSON.parse(packResult.stdout) as Array<{ filename: string }>
    if (packEntries.length !== 1) {
      throw new Error(`Expected npm pack to produce one tarball, got ${packEntries.length}`)
    }
    const packedTarballPath = join(packedTempDirectory, packEntries[0].filename)

    const listResult = spawnSync("tar", ["-tzf", packedTarballPath], {
      cwd: packedTempDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      timeout: CLI_COMMAND_TIMEOUT_MS,
    })
    if (listResult.status !== 0) {
      throw new Error(`tar listing failed:\n${listResult.stderr}`)
    }
    packedTarballEntries = listResult.stdout.trim().split("\n").sort()

    const extractResult = spawnSync(
      "tar",
      ["-xzf", packedTarballPath, "--strip-components", "1", "-C", packedPackageRootDirectory],
      {
        cwd: packedTempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        timeout: CLI_COMMAND_TIMEOUT_MS,
      }
    )
    if (extractResult.status !== 0) {
      throw new Error(`tar extraction failed:\n${extractResult.stderr}`)
    }
  })

  afterAll(() => {
    rmSync(packedTempDirectory, { force: true, recursive: true })
  })

  it("packs the required published files and excludes source-only files", () => {
    expect(packedTarballEntries).toStrictEqual(
      expect.arrayContaining([
        "package/LICENSE",
        "package/README.md",
        "package/dist/index.d.ts",
        "package/dist/index.js",
        "package/package.json",
      ])
    )
    expect(packedTarballEntries.some((entry) => entry.startsWith("package/src/"))).toBe(false)
    expect(packedTarballEntries.some((entry) => entry.startsWith("package/test/"))).toBe(false)
  })

  it("runs the published binary target for an early usage error", () => {
    const packageJson = readPackageJson()
    expect(packageJson.bin["create-paratix"]).toBe("./dist/index.js")

    const distCliPath = resolve(packedPackageRootDirectory, packageJson.bin["create-paratix"])
    const firstLine = readFileSync(distCliPath, "utf8").split("\n")[0]
    expect(firstLine).toBe("#!/usr/bin/env node")

    const result = spawnSync(process.execPath, [distCliPath], {
      cwd: packedPackageRootDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      timeout: CLI_COMMAND_TIMEOUT_MS,
    })

    expect(result.status).toBe(1)
    expect(result.stdout).toBe("")
    expect(result.stderr).toContain("Usage: create-paratix <project-name>")
  })

  it("exposes the published dist entry point to ESM consumers", () => {
    const packageJson = readPackageJson()
    expect(packageJson.main).toBe("./dist/index.js")
    expect(packageJson.types).toBe("./dist/index.d.ts")
    expect(packageJson.exports["."]).toStrictEqual({
      import: "./dist/index.js",
      types: "./dist/index.d.ts",
    })

    const tempDirectory = mkdtempSync(join(tmpdir(), "create-paratix-runtime-consumer-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")

    try {
      mkdirSync(nodeModulesDirectory)
      symlinkSync(packedPackageRootDirectory, join(nodeModulesDirectory, "create-paratix"))

      const result = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          'import("create-paratix").then((mod) => console.log(typeof mod.scaffoldProject))',
        ],
        {
          cwd: tempDirectory,
          encoding: "utf8",
          killSignal: "SIGTERM",
          timeout: CLI_COMMAND_TIMEOUT_MS,
        }
      )

      expect(result.status).toBe(0)
      expect(result.stderr).toBe("")
      expect(result.stdout).toBe("function\n")
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("exposes the published declaration entry point to TypeScript consumers", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "create-paratix-types-consumer-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")
    // `typescript` is aliased to @typescript/typescript6, whose binary is
    // `tsc6`. This consumer check keeps using the 6.x compiler, as it did
    // before the alias; its tsconfig below has no `baseUrl`, so TypeScript 7
    // would work here too, but switching it would change what the test proves.
    const tscPath = require.resolve("typescript/bin/tsc6")

    try {
      mkdirSync(nodeModulesDirectory)
      symlinkSync(packedPackageRootDirectory, join(nodeModulesDirectory, "create-paratix"))
      writeFileSync(
        join(tempDirectory, "package.json"),
        `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`
      )
      writeFileSync(
        join(tempDirectory, "tsconfig.json"),
        `${JSON.stringify(
          {
            compilerOptions: {
              module: "NodeNext",
              moduleResolution: "NodeNext",
              noEmit: true,
              strict: true,
              target: "ES2022",
            },
            files: ["index.ts"],
          },
          null,
          2
        )}\n`
      )
      writeFileSync(
        join(tempDirectory, "index.ts"),
        [
          'import { scaffoldProject, type ScaffoldOptions } from "create-paratix"',
          "",
          "const options: ScaffoldOptions = { installer: () => true }",
          'const didScaffold: boolean = scaffoldProject("typed-consumer-project", { command: { args: ["install"], executable: "pnpm" }, name: "pnpm" }, options)',
          "void didScaffold",
          "",
        ].join("\n")
      )

      const result = spawnSync(process.execPath, [tscPath, "--project", "tsconfig.json"], {
        cwd: tempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        timeout: CLI_COMMAND_TIMEOUT_MS,
      })

      expect(result.status).toBe(0)
      expect(result.stdout).toBe("")
      expect(result.stderr).toBe("")
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("runs when invoked through an npm-style bin symlink", () => {
    const packageJson = readPackageJson()
    const distCliPath = resolve(packedPackageRootDirectory, packageJson.bin["create-paratix"])
    const tempDirectory = mkdtempSync(join(tmpdir(), "create-paratix-bin-smoke-"))
    const linkedCliPath = join(tempDirectory, "create-paratix")

    try {
      symlinkSync(distCliPath, linkedCliPath)
      const result = spawnSync(linkedCliPath, [], {
        cwd: packedPackageRootDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        timeout: CLI_COMMAND_TIMEOUT_MS,
      })

      expect(result.status).toBe(1)
      expect(result.stdout).toBe("")
      expect(result.stderr).toContain("Usage: create-paratix <project-name>")
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("scaffolds a project through the published dist CLI in non-interactive mode", async () => {
    const packageJson = readPackageJson()
    const distCliPath = resolve(packedPackageRootDirectory, packageJson.bin["create-paratix"])
    const tempDirectory = mkdtempSync(join(tmpdir(), "create-paratix-dist-success-"))
    const binDirectory = join(tempDirectory, "bin")
    const scaffoldCwd = join(tempDirectory, "cwd")
    const installLogPath = join(tempDirectory, "install-log.json")
    const projectName = "dist-success-project"
    const pnpmStubPath = join(binDirectory, "pnpm")

    try {
      mkdirSync(binDirectory)
      mkdirSync(scaffoldCwd)
      const projectDirectory = join(realpathSync(scaffoldCwd), projectName)
      writeFileSync(
        pnpmStubPath,
        [
          "#!/usr/bin/env node",
          'const { writeFileSync } = require("node:fs")',
          'writeFileSync(process.env.CREATE_PARATIX_INSTALL_LOG, JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd() }) + "\\n")',
          "",
        ].join("\n")
      )
      chmodSync(pnpmStubPath, 0o755)

      const result = spawnSync(
        process.execPath,
        [
          distCliPath,
          projectName,
          "--host",
          "server.example.com",
          "--initial-user",
          "deploy",
          "--expected-host-fingerprint",
          TEST_HOST_FINGERPRINT,
          "--admin-public-key",
          TEST_ADMIN_PUBLIC_KEY,
        ],
        {
          cwd: scaffoldCwd,
          encoding: "utf8",
          env: {
            ...process.env,
            CREATE_PARATIX_INSTALL_LOG: installLogPath,
            npm_config_user_agent: "pnpm/10.0.0 node/v24.0.0",
            PATH: [binDirectory, process.env.PATH].join(delimiter),
          },
          killSignal: "SIGTERM",
          timeout: CLI_COMMAND_TIMEOUT_MS,
        }
      )

      expect(result.status).toBe(0)
      expect(result.stderr).toBe("")
      expect(result.stdout).toContain(`Creating Paratix project in ${projectDirectory}...`)
      expect(result.stdout).toContain("Installing dependencies with pnpm...")
      expect(result.stdout).toContain("Project created successfully!")
      expect(result.stdout).toContain("pnpm apply:first-run:dry")

      const installLog = JSON.parse(readFileSync(installLogPath, "utf8")) as {
        argv: string[]
        cwd: string
      }
      expect(installLog).toStrictEqual({ argv: ["install"], cwd: projectDirectory })

      expect(existsSync(join(projectDirectory, "package.json"))).toBe(true)
      expect(existsSync(join(projectDirectory, "tsconfig.json"))).toBe(true)
      expect(existsSync(join(projectDirectory, ".env.example"))).toBe(true)
      expect(existsSync(join(projectDirectory, "files", "20auto-upgrades"))).toBe(true)

      const generatedPackageJson = JSON.parse(
        readFileSync(join(projectDirectory, "package.json"), "utf8")
      ) as {
        name: string
        scripts: Record<string, string>
      }
      expect(generatedPackageJson.name).toBe(projectName)
      expect(generatedPackageJson.scripts["apply:first-run"]).toBe(
        "paratix apply server.ts --first-run"
      )

      const serverTemplate = readFileSync(join(projectDirectory, "server.ts"), "utf8")
      expect(serverTemplate).toContain('host: "server.example.com"')
      expect(serverTemplate).toContain(`expectedHostFingerprint: "${TEST_HOST_FINGERPRINT}"`)
      expect(serverTemplate).toContain(TEST_ADMIN_PUBLIC_KEY)
      expect(serverTemplate).toContain('const adminUser = "deploy"')
      expect(serverTemplate).toContain("import { firstRun, isFirstRun, recipe, server, when }")
      expect(serverTemplate).toContain("const FIRST_RUN = isFirstRun()")

      linkGeneratedProjectParatixRuntime(projectDirectory)
      writeFileSync(join(projectDirectory, "server.first-run.ts"), serverTemplate)
      writeFileSync(join(projectDirectory, "server.regular-run.ts"), serverTemplate)

      const firstRunDefinition = await loadGeneratedServerDefinitionFromFile(
        join(projectDirectory, "server.first-run.ts"),
        { firstRun: true }
      )
      const regularRunDefinition = await loadGeneratedServerDefinitionFromFile(
        join(projectDirectory, "server.regular-run.ts"),
        { firstRun: false }
      )

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
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })
})

function readPackageJson(): {
  bin: { "create-paratix": string }
  dependencies: Record<string, string>
  exports: { ".": { import: string; types: string } }
  main: string
  types: string
} {
  return JSON.parse(readFileSync(resolve(packageRootDirectory, "package.json"), "utf8")) as {
    bin: { "create-paratix": string }
    dependencies: Record<string, string>
    exports: { ".": { import: string; types: string } }
    main: string
    types: string
  }
}

function linkRuntimeDependencies(tempDirectory: string): void {
  const packageJson = readPackageJson()
  for (const dependencyName of Object.keys(packageJson.dependencies)) {
    const dependencyRootDirectory = dirname(require.resolve(`${dependencyName}/package.json`))
    const dependencyInstallPath = join(tempDirectory, "node_modules", dependencyName)
    mkdirSync(dirname(dependencyInstallPath), { recursive: true })
    symlinkSync(dependencyRootDirectory, dependencyInstallPath)
  }
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

async function loadGeneratedServerDefinitionFromFile(
  file: string,
  options: { firstRun: boolean }
): Promise<{
  env?: Record<string, unknown>
  ssh: {
    ports: number[]
    strictHostKeyChecking?: string
    user: string
  }
}> {
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
  return loadServerDefinitionFromFile(file, options)
}
