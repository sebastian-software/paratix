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
import { tmpdir } from "node:os"
import { delimiter, join, resolve } from "node:path"
import { describe, expect, it } from "vitest"

import { TEST_ADMIN_PUBLIC_KEY, TEST_HOST_FINGERPRINT } from "../helpers.js"

const packageRootDirectory = resolve(import.meta.dirname, "../..")
const CLI_COMMAND_TIMEOUT_MS = 30_000

describe("dist CLI", () => {
  it("runs the published binary target for an early usage error", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { "create-paratix": string }
    }
    expect(packageJson.bin["create-paratix"]).toBe("./dist/index.js")

    const distCliPath = resolve(packageRootDirectory, packageJson.bin["create-paratix"])
    const firstLine = readFileSync(distCliPath, "utf8").split("\n")[0]
    expect(firstLine).toBe("#!/usr/bin/env node")

    const result = spawnSync(process.execPath, [distCliPath], {
      cwd: packageRootDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      timeout: CLI_COMMAND_TIMEOUT_MS,
    })

    expect(result.status).toBe(1)
    expect(result.stdout).toBe("")
    expect(result.stderr).toContain("Usage: create-paratix <project-name>")
  })

  it("runs when invoked through an npm-style bin symlink", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { "create-paratix": string }
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin["create-paratix"])
    const tempDirectory = mkdtempSync(join(tmpdir(), "create-paratix-bin-smoke-"))
    const linkedCliPath = join(tempDirectory, "create-paratix")

    try {
      symlinkSync(distCliPath, linkedCliPath)
      const result = spawnSync(linkedCliPath, [], {
        cwd: packageRootDirectory,
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

  it("scaffolds a project through the published dist CLI in non-interactive mode", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { "create-paratix": string }
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin["create-paratix"])
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
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })
})
