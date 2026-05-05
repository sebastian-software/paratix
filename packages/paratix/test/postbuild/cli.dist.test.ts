import { execFileSync } from "node:child_process"
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { pathToFileURL } from "node:url"
import { describe, expect, it } from "vitest"

const packageRootDirectory = resolve(import.meta.dirname, "../..")
const CLI_COMMAND_TIMEOUT_MS = 30_000
const CLI_COMMAND_MAX_BUFFER = 10 * 1024 * 1024
const PACKAGE_COMMAND_TIMEOUT_MS = 60_000

describe("dist CLI", () => {
  it("runs the published CLI for version and apply validation errors", () => {
    const packageJson = JSON.parse(
      readFileSync(join(packageRootDirectory, "package.json"), "utf8")
    ) as {
      bin: { paratix: string }
      version: string
    }
    const distCliPath = resolve(packageRootDirectory, packageJson.bin.paratix)
    const firstLine = readFileSync(distCliPath, "utf8").split("\n")[0]
    expect(firstLine).toBe("#!/usr/bin/env node")

    const versionOutput = execFileSync(process.execPath, [distCliPath, "--version"], {
      cwd: packageRootDirectory,
      encoding: "utf8",
      killSignal: "SIGTERM",
      maxBuffer: CLI_COMMAND_MAX_BUFFER,
      timeout: CLI_COMMAND_TIMEOUT_MS,
    }).trim()
    // eslint-disable-next-line security/detect-non-literal-regexp -- package version comes from local package.json
    expect(versionOutput).toMatch(new RegExp(`^${packageJson.version}(?:-[0-9a-f]{7,})?$`, "v"))

    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-cli-dist-"))
    const invalidPlaybookPath = join(tempDirectory, "invalid.mjs")
    try {
      writeFileSync(invalidPlaybookPath, "export default {}\n")
      expect(() =>
        execFileSync(process.execPath, [distCliPath, "apply", invalidPlaybookPath, "--dry-run"], {
          cwd: packageRootDirectory,
          encoding: "utf8",
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          stdio: "pipe",
          timeout: CLI_COMMAND_TIMEOUT_MS,
        })
      ).toThrow(/does not export a valid ServerDefinition[\s\S]*Missing property 'name'/v)
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })

  it("exports resolveEnvironment from the published package entry point", async () => {
    const distIndexUrl = pathToFileURL(resolve(packageRootDirectory, "dist/index.js")).href
    const { resolveEnvironment } = (await import(distIndexUrl)) as {
      resolveEnvironment: (environment: Record<string, unknown>, key: string) => Promise<unknown>
    }

    await expect(
      resolveEnvironment(
        {
          async SECRET() {
            await Promise.resolve()
            return "resolved-secret"
          },
        },
        "SECRET"
      )
    ).resolves.toBe("resolved-secret")
  })

  it("supports package specifier imports from a consumer project", () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), "paratix-consumer-dist-"))
    const nodeModulesDirectory = join(tempDirectory, "node_modules")
    const consumerPackageDirectory = join(nodeModulesDirectory, "paratix")
    const consumerScriptPath = join(tempDirectory, "consumer.mjs")

    try {
      execFileSync("pnpm", ["pack", "--pack-destination", tempDirectory], {
        cwd: packageRootDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: PACKAGE_COMMAND_TIMEOUT_MS,
      })

      const packageTarball = readdirSync(tempDirectory).find((entry) => entry.endsWith(".tgz"))
      expect(packageTarball).toBeDefined()

      mkdirSync(consumerPackageDirectory, { recursive: true })
      execFileSync(
        "tar",
        [
          "-xzf",
          join(tempDirectory, packageTarball!),
          "-C",
          consumerPackageDirectory,
          "--strip-components=1",
        ],
        {
          cwd: tempDirectory,
          killSignal: "SIGTERM",
          maxBuffer: CLI_COMMAND_MAX_BUFFER,
          timeout: PACKAGE_COMMAND_TIMEOUT_MS,
        }
      )

      const packedPackageJson = JSON.parse(
        readFileSync(join(consumerPackageDirectory, "package.json"), "utf8")
      ) as {
        dependencies: Record<string, string>
      }
      for (const dependencyName of Object.keys(packedPackageJson.dependencies)) {
        const dependencyTarget = join(packageRootDirectory, "node_modules", dependencyName)
        const dependencyLink = join(nodeModulesDirectory, dependencyName)
        mkdirSync(dirname(dependencyLink), { recursive: true })
        symlinkSync(dependencyTarget, dependencyLink)
      }

      writeFileSync(join(tempDirectory, "package.json"), '{ "type": "module" }\n')
      writeFileSync(
        consumerScriptPath,
        `
import { resolveEnvironment } from "paratix"
import { file, package as pkg, service } from "paratix/modules"

if (typeof resolveEnvironment !== "function") {
  throw new Error("paratix did not export resolveEnvironment")
}
if (typeof file?.directory !== "function") {
  throw new Error("paratix/modules did not export file.directory")
}
if (typeof pkg?.installed !== "function") {
  throw new Error("paratix/modules did not export package.installed")
}
if (typeof service?.enabled !== "function") {
  throw new Error("paratix/modules did not export service.enabled")
}

const resolved = await resolveEnvironment({ async SECRET() { return "resolved-secret" } }, "SECRET")
if (resolved !== "resolved-secret") {
  throw new Error("resolveEnvironment did not resolve lazy consumer values")
}

const modules = [
  file.directory("/tmp/paratix-consumer-test"),
  pkg.installed("curl"),
  service.enabled("ssh"),
]
for (const module of modules) {
  if (typeof module.name !== "string" || typeof module.check !== "function" || typeof module.apply !== "function") {
    throw new Error("module export did not create a valid runtime module")
  }
}

console.log("consumer imports ok")
`
      )

      const output = execFileSync(process.execPath, [consumerScriptPath], {
        cwd: tempDirectory,
        encoding: "utf8",
        killSignal: "SIGTERM",
        maxBuffer: CLI_COMMAND_MAX_BUFFER,
        timeout: CLI_COMMAND_TIMEOUT_MS,
      }).trim()

      expect(output).toBe("consumer imports ok")
    } finally {
      rmSync(tempDirectory, { force: true, recursive: true })
    }
  })
})
