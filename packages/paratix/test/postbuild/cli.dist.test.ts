import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, expect, it } from "vitest"

const packageRootDirectory = resolve(import.meta.dirname, "../..")
const CLI_COMMAND_TIMEOUT_MS = 30_000
const CLI_COMMAND_MAX_BUFFER = 10 * 1024 * 1024

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
})
