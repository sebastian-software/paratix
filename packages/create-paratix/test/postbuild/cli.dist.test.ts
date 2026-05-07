import { spawnSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { describe, expect, it } from "vitest"

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
})
