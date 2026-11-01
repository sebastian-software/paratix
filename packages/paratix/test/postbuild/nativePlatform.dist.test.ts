import { spawnSync } from "node:child_process"
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, expect, it } from "vitest"

const packageRoot = resolve(import.meta.dirname, "../..")
const cliPath = join(packageRoot, "dist/cli.js")
const PROCESS_TIMEOUT_MS = 30_000
const unsupportedArchitecture = "riscv64"
const originalPath = process.env.PATH ?? ""

/**
 * Create an isolated consumer project with the workspace package available.
 * @returns The temporary project directory; the caller must remove it.
 */
function createConsumer(): string {
  const directory = mkdtempSync(join(tmpdir(), "paratix-native-platform-"))
  mkdirSync(join(directory, "node_modules"))
  symlinkSync(packageRoot, join(directory, "node_modules/paratix"), "dir")
  writeFileSync(join(directory, "package.json"), JSON.stringify({ type: "module" }))
  return directory
}

describe("native platform boundary in dist (#257)", () => {
  it("rejects an unsupported architecture before warming secrets", () => {
    const directory = createConsumer()
    const preload = join(directory, "preload.mjs")
    const playbook = join(directory, "server.mjs")
    const marker = join(directory, "secret-provider-called")
    const bin = join(directory, "bin")
    try {
      writeFileSync(preload, 'Object.defineProperty(process, "arch", { value: "riscv64" })\n')
      mkdirSync(bin)
      const provider = join(bin, "op")
      writeFileSync(
        provider,
        `#!/bin/sh\ntouch "$PARATIX_PROVIDER_MARKER"\nprintf 'secret-value\\n'\n`
      )
      chmodSync(provider, 0o700)
      writeFileSync(
        playbook,
        `
import { server } from "paratix"
import { secret } from "paratix/modules"
export default server({
  name: "unsupported-native-platform", host: "127.0.0.1",
  ssh: { ports: [65535], user: "root" },
  run: [secret.provider("1password").resolve({ TOKEN: "op://test/item/password" })],
})
`
      )
      const result = spawnSync(
        process.execPath,
        ["--import", preload, cliPath, "apply", playbook],
        {
          cwd: directory,
          encoding: "utf8",
          env: {
            ...process.env,
            NO_COLOR: "1",
            PARATIX_PROVIDER_MARKER: marker,
            PATH: `${bin}:${originalPath}`,
          },
          timeout: PROCESS_TIMEOUT_MS,
        }
      )
      expect(result.error).toBeUndefined()
      expect(result.status).not.toBe(0)
      expect(result.stderr).toContain(
        `Paratix could not load its native SSH binding for platform ${process.platform}, architecture ${unsupportedArchitecture}`
      )
      expect(result.stderr).toContain("Supported targets: linux-x64-gnu")
      expect(result.stderr).toContain("glibc >= 2.35")
      expect(result.stderr).toContain("#supported-platforms")
      expect(result.stderr).not.toContain("Reinstall with optional dependencies")
      expect(`${result.stdout}${result.stderr}`).not.toContain(
        "Resolving secrets before connecting"
      )
      expect(existsSync(marker)).toBe(false)
      const verbose = spawnSync(
        process.execPath,
        ["--import", preload, cliPath, "apply", playbook, "--verbose"],
        {
          cwd: directory,
          encoding: "utf8",
          timeout: PROCESS_TIMEOUT_MS,
        }
      )
      expect(verbose.error).toBeUndefined()
      expect(verbose.status).not.toBe(0)
      expect(verbose.stderr).toContain("Caused by: @paratix/ssh-native")
      expect(verbose.stderr).toContain("Reinstall with optional dependencies")
    } finally {
      rmSync(directory, { force: true, recursive: true })
    }
  })

  it.each([
    { args: ["--input-type=module", "--eval", 'await import("paratix")'], operation: "import" },
    { args: [cliPath, "--help"], operation: "--help" },
    { args: [cliPath, "--version"], operation: "--version" },
  ])("allows $operation on Windows without loading a binary", ({ args }) => {
    const directory = createConsumer()
    const preload = join(directory, "preload.mjs")
    try {
      writeFileSync(preload, 'Object.defineProperty(process, "platform", { value: "win32" })\n')
      const result = spawnSync(process.execPath, ["--import", preload, ...args], {
        cwd: directory,
        encoding: "utf8",
        timeout: PROCESS_TIMEOUT_MS,
      })
      expect(result.error).toBeUndefined()
      expect(result.status).toBe(0)
      expect(result.stderr).not.toContain("native SSH binding")
    } finally {
      rmSync(directory, { force: true, recursive: true })
    }
  })
})
