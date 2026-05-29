import { execSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { defineConfig } from "vitest/config"

const packageJsonPath = resolve(import.meta.dirname, "package.json")
// eslint-disable-next-line security/detect-non-literal-fs-filename -- build-time config: path is statically resolved from import.meta.dirname
const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, "utf8"))
// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- build-time config: package.json always has version
const { version } = packageJson as { version: string }

function resolveGitShortHash(cwd: string): string {
  try {
    return execSync("git rev-parse --short HEAD", {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim()
  } catch {
    return ""
  }
}

const gitShortHash = resolveGitShortHash(import.meta.dirname)
const displayVersion = gitShortHash === "" ? version : `${version}-${gitShortHash}`

export default defineConfig({
  define: {
    PACKAGE_DISPLAY_VERSION: JSON.stringify(displayVersion),
    PACKAGE_VERSION: JSON.stringify(version),
  },
  test: {
    // picocolors auto-enables ANSI when `CI` is present in the env, which
    // breaks substring assertions on UI output. Force colors off for tests
    // so the assertions match the same plain output developers see locally.
    env: { NO_COLOR: "1" },
    exclude: ["test/integration/**/*.test.ts", "test/postbuild/**/*.test.ts"],
    include: ["test/**/*.test.ts"],
  },
})
