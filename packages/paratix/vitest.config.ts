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
    coverage: {
      // Only measure the shipped source. Test helpers, config files, generated
      // type declarations, and the CLI/library entrypoints (thin wiring that is
      // exercised end-to-end by the distribution/integration suites rather than
      // by unit tests) are excluded so the thresholds reflect meaningful
      // logic coverage.
      exclude: ["src/**/*.d.ts", "src/cli.ts", "src/index.ts", "src/modules/index.ts"],
      include: ["src/**/*.ts"],
      provider: "v8",
      reporter: ["text", "text-summary", "lcov", "html"],
      // Thresholds are set slightly below the measured baseline (statements
      // 93.24%, branches 85.85%, functions 97.66%, lines 95.22%) so the gate
      // stays green today while still failing CI on a meaningful regression.
      thresholds: {
        branches: 82,
        functions: 90,
        lines: 90,
        statements: 90,
      },
    },
    // picocolors auto-enables ANSI when `CI` is present in the env, which
    // breaks substring assertions on UI output. Force colors off for tests
    // so the assertions match the same plain output developers see locally.
    env: { NO_COLOR: "1" },
    exclude: ["test/integration/**/*.test.ts", "test/postbuild/**/*.test.ts"],
    include: ["test/**/*.test.ts"],
  },
})
