import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { defineConfig } from "vitest/config"

const packageJsonPath = resolve(import.meta.dirname, "package.json")
// eslint-disable-next-line security/detect-non-literal-fs-filename -- build-time config: path is statically resolved from import.meta.dirname
const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, "utf8"))
// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- build-time config: package.json always has version
const { version } = packageJson as { version: string }

export default defineConfig({
  define: { PACKAGE_VERSION: JSON.stringify(version) },
  test: {
    include: ["test/**/*.test.ts"],
  },
})
