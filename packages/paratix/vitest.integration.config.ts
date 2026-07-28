import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { defineConfig } from "vitest/config"

const packageJsonPath = resolve(import.meta.dirname, "package.json")
const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, "utf8"))
// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- build-time config: package.json always has version
const { version } = packageJson as { version: string }

export default defineConfig({
  define: { PACKAGE_VERSION: JSON.stringify(version) },
  test: {
    hookTimeout: 180_000,
    include: ["test/integration/**/*.test.ts"],
    testTimeout: 180_000,
  },
})
