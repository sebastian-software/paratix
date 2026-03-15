import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { defineConfig } from "tsup"

const packageJsonPath = resolve(import.meta.dirname, "package.json")
// eslint-disable-next-line security/detect-non-literal-fs-filename -- build-time config: path is statically resolved from import.meta.dirname
const packageJson: unknown = JSON.parse(readFileSync(packageJsonPath, "utf8"))
// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- build-time config: package.json always has version
const { version } = packageJson as { version: string }

export default defineConfig({
  clean: true,
  define: { PACKAGE_VERSION: JSON.stringify(version) },
  dts: true,
  entry: {
    cli: "src/cli.ts",
    index: "src/index.ts",
    "modules/index": "src/modules/index.ts",
  },
  format: ["esm"],
  sourcemap: true,
  splitting: true,
  target: "node24",
})
