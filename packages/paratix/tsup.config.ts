import { defineConfig } from "tsup"

export default defineConfig({
  clean: true,
  dts: true,
  entry: {
    cli: "src/cli.ts",
    index: "src/index.ts",
    "modules/index": "src/modules/index.ts",
  },
  format: ["esm"],
  sourcemap: true,
  splitting: true,
  target: "node22",
})
