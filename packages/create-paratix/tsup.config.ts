import { defineConfig } from "tsup"

export default defineConfig({
  banner: { js: "#!/usr/bin/env node" },
  clean: true,
  // tsup hardcodes baseUrl for its dts pass (rollup.js: baseUrl ||
  // "."), which TypeScript 6 reports as a deprecation. The dts pass runs
  // on the aliased @typescript/typescript6, so the suppression lives here
  // rather than in the shared tsconfig, which tsc 7 reads.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node24",
})
