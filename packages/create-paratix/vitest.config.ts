import { defineConfig } from "vitest/config"

export default defineConfig({
  define: {
    PACKAGE_DISPLAY_VERSION: JSON.stringify("0.0.0-test"),
  },
  test: {
    // Both suites need their own entry point: postbuild runs against the
    // packed artefact, integration installs from the registry. Neither belongs
    // in the default run, which must stay fast and work offline.
    exclude: ["test/postbuild/**/*.test.ts", "test/integration/**/*.test.ts"],
    include: ["test/**/*.test.ts"],
  },
})
