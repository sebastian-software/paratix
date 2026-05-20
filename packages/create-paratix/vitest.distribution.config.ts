import { defineConfig } from "vitest/config"

export default defineConfig({
  define: {
    PACKAGE_DISPLAY_VERSION: JSON.stringify("0.0.0-test"),
  },
  test: {
    include: ["test/postbuild/**/*.test.ts"],
  },
})
