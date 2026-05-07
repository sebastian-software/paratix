import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    include: ["test/postbuild/**/*.test.ts"],
  },
})
