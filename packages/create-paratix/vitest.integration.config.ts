import { defineConfig } from "vitest/config"

const INSTALL_TIMEOUT_MS = 600_000

export default defineConfig({
  test: {
    // A cold pnpm store makes the install dominate the runtime, so the default
    // per-test timeout is far too short here.
    hookTimeout: INSTALL_TIMEOUT_MS,
    include: ["test/integration/**/*.test.ts"],
    testTimeout: INSTALL_TIMEOUT_MS,
  },
})
