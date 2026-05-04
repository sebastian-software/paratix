import { describe, expect, it } from "vitest"

import { resolveEnvironment } from "../src/index.js"

describe("public API", () => {
  it("exports resolveEnvironment from the package entry point", async () => {
    await expect(
      resolveEnvironment(
        {
          async SECRET() {
            await Promise.resolve()
            return "resolved-secret"
          },
        },
        "SECRET"
      )
    ).resolves.toBe("resolved-secret")
  })
})
