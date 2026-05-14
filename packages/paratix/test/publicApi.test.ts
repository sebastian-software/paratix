import { describe, expect, it } from "vitest"

import * as packageApi from "../src/index.js"
import { resolveEnvironment } from "../src/index.js"
import * as moduleApi from "../src/modules/index.js"

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

  it("re-exports every built-in module from the package entry point", () => {
    for (const exportName of Object.keys(moduleApi)) {
      expect(packageApi, `missing root built-in export: ${exportName}`).toHaveProperty(exportName)
      expect(packageApi[exportName as keyof typeof packageApi]).toBe(
        moduleApi[exportName as keyof typeof moduleApi]
      )
    }
  })
})
