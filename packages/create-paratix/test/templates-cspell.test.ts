import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"

describe("R-0000056: templates.ts must not contain inline cspell:ignore", () => {
  it("contains no `cspell:ignore` directives in src/templates.ts", () => {
    const templatesPath = new URL("../src/templates.ts", import.meta.url)
    const content = readFileSync(templatesPath, "utf8")
    expect(content).not.toMatch(/cspell:ignore/v)
  })
})
