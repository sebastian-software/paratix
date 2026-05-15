import { readdirSync, readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

describe("src/**/*.ts must not contain inline cspell:ignore", () => {
  it("contains no `cspell:ignore` directives in any source file", () => {
    const testDir = dirname(fileURLToPath(import.meta.url))
    const srcDir = join(testDir, "..", "src")

    const entries = readdirSync(srcDir, {
      recursive: true,
      withFileTypes: true,
    })

    const offenders: string[] = []
    for (const entry of entries) {
      if (!entry.isFile()) continue
      if (!entry.name.endsWith(".ts")) continue

      const parentPath =
        (entry as unknown as { parentPath?: string; path?: string })
          .parentPath ??
        (entry as unknown as { parentPath?: string; path?: string }).path ??
        srcDir
      const filePath = join(parentPath, entry.name)
      const content = readFileSync(filePath, "utf8")
      if (/cspell:ignore/v.test(content)) {
        offenders.push(filePath)
      }
    }

    expect(offenders).toEqual([])
  })
})
