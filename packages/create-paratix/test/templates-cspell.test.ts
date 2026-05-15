import { type Dirent, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

const SRC_DIR = join(import.meta.dirname, "..", "src")

function resolveEntryFilePath(entry: Dirent, fallbackDir: string): string {
  const parents = entry as unknown as { parentPath?: string; path?: string }
  const parentPath = parents.parentPath ?? parents.path ?? fallbackDir
  return join(parentPath, entry.name)
}

function collectCspellIgnoreOffenders(srcDir: string): string[] {
  const entries = readdirSync(srcDir, {
    recursive: true,
    withFileTypes: true,
  })
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
    .map((entry) => resolveEntryFilePath(entry, srcDir))
    .filter((filePath) => readFileSync(filePath, "utf8").includes("cspell:ignore"))
}

describe("src/**/*.ts must not contain inline cspell:ignore", () => {
  it("contains no `cspell:ignore` directives in any source file", () => {
    expect(collectCspellIgnoreOffenders(SRC_DIR)).toStrictEqual([])
  })
})
