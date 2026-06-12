import { describe, expect, it } from "vitest"

import { buildKeyValueDiff, buildUnifiedDiff } from "../../src/modules/diffHelpers.js"

describe("buildUnifiedDiff", () => {
  it("returns an empty string when both sides match", () => {
    expect(buildUnifiedDiff("foo\nbar\n", "foo\nbar\n")).toBe("")
  })

  it("renders a single-line replacement with default labels and context", () => {
    const diff = buildUnifiedDiff("Port 22\n", "Port 2222\n")
    expect(diff).toContain("--- current")
    expect(diff).toContain("+++ desired")
    expect(diff).toContain("-Port 22")
    expect(diff).toContain("+Port 2222")
  })

  it("uses the provided labels in the header", () => {
    const diff = buildUnifiedDiff("a\n", "b\n", {
      currentLabel: "/etc/foo",
      desiredLabel: "/tmp/desired",
    })
    expect(diff.split("\n").slice(0, 2)).toStrictEqual(["--- /etc/foo", "+++ /tmp/desired"])
  })

  it("treats an empty current as a new file (all inserts)", () => {
    const diff = buildUnifiedDiff("", "first\nsecond\n")
    expect(diff).toContain("+first")
    expect(diff).toContain("+second")
    // No `-` *content* lines beyond the `--- current` header.
    const allMinusLines = diff.split("\n").filter((line) => line.startsWith("-"))
    expect(allMinusLines).toStrictEqual(["--- current"])
  })

  it("treats an empty desired as a full delete", () => {
    const diff = buildUnifiedDiff("first\nsecond\n", "")
    expect(diff).toContain("-first")
    expect(diff).toContain("-second")
    // The `+++ desired` header must remain the only `+` line.
    const allPlusLines = diff.split("\n").filter((line) => line.startsWith("+"))
    expect(allPlusLines).toStrictEqual(["+++ desired"])
  })

  it("emits separate hunks for far-apart changes", () => {
    const current = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"].join("\n")
    const desired = ["A", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "L"].join("\n")
    const diff = buildUnifiedDiff(current, desired, { contextLines: 1 })
    const hunkHeaders = diff.split("\n").filter((line) => line.startsWith("@@"))
    expect(hunkHeaders.length).toBeGreaterThanOrEqual(2)
  })

  it("normalizes CRLF line endings before diffing", () => {
    expect(buildUnifiedDiff("foo\r\nbar\r\n", "foo\nbar\n")).toBe("")
  })

  it("falls back to a degenerate diff when the LCS table would exceed the cap", () => {
    // R-0001017: 1001 x 1001 = 1_002_001 effective cells exceed the
    // `MAX_DIFF_CELLS` soft cap (1_000_000). The helper must return without
    // allocating the O(n*m) table and still produce a structurally valid
    // unified diff with delete/insert lines for the differing content.
    const lineCount = 1001
    const currentLines: string[] = []
    const desiredLines: string[] = []
    for (let index = 0; index < lineCount; index++) {
      currentLines.push(`current-${String(index)}`)
      desiredLines.push(`desired-${String(index)}`)
    }
    const current = `${currentLines.join("\n")}\n`
    const desired = `${desiredLines.join("\n")}\n`
    const diff = buildUnifiedDiff(current, desired)
    expect(diff.startsWith("--- current\n+++ desired")).toBe(true)
    expect(diff).toContain("-current-0")
    expect(diff).toContain("+desired-0")
    expect(diff).toContain(`-current-${String(lineCount - 1)}`)
    expect(diff).toContain(`+desired-${String(lineCount - 1)}`)
    expect(diff.split("\n").some((line) => line.startsWith("@@"))).toBe(true)
  })
})

describe("buildKeyValueDiff", () => {
  it("returns an empty string when both values match", () => {
    expect(buildKeyValueDiff("vm.swappiness", "10", "10")).toBe("")
  })

  it("renders the alt to new transition for an existing key", () => {
    expect(buildKeyValueDiff("vm.swappiness", "60", "10")).toBe(
      "-vm.swappiness = 60\n+vm.swappiness = 10"
    )
  })

  it("renders only the insert when the current value is missing", () => {
    expect(buildKeyValueDiff("vm.swappiness", null, "10")).toBe("+vm.swappiness = 10")
  })
})
