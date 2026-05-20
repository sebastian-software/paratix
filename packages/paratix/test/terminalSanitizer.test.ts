import { describe, expect, it } from "vitest"

import { createTerminalSanitizer, sanitizeTerminalText } from "../src/terminalSanitizer.js"

describe("sanitizeTerminalText", () => {
  it("removes CSI/ANSI sequences while preserving printable text", () => {
    expect(sanitizeTerminalText("before \u001B[31mred\u001B[0m after")).toBe("before red after")
  })

  it("removes OSC sequences terminated by BEL or ST", () => {
    expect(sanitizeTerminalText("a\u001B]0;bad-title\u0007b\u001B]8;;https://evil\u001B\\c")).toBe(
      "abc"
    )
  })

  it("removes standalone ESC, BEL and unsafe C0 control bytes", () => {
    expect(sanitizeTerminalText("a\u001Bb\u0007c\u0000d\re\tf\ng")).toBe("acde\tf\ng")
  })
})

describe("createTerminalSanitizer", () => {
  it("removes escape sequences split across chunks", () => {
    const sanitizer = createTerminalSanitizer()

    const output =
      sanitizer.push("before \u001B]0;bad") +
      sanitizer.push("-title") +
      sanitizer.push("\u0007 after \u001B[31") +
      sanitizer.push("mred") +
      sanitizer.flush()

    expect(output).toBe("before  after red")
  })
})
