type TerminalSanitizerState = "csi" | "esc" | "osc" | "oscEsc" | "text"

const BYTE_BEL = 0x07
const BYTE_TAB = 0x09
const BYTE_LF = 0x0a
const BYTE_C0_MAX = 0x1f
const BYTE_ESC_SEQUENCE_MIN = 0x30
const BYTE_CSI_FINAL_MIN = 0x40
const BYTE_FINAL_MAX = 0x7e
const BYTE_DEL = 0x7f
const BYTE_C1_MIN = 0x80
const BYTE_C1_CSI = 0x9b
const BYTE_C1_ST = 0x9c
const BYTE_C1_OSC = 0x9d
const BYTE_C1_MAX = 0x9f
const ESC = "\u001B"
const CSI_START = "["
const OSC_START = "]"
const ST_FINAL = "\\"

function isAllowedTextControl(code: number): boolean {
  return code === BYTE_TAB || code === BYTE_LF
}

function isControlByte(code: number): boolean {
  return code <= BYTE_C0_MAX || code === BYTE_DEL || (code >= BYTE_C1_MIN && code <= BYTE_C1_MAX)
}

function isCsiFinalByte(code: number): boolean {
  return code >= BYTE_CSI_FINAL_MIN && code <= BYTE_FINAL_MAX
}

function isEscSequenceFinalByte(code: number): boolean {
  return code >= BYTE_ESC_SEQUENCE_MIN && code <= BYTE_FINAL_MAX
}

function consumeEscState(char: string, code: number): TerminalSanitizerState {
  if (char === CSI_START) return "csi"
  if (char === OSC_START) return "osc"
  return isEscSequenceFinalByte(code) || isControlByte(code) ? "text" : "esc"
}

function consumeOscState(char: string, code: number): TerminalSanitizerState {
  if (code === BYTE_BEL || code === BYTE_C1_ST) return "text"
  return char === ESC ? "oscEsc" : "osc"
}

function consumeTextState(
  char: string,
  code: number
): { nextState: TerminalSanitizerState; text: string } {
  if (char === ESC) return { nextState: "esc", text: "" }
  if (code === BYTE_C1_CSI) return { nextState: "csi", text: "" }
  if (code === BYTE_C1_OSC) return { nextState: "osc", text: "" }
  return {
    nextState: "text",
    text: !isControlByte(code) || isAllowedTextControl(code) ? char : "",
  }
}

function consumeTerminalChar(
  state: TerminalSanitizerState,
  char: string
): { nextState: TerminalSanitizerState; text: string } {
  const code = char.charCodeAt(0)
  switch (state) {
    case "csi": {
      return { nextState: isCsiFinalByte(code) ? "text" : "csi", text: "" }
    }
    case "esc": {
      return { nextState: consumeEscState(char, code), text: "" }
    }
    case "osc": {
      return { nextState: consumeOscState(char, code), text: "" }
    }
    case "oscEsc": {
      return { nextState: char === ST_FINAL ? "text" : "osc", text: "" }
    }
    case "text": {
      return consumeTextState(char, code)
    }
  }
}

/**
 * Create a stateful sanitizer for untrusted terminal text.
 *
 * It removes ANSI/CSI/OSC escape sequences and terminal control bytes while
 * preserving printable text, tabs and newlines. Use one sanitizer per stream
 * when data can arrive in chunks.
 *
 * @returns A sanitizer with `push` for chunks and `flush` for final cleanup.
 */
export function createTerminalSanitizer(): { flush: () => string; push: (text: string) => string } {
  let state: TerminalSanitizerState = "text"

  return {
    flush(): string {
      state = "text"
      return ""
    },
    push(text: string): string {
      let sanitized = ""

      for (const char of text) {
        const consumed = consumeTerminalChar(state, char)
        state = consumed.nextState
        sanitized += consumed.text
      }

      return sanitized
    },
  }
}

export function sanitizeTerminalText(text: string): string {
  const sanitizer = createTerminalSanitizer()
  return `${sanitizer.push(text)}${sanitizer.flush()}`
}
