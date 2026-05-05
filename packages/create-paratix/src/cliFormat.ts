const HEX_RADIX = 16
const MINIMUM_ESCAPE_WIDTH = 4

/* eslint-disable regexp/no-control-character, prefer-regex-literals, regexp/require-unicode-sets-regexp -- escaping these codepoints is the purpose of the helper */
// oxlint-disable-next-line no-control-regex
const TERMINAL_CONTROL_CODEPOINTS = new RegExp("[\\u0000-\\u001F\\u007F-\\u009F]", "gu")
/* eslint-enable regexp/no-control-character, prefer-regex-literals, regexp/require-unicode-sets-regexp */

function formatCodePointEscape(character: string): string {
  const codePoint = character.codePointAt(0)
  if (codePoint == null) return ""
  return `\\u{${codePoint.toString(HEX_RADIX).toUpperCase().padStart(MINIMUM_ESCAPE_WIDTH, "0")}}`
}

export function escapeCliControlCharacters(value: string): string {
  return value.replace(TERMINAL_CONTROL_CODEPOINTS, formatCodePointEscape)
}

export function formatCliValue(value: string): string {
  return `"${escapeCliControlCharacters(value)}"`
}
