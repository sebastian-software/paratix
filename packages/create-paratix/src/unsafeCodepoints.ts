// R-0000125 / R-0000233: ASCII/C1 control characters and Unicode
// bidirectional formatting codepoints. Control characters (incl. CR/LF/TAB
// and DEL) and bidi overrides such as U+202D/U+202E or the isolate marks
// U+2066–U+2069 can be used to smuggle hostnames or public-key comments
// that visually look benign but resolve to attacker-controlled material
// when emitted verbatim into server.ts.
//
// Codepoint ranges covered:
//   U+0000–U+001F  C0 control characters
//   U+007F         DEL
//   U+0080–U+009F  C1 control characters
//   U+200E, U+200F LRM / RLM
//   U+202A–U+202E  LRE / RLE / PDF / LRO / RLO
//   U+2066–U+2069  LRI / RLI / FSI / PDI
//
// The pattern is built from a string source so that the unicode escape
// sequences survive editor and formatter passes that would otherwise
// replace them with the actual control codepoints.
//
// eslint-disable rationale:
//   - regexp/no-control-character: rejecting these codepoints is the goal
//   - prefer-regex-literals: a literal would re-introduce the formatter
//     mangling we are explicitly avoiding here
//   - regexp/require-unicode-sets-regexp: the `v` flag rejects bare control
//     codepoints in a character class, so we use the `u` flag instead
/* eslint-disable regexp/no-control-character, prefer-regex-literals, regexp/require-unicode-sets-regexp -- rejecting these codepoints is the entire purpose of the check */
export const UNSAFE_CODEPOINTS_PATTERN = new RegExp(
  // oxlint-disable-next-line no-control-regex
  "[\\u0000-\\u001F\\u007F-\\u009F\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]",
  "u"
)
/* eslint-enable regexp/no-control-character, prefer-regex-literals, regexp/require-unicode-sets-regexp */

export function containsUnsafeCodepoint(value: string): boolean {
  return UNSAFE_CODEPOINTS_PATTERN.test(value)
}
