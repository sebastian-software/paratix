/**
 * Parse a single sshd_config line into its directive name and value, or
 * `null` when the line is empty / a comment / cannot be split into the
 * `<directive> <value>` shape. Leading whitespace is allowed (Match-block
 * lines are commonly indented). sshd_config only recognises whole-line
 * comments (`#` at the start of the trimmed line), so `#` characters are
 * preserved verbatim inside the value — matching the apply path
 * (`applySshdSettingToContent`) which writes the value as-is.
 *
 * @param rawLine - A single line from sshd_config.
 * @returns The parsed directive and trimmed value, or `null` if the line
 *   carries no active directive.
 */
export function parseSshdConfigLine(rawLine: string): { directive: string; value: string } | null {
  const stripped = rawLine.replace(/^\s+/v, "")
  if (stripped.length === 0 || stripped.startsWith("#")) return null

  // Find the boundary between the directive and its value via the first
  // whitespace character. This is unambiguous for sshd_config: directive
  // names never contain whitespace.
  const firstSpace = stripped.search(/\s/v)
  if (firstSpace <= 0) return null

  const directive = stripped.slice(0, firstSpace)
  const value = stripped.slice(firstSpace).trim()
  if (value.length === 0) return null

  return { directive, value }
}

/**
 * Detect whether a sshd_config line opens a `Match` block. Match conditions
 * scope every directive that follows them until the next `Match` line or
 * the end of the file (per `sshd_config(5)`).
 *
 * @param rawLine - A single line from sshd_config.
 * @returns `true` when the line is an active `Match` directive.
 */
export function isMatchBlockLine(rawLine: string): boolean {
  const parsed = parseSshdConfigLine(rawLine)
  return parsed?.directive.toLowerCase() === "match"
}

/**
 * Check whether every top-level active occurrence of `key` in the sshd_config
 * `content` has the given `value`. An "active" occurrence is a non-comment
 * line whose first token equals `key` (case-insensitive, leading whitespace
 * allowed). Lines inside a `Match` block (everything after the first
 * top-level `Match` directive) are intentionally ignored: the apply path
 * only edits top-level directives, so the check must mirror that scope.
 *
 * Returns `true` when at least one top-level occurrence exists and all of
 * them match the desired value. Returns `false` when:
 * - no top-level occurrence of `key` exists at all (apply will need to append it), or
 * - at least one top-level occurrence has a different value.
 *
 * @param content - The full sshd_config file content.
 * @param key - The directive name to scan for (case-insensitive).
 * @param value - The desired value; every top-level occurrence must match this.
 * @returns `true` when at least one top-level occurrence exists and all of
 *   them match the desired value, `false` otherwise.
 */
export function sshdSettingMatchesEverywhere(content: string, key: string, value: string): boolean {
  const desiredValue = value.trim()
  const expectedKeyLower = key.toLowerCase()
  let foundAny = false

  for (const rawLine of content.split(/\r?\n/v)) {
    if (isMatchBlockLine(rawLine)) break

    const parsed = parseSshdConfigLine(rawLine)
    if (parsed == null) continue
    if (parsed.directive.toLowerCase() !== expectedKeyLower) continue

    foundAny = true
    if (parsed.value !== desiredValue) return false
  }

  return foundAny
}

/**
 * Decide whether a single line's directive matches the expected key
 * (case-insensitive). Returns the rewritten line preserving leading
 * whitespace, or `null` when the line should be left unchanged.
 *
 * @param rawLine - The original line.
 * @param expectedKeyLower - The lowercased directive name to match.
 * @param replacement - The `key value` replacement, formatted by the caller.
 * @returns The rewritten line, or `null` when no rewrite applies.
 */
function rewriteMatchingDirectiveLine(
  rawLine: string,
  expectedKeyLower: string,
  replacement: string
): null | string {
  const parsed = parseSshdConfigLine(rawLine)
  if (parsed == null) return null
  if (parsed.directive.toLowerCase() !== expectedKeyLower) return null

  // Preserve any leading whitespace from the original line so indentation
  // (rare at top level, but possible) is not silently rewritten.
  const leadingWhitespace = rawLine.slice(0, rawLine.length - rawLine.trimStart().length)
  return `${leadingWhitespace}${replacement}`
}

/**
 * Replace every top-level occurrence of `key` in `lines` with the desired
 * `key value` line. Stops scanning at the first `Match` block. Preserves
 * leading whitespace on each rewritten line.
 *
 * @param lines - The split sshd_config content (read-only input).
 * @param key - The directive name to rewrite.
 * @param value - The desired directive value.
 * @returns A copy of `lines` with replacements applied, the index of the
 *   first `Match` block (or `-1` if none), and whether any replacement
 *   happened.
 */
function rewriteTopLevelLines(
  lines: readonly string[],
  key: string,
  value: string
): { didReplace: boolean; firstMatchIndex: number; rewritten: string[] } {
  const expectedKeyLower = key.toLowerCase()
  const replacement = `${key} ${value}`
  const rewritten = [...lines]
  let firstMatchIndex = -1
  let didReplace = false

  for (let index = 0; index < rewritten.length; index++) {
    const rawLine = rewritten[index] ?? ""
    if (isMatchBlockLine(rawLine)) {
      firstMatchIndex = index
      break
    }
    const replaced = rewriteMatchingDirectiveLine(rawLine, expectedKeyLower, replacement)
    if (replaced == null) continue
    rewritten[index] = replaced
    didReplace = true
  }

  return { didReplace, firstMatchIndex, rewritten }
}

/**
 * Rewrite every top-level occurrence of `key` to `value`, leaving any
 * `Match`-block override of the same directive untouched. When no top-level
 * occurrence exists, the directive is inserted just before the first
 * `Match` block (or appended at the end of the file when no `Match` block
 * exists).
 *
 * Editing inside `Match` blocks would silently change the security posture
 * of an existing override (e.g. flipping `PasswordAuthentication` for an
 * admin Match-User group), which is why this function refuses to touch
 * anything past the first `Match` line.
 *
 * @param content - The full sshd_config file content.
 * @param key - The directive name to set.
 * @param value - The desired directive value.
 * @returns The new sshd_config content with the directive applied.
 */
export function applySshdSettingToContent(content: string, key: string, value: string): string {
  const lines = content.split(/\r?\n/v)
  const trailingNewline = content.endsWith("\n")
  const { didReplace, firstMatchIndex, rewritten } = rewriteTopLevelLines(lines, key, value)

  if (didReplace) {
    return rewritten.join("\n")
  }

  const newDirectiveLine = `${key} ${value}`
  if (firstMatchIndex >= 0) {
    rewritten.splice(firstMatchIndex, 0, newDirectiveLine)
    return rewritten.join("\n")
  }

  return trailingNewline ? `${content}${newDirectiveLine}\n` : `${content}\n${newDirectiveLine}\n`
}
