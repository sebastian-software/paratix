import type { Environment } from "./types.js"

import { resolveEnvironment } from "./environment.js"
import { shellQuote } from "./sshHelpers.js"

/** Registry of supported template modifiers. */
const modifiers: Partial<Record<string, (value: string) => string>> = {
  shell: shellQuote,
}

/**
 * Apply a template modifier to a resolved value.
 *
 * @param value - The stringified resolved value.
 * @param modifier - The modifier name extracted from the placeholder, or `undefined` if none.
 * @returns The value after applying the modifier transformation.
 */
function applyModifier(value: string, modifier: string | undefined): string {
  if (modifier === undefined) return value
  const transform = modifiers[modifier]
  if (!transform) throw new Error(`Unknown template modifier "${modifier}"`)
  return transform(value)
}

/**
 * Render a template string by replacing all `\{\{key\}\}` (or `\{\{key|modifier\}\}`)
 * placeholders with the corresponding resolved env values.
 *
 * Supported modifiers:
 * - `shell` — wraps the resolved value with {@link shellQuote} for safe shell interpolation.
 *
 * Placeholders are resolved concurrently via Promise.all; insertion order is preserved.
 *
 * @param template - The template string containing placeholders.
 * @param environment - The env map used to resolve placeholder values.
 * @returns The rendered string with all placeholders replaced.
 * @throws {Error} When a placeholder key is not found in `environment`.
 */
export async function renderTemplate(template: string, environment: Environment): Promise<string> {
  // Handle escaped \{{ by replacing with a placeholder
  const escapedBraceMarker = "\x00ESCAPED_BRACE\x00"
  const result = template.replaceAll("\\{{", escapedBraceMarker)

  // Find all {{key}} or {{key|modifier}} patterns and resolve values in parallel
  // eslint-disable-next-line security/detect-unsafe-regex, regexp/no-unused-capturing-group -- modifier group is consumed via match.groups
  const pattern = /\{\{(?<varName>\w+)(?:\|(?<modifier>\w*))?\}\}/gv
  const matches = [...result.matchAll(pattern)]
  const resolvedValues = await Promise.all(
    matches.map(async (match) => resolveEnvironment(environment, match.groups?.varName ?? ""))
  )

  // Build result from segments between matches
  let cursor = 0
  let output = ""

  for (const [index, match] of matches.entries()) {
    const matchIndex = match.index
    const value = applyModifier(String(resolvedValues[index]), match.groups?.modifier)
    output += result.slice(cursor, matchIndex) + value
    cursor = matchIndex + match[0].length
  }

  output += result.slice(cursor)

  // Restore escaped braces
  return output.replaceAll(escapedBraceMarker, "{{")
}
