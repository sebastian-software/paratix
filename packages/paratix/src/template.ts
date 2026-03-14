import type { Environment } from "./types.js"

import { resolveEnvironment } from "./environment.js"

/**
 * Render a template string by replacing all `\{\{key\}\}` placeholders with
 * the corresponding resolved env values.
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

  // Find all {{key}} patterns and resolve values in parallel
  const pattern = /\{\{(?<varName>\w+)\}\}/gv
  const matches = [...result.matchAll(pattern)]
  const resolvedValues = await Promise.all(
    matches.map(async (match) => resolveEnvironment(environment, match.groups?.varName ?? ""))
  )

  // Build result from segments between matches
  let cursor = 0
  let output = ""

  for (const [index, match] of matches.entries()) {
    const matchIndex = match.index
    output += result.slice(cursor, matchIndex) + String(resolvedValues[index])
    cursor = matchIndex + match[0].length
  }

  output += result.slice(cursor)

  // Restore escaped braces
  output = output.replaceAll(escapedBraceMarker, "{{")

  return output
}
