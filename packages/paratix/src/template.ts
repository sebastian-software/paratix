import type { Environment } from "./types.js"

import { resolveEnvironment } from "./environment.js"

/**
 * Render a template string by replacing all `\{\{key\}\}` placeholders with
 * the corresponding resolved env values.
 *
 * Placeholders are resolved concurrently-safe but serially to preserve order.
 *
 * @param template - The template string containing placeholders.
 * @param environment - The env map used to resolve placeholder values.
 * @returns The rendered string with all placeholders replaced.
 * @throws {Error} When a placeholder key is not found in `environment`.
 */
export async function renderTemplate(template: string, environment: Environment): Promise<string> {
  // Handle escaped \{{ by replacing with a placeholder
  const escapedBraceMarker = "\x00ESCAPED_BRACE\x00"
  let result = template.replaceAll("\\{{", escapedBraceMarker)

  // Find all {{key}} patterns
  const pattern = /\{\{(?<varName>\w+)\}\}/gv
  const matches: Array<{ full: string; key: string }> = []
  let match: null | RegExpExecArray

  while ((match = pattern.exec(result)) !== null) {
    matches.push({ full: match[0], key: match.groups?.varName ?? "" })
  }

  // Resolve all keys
  for (const { full, key } of matches) {
    // eslint-disable-next-line no-await-in-loop
    const value = await resolveEnvironment(environment, key)
    result = result.replace(full, String(value))
  }

  // Restore escaped braces
  result = result.replaceAll(escapedBraceMarker, "{{")

  return result
}
