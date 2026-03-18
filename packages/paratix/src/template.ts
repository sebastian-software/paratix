import type { Environment } from "./types.js"

import { resolveEnvironment } from "./environment.js"
import { shellQuote } from "./sshHelpers.js"

/** Options for controlling template rendering behaviour. */
export type RenderOptions = {
  /** When `true`, every placeholder must use an explicit modifier (e.g. `|shell` or `|raw`). */
  strict?: boolean
}

/** Registry of supported template modifiers. */
const modifiers: Partial<Record<string, (value: string) => string>> = {
  raw: (value: string) => value,
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
 * Throw if any placeholder in {@link matches} lacks an explicit modifier.
 *
 * @param matches - The regex matches to validate.
 */
function enforceStrictModifiers(matches: RegExpExecArray[]): void {
  for (const match of matches) {
    if (match.groups?.modifier === undefined) {
      throw new Error(
        `Strict mode: placeholder "{{${match.groups?.varName}}}" requires an explicit modifier (e.g. |shell or |raw)`
      )
    }
  }
}

/**
 * Render a template string by replacing all `\{\{key\}\}` (or `\{\{key|modifier\}\}`)
 * placeholders with the corresponding resolved env values.
 *
 * **Security: No default escaping.** Values are inserted verbatim unless a modifier
 * is applied. When the rendered output is used in a shell context (e.g. a script or
 * shell config file), always use the `|shell` modifier on every user-controlled
 * placeholder to prevent shell injection: `\{\{VALUE|shell\}\}`.
 *
 * Supported modifiers:
 * - `shell` — wraps the resolved value with {@link shellQuote} for safe shell interpolation.
 * - `raw` — passes the value through unchanged (explicit verbatim insertion).
 *
 * When `options.strict` is `true` (the default), every placeholder **must** specify
 * a modifier; bare `\{\{KEY\}\}` placeholders will throw an error. Pass `strict: false`
 * to disable this check.
 *
 * Placeholders are resolved concurrently via Promise.all; insertion order is preserved.
 *
 * @param template - The template string containing placeholders.
 * @param environment - The env map used to resolve placeholder values.
 * @param options - Optional rendering options.
 * @returns The rendered string with all placeholders replaced.
 * @throws {Error} When a placeholder key is not found in `environment`.
 * @throws {Error} When `strict` is `true` and a placeholder has no modifier.
 */
export async function renderTemplate(
  template: string,
  environment: Environment,
  options?: RenderOptions
): Promise<string> {
  // Handle escaped \{{ by replacing with a placeholder
  const escapedBraceMarker = "\x00ESCAPED_BRACE\x00"
  const result = template.replaceAll("\\{{", escapedBraceMarker)

  // Find all {{key}} or {{key|modifier}} patterns and resolve values in parallel
  // eslint-disable-next-line security/detect-unsafe-regex, regexp/no-unused-capturing-group -- modifier group is consumed via match.groups
  const pattern = /\{\{(?<varName>\w+)(?:\|(?<modifier>\w*))?\}\}/gv
  const matches = [...result.matchAll(pattern)]

  // In strict mode, validate that all placeholders have explicit modifiers before resolving values
  if (options?.strict ?? true) enforceStrictModifiers(matches)

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
