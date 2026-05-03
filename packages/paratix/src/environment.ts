import { readFile } from "node:fs/promises"

import type { Environment } from "./types.js"

/**
 * R-0000069: keep this regex in sync with the same pattern used by
 * `collectEnvironment` in cli.ts so values supplied via `--env` and values
 * loaded from a `.env` file go through the same allow-list. Lifting the
 * pattern out of the loader keeps the failure message consistent.
 */
const ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_]\w*$/v

/**
 * Reserved JavaScript identifiers that, when set as a property, can leak
 * into prototype semantics on a plain object. The loader rejects them
 * explicitly even though the regex above already excludes some of these
 * (e.g. those starting with non-word characters); the explicit list is the
 * defensive failsafe so the behaviour is obvious from the source.
 */
export const ENVIRONMENT_FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"])

/**
 * R-0000069/R-0000070: produce a null-prototype object typed as
 * {@link Environment}. The wrapper exists because
 * `Object.create(null) as Environment` is reported as an unsafe-`any`
 * assertion by the type-aware lint rule; routing through this helper
 * narrows the cast to a single, documented place.
 *
 * @returns A fresh empty {@link Environment} without a prototype chain.
 */
export function createNullPrototypeEnvironment(): Environment {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- intentional: Object.create(null) is the prototype-pollution defense
  return Object.create(null) as Environment
}

/**
 * Resolve a single env key to its concrete value.
 * Lazy function values are awaited; plain primitive values are returned as-is.
 *
 * @param environment - The env map to look up the key in.
 * @param key - The key to resolve.
 * @returns The resolved primitive value.
 * @throws {Error} When the key is not present in `environment`.
 */
export async function resolveEnvironment(
  environment: Environment,
  key: string
): Promise<boolean | number | string> {
  const value = environment[key]
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Record index may be undefined at runtime
  if (value === undefined) {
    throw new Error(`Env key "${key}" is not defined`)
  }
  if (typeof value === "function") {
    return value()
  }
  return value
}

/**
 * Parse a `.env` file and return its contents as an {@link Environment} map.
 * Blank lines and lines starting with `#` are ignored.
 * Surrounding single or double quotes are stripped from values.
 * Double-quoted values support escape sequences (`\\n`, `\\"`, `\\\\`).
 * Unquoted values support inline comments (`value # comment`, `value\t# comment`).
 *
 * @param filePath - Absolute path to the `.env` file.
 * @returns The parsed env map.
 */
/**
 * R-0000069: enforce the same key allow-list that `collectEnvironment` in
 * cli.ts applies, and explicitly reject reserved JavaScript identifiers
 * that could leak into prototype semantics. Throws an Error that names the
 * file, the 1-based line number and the offending key.
 *
 * @param filePath - Path to the `.env` file (used in the error message).
 * @param lineNumber - 1-based line number (used in the error message).
 * @param key - The candidate key from the parsed line.
 */
function validateDotEnvironmentKey(filePath: string, lineNumber: number, key: string): void {
  if (!ENVIRONMENT_KEY_PATTERN.test(key)) {
    throw new Error(
      `Invalid env key in ${filePath} line ${lineNumber}: ${key === "" ? "(empty)" : JSON.stringify(key)} (expected [A-Za-z_][A-Za-z0-9_]*)`
    )
  }
  if (ENVIRONMENT_FORBIDDEN_KEYS.has(key)) {
    throw new Error(
      `Forbidden env key in ${filePath} line ${lineNumber}: ${JSON.stringify(key)} (reserved JavaScript identifier)`
    )
  }
}

export async function loadDotEnvironment(filePath: string): Promise<Environment> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = await readFile(filePath, "utf8")
  // R-0000069/R-0000070: use a null-prototype object so a malicious
  // `__proto__` line cannot pollute the loaded map even before the
  // explicit reject below catches it. This complements the explicit
  // ENVIRONMENT_FORBIDDEN_KEYS check and the ENVIRONMENT_KEY_PATTERN
  // allow-list.
  const environment: Environment = createNullPrototypeEnvironment()

  const lines = content.split("\n")
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const eqIndex = trimmed.indexOf("=")
    if (eqIndex === -1) continue

    const key = trimmed.slice(0, eqIndex).trim()
    validateDotEnvironmentKey(filePath, index + 1, key)
    environment[key] = processValue(trimmed.slice(eqIndex + 1).trim())
  }

  return environment
}

function processValue(raw: string): string {
  if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) {
    // Double-quoted: strip quotes and process escape sequences.
    // Use \0 as sentinel for escaped backslashes — safe because .env files never contain null bytes.
    return raw
      .slice(1, -1)
      .replaceAll("\\\\", "\0")
      .replaceAll("\\n", "\n")
      .replaceAll('\\"', '"')
      .replaceAll("\0", "\\")
  }
  if (raw.length >= 2 && raw.startsWith("'") && raw.endsWith("'")) {
    // Single-quoted: strip quotes, keep value literal
    return raw.slice(1, -1)
  }
  // Unquoted: strip inline comments after any whitespace before #
  const commentIndex = raw.search(/\s#/v)
  return commentIndex === -1 ? raw : raw.slice(0, commentIndex).trimEnd()
}

/**
 * Merge multiple env maps left-to-right into a new object.
 * Later entries overwrite earlier ones for the same key.
 * `undefined` entries are silently skipped.
 *
 * @param environments - One or more env maps to merge.
 * @returns The merged env map.
 */
export function mergeEnvironment(...environments: Array<Environment | undefined>): Environment {
  // R-0000070: start from a null-prototype object so reserved property
  // names like `__proto__` and `constructor` cannot inherit prototype
  // semantics on the merged result. Downstream consumers
  // (resolveEnvironment, resolveEnvironmentAsString, template rendering,
  // meta.env) only access the map via bracket notation and Object.entries,
  // both of which work on null-prototype objects.
  const result: Environment = createNullPrototypeEnvironment()
  for (const environment of environments) {
    if (environment != null) {
      Object.assign(result, environment)
    }
  }
  return result
}

/**
 * Like {@link resolveEnvironment} but always returns a string.
 * Numbers are converted via `String()`.
 *
 * @param environment - The env map to look up the key in.
 * @param key - The key to resolve.
 * @returns The resolved value as a string.
 */
export async function resolveEnvironmentAsString(
  environment: Environment,
  key: string
): Promise<string> {
  const value = await resolveEnvironment(environment, key)
  return String(value)
}
