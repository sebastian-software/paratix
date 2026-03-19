import { readFile } from "node:fs/promises"

import type { Environment } from "./types.js"

/**
 * Resolve a single env key to its concrete value.
 * Lazy function values are awaited; plain strings and numbers are returned as-is.
 *
 * @param environment - The env map to look up the key in.
 * @param key - The key to resolve.
 * @returns The resolved string or number value.
 * @throws {Error} When the key is not present in `environment`.
 */
export async function resolveEnvironment(
  environment: Environment,
  key: string
): Promise<number | string> {
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
export async function loadDotEnvironment(filePath: string): Promise<Environment> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = await readFile(filePath, "utf8")
  const environment: Environment = {}

  for (const line of content.split("\n")) {
    const trimmed = line.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const eqIndex = trimmed.indexOf("=")
    if (eqIndex === -1) continue

    const key = trimmed.slice(0, eqIndex).trim()
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
  const result: Environment = {}
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
