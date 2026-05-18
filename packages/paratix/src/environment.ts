import { readFile } from "node:fs/promises"

import type { Environment } from "./types.js"

/**
 * R-0000069: keep this regex in sync with the same pattern used by
 * `collectEnvironment` in cli.ts so values supplied via `--env` and values
 * loaded from a `.env` file go through the same allow-list. Lifting the
 * pattern out of the loader keeps the failure message consistent.
 *
 * R-0000745: exported so `meta.assertAllowedEnvironmentMetaName` can derive
 * its own (dot-aware) variant from the same dotenv allow-list. The pattern
 * itself stays strict here because dotenv keys must not contain dots — the
 * dot-aware extension lives in meta.ts to keep dotenv parsing untouched.
 */
export const ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_]\w*$/v

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

/**
 * R-0000843: bound the size of an inbound dotenv file and the size of each
 * decoded value. A misconfigured operator (or a malicious overlay) could
 * otherwise feed a multi-gigabyte file into the loader and exhaust process
 * memory long before the parser reaches its first real assignment.
 *
 * 1 MiB ist großzügig für legitime `.env`-Dateien (Tausende Schlüssel) und
 * gleichzeitig klein genug, damit der Parser frühzeitig fehlschlägt.
 */
const KIBIBYTE = 1024
const MEBIBYTE = KIBIBYTE * KIBIBYTE
const ENVIRONMENT_FILE_BYTE_LIMIT_MIB = 1
const ENVIRONMENT_VALUE_BYTE_LIMIT_KIB = 64
export const ENVIRONMENT_FILE_BYTE_LIMIT = ENVIRONMENT_FILE_BYTE_LIMIT_MIB * MEBIBYTE
/** Pro-Wert-Cap (64 KiB) für decodierte Werte vor dem Persistieren in der Map. */
export const ENVIRONMENT_VALUE_BYTE_LIMIT = ENVIRONMENT_VALUE_BYTE_LIMIT_KIB * KIBIBYTE

/**
 * R-0000843: control-Bytes (außer Tab, LF, CR) sind in dotenv-Werten nicht
 * vorgesehen. Backspaces, ESC, oder Vertical-Tab überleben den Parser sonst
 * intransparent und können Terminals oder nachgelagerte Shells in
 * unvorhersehbare Zustände bringen. NUL und CR werden bereits in
 * `processValue` abgelehnt; dieses Muster fängt zusätzlich BS, VT, FF und
 * den restlichen C0-Bereich sowie DEL (0x7F) ab. Wird über RegExp()
 * konstruiert, damit die Quelle lesbar bleibt und keine echten
 * Steuerbytes im Source stehen.
 */
// Reject the entire C0 control range except Tab (0x09), LF (0x0A), CR (0x0D),
// plus DEL (0x7F). The regex literal uses JavaScript control-character
// escape sequences so the source stays readable while the produced pattern
// matches the raw control bytes themselves.
/* eslint-disable-next-line regexp/no-control-character -- intentional: pattern catches forbidden control bytes */ /* oxlint-disable-next-line no-control-regex */
const FORBIDDEN_CONTROL_CHARACTER_PATTERN = /[\x00-\x08\v\f\x0E-\x1F\x7F]/v

/**
 * R-0000843: enforce the per-value cap and the control-byte allowlist for a
 * single decoded dotenv value. Extracted from {@link loadDotEnvironment} so
 * the loader stays inside the per-function statement budget while keeping
 * the validation behaviour discoverable from a single helper.
 *
 * @param filePath - Path to the dotenv file (used in error messages).
 * @param lineNumber - 1-based line number for the offending value.
 * @param value - The already-decoded value about to be persisted.
 */
function validateDotEnvironmentValue(filePath: string, lineNumber: number, value: string): void {
  if (Buffer.byteLength(value, "utf8") > ENVIRONMENT_VALUE_BYTE_LIMIT) {
    throw new Error(
      `Invalid env value in ${filePath} line ${lineNumber}: value exceeds the ${ENVIRONMENT_VALUE_BYTE_LIMIT}-byte cap`
    )
  }
  if (FORBIDDEN_CONTROL_CHARACTER_PATTERN.test(value)) {
    throw new Error(
      `Invalid env value in ${filePath} line ${lineNumber}: contains a forbidden control byte`
    )
  }
}

/**
 * R-0000843: enforce the file-size cap before the loader walks the content.
 * Extracted so {@link loadDotEnvironment} stays under the max-statements
 * lint budget while keeping the early-fail behaviour traceable.
 *
 * @param filePath - Path to the dotenv file (used in error messages).
 * @param content - The full UTF-8 content read from `filePath`.
 */
function assertDotEnvironmentFileSize(filePath: string, content: string): void {
  const fileByteLength = Buffer.byteLength(content, "utf8")
  if (fileByteLength > ENVIRONMENT_FILE_BYTE_LIMIT) {
    throw new Error(
      `Refusing to load env file ${filePath}: size ${fileByteLength} bytes exceeds the ${ENVIRONMENT_FILE_BYTE_LIMIT}-byte cap`
    )
  }
}

export async function loadDotEnvironment(filePath: string): Promise<Environment> {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  const content = await readFile(filePath, "utf8")
  // R-0000843: enforce the upper bound on the read content before we
  // tokenise. Byte length is approximated via Buffer.byteLength so the
  // limit reflects the on-disk size, not the JS string length.
  assertDotEnvironmentFileSize(filePath, content)
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
    const value = processValue(trimmed.slice(eqIndex + 1).trim(), filePath, index + 1)
    // R-0000843: reject decoded values that exceed the per-value cap or
    // carry forbidden control bytes (anything outside Tab/LF/CR in the
    // ASCII control range, plus DEL). Tab/LF/CR may appear after
    // double-quoted escape processing and are intentional, but a literal
    // ESC or vertical-tab byte almost always indicates a copy-paste
    // artefact or a hostile payload trying to influence downstream consumers.
    validateDotEnvironmentValue(filePath, index + 1, value)
    environment[key] = value
  }

  return environment
}

function processValue(raw: string, filePath: string, lineNumber: number): string {
  // R-0000747: the double-quoted branch uses NUL (`\0`) as a temporary
  // sentinel for escaped backslashes ("\\\\" → "\0" → "\\"). A literal NUL
  // in the raw input would survive the sentinel swap and emerge as a
  // backslash in the decoded value, silently corrupting the loaded
  // environment. Refuse the file outright so the operator notices the
  // unexpected byte instead of debugging a mangled secret hours later.
  // The same byte is rejected for unquoted/single-quoted values because a
  // downstream consumer (shell, sub-process spawn, system call) treats NUL
  // as a string terminator and would silently truncate the value.
  if (raw.includes("\0")) {
    throw new Error(`Invalid env value in ${filePath} line ${lineNumber}: contains a NUL byte`)
  }

  // R-0000791: reject literal CR (0x0D) bytes for the same reason NUL is
  // rejected — a bare \r emerges as an unprintable byte downstream, hides
  // line-ending mismatches inside dotenv values, and can re-introduce
  // mixed CRLF state into command lines that the SSH command builder
  // already guards against. The double-quoted branch interprets only
  // `\n`/`\\`/`\"` escapes, so a literal CR is never the intended way to
  // smuggle a newline into the value.
  if (raw.includes("\r")) {
    throw new Error(
      `Invalid env value in ${filePath} line ${lineNumber}: contains a carriage return`
    )
  }

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
