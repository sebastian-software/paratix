/* eslint-disable max-lines -- CLI entrypoint co-locates parsers, validators, and command wiring */
import { Command } from "commander"
import { realpathSync } from "node:fs"
import { extname, resolve } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { inspect } from "node:util"
import pc from "picocolors"

import type { Environment, ServerDefinition } from "./types.js"

import { isMissingTsxDependencyError } from "./cliTsxHelpers.js"
import { ENVIRONMENT_FORBIDDEN_KEYS } from "./environment.js"
import { printCliHeader } from "./output.js"
import { type RunOptions, runPlaybook } from "./runner.js"
import { maskRegisteredSecrets } from "./secretSink.js"
import { collectSshConfigErrors } from "./serverDefinitionValidation.js"

declare const PACKAGE_DISPLAY_VERSION: string

const SECONDS_TO_MS = 1000
const ENVIRONMENT_KEY_PATTERN = /^[A-Za-z_]\w*$/v
const FIRST_RUN_ENV_NAME = "PARATIX_FIRST_RUN"
const TYPESCRIPT_ENTRY_EXTENSIONS = new Set([".cts", ".mts", ".ts"])

/**
 * Upper bound for second-based CLI timeouts (24h).
 *
 * Avoids overflow when the parsed value is later multiplied by
 * `SECONDS_TO_MS` and added to `Date.now()` for deadline checks.
 */
const RECONNECT_TIMEOUT_MAX_SECONDS = 86_400

function resolveRealPath(path: string): null | string {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is either import.meta-derived or process argv entrypoint; direct file resolution is the intended check
    return realpathSync(path)
  } catch {
    // Symlink loops, EACCES, ENOENT, or unusual pnpm shim layouts can throw
    // before any try/catch in apply() can intercept the failure. Returning
    // null lets callers fall back safely (e.g. treat as "not direct CLI
    // execution") instead of producing an uncaught Node-internal error.
    return null
  }
}

/**
 * Type guard that checks whether `value` has the shape of a
 * {@link ServerDefinition} — an object with a non-empty string `name`,
 * a non-empty string `host`, a valid `ssh` config, and a non-empty `run` array.
 *
 * @param value - The value to inspect.
 * @returns `true` when `value` satisfies the structural requirements of `ServerDefinition`.
 */
export function isServerDefinitionLike(value: unknown): value is ServerDefinition {
  return collectDefinitionErrors(value).length === 0
}

/** Descriptor for a property validation check. */
type PropertyCheck = {
  /** The key to look up in the object. */
  key: string
  /** The label to use in error messages (defaults to `key`). */
  label?: string
}

/**
 * Validates that a required string property exists, has the correct type, and
 * is not empty.  Pushes a human-readable error into `errors` when any check
 * fails.
 *
 * @param object - The object to inspect.
 * @param check - Property key and optional display label.
 * @param errors - Accumulator for error messages.
 */
function collectStringErrors(
  object: Record<string, unknown>,
  check: PropertyCheck,
  errors: string[]
): void {
  const name = check.label ?? check.key
  if (!(check.key in object)) {
    errors.push(`Missing property '${name}' (expected string)`)
  } else if (typeof object[check.key] !== "string") {
    errors.push(`Invalid property '${name}' (expected string, got ${typeof object[check.key]})`)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by typeof check above
  } else if ((object[check.key] as string).length === 0) {
    errors.push(`Property '${name}' must not be empty`)
  }
}

/**
 * Validates that a required array property exists, has the correct type, and
 * is not empty.  Pushes a human-readable error into `errors` when any check
 * fails.
 *
 * @param object - The object to inspect.
 * @param check - Property key and optional display label.
 * @param errors - Accumulator for error messages.
 */
function collectArrayErrors(
  object: Record<string, unknown>,
  check: PropertyCheck,
  errors: string[]
): void {
  const name = check.label ?? check.key
  if (!(check.key in object)) {
    errors.push(`Missing property '${name}' (expected array)`)
  } else if (!Array.isArray(object[check.key])) {
    errors.push(`Invalid property '${name}' (expected array, got ${typeof object[check.key]})`)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by Array.isArray check above
  } else if ((object[check.key] as unknown[]).length === 0) {
    errors.push(`Property '${name}' must not be empty`)
  }
}

function collectSshErrors(value: Record<string, unknown>, errors: string[]): void {
  if (!("ssh" in value)) {
    errors.push("Missing property 'ssh' (expected object)")
    return
  }
  errors.push(...collectSshConfigErrors(value.ssh))
}

/**
 * Collects human-readable error messages for every property of `value` that
 * does not conform to the `ServerDefinition` shape.
 *
 * @param value - The value to validate.
 * @returns An array of error strings, empty when `value` is structurally valid.
 */
export function collectDefinitionErrors(value: unknown): string[] {
  const errors: string[] = []
  if (typeof value !== "object" || value === null) {
    errors.push("Export is not an object")
    return errors
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by typeof/null checks above
  const object = value as Record<string, unknown>
  collectStringErrors(object, { key: "name" }, errors)
  collectStringErrors(object, { key: "host" }, errors)
  collectSshErrors(object, errors)
  collectArrayErrors(object, { key: "run" }, errors)
  return errors
}

/**
 * Assertion function that ensures `value` is a valid {@link ServerDefinition}.
 *
 * When validation fails, all collected errors are printed to stderr and the
 * process exits with code `2`, so callers can treat the function as a
 * narrowing assertion without additional error handling.
 *
 * @param value - The value to validate.
 * @param file - Path of the file that exported `value`, used in the error message.
 */
function validateServerDefinition(value: unknown, file: string): asserts value is ServerDefinition {
  if (isServerDefinitionLike(value)) {
    return
  }
  const errors = collectDefinitionErrors(value)
  const details = errors.map((entry) => `  - ${entry}`).join("\n")
  console.error(
    `Error: ${file} does not export a valid ServerDefinition.\n${details}\n  Use the server() helper to create a valid definition.`
  )
  // eslint-disable-next-line node/no-process-exit
  process.exit(2)
}

/**
 * Returns a human-readable string for any caught value.
 * Uses `.message` for `Error` instances and falls back to the string
 * representation for primitives.  For plain objects that have no meaningful
 * `toString`, the JSON representation is used instead of `[object Object]`.
 *
 * @param value - The value to convert to a string.
 * @returns A human-readable string representation of `value`.
 */
function errorToString(value: unknown): string {
  if (value instanceof Error) return maskRegisteredSecrets(value.message)
  if (typeof value === "object" && value !== null) {
    try {
      return maskRegisteredSecrets(JSON.stringify(value))
    } catch {
      return maskRegisteredSecrets(inspect(value, { breakLength: Infinity, depth: 5 }))
    }
  }
  return maskRegisteredSecrets(String(value))
}

/**
 * Walks the cause chain of `error` and prints each cause to stderr.
 *
 * Uses a WeakSet to detect cyclic `cause` references (e.g. produced by
 * third-party libraries that wrap the same Error twice) so the loop always
 * terminates instead of hanging the CLI before `process.exit` is reached.
 *
 * @param error - The root `Error` whose `.cause` chain should be printed.
 */
function printCauseChain(error: Error): void {
  const visitedCauses = new WeakSet<Error>()
  visitedCauses.add(error)
  let cause = error.cause
  while (cause != null) {
    if (cause instanceof Error) {
      if (visitedCauses.has(cause)) {
        console.error("  Caused by: <cycle detected>")
        return
      }
      visitedCauses.add(cause)
    }
    console.error(`  Caused by: ${errorToString(cause)}`)
    cause = cause instanceof Error ? cause.cause : undefined
  }
}

/**
 * Prints a structured error message to stderr, including the cause chain and
 * optionally the full stack trace when `verbose` is `true`.
 *
 * @param error - The caught value (may be any type).
 * @param verbose - When `true`, the stack trace of `error` is printed.
 */
export function printExceptionError(error: unknown, verbose: boolean): void {
  console.error(`Error: ${errorToString(error)}`)

  if (error instanceof Error) {
    printCauseChain(error)

    if (verbose && error.stack != null) {
      console.error(`\n${maskRegisteredSecrets(error.stack)}`)
    }
  }
}

/**
 * Handles a failed attempt to load the `tsx` runtime.
 *
 * When the failed import is for a TypeScript file (`.ts`, `.mts`, `.cts`), a
 * clear error message is printed to stderr and the process exits with code 2.
 * For JavaScript files the failure is silently ignored because `tsx` is not
 * required there.
 *
 * @param filePath - The resolved path of the playbook file being loaded.
 */
export function handleTsxLoadFailure(filePath: string): void {
  if (/\.[cm]?ts$/v.test(filePath)) {
    console.error(
      `${pc.red("Error:")} tsx is required to run TypeScript playbooks but could not be loaded.\n` +
        `  Install it with: ${pc.bold("npm install -g tsx")} or add it as a devDependency.`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
}

/**
 * Returns whether the current CLI module is the direct process entrypoint.
 *
 * This resolves symlinks on both sides so pnpm-style executable shims and
 * symlinked `node_modules` entries still count as direct execution.
 *
 * @param moduleUrl - The current module URL, usually `import.meta.url`.
 * @param candidateEntryScript - The process entry script path, usually `process.argv[1]`.
 * @returns `true` when both paths resolve to the same file on disk.
 */
export function isDirectCliExecution(moduleUrl: string, candidateEntryScript?: string): boolean {
  if (candidateEntryScript == null) {
    return false
  }

  const moduleRealPath = resolveRealPath(fileURLToPath(moduleUrl))
  const entryRealPath = resolveRealPath(candidateEntryScript)
  if (moduleRealPath == null || entryRealPath == null) {
    return false
  }

  return moduleRealPath === entryRealPath
}

export function applyCliEnvironmentOverrides(
  environment: Environment,
  options: { firstRun: boolean }
): Environment {
  if (!options.firstRun) return environment
  return { ...environment, [FIRST_RUN_ENV_NAME]: "true" }
}

/**
 * Snapshot of the original `process.env[FIRST_RUN_ENV_NAME]` value before the
 * outermost {@link applyCliProcessEnvironment} mutation. The CLI is normally
 * single-shot, but tests and embedded runners can call it reentrantly. Without
 * this stack the second call would capture the synthetic "true" the first call
 * just installed, and "restore" it back instead of removing the key. The
 * snapshot is only cleared once the outermost frame restores, so nested calls
 * always see the genuine pre-CLI value as the eventual restore target.
 */
type FirstRunEnvironmentSnapshot = {
  hadPreviousValue: boolean
  previousValue: string | undefined
}

let firstRunEnvironmentSnapshot: FirstRunEnvironmentSnapshot | null = null
let firstRunEnvironmentDepth = 0

function captureFirstRunEnvironmentSnapshot(): FirstRunEnvironmentSnapshot {
  if (firstRunEnvironmentSnapshot != null) {
    return firstRunEnvironmentSnapshot
  }
  const snapshot: FirstRunEnvironmentSnapshot = {
    hadPreviousValue: Object.hasOwn(process.env, FIRST_RUN_ENV_NAME),
    previousValue: process.env[FIRST_RUN_ENV_NAME],
  }
  firstRunEnvironmentSnapshot = snapshot
  return snapshot
}

export function applyCliProcessEnvironment(options: { firstRun: boolean }): () => void {
  const snapshot = captureFirstRunEnvironmentSnapshot()
  firstRunEnvironmentDepth += 1
  let restored = false
  const restoreProcessEnvironment = (): void => {
    if (restored) return
    restored = true
    firstRunEnvironmentDepth -= 1
    if (firstRunEnvironmentDepth > 0) {
      // Inner frame finished but an outer frame still relies on the synthetic
      // "true" value — leave process.env alone until the outer frame restores.
      return
    }
    firstRunEnvironmentSnapshot = null
    // Use FIRST_RUN_ENV_NAME consistently and avoid assigning `undefined`
    // (which would coerce to the literal string "undefined" on process.env).
    if (!snapshot.hadPreviousValue || snapshot.previousValue == null) {
      Reflect.deleteProperty(process.env, FIRST_RUN_ENV_NAME)
      return
    }
    process.env[FIRST_RUN_ENV_NAME] = snapshot.previousValue
  }
  if (!options.firstRun) return restoreProcessEnvironment
  process.env[FIRST_RUN_ENV_NAME] = "true"
  return restoreProcessEnvironment
}

async function registerTsxForTypeScriptEntry(filePath: string): Promise<void> {
  try {
    const tsx = (await import("tsx/esm/api")) as { register: () => void }
    tsx.register()
  } catch (error) {
    if (isMissingTsxDependencyError(error)) {
      handleTsxLoadFailure(filePath)
      return
    }
    throw new Error(
      `Failed to load tsx/esm/api: ${error instanceof Error ? error.message : String(error)}`,
      {
        cause: error,
      }
    )
  }
}

export async function loadServerDefinitionFromFile(
  file: string,
  options: { firstRun: boolean }
): Promise<ServerDefinition> {
  const filePath = resolve(file)
  const fileUrl = pathToFileURL(filePath).href
  const isTypeScriptEntry = TYPESCRIPT_ENTRY_EXTENSIONS.has(extname(filePath).toLowerCase())

  const restoreProcessEnvironment = applyCliProcessEnvironment(options)

  try {
    // Register tsx for TypeScript imports.
    // R-0000071: narrow the catch so only a genuine missing-tsx error is
    // routed through handleTsxLoadFailure. Any other error from the dynamic
    // import (incompatible Node, broken install, OOM, transitive dep
    // missing) is rethrown with the original cause so the CLI exit handler
    // surfaces the real loader failure instead of falsely reporting that
    // tsx is not installed.
    if (isTypeScriptEntry) await registerTsxForTypeScriptEntry(filePath)

    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- Dynamic import has unknown shape
    const imported = await import(fileUrl)
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-type-assertion -- Accessing .default on dynamic import
    const definition = (imported.default ?? imported) as ServerDefinition

    validateServerDefinition(definition, filePath)
    return definition
  } finally {
    restoreProcessEnvironment()
  }
}

type ApplyCommandOptions = {
  dryRun: boolean
  env: Environment
  envFile?: string
  firstRun: boolean
  reconnectTimeout?: number
  verbose: boolean
}

type RunPlaybookFunction = (definition: ServerDefinition, options: RunOptions) => Promise<void>

export async function runApplyCommand(
  file: string,
  options: ApplyCommandOptions,
  run: RunPlaybookFunction = runPlaybook
): Promise<void> {
  printCliHeader(PACKAGE_DISPLAY_VERSION)
  const environmentOverrides = applyCliEnvironmentOverrides(options.env, {
    firstRun: options.firstRun,
  })
  const definition = await loadServerDefinitionFromFile(file, {
    firstRun: options.firstRun,
  })

  const runOptions: RunOptions = {
    dryRun: options.dryRun,
    envFile: options.envFile,
    envOverrides: environmentOverrides,
    verbose: options.verbose,
  }
  if (options.reconnectTimeout !== undefined) {
    runOptions.reconnectTimeout = options.reconnectTimeout * SECONDS_TO_MS
  }

  await run(definition, runOptions)
}

export function exitAfterApplyError(error: unknown, verbose: boolean): never {
  printExceptionError(error, verbose)
  // eslint-disable-next-line node/no-process-exit
  process.exit(process.exitCode ?? 2)
}

const program = new Command()

program
  .name("paratix")
  .description("Idempotent VPS setup tool in TypeScript")
  .version(PACKAGE_DISPLAY_VERSION)

program
  .command("apply <file>")
  .description("Apply a server definition")
  .option(
    "--dry-run",
    "Only check, do not apply. Some modules validate prospective config but cannot verify runtime restarts.",
    false
  )
  .option("--env <key=value...>", "Set env values", collectEnvironment, {})
  .option("--env-file <path>", "Load dotenv file")
  .option("--first-run", "Set PARATIX_FIRST_RUN=true before loading the playbook", false)
  .option(
    "--reconnect-timeout <seconds>",
    "SSH reconnect timeout (seconds, max 86400)",
    parseReconnectTimeoutSeconds
  )
  .option("--verbose", "Show full stack traces on error", false)
  .action(async (file: string, options: Record<string, unknown>) => {
    try {
      await runApplyCommand(file, {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        dryRun: options.dryRun as boolean,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        env: options.env as Environment,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        envFile: options.envFile as string | undefined,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        firstRun: options.firstRun as boolean,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        reconnectTimeout: options.reconnectTimeout as number,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        verbose: options.verbose as boolean,
      })
    } catch (error) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
      exitAfterApplyError(error, options.verbose as boolean)
    }
  })

export function parsePositiveNumber(value: string, options: { max?: number } = {}): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    console.error(`Invalid --reconnect-timeout value: ${value} (expected a positive number)`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  // Enforce an explicit upper bound to prevent later overflow when the value
  // is converted to milliseconds and added to `Date.now()`.
  if (options.max !== undefined && parsed > options.max) {
    console.error(
      `Invalid --reconnect-timeout value: ${value} (must be at most ${options.max} seconds)`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  return parsed
}

/**
 * Commander option parser for `--reconnect-timeout` (seconds).
 *
 * Wraps {@link parsePositiveNumber} with a hard upper bound of
 * {@link RECONNECT_TIMEOUT_MAX_SECONDS} so values such as `1e10` are rejected
 * with a clear error message instead of silently producing a deadline that
 * overflows `Number.MAX_SAFE_INTEGER` after the seconds-to-ms multiplication.
 *
 * @param value - The raw CLI string (in seconds) to parse.
 * @returns The validated numeric value.
 */
export function parseReconnectTimeoutSeconds(value: string): number {
  return parsePositiveNumber(value, { max: RECONNECT_TIMEOUT_MAX_SECONDS })
}

export function collectEnvironment(
  value: string,
  previous: Record<string, string>
): Record<string, string> {
  const eqIndex = value.indexOf("=")
  if (eqIndex === -1) {
    console.error(`Invalid --env format: ${value} (expected key=value)`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  const key = value.slice(0, eqIndex)
  const value_ = value.slice(eqIndex + 1)
  if (!ENVIRONMENT_KEY_PATTERN.test(key)) {
    console.error(
      `Invalid --env name: ${key === "" ? "(empty)" : key} (expected [A-Za-z_][A-Za-z0-9_]*)`
    )
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  if (ENVIRONMENT_FORBIDDEN_KEYS.has(key)) {
    console.error(`Forbidden --env name: ${key} (reserved JavaScript identifier)`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  return { ...previous, [key]: value_ }
}

// Only parse when executed directly, not when imported (e.g. in tests)
const entryScript = process.argv[1]
if (isDirectCliExecution(import.meta.url, entryScript)) {
  await program.parseAsync()
}
