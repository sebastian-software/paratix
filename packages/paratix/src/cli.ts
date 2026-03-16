import { Command } from "commander"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"
import pc from "picocolors"

import type { Environment, ServerDefinition } from "./types.js"

import { runPlaybook } from "./runner.js"

declare const PACKAGE_VERSION: string

const SECONDS_TO_MS = 1000
const DEFAULT_RECONNECT_TIMEOUT_SECONDS = 300

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

/**
 * Validates the `ssh` property of a server definition candidate.
 * Pushes errors for a missing / wrong-typed `ssh` object as well as for its
 * required sub-fields (`ports`, `privateKey`, `user`).
 *
 * @param value - The top-level object containing the `ssh` property.
 * @param errors - Accumulator for error messages.
 */
function collectSshErrors(value: Record<string, unknown>, errors: string[]): void {
  if (!("ssh" in value)) {
    errors.push("Missing property 'ssh' (expected object)")
    return
  }
  if (value.ssh === null) {
    errors.push("Invalid property 'ssh' (expected object, got null)")
    return
  }
  if (typeof value.ssh !== "object") {
    errors.push(`Invalid property 'ssh' (expected object, got ${typeof value.ssh})`)
    return
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- narrowed by typeof/null checks above
  const ssh = value.ssh as Record<string, unknown>
  collectArrayErrors(ssh, { key: "ports", label: "ssh.ports" }, errors)
  collectStringErrors(ssh, { key: "privateKey", label: "ssh.privateKey" }, errors)
  collectStringErrors(ssh, { key: "user", label: "ssh.user" }, errors)
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
  if (value instanceof Error) return value.message
  if (typeof value === "object" && value !== null) return JSON.stringify(value)
  return String(value)
}

/**
 * Walks the cause chain of `error` and prints each cause to stderr.
 *
 * @param error - The root `Error` whose `.cause` chain should be printed.
 */
function printCauseChain(error: Error): void {
  let cause = error.cause
  while (cause != null) {
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
      console.error(`\n${error.stack}`)
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

const program = new Command()

program
  .name("paratix")
  .description("Idempotent VPS setup tool in TypeScript")
  .version(PACKAGE_VERSION)

program
  .command("apply <file>")
  .description("Apply a server definition")
  .option("--dry-run", "Only check, do not apply", false)
  .option("--env <key=value...>", "Set env values", collectEnvironment, {})
  .option("--env-file <path>", "Load dotenv file")
  .option(
    "--reconnect-timeout <seconds>",
    "SSH reconnect timeout",
    parsePositiveNumber,
    DEFAULT_RECONNECT_TIMEOUT_SECONDS
  )
  .option("--verbose", "Show full stack traces on error", false)
  .action(async (file: string, options: Record<string, unknown>) => {
    try {
      const filePath = resolve(file)
      const fileUrl = pathToFileURL(filePath).href

      // Register tsx for TypeScript imports
      await import("tsx/esm/api")
        .then((tsx: { register: () => void }) => {
          tsx.register()
        })
        .catch(() => {
          handleTsxLoadFailure(filePath)
        })

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- Dynamic import has unknown shape
      const imported = await import(fileUrl)
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-type-assertion -- Accessing .default on dynamic import
      const definition = (imported.default ?? imported) as ServerDefinition

      validateServerDefinition(definition, filePath)

      await runPlaybook(definition, {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        dryRun: options.dryRun as boolean,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        envFile: options.envFile as string | undefined,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        envOverrides: options.env as Environment,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        reconnectTimeout: (options.reconnectTimeout as number) * SECONDS_TO_MS,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
        verbose: options.verbose as boolean,
      })
    } catch (error) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- Commander options typed as Record<string, unknown>
      printExceptionError(error, options.verbose as boolean)
      // eslint-disable-next-line node/no-process-exit
      process.exit(process.exitCode ?? 2)
    }
  })

export function parsePositiveNumber(value: string): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    console.error(`Invalid --reconnect-timeout value: ${value} (expected a positive number)`)
    // eslint-disable-next-line node/no-process-exit
    process.exit(2)
  }
  return parsed
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
  return { ...previous, [key]: value_ }
}

// Only parse when executed directly, not when imported (e.g. in tests)
const entryScript = process.argv[1]
// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- argv[1] can be undefined at runtime despite string[] type
if (entryScript != null && import.meta.url.endsWith(entryScript.replaceAll("\\", "/"))) {
  program.parse()
}
