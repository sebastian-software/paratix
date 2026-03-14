import { Command } from "commander"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"

import type { Environment, ServerDefinition } from "./types.js"

import { runPlaybook } from "./runner.js"

const SECONDS_TO_MS = 1000

/**
 * Type guard that checks whether `value` has the minimal shape of a
 * {@link ServerDefinition} (an object with a string `host` and an array `run`).
 *
 * @param value - The value to inspect.
 * @returns `true` when `value` satisfies the structural requirements of `ServerDefinition`.
 */
export function isServerDefinitionLike(value: unknown): value is ServerDefinition {
  return collectDefinitionErrors(value).length === 0
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
  if (!("host" in value)) {
    errors.push("Missing property 'host' (expected string)")
  } else if (typeof value.host !== "string") {
    errors.push(`Invalid property 'host' (expected string, got ${typeof value.host})`)
  } else if (value.host.length === 0) {
    errors.push("Property 'host' must not be empty")
  }
  if (!("run" in value)) {
    errors.push("Missing property 'run' (expected array)")
  } else if (!Array.isArray(value.run)) {
    errors.push(`Invalid property 'run' (expected array, got ${typeof value.run})`)
  } else if (value.run.length === 0) {
    errors.push("Property 'run' must not be empty")
  }
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

const program = new Command()

program.name("paratix").description("Idempotent VPS setup tool in TypeScript").version("0.1.0")

program
  .command("apply <file>")
  .description("Apply a server definition")
  .option("--dry-run", "Only check, do not apply", false)
  .option("--env <key=value...>", "Set env values", collectEnvironment, {})
  .option("--env-file <path>", "Load dotenv file")
  .option("--reconnect-timeout <seconds>", "SSH reconnect timeout", "300")
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
          // noop
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
        reconnectTimeout: Number(options.reconnectTimeout) * SECONDS_TO_MS,
      })
    } catch (error) {
      console.error(`Error: ${String(error)}`)
      // eslint-disable-next-line node/no-process-exit
      process.exit(2)
    }
  })

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
