import { Command } from "commander"
import { resolve } from "node:path"
import { pathToFileURL } from "node:url"

import type { Environment, ServerDefinition } from "./types.js"

import { runPlaybook } from "./runner.js"

const SECONDS_TO_MS = 1000

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

      if (definition.host.length === 0 || definition.run.length === 0) {
        console.error("Error: File must export a valid ServerDefinition (use server() helper)")
        // eslint-disable-next-line node/no-process-exit
        process.exit(2)
      }

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
