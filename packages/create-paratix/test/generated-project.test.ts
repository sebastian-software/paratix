import { writeFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import {
  createScaffoldedProject,
  describeLintOutcome,
  ESLINT_BINARY_PATH,
  linkParatixRuntime,
  linkWorkspaceDependency,
  PRETTIER_BINARY_PATH,
  runInProject,
  SCAFFOLD_VARIANTS,
  type ScaffoldVariant,
  TSC_BINARY_PATH,
} from "./scaffoldFixtures.js"

// Scaffolding plus a full ESLint run sits just above Vitest's default timeout.
const CHECK_TIMEOUT_MS = 60_000

/**
 * Scaffold a project and give it just enough of a `node_modules` to be checked.
 *
 * @param variant - Which scaffold shape to produce.
 * @returns The project directory and its cleanup callback.
 */
function prepareCheckableProject(variant: ScaffoldVariant): {
  cleanup: () => void
  projectDirectory: string
} {
  const { cleanup, projectDirectory } = createScaffoldedProject(variant)
  try {
    linkWorkspaceDependency(projectDirectory, "eslint-config-setup")
    linkWorkspaceDependency(projectDirectory, "jiti")
    // The generated tsconfig sets types: ["node"], which tsc resolves from the
    // project rather than the workspace.
    linkWorkspaceDependency(projectDirectory, "@types/node")
    linkParatixRuntime(projectDirectory)
  } catch (error) {
    cleanup()
    throw error
  }
  return { cleanup, projectDirectory }
}

/**
 * Verify that a scaffolded project passes the checks it ships.
 *
 * These run the workspace's own eslint, prettier and tsc against the generated
 * files, which keeps them fast and offline. The versions therefore differ from
 * the ones the scaffold declares; closing that gap is the job of the
 * install-level check under `test/integration/`.
 */
describe("a scaffolded project passes its own checks", () => {
  for (const variant of SCAFFOLD_VARIANTS) {
    it(
      `lints clean in the ${variant} variant`,
      () => {
        const { cleanup, projectDirectory } = prepareCheckableProject(variant)

        try {
          const failure = describeLintOutcome(
            runInProject(projectDirectory, ESLINT_BINARY_PATH, ["."])
          )

          expect(failure).toBeNull()
        } finally {
          cleanup()
        }
      },
      CHECK_TIMEOUT_MS
    )

    it(
      `is formatted according to its own prettier config in the ${variant} variant`,
      () => {
        const { cleanup, projectDirectory } = prepareCheckableProject(variant)

        try {
          // Prettier resolves .prettierrc from the working directory, so this
          // checks the generated files against the configuration the scaffold
          // hands out rather than the workspace's own.
          const result = runInProject(projectDirectory, PRETTIER_BINARY_PATH, [
            "--check",
            "server.ts",
          ])

          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0)
        } finally {
          cleanup()
        }
      },
      CHECK_TIMEOUT_MS
    )

    it(
      `type-checks in the ${variant} variant`,
      () => {
        const { cleanup, projectDirectory } = prepareCheckableProject(variant)

        try {
          writeFileSync(
            join(projectDirectory, "tsconfig.typecheck.json"),
            `${JSON.stringify({ extends: "./tsconfig.json", include: ["server.ts"] }, null, 2)}\n`
          )

          const result = runInProject(projectDirectory, TSC_BINARY_PATH, [
            "--noEmit",
            "--project",
            "tsconfig.typecheck.json",
          ])

          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0)
        } finally {
          cleanup()
        }
      },
      CHECK_TIMEOUT_MS
    )
  }
})
