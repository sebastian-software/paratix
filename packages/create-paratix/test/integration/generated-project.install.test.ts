import { spawnSync } from "node:child_process"
import { describe, expect, it } from "vitest"

import { createScaffoldedProject, SCAFFOLD_VARIANTS } from "../scaffoldFixtures.js"

const INSTALL_TIMEOUT_MS = 600_000

/**
 * Run one of the generated project's own scripts through pnpm.
 *
 * Unlike the fast checks, this uses whatever pnpm resolves from the project's
 * own `node_modules`, which is the point: it exercises the versions the
 * scaffold declares rather than the ones the workspace happens to run.
 *
 * @param projectDirectory - The generated project.
 * @param script - Name of the script to run.
 * @returns Its exit status and combined output.
 */
function runProjectScript(
  projectDirectory: string,
  script: string
): { output: string; status: null | number } {
  const result = spawnSync("pnpm", [script], {
    cwd: projectDirectory,
    encoding: "utf8",
    timeout: INSTALL_TIMEOUT_MS,
  })
  return { output: `${result.stdout}\n${result.stderr}`, status: result.status }
}

/**
 * Verify that a scaffolded project installs and passes its own scripts.
 *
 * This is the only check that exercises the dependency versions the scaffold
 * declares, and the only one that can catch an install-level failure such as a
 * missing build approval. It needs network access and therefore lives in the
 * integration run rather than in `test` or `test:dist`.
 *
 * The `paratix` dependency resolves from the registry, not from the working
 * tree — a scaffolded project declares a published range. A failure here that
 * points at paratix itself is therefore about the published package; the rest
 * of the suite covers the working tree.
 */
describe("a scaffolded project installs and passes its own scripts", () => {
  for (const variant of SCAFFOLD_VARIANTS) {
    it(`installs and checks out clean in the ${variant} variant`, () => {
      const { cleanup, projectDirectory } = createScaffoldedProject(variant)

      try {
        const install = spawnSync("pnpm", ["install"], {
          cwd: projectDirectory,
          encoding: "utf8",
          timeout: INSTALL_TIMEOUT_MS,
        })
        expect(
          install.status,
          `pnpm install failed in the generated project:\n${install.stdout}\n${install.stderr}`
        ).toBe(0)

        for (const script of ["typecheck", "lint", "format:check"]) {
          const { output, status } = runProjectScript(projectDirectory, script)
          expect(status, `pnpm ${script} failed in the generated project:\n${output}`).toBe(0)
        }
      } finally {
        cleanup()
      }
    })
  }
})
