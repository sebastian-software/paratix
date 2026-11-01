import { spawnSync, type SpawnSyncReturns } from "node:child_process"
import { readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

import {
  createScaffoldedProject,
  packParatixTarball,
  packSshNativeTarball,
  SCAFFOLD_VARIANTS,
} from "../scaffoldFixtures.js"

const INSTALL_TIMEOUT_MS = 600_000

/**
 * Install a generated project, resolving `paratix` from the working tree.
 *
 * Every other dependency installs from the registry exactly as the scaffold
 * declares it — that is what makes this check able to catch an install-level
 * failure such as a missing build approval. `paratix` and `@paratix/ssh-native`
 * are redirected via `pnpm-workspace.yaml` overrides because both are versioned
 * in lockstep with `create-paratix` and are not on the registry yet at release
 * time; see `packParatixTarball`. The native platform package is unnecessary:
 * these scripts only inspect types and source without loading the binding.
 *
 * The override is reverted once the install is done, so the project's own
 * scripts run against exactly the files the scaffold wrote — `format:check`
 * inspects `pnpm-workspace.yaml` too.
 *
 * @param projectDirectory - The generated project.
 * @returns The completed install process.
 */
function installProject(projectDirectory: string): SpawnSyncReturns<string> {
  const workspaceFilePath = join(projectDirectory, "pnpm-workspace.yaml")
  const generatedWorkspaceFile = readFileSync(workspaceFilePath, "utf8")

  writeFileSync(
    workspaceFilePath,
    `${generatedWorkspaceFile}overrides:\n  paratix: file:${packParatixTarball()}\n  "@paratix/ssh-native": file:${packSshNativeTarball()}\n`
  )
  try {
    return spawnSync("pnpm", ["install"], {
      cwd: projectDirectory,
      encoding: "utf8",
      timeout: INSTALL_TIMEOUT_MS,
    })
  } finally {
    writeFileSync(workspaceFilePath, generatedWorkspaceFile)
  }
}

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
  // The generated workspace has been restored after installation. pnpm's
  // pre-script verification would re-resolve its unpublished release version
  // against the registry because the installed lockfile records our overrides.
  // Keep checking the installed tarballs while inspecting the original files.
  const result = spawnSync("pnpm", ["--config.verifyDepsBeforeRun=false", script], {
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
 * `paratix` and `@paratix/ssh-native` come from the working tree, for
 * the release-ordering reason `installProject` describes.
 */
describe("a scaffolded project installs and passes its own scripts", () => {
  for (const variant of SCAFFOLD_VARIANTS) {
    it(`installs and checks out clean in the ${variant} variant`, () => {
      const { cleanup, projectDirectory } = createScaffoldedProject(variant)

      try {
        const install = installProject(projectDirectory)
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
