import { spawnSync, type SpawnSyncReturns } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import { writeProjectFiles } from "../src/index.js"
import { TEST_ADMIN_PUBLIC_KEY } from "./helpers.js"

const CHECK_TIMEOUT_MS = 60_000

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)))
const paratixPackageRoot = resolve(fileURLToPath(new URL("../../paratix", import.meta.url)))
const paratixDeclarationPath = join(paratixPackageRoot, "dist", "index.d.ts")

// The workspace aliases `typescript` to @typescript/typescript6, whose binary
// is `tsc6`. A scaffolded project pins its own compiler, so these paths are the
// workspace's tools pointed at generated files — deliberately not the tools the
// scaffold declares. The install-level check covers that difference.
export const ESLINT_BINARY_PATH = resolve(
  fileURLToPath(new URL("../../../node_modules/eslint/bin/eslint.js", import.meta.url))
)
export const PRETTIER_BINARY_PATH = resolve(
  fileURLToPath(new URL("../../../node_modules/prettier/bin/prettier.cjs", import.meta.url))
)
export const TSC_BINARY_PATH = resolve(
  fileURLToPath(new URL("../../../node_modules/typescript/bin/tsc6", import.meta.url))
)

/**
 * The two shapes the scaffold produces.
 *
 * They differ in more than a flag: only the root bootstrap emits the `ssh`
 * import and the `adminPublicKey` constant, and its key is long enough that
 * Prettier moves the value onto its own line. Checking one variant would leave
 * the other layout unverified.
 */
export type ScaffoldVariant = "admin" | "root-bootstrap"

export const SCAFFOLD_VARIANTS: ScaffoldVariant[] = ["admin", "root-bootstrap"]

/**
 * Create a scaffolded project in a fresh temporary directory.
 *
 * @param variant - Which scaffold shape to produce.
 * @returns The project directory, and a cleanup callback that must run even
 *   when the check fails, because each project carries a `node_modules` tree.
 */
export function createScaffoldedProject(variant: ScaffoldVariant): {
  cleanup: () => void
  projectDirectory: string
} {
  const projectDirectory = mkdtempSync(join(tmpdir(), `create-paratix-${variant}-`))
  const cleanup = (): void => {
    rmSync(projectDirectory, { force: true, recursive: true })
  }

  try {
    writeProjectFiles(
      projectDirectory,
      variant === "root-bootstrap"
        ? { adminPublicKey: TEST_ADMIN_PUBLIC_KEY, initialUser: { kind: "root" } }
        : undefined
    )
  } catch (error) {
    cleanup()
    throw error
  }

  return { cleanup, projectDirectory }
}

/**
 * Symlink a workspace package into the generated project's `node_modules`.
 *
 * @param projectDirectory - The generated project.
 * @param dependencyName - Package name, scoped names included.
 */
export function linkWorkspaceDependency(projectDirectory: string, dependencyName: string): void {
  const dependencyLink = join(projectDirectory, "node_modules", dependencyName)
  // A scoped name needs its @scope directory before the link can be placed.
  mkdirSync(dirname(dependencyLink), { recursive: true })
  symlinkSync(resolve(packageRoot, "../../node_modules", dependencyName), dependencyLink)
}

/**
 * Link the built `paratix` package into the generated project.
 *
 * The declaration files matter here: type-aware lint rules such as
 * `no-unsafe-call` treat every import they cannot resolve as `any` and then
 * flag every use of it. A source-level re-export shim resolves at runtime but
 * carries no types, which turns a clean project into dozens of findings that
 * say nothing about the scaffold.
 *
 * @param projectDirectory - The generated project.
 */
export function linkParatixRuntime(projectDirectory: string): void {
  if (!existsSync(paratixDeclarationPath)) {
    throw new Error(
      `The generated project needs paratix's declaration files at ${paratixDeclarationPath}. Run \`pnpm --filter paratix build\` first; \`pnpm agent:check\` does this before the tests.`
    )
  }
  const nodeModulesDirectory = join(projectDirectory, "node_modules")
  mkdirSync(nodeModulesDirectory, { recursive: true })
  symlinkSync(paratixPackageRoot, join(nodeModulesDirectory, "paratix"))
}

/**
 * Run a Node-based CLI inside the generated project.
 *
 * @param projectDirectory - Working directory for the call.
 * @param binaryPath - Absolute path to the CLI entry point.
 * @param args - Arguments passed to the CLI.
 * @returns The completed process, including its status and output.
 */
export function runInProject(
  projectDirectory: string,
  binaryPath: string,
  args: string[]
): SpawnSyncReturns<string> {
  return spawnSync(process.execPath, [binaryPath, ...args], {
    cwd: projectDirectory,
    encoding: "utf8",
    timeout: CHECK_TIMEOUT_MS,
  })
}

const ESLINT_EXIT_FINDINGS = 1
const ESLINT_EXIT_CONFIGURATION_ERROR = 2

/**
 * Describe an ESLint run against a generated project.
 *
 * The two failure modes need to stay distinguishable. A configuration error
 * aborts before any file is inspected, which is exactly how a broken
 * rule-to-language mapping once hid real findings underneath it.
 *
 * @param result - The completed ESLint process.
 * @returns `null` when the run was clean, otherwise the message to fail with.
 */
export function describeLintOutcome(result: SpawnSyncReturns<string>): null | string {
  if (result.status === 0) return null
  if (result.status === ESLINT_EXIT_CONFIGURATION_ERROR) {
    return `ESLint could not run against the generated project — this is a configuration error, not a finding:\n${result.stdout}\n${result.stderr}`
  }
  if (result.status === ESLINT_EXIT_FINDINGS) {
    return `The generated project reports lint findings:\n${result.stdout}`
  }
  return `ESLint exited with status ${String(result.status)}:\n${result.stdout}\n${result.stderr}`
}
