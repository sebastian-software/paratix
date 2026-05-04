import { mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

import {
  promptForAdminPublicKey,
  promptForHost,
  promptForHostFingerprint,
  promptForInitialUserConfig,
} from "./interactivePrompts.js"
import { readAdminPublicKeyFile, validateAdminPublicKey } from "./publicKeySelection.js"
import {
  parseCliArguments as parseScaffoldCliArguments,
  parseInitialUserConfig as parseScaffoldInitialUserConfig,
  validateHost as validateScaffoldHost,
} from "./scaffoldConfig.js"
import {
  detectPackageManager,
  installDependencies,
  type PackageManager,
  printPartialSuccessMessage,
  printSuccessMessage,
} from "./scaffoldRuntime.js"
import {
  AUTO_UPGRADES_20_TEMPLATE,
  createAdminNopasswdSudoersContent,
  createServerTemplate,
  ENV_EXAMPLE_TEMPLATE,
  ESLINT_CONFIG_TEMPLATE,
  GITIGNORE_TEMPLATE,
  type InitialUserConfig,
  PRETTIER_IGNORE_TEMPLATE,
  PRETTIER_RC_TEMPLATE,
  TSCONFIG_TEMPLATE,
  UNATTENDED_UPGRADES_50_TEMPLATE,
} from "./templates.js"

export {
  promptForAdminPublicKey,
  promptForHost,
  promptForHostFingerprint,
  promptForInitialUserConfig,
} from "./interactivePrompts.js"
export {
  isValidHost,
  isValidInitialUserName,
  normalizeHost,
  normalizeInitialUserName,
} from "./scaffoldConfig.js"
export type { InitialUserConfig } from "./templates.js"

const PARATIX_DEPENDENCY_RANGE = "^0.10.0"

type ScaffoldOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host?: string
  initialUser?: InitialUserConfig
  installer?: (projectDirectory: string, packageManager: PackageManager) => boolean
}

function writeSharedScaffoldFiles(projectDirectory: string): void {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "tsconfig.json"), TSCONFIG_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".gitignore"), GITIGNORE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".prettierrc"), PRETTIER_RC_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".prettierignore"), PRETTIER_IGNORE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "eslint.config.ts"), ESLINT_CONFIG_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".env.example"), ENV_EXAMPLE_TEMPLATE)
}

function writeScaffoldSupportFiles(projectDirectory: string, initialUser: InitialUserConfig): void {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "files", ".gitkeep"), "")
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "files", "20auto-upgrades"), AUTO_UPGRADES_20_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(
    join(projectDirectory, "files", "50unattended-upgrades"),
    UNATTENDED_UPGRADES_50_TEMPLATE
  )
  if (initialUser.kind !== "root") return
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(
    join(projectDirectory, "files", "admin-nopasswd-sudoers"),
    createAdminNopasswdSudoersContent("paratix")
  )
}

function validateRootBootstrapConfiguration(options?: ScaffoldOptions): void {
  if (options?.initialUser?.kind === "root" && options.adminPublicKey == null) {
    throw new Error(
      "Root bootstrap requires --admin-public-key or --admin-public-key-file so the generated admin user can log in after the first run."
    )
  }
}

export function writeProjectFiles(projectDirectory: string, options?: ScaffoldOptions): void {
  validateRootBootstrapConfiguration(options)

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(projectDirectory, { recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(join(projectDirectory, "files"), { recursive: true })

  const host = options?.host ?? "1.2.3.4"
  const initialUser = options?.initialUser ?? { kind: "admin", user: "paratix" }
  const adminPublicKey = options?.adminPublicKey
  const expectedHostFingerprint = options?.expectedHostFingerprint

  const packageJson = {
    dependencies: {
      paratix: PARATIX_DEPENDENCY_RANGE,
    },
    devDependencies: {
      "@types/node": "^24.5.2",
      eslint: "^10.0.3",
      "eslint-config-setup": "^0.3.3",
      prettier: "^3.6.2",
      tsx: "^4.20.6",
    },
    engines: {
      node: ">=24.0.0",
    },
    name: derivePackageName(projectDirectory),
    private: true,
    scripts: {
      apply: "paratix apply server.ts",
      "apply:dry": "paratix apply server.ts --dry-run",
      "apply:first-run": "paratix apply server.ts --first-run",
      "apply:first-run:dry": "paratix apply server.ts --dry-run --first-run",
      "format:check": "prettier --check .",
      "format:fix": "prettier --write .",
      lint: "eslint .",
    },
    type: "module",
  }

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "package.json"), `${JSON.stringify(packageJson, null, 2)}\n`)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(
    join(projectDirectory, "server.ts"),
    createServerTemplate({ adminPublicKey, expectedHostFingerprint, host, initialUser })
  )
  writeSharedScaffoldFiles(projectDirectory)
  writeScaffoldSupportFiles(projectDirectory, initialUser)
}

export function isValidProjectName(name: string): boolean {
  const trimmed = name.trim()
  return /^[a-z0-9][a-z0-9\x2d]*$/v.test(trimmed)
}

export function normalizeProjectName(name: string): string {
  return name.trim()
}

function derivePackageName(projectDirectory: string): string {
  return basename(projectDirectory.replaceAll("\\", "/"))
}

function exitWithMessage(message: string): never {
  console.error(message)
  // eslint-disable-next-line node/no-process-exit
  process.exit(1)
}

export function parseCliArguments(argv: string[]): {
  adminPublicKey: string | undefined
  adminPublicKeyFile: string | undefined
  expectedHostFingerprint: string | undefined
  host: string | undefined
  initialUser: string | undefined
  projectName: string | undefined
} {
  return parseScaffoldCliArguments(argv, exitWithMessage)
}

export function parseInitialUserConfig(value: string): InitialUserConfig {
  return parseScaffoldInitialUserConfig(exitWithMessage, value)
}

export function validateHost(value: string): string {
  return validateScaffoldHost(exitWithMessage, value)
}

function validateProjectName(name: string | undefined): string {
  if (name == null || name === "") {
    exitWithMessage("Usage: create-paratix <project-name>")
  }

  const normalizedName = normalizeProjectName(name)

  if (!isValidProjectName(normalizedName)) {
    exitWithMessage(
      `Error: Invalid project name "${name}" — use only lowercase letters, numbers, and hyphens.`
    )
  }

  return normalizedName
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && typeof error.code === "string"
}

/**
 * Atomically create the project directory.
 *
 * R-0000124: Atomic directory creation — `mkdirSync` without `recursive`
 * throws EEXIST if the target already exists, closing the TOCTOU window
 * between an `existsSync` pre-check and the subsequent `writeFileSync`
 * calls. A racing process that creates the directory between the check
 * and the create would otherwise let us silently overwrite its files.
 *
 * @param projectDirectory The absolute path of the project directory to create.
 * @param normalizedProjectName The trimmed project name used in the
 *   user-visible error message when the directory already exists.
 */
function createProjectDirectoryAtomically(
  projectDirectory: string,
  normalizedProjectName: string
): void {
  try {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    mkdirSync(projectDirectory, { recursive: false })
  } catch (error: unknown) {
    if (isErrnoException(error) && error.code === "EEXIST") {
      exitWithMessage(`Error: Directory "${normalizedProjectName}" already exists.`)
    }
    throw error
  }
}

export function scaffoldProject(
  projectName: string,
  pm: PackageManager,
  options?: ScaffoldOptions
): boolean {
  const normalizedProjectName = normalizeProjectName(projectName)
  const projectDirectory = resolve(normalizedProjectName)
  validateRootBootstrapConfiguration(options)
  createProjectDirectoryAtomically(projectDirectory, normalizedProjectName)

  console.log(`Creating Paratix project in ${projectDirectory}...`)

  writeProjectFiles(projectDirectory, options)
  const installer = options?.installer ?? installDependencies
  const installed = installer(projectDirectory, pm)
  if (!installed) {
    process.exitCode = 1
    printPartialSuccessMessage(normalizedProjectName, pm)
    return false
  }

  printSuccessMessage(normalizedProjectName, pm)
  return true
}

async function resolveCliOrPromptAdminPublicKey(parameters: {
  adminPublicKey: string | undefined
  adminPublicKeyFile: string | undefined
}): Promise<string | undefined> {
  const { adminPublicKey, adminPublicKeyFile } = parameters

  if (adminPublicKey !== undefined) {
    return validateAdminPublicKey(exitWithMessage, adminPublicKey)
  }

  if (adminPublicKeyFile !== undefined) {
    return readAdminPublicKeyFile(exitWithMessage, adminPublicKeyFile)
  }

  if (process.stdin.isTTY && process.stdout.isTTY) {
    return promptForAdminPublicKey()
  }

  return undefined
}

export async function resolveCliOrPromptHost(
  host: string | undefined,
  prompt: () => Promise<string> = promptForHost
): Promise<string> {
  if (host !== undefined) return validateHost(host)
  if (process.stdin.isTTY && process.stdout.isTTY) return prompt()

  exitWithMessage("Missing --host in non-interactive environment. Pass --host <domain-or-ip>.")
}

function main(): void {
  const {
    adminPublicKey,
    adminPublicKeyFile,
    expectedHostFingerprint,
    host,
    initialUser,
    projectName,
  } = parseCliArguments(process.argv.slice(2))

  const normalizedProjectName = validateProjectName(projectName)

  const pm = detectPackageManager()
  void (async () => {
    const validatedHost = await resolveCliOrPromptHost(host)
    const resolvedExpectedHostFingerprint =
      expectedHostFingerprint ??
      (process.stdin.isTTY && process.stdout.isTTY
        ? await promptForHostFingerprint(validatedHost)
        : undefined)
    const initialUserConfig =
      initialUser == null ? await promptForInitialUserConfig() : parseInitialUserConfig(initialUser)
    const resolvedAdminPublicKey = await resolveCliOrPromptAdminPublicKey({
      adminPublicKey,
      adminPublicKeyFile,
    })
    scaffoldProject(normalizedProjectName, pm, {
      adminPublicKey: resolvedAdminPublicKey,
      expectedHostFingerprint: resolvedExpectedHostFingerprint,
      host: validatedHost,
      initialUser: initialUserConfig,
    })
  })().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  })
}

// Only run when executed directly, not when imported (e.g. in tests)
// Exported for testing: verifies the guard is safe when argv[1] is undefined.
export function isDirectExecution(moduleUrl: string, argv1: null | string | undefined): boolean {
  if (argv1 == null) return false
  try {
    return resolve(fileURLToPath(moduleUrl)) === resolve(argv1)
  } catch {
    return false
  }
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main()
}
