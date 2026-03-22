import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"

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
  createServerTemplate,
  ENV_EXAMPLE_TEMPLATE,
  GITIGNORE_TEMPLATE,
  type InitialUserConfig,
  TSCONFIG_TEMPLATE,
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
type ScaffoldOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host?: string
  initialUser?: InitialUserConfig
  installer?: (projectDirectory: string, packageManager: PackageManager) => boolean
}

export function writeProjectFiles(projectDirectory: string, options?: ScaffoldOptions): void {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(projectDirectory, { recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(join(projectDirectory, "files"), { recursive: true })

  const host = options?.host ?? "1.2.3.4"
  const initialUser = options?.initialUser ?? { kind: "admin", user: "admin" }
  const adminPublicKey = options?.adminPublicKey
  const expectedHostFingerprint = options?.expectedHostFingerprint

  const packageJson = {
    dependencies: {
      paratix: "^0.1.0",
    },
    devDependencies: {
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
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "tsconfig.json"), TSCONFIG_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".gitignore"), GITIGNORE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, ".env.example"), ENV_EXAMPLE_TEMPLATE)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  writeFileSync(join(projectDirectory, "files", ".gitkeep"), "")
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

export function scaffoldProject(
  projectName: string,
  pm: PackageManager,
  options?: ScaffoldOptions
): boolean {
  const normalizedProjectName = normalizeProjectName(projectName)
  const projectDirectory = resolve(normalizedProjectName)
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  if (existsSync(projectDirectory)) {
    exitWithMessage(`Error: Directory "${normalizedProjectName}" already exists.`)
  }

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

function main(): void {
  const { adminPublicKey, adminPublicKeyFile, host, initialUser, projectName } = parseCliArguments(
    process.argv.slice(2)
  )

  const normalizedProjectName = validateProjectName(projectName)

  const pm = detectPackageManager()
  void (async () => {
    const validatedHost = host == null ? await promptForHost() : validateHost(host)
    const resolvedExpectedHostFingerprint =
      process.stdin.isTTY && process.stdout.isTTY
        ? await promptForHostFingerprint(validatedHost)
        : undefined
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
  return argv1 != null && moduleUrl.endsWith(argv1.replaceAll("\\", "/"))
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main()
}
