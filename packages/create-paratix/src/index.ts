import { mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"

import { escapeCliControlCharacters, formatCliValue } from "./cliFormat.js"
import {
  exitWithMessage,
  parseCliArguments,
  parseInitialUserConfig,
  resolveCliOrPromptAdminPublicKey,
  resolveCliOrPromptHost,
} from "./cliValidation.js"
import { deriveParatixDependencyRange } from "./dependencyRange.js"
import { isDirectExecution } from "./directExecution.js"
import { promptForHostFingerprint, promptForInitialUserConfig } from "./interactivePrompts.js"
import { createProjectDirectoryAtomically } from "./projectDirectory.js"
import {
  normalizeProgrammaticScaffoldStringOptions,
  parseInitialUserConfig as parseScaffoldInitialUserConfig,
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
  parseCliArguments,
  parseInitialUserConfig,
  resolveCliOrPromptHost,
  validateExpectedHostFingerprint,
  validateHost,
} from "./cliValidation.js"
export { deriveParatixDependencyRange } from "./dependencyRange.js"
export { isDirectExecution } from "./directExecution.js"
export {
  promptForAdminPublicKey,
  promptForHost,
  promptForHostFingerprint,
  promptForInitialUserConfig,
} from "./interactivePrompts.js"
export {
  isValidExpectedHostFingerprint,
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

function normalizeProgrammaticInitialUserConfig(
  initialUser?: InitialUserConfig
): InitialUserConfig {
  if (initialUser == null) return { kind: "admin", user: "paratix" }
  if (initialUser.kind === "root") return { kind: "root" }

  const parsedInitialUser = parseScaffoldInitialUserConfig((message) => {
    throw new Error(message)
  }, initialUser.user)

  if (parsedInitialUser.kind !== "admin") {
    throw new Error(
      `Error: Invalid initial user ${formatCliValue(initialUser.user)} — use a non-root lowercase Linux username for admin mode.`
    )
  }

  return parsedInitialUser
}

function validateRootBootstrapConfiguration(
  initialUser: InitialUserConfig,
  adminPublicKey: string | undefined
): void {
  if (initialUser.kind === "root" && adminPublicKey == null) {
    throw new Error(
      "Root bootstrap requires --admin-public-key or --admin-public-key-file so the generated admin user can log in after the first run."
    )
  }
}

export function writeProjectFiles(projectDirectory: string, options?: ScaffoldOptions): void {
  const initialUser = normalizeProgrammaticInitialUserConfig(options?.initialUser)
  validateRootBootstrapConfiguration(initialUser, options?.adminPublicKey)
  const { adminPublicKey, expectedHostFingerprint, host } =
    normalizeProgrammaticScaffoldStringOptions(options)

  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(projectDirectory, { recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(join(projectDirectory, "files"), { recursive: true })

  const packageJson = {
    dependencies: {
      paratix: deriveParatixDependencyRange(),
    },
    devDependencies: {
      "@types/node": "^24.5.2",
      eslint: "^10.0.3",
      "eslint-config-setup": "^0.3.3",
      prettier: "^3.6.2",
      tsx: "^4.20.6",
      typescript: "^5.9.2",
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

function validateProjectName(name: string | undefined): string {
  if (name == null || name === "") {
    exitWithMessage("Usage: create-paratix <project-name>")
  }

  const normalizedName = normalizeProjectName(name)

  if (!isValidProjectName(normalizedName)) {
    exitWithMessage(
      `Error: Invalid project name ${formatCliValue(name)} — use only lowercase letters, numbers, and hyphens.`
    )
  }

  return normalizedName
}

export function scaffoldProject(
  projectName: string,
  pm: PackageManager,
  options?: ScaffoldOptions
): boolean {
  const normalizedProjectName = validateProjectName(projectName)
  const projectDirectory = resolve(normalizedProjectName)
  const initialUser = normalizeProgrammaticInitialUserConfig(options?.initialUser)
  const normalizedStringOptions = normalizeProgrammaticScaffoldStringOptions(options)
  validateRootBootstrapConfiguration(initialUser, normalizedStringOptions.adminPublicKey)
  createProjectDirectoryAtomically(projectDirectory, normalizedProjectName)

  console.log(`Creating Paratix project in ${projectDirectory}...`)

  writeProjectFiles(projectDirectory, { ...options, ...normalizedStringOptions, initialUser })
  const installer = options?.installer ?? installDependencies
  if (!installer(projectDirectory, pm)) {
    process.exitCode = 1
    printPartialSuccessMessage(normalizedProjectName, pm)
    return false
  }

  printSuccessMessage(normalizedProjectName, pm)
  return true
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
      allowPlaceholder: initialUserConfig.kind !== "root",
    })
    scaffoldProject(normalizedProjectName, pm, {
      adminPublicKey: resolvedAdminPublicKey,
      expectedHostFingerprint: resolvedExpectedHostFingerprint,
      host: validatedHost,
      initialUser: initialUserConfig,
    })
  })().catch((error: unknown) => {
    console.error(
      escapeCliControlCharacters(error instanceof Error ? error.message : String(error))
    )
    process.exitCode = 1
  })
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main()
}
