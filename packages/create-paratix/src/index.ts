import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"

import { formatCliValue } from "./cliFormat.js"
import {
  exitWithMessage,
  handleCliExit,
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
import { containsUnsafeCodepoint } from "./unsafeCodepoints.js"

export {
  CliExitError,
  handleCliExit,
  parseCliArguments,
  parseInitialUserConfig,
  resolveCliOrPromptHost,
  restoreInteractiveTerminal,
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

function getManagedScaffoldPaths(
  projectDirectory: string,
  initialUser: InitialUserConfig
): string[] {
  const managedPaths = [
    "package.json",
    "server.ts",
    "tsconfig.json",
    ".gitignore",
    ".prettierrc",
    ".prettierignore",
    "eslint.config.ts",
    ".env.example",
    join("files", ".gitkeep"),
    join("files", "20auto-upgrades"),
    join("files", "50unattended-upgrades"),
  ]

  if (initialUser.kind === "root") {
    managedPaths.push(join("files", "admin-nopasswd-sudoers"))
  }

  return managedPaths.map((managedPath) => join(projectDirectory, managedPath))
}

function assertManagedScaffoldPathsAvailable(
  projectDirectory: string,
  initialUser: InitialUserConfig
): void {
  for (const managedPath of getManagedScaffoldPaths(projectDirectory, initialUser)) {
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    if (existsSync(managedPath)) {
      throw new Error(
        `Error: Scaffold file ${formatCliValue(managedPath)} already exists; refusing to overwrite it.`
      )
    }
  }
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
  // R-0000234: scaffoldProject validates the project name up front, but
  // writeProjectFiles is exported for direct programmatic use. A caller that
  // bypasses scaffoldProject would otherwise embed an unvalidated basename
  // into packageJson.name — including newlines, control characters, or
  // Unicode bidi formatting codepoints. Validate the derived name at the
  // entry point so the security check is enforced regardless of which
  // public function is called.
  const packageName = derivePackageName(projectDirectory)
  if (!isSecureDerivedPackageName(packageName)) {
    throw new Error(
      `Error: Invalid project directory ${formatCliValue(projectDirectory)} — the derived package name contains control or bidi codepoints.`
    )
  }
  assertManagedScaffoldPathsAvailable(projectDirectory, initialUser)

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
      jiti: "^2.6.1",
      prettier: "^3.6.2",
      tsx: "^4.20.6",
      typescript: "^5.9.2",
    },
    engines: {
      node: ">=24.0.0",
    },
    name: packageName,
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

// R-0000234: writeProjectFiles is exported and accepts an arbitrary path.
// `validateProjectName` (used by scaffoldProject) is too strict for this
// entry point — it rejects uppercase letters and would break callers that
// pass a `mkdtempSync`-generated temp directory. We restrict the check to
// the actual security concerns: empty, whitespace-only, multi-line, and
// codepoints from the shared unsafe-codepoint allowlist (control bytes and
// Unicode bidi formatting marks).
function isSecureDerivedPackageName(name: string): boolean {
  if (name.length === 0) return false
  if (name.trim().length === 0) return false
  if (/[\r\n]/v.test(name)) return false
  if (containsUnsafeCodepoint(name)) return false
  return true
}

function validateProjectName(name: string | undefined): string {
  // R-0000230: ExitWithMessage is typed `never`, but TypeScript does not
  // enforce that at runtime — a test stub or future caller that does not
  // throw would otherwise flow into `name.trim()` with `undefined` and crash
  // with a confusing "Cannot read properties of undefined" error. Mirror the
  // failWithReadError pattern in publicKeySelection (R-0000185): wrap the
  // exitWithMessage call in a closure that guarantees a local throw, then
  // bind the validated value before any property access.
  const failWithUsage = (): never => {
    exitWithMessage("Usage: create-paratix <project-name>")
    throw new Error("Usage: create-paratix <project-name>")
  }
  const failWithInvalidName = (rawName: string): never => {
    const message = `Error: Invalid project name ${formatCliValue(rawName)} — use only lowercase letters, numbers, and hyphens.`
    exitWithMessage(message)
    throw new Error(message)
  }

  if (name == null || name === "") {
    return failWithUsage()
  }

  const normalizedName = normalizeProjectName(name)

  if (!isValidProjectName(normalizedName)) {
    return failWithInvalidName(name)
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
  // R-0000189: synchronous validators (parseCliArguments, validateProjectName)
  // also throw CliExitError now. Wrap the whole pipeline in a single async
  // closure so a single .catch handler can run cleanup for both synchronous
  // and asynchronous failures.
  void (async () => {
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
    // R-0000189: handleCliExit centralises terminal cleanup before assigning
    // the exit code so a CliExitError raised mid-prompt cannot leave the
    // operator's terminal in raw mode with the cursor still hidden.
    handleCliExit(error)
  })
}

if (isDirectExecution(import.meta.url, process.argv[1])) {
  main()
}
