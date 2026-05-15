import { rmSync } from "node:fs"
import { basename, resolve } from "node:path"

import type { InitialUserConfig } from "./templates.js"

import { formatCliValue } from "./cliFormat.js"
import {
  exitWithMessage,
  handleCliExit,
  parseCliArguments,
  parseInitialUserConfig,
  resolveCliOrPromptAdminPublicKey,
  resolveCliOrPromptHost,
} from "./cliValidation.js"
import { isDirectExecution } from "./directExecution.js"
import { promptForHostFingerprint, promptForInitialUserConfig } from "./interactivePrompts.js"
import { createProjectDirectoryAtomically } from "./projectDirectory.js"
import {
  normalizeProgrammaticScaffoldStringOptions,
  parseInitialUserConfig as parseScaffoldInitialUserConfig,
} from "./scaffoldConfig.js"
import { writeScaffoldFiles } from "./scaffoldFiles.js"
import {
  detectPackageManager,
  installDependencies,
  type PackageManager,
  printPartialSuccessMessage,
  printSuccessMessage,
} from "./scaffoldRuntime.js"
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

export type ScaffoldOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host?: string
  initialUser?: InitialUserConfig
  installer?: (projectDirectory: string, packageManager: PackageManager) => boolean
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
  writeScaffoldFiles(projectDirectory, {
    adminPublicKey,
    expectedHostFingerprint,
    host,
    initialUser,
    packageName,
  })
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

  // R-0000499: if writeProjectFiles or the installer throws after we have
  // already created the empty project directory, leaving the half-built
  // directory behind blocks any retry with the same name. Remove the
  // directory before rethrowing so the operator can run create-paratix again
  // without manually cleaning up. The non-throwing installer return value
  // (false) signals a partial success — the scaffold files are valid, only
  // the install step failed — so we do NOT remove the directory in that
  // branch.
  let installerSucceeded: boolean
  try {
    writeProjectFiles(projectDirectory, { ...options, ...normalizedStringOptions, initialUser })
    const installer = options?.installer ?? installDependencies
    installerSucceeded = installer(projectDirectory, pm)
  } catch (error) {
    rmSync(projectDirectory, { force: true, recursive: true })
    throw error
  }

  if (!installerSucceeded) {
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
