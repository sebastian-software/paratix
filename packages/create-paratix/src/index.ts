import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"
import { createInterface } from "node:readline/promises"

import { createTerminalSelect, type SelectFunction, type SelectOption } from "./promptUi.js"
import { promptForAdminPublicKey as promptForScaffoldAdminPublicKey } from "./publicKeySelection.js"
import {
  isValidInitialUserName,
  normalizeInitialUserName,
  parseCliArguments as parseScaffoldCliArguments,
  parseInitialUserConfig as parseScaffoldInitialUserConfig,
  promptForHost as promptForScaffoldHost,
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
  isValidHost,
  isValidInitialUserName,
  normalizeHost,
  normalizeInitialUserName,
} from "./scaffoldConfig.js"
export type { InitialUserConfig } from "./templates.js"
type ScaffoldOptions = {
  adminPublicKey?: string
  host?: string
  initialUser?: InitialUserConfig
  installer?: (projectDirectory: string, packageManager: PackageManager) => boolean
}

type PromptFunction = (question: string) => Promise<string>
const NOOP = (): void => undefined
const UNAVAILABLE_SELECT = (() => {
  throw new Error("Interactive selection is unavailable.")
}) as SelectFunction<"admin" | "root">
const INITIAL_USER_OPTIONS: Array<SelectOption<"admin" | "root">> = [
  {
    description:
      "Fresh server with SSH access only as root. Paratix bootstraps a dedicated admin user first.",
    label: "Root user",
    value: "root",
  },
  {
    description:
      "A named admin user already exists. Paratix connects directly as that user and skips root bootstrap.",
    label: "Admin user",
    value: "admin",
  },
]

export function writeProjectFiles(projectDirectory: string, options?: ScaffoldOptions): void {
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(projectDirectory, { recursive: true })
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  mkdirSync(join(projectDirectory, "files"), { recursive: true })

  const host = options?.host ?? "1.2.3.4"
  const initialUser = options?.initialUser ?? { kind: "admin", user: "admin" }
  const adminPublicKey = options?.adminPublicKey

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
    createServerTemplate({ adminPublicKey, host, initialUser })
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
  host: string | undefined
  initialUser: string | undefined
  projectName: string | undefined
} {
  return parseScaffoldCliArguments(argv, exitWithMessage)
}

export function parseInitialUserConfig(value: string): InitialUserConfig {
  return parseScaffoldInitialUserConfig(exitWithMessage, value)
}

function createTerminalPrompt(): { close: () => void; prompt: PromptFunction } {
  const readline = createInterface({ input: process.stdin, output: process.stdout })
  return {
    close: (): void => {
      readline.close()
    },
    prompt: async (question: string): Promise<string> => readline.question(question),
  }
}

export function validateHost(value: string): string {
  return validateScaffoldHost(exitWithMessage, value)
}

function createPromptSession(prompt?: PromptFunction): {
  ask: PromptFunction
  chooseInitialUser: SelectFunction<"admin" | "root">
  closePrompt: () => void
  closeSelect: () => void
} {
  const terminalPrompt = prompt == null ? createTerminalPrompt() : null
  const terminalSelect = prompt == null ? createTerminalSelect() : null
  if (terminalPrompt != null && terminalSelect != null) {
    return {
      ask: terminalPrompt.prompt,
      chooseInitialUser: terminalSelect.select,
      closePrompt: terminalPrompt.close,
      closeSelect: terminalSelect.close,
    }
  }
  if (prompt == null) {
    throw new Error("Interactive prompt is unavailable.")
  }
  return {
    ask: prompt,
    chooseInitialUser: UNAVAILABLE_SELECT,
    closePrompt: NOOP,
    closeSelect: NOOP,
  }
}

async function promptForAdminUser(
  ask: PromptFunction,
  closePrompt: () => void
): Promise<InitialUserConfig> {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  while (true) {
    // eslint-disable-next-line no-await-in-loop
    const adminUser = normalizeInitialUserName(await ask("Admin username: "))
    if (isValidInitialUserName(adminUser) && adminUser !== "root") {
      closePrompt()
      return { kind: "admin", user: adminUser }
    }
    console.error(
      'Error: Invalid admin username. Use a valid lowercase Linux username other than "root".'
    )
  }
}

export async function promptForHost(prompt?: PromptFunction): Promise<string> {
  return promptForScaffoldHost(prompt ?? createTerminalPrompt().prompt)
}

export async function promptForInitialUserConfig(
  prompt?: PromptFunction,
  select?: SelectFunction<"admin" | "root">
): Promise<InitialUserConfig> {
  const promptSession = createPromptSession(prompt)
  const chooseInitialUser = select ?? promptSession.chooseInitialUser

  try {
    const initialUserType = await chooseInitialUser(
      "Which SSH user already works for the first connection to this server?",
      INITIAL_USER_OPTIONS
    )

    if (initialUserType === "root") {
      promptSession.closeSelect()
      promptSession.closePrompt()
      return { kind: "root" }
    }

    return await promptForAdminUser(promptSession.ask, promptSession.closePrompt)
  } finally {
    promptSession.closeSelect()
  }
}

export async function promptForAdminPublicKey(
  select?: SelectFunction<string>,
  publicKeys?: Array<{ key: string; label: string; path: string }>
): Promise<string | undefined> {
  const terminalSelect = select == null ? createTerminalSelect() : null
  const choose = select ?? terminalSelect?.select

  if (choose == null) {
    throw new Error("Interactive selection is unavailable.")
  }

  try {
    return await promptForScaffoldAdminPublicKey(choose, publicKeys)
  } finally {
    terminalSelect?.close()
  }
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

function main(): void {
  const { host, initialUser, projectName } = parseCliArguments(process.argv.slice(2))

  const normalizedProjectName = validateProjectName(projectName)

  const pm = detectPackageManager()
  void (async () => {
    const validatedHost = host == null ? await promptForHost() : validateHost(host)
    const initialUserConfig =
      initialUser == null ? await promptForInitialUserConfig() : parseInitialUserConfig(initialUser)
    const adminPublicKey =
      process.stdin.isTTY && process.stdout.isTTY ? await promptForAdminPublicKey() : undefined
    scaffoldProject(normalizedProjectName, pm, {
      adminPublicKey,
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
