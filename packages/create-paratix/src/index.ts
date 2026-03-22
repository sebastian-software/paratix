import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { basename, join, resolve } from "node:path"
import { createInterface } from "node:readline/promises"

import { createTerminalSelect, type SelectFunction, type SelectOption } from "./promptUi.js"
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

export type { InitialUserConfig } from "./templates.js"
type ScaffoldOptions = {
  initialUser?: InitialUserConfig
  installer?: (projectDirectory: string, packageManager: PackageManager) => boolean
}

type PromptFunction = (question: string) => Promise<string>
const NOOP = (): void => undefined
const UNAVAILABLE_SELECT = (() => {
  throw new Error("Interactive selection is unavailable.")
}) as SelectFunction<"admin" | "root">
const CLI_USAGE = "Usage: create-paratix <project-name> [--initial-user <root|name>]"
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

  const initialUser = options?.initialUser ?? { kind: "admin", user: "admin" }

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
  writeFileSync(join(projectDirectory, "server.ts"), createServerTemplate(initialUser))
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

export function isValidInitialUserName(name: string): boolean {
  return /^(?:root|[a-z_][a-z0-9_\x2d]*\$?)$/v.test(name)
}

function normalizeInitialUserName(name: string): string {
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

function parseInitialUserArgument(argv: string[], index: number): string {
  const value = argv.at(index + 1)
  if (value == null) {
    exitWithMessage('Error: Missing value for "--initial-user".')
  }
  if (value.startsWith("--")) {
    exitWithMessage('Error: Missing value for "--initial-user".')
  }
  return value
}

function handleUnknownOption(argument: string): never {
  if (argument === "--bootstrap-root") {
    exitWithMessage('Error: "--bootstrap-root" was removed. Use "--initial-user root" instead.')
  }
  exitWithMessage(`Error: Unknown option "${argument}".`)
}

export function parseCliArguments(argv: string[]): {
  initialUser: string | undefined
  projectName: string | undefined
} {
  let initialUser: string | undefined
  let projectName: string | undefined

  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    if (argument === "--initial-user") {
      initialUser = parseInitialUserArgument(argv, index)
      index++
      continue
    }

    if (argument.startsWith("--")) {
      handleUnknownOption(argument)
    }

    if (projectName == null) {
      projectName = argument
      continue
    }

    exitWithMessage(CLI_USAGE)
  }

  return { initialUser, projectName }
}

export function parseInitialUserConfig(value: string): InitialUserConfig {
  const normalizedValue = normalizeInitialUserName(value)
  if (!isValidInitialUserName(normalizedValue)) {
    exitWithMessage(
      `Error: Invalid initial user "${value}" — use "root" or a valid lowercase Linux username.`
    )
  }

  return normalizedValue === "root" ? { kind: "root" } : { kind: "admin", user: normalizedValue }
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
  const { initialUser, projectName } = parseCliArguments(process.argv.slice(2))

  const normalizedProjectName = validateProjectName(projectName)

  const pm = detectPackageManager()
  void (async () => {
    const initialUserConfig =
      initialUser == null ? await promptForInitialUserConfig() : parseInitialUserConfig(initialUser)
    scaffoldProject(normalizedProjectName, pm, { initialUser: initialUserConfig })
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
