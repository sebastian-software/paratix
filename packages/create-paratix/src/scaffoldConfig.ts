import type { InitialUserConfig } from "./templates.js"

type ExitWithMessage = (message: string) => never
type PromptFunction = (question: string) => Promise<string>

const CLI_USAGE =
  "Usage: create-paratix <project-name> [--host <domain-or-ip>] [--initial-user <root|name>] [--admin-public-key <ssh-public-key>] [--admin-public-key-file <path>]"

export function getCliUsage(): string {
  return CLI_USAGE
}

export function normalizeInitialUserName(name: string): string {
  return name.trim()
}

export function isValidInitialUserName(name: string): boolean {
  return /^(?:root|[a-z_][a-z0-9_\x2d]*\$?)$/v.test(name)
}

export function parseInitialUserConfig(
  exitWithMessage: ExitWithMessage,
  value: string
): InitialUserConfig {
  const normalizedValue = normalizeInitialUserName(value)
  if (!isValidInitialUserName(normalizedValue)) {
    exitWithMessage(
      `Error: Invalid initial user "${value}" — use "root" or a valid lowercase Linux username.`
    )
  }

  return normalizedValue === "root" ? { kind: "root" } : { kind: "admin", user: normalizedValue }
}

export function normalizeHost(value: string): string {
  return value.trim()
}

export function isValidHost(value: string): boolean {
  const normalizedValue = normalizeHost(value)
  return normalizedValue.length > 0 && !/\s/v.test(normalizedValue)
}

export function validateHost(exitWithMessage: ExitWithMessage, value: string): string {
  const normalizedValue = normalizeHost(value)
  if (!isValidHost(normalizedValue)) {
    exitWithMessage(
      `Error: Invalid host "${value}" — use a domain name, IPv4, or IPv6 address without spaces.`
    )
  }
  return normalizedValue
}

export async function promptForHost(prompt: PromptFunction): Promise<string> {
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    const host = normalizeHost(await prompt("Server host (domain or IP): "))
    if (isValidHost(host)) {
      return host
    }
    console.error("Error: Please enter a domain name, IPv4, or IPv6 address without spaces.")
  }
}

function parseArgumentValue(
  argv: string[],
  index: number,
  parameters: {
    exitWithMessage: ExitWithMessage
    optionName: "--admin-public-key-file" | "--admin-public-key" | "--host" | "--initial-user"
  }
): string {
  const value = argv.at(index + 1)
  if (value == null || value.startsWith("--")) {
    parameters.exitWithMessage(`Error: Missing value for "${parameters.optionName}".`)
  }
  return value
}

function handleUnknownOption(argument: string, exitWithMessage: ExitWithMessage): never {
  if (argument === "--bootstrap-root") {
    exitWithMessage('Error: "--bootstrap-root" was removed. Use "--initial-user root" instead.')
  }
  exitWithMessage(`Error: Unknown option "${argument}".`)
}

type ParsedCliArguments = {
  adminPublicKey: string | undefined
  adminPublicKeyFile: string | undefined
  host: string | undefined
  initialUser: string | undefined
  projectName: string | undefined
}

function parseOptionAssignment(parameters: {
  argument: string
  argv: string[]
  exitWithMessage: ExitWithMessage
  index: number
}): null | Partial<ParsedCliArguments> {
  if (parameters.argument === "--host") {
    return {
      host: parseArgumentValue(parameters.argv, parameters.index, {
        exitWithMessage: parameters.exitWithMessage,
        optionName: "--host",
      }),
    }
  }

  if (parameters.argument === "--initial-user") {
    return {
      initialUser: parseArgumentValue(parameters.argv, parameters.index, {
        exitWithMessage: parameters.exitWithMessage,
        optionName: "--initial-user",
      }),
    }
  }

  if (parameters.argument === "--admin-public-key") {
    return {
      adminPublicKey: parseArgumentValue(parameters.argv, parameters.index, {
        exitWithMessage: parameters.exitWithMessage,
        optionName: "--admin-public-key",
      }),
    }
  }

  if (parameters.argument === "--admin-public-key-file") {
    return {
      adminPublicKeyFile: parseArgumentValue(parameters.argv, parameters.index, {
        exitWithMessage: parameters.exitWithMessage,
        optionName: "--admin-public-key-file",
      }),
    }
  }

  return null
}

export function parseCliArguments(
  argv: string[],
  exitWithMessage: ExitWithMessage
): ParsedCliArguments {
  const parsed: ParsedCliArguments = {
    adminPublicKey: undefined,
    adminPublicKeyFile: undefined,
    host: undefined,
    initialUser: undefined,
    projectName: undefined,
  }

  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    const optionAssignment = parseOptionAssignment({ argument, argv, exitWithMessage, index })
    if (optionAssignment != null) {
      Object.assign(parsed, optionAssignment)
      index++
      continue
    }

    parsed.projectName = handlePositionalOrUnknownArgument(
      parsed.projectName,
      argument,
      exitWithMessage
    )
  }

  validatePublicKeyOptions(parsed, exitWithMessage)

  return parsed
}

function handlePositionalOrUnknownArgument(
  projectName: string | undefined,
  argument: string,
  exitWithMessage: ExitWithMessage
): string {
  if (argument.startsWith("--")) {
    handleUnknownOption(argument, exitWithMessage)
  }

  if (projectName == null) {
    return argument
  }

  exitWithMessage(CLI_USAGE)
}

function validatePublicKeyOptions(
  parsed: ParsedCliArguments,
  exitWithMessage: ExitWithMessage
): void {
  if (parsed.adminPublicKey == null || parsed.adminPublicKeyFile == null) {
    return
  }

  exitWithMessage('Error: Use either "--admin-public-key" or "--admin-public-key-file", not both.')
}
