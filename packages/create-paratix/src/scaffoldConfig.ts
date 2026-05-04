import type { InitialUserConfig } from "./templates.js"

import { validateAdminPublicKey } from "./publicKeySelection.js"

type ExitWithMessage = (message: string) => never
type PromptFunction = (question: string) => Promise<string>

type ProgrammaticScaffoldStringOptions = {
  adminPublicKey?: string
  expectedHostFingerprint?: string
  host?: string
}

const CLI_USAGE =
  "Usage: create-paratix <project-name> [--host <domain-or-ip>] [--initial-user <root|name>] [--expected-host-fingerprint <fingerprint>] [--admin-public-key <ssh-public-key>] [--admin-public-key-file <path>]"

const OPENSSH_SHA256_FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+\/]{43}$/v

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

// R-0000125: Reject ASCII/C1 control characters and Unicode bidirectional
// formatting codepoints. Control characters (incl. CR/LF/TAB and DEL) and
// bidi overrides such as U+202D/U+202E or the isolate marks U+2066–U+2069
// can be used to smuggle hostnames that visually look benign but resolve to
// attacker infrastructure when emitted verbatim into server.ts. We keep
// the legacy non-whitespace and non-empty checks and add a stricter
// unsafe-codepoint guard on top.
//
// Codepoint ranges covered:
//   U+0000–U+001F  C0 control characters
//   U+007F         DEL
//   U+0080–U+009F  C1 control characters
//   U+200E, U+200F LRM / RLM
//   U+202A–U+202E  LRE / RLE / PDF / LRO / RLO
//   U+2066–U+2069  LRI / RLI / FSI / PDI
//
// The pattern is built from a string source so that the unicode escape
// sequences survive editor and formatter passes that would otherwise replace
// them with the actual control codepoints.
//
// eslint-disable rationale:
//   - regexp/no-control-character: rejecting these codepoints is the goal
//   - prefer-regex-literals: a literal would re-introduce the formatter
//     mangling we are explicitly avoiding here
//   - regexp/require-unicode-sets-regexp: the `v` flag rejects bare control
//     codepoints in a character class, so we use the `u` flag instead
/* eslint-disable regexp/no-control-character, prefer-regex-literals, regexp/require-unicode-sets-regexp -- rejecting these codepoints is the entire purpose of the check */
const UNSAFE_HOST_CODEPOINTS = new RegExp(
  // oxlint-disable-next-line no-control-regex
  "[\\u0000-\\u001F\\u007F-\\u009F\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]",
  "u"
)
/* eslint-enable regexp/no-control-character, prefer-regex-literals, regexp/require-unicode-sets-regexp */

export function isValidHost(value: string): boolean {
  const normalizedValue = normalizeHost(value)
  if (normalizedValue.length === 0) return false
  if (/\s/v.test(normalizedValue)) return false
  if (UNSAFE_HOST_CODEPOINTS.test(normalizedValue)) return false
  return true
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

export function isValidExpectedHostFingerprint(value: string): boolean {
  return OPENSSH_SHA256_FINGERPRINT_PATTERN.test(value)
}

export function validateExpectedHostFingerprint(
  exitWithMessage: ExitWithMessage,
  value: string
): string {
  if (!isValidExpectedHostFingerprint(value)) {
    exitWithMessage(
      `Error: Invalid expected host fingerprint "${value}" — use an OpenSSH SHA256 fingerprint.`
    )
  }

  return value
}

function throwValidationError(message: string): never {
  throw new Error(message)
}

export function normalizeProgrammaticScaffoldStringOptions(
  options: ProgrammaticScaffoldStringOptions | undefined
): { host: string } & ProgrammaticScaffoldStringOptions {
  return {
    adminPublicKey:
      options?.adminPublicKey == null
        ? undefined
        : validateAdminPublicKey(throwValidationError, options.adminPublicKey),
    expectedHostFingerprint:
      options?.expectedHostFingerprint == null
        ? undefined
        : validateExpectedHostFingerprint(throwValidationError, options.expectedHostFingerprint),
    host: options?.host == null ? "1.2.3.4" : validateHost(throwValidationError, options.host),
  }
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
    optionName:
      | "--admin-public-key-file"
      | "--admin-public-key"
      | "--expected-host-fingerprint"
      | "--host"
      | "--initial-user"
  }
): string {
  const value = argv.at(index + 1)
  if (value == null || value.startsWith("--")) {
    parameters.exitWithMessage(`Error: Missing value for "${parameters.optionName}".`)
  }
  // R-0000129: After the missing-value/long-flag guard above, also reject
  // values that consist only of whitespace and values that span multiple
  // lines. Empty or whitespace-only values silently disable downstream
  // validation (`""` would later present as a missing host or username),
  // and `\r\n`-bearing values can smuggle an entire second line into log
  // output or files generated from the option (e.g. via header injection
  // into `server.ts`). Both cases are rejected with a clear,
  // option-specific error message.
  if (value.trim() === "") {
    parameters.exitWithMessage(
      `Error: Empty value for "${parameters.optionName}" — provide a non-empty value.`
    )
  }
  if (/[\r\n]/v.test(value)) {
    parameters.exitWithMessage(
      `Error: Multi-line value for "${parameters.optionName}" — provide a single-line value.`
    )
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
  expectedHostFingerprint: string | undefined
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

  if (parameters.argument === "--expected-host-fingerprint") {
    const expectedHostFingerprint = parseArgumentValue(parameters.argv, parameters.index, {
      exitWithMessage: parameters.exitWithMessage,
      optionName: "--expected-host-fingerprint",
    })

    return {
      expectedHostFingerprint: validateExpectedHostFingerprint(
        parameters.exitWithMessage,
        expectedHostFingerprint
      ),
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
    expectedHostFingerprint: undefined,
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
