import type { InitialUserConfig } from "./templates.js"

import { CliExitError } from "./cliExitError.js"
import { formatCliValue } from "./cliFormat.js"
import { validateAdminPublicKey } from "./publicKeySelection.js"
import { containsUnsafeCodepoint } from "./unsafeCodepoints.js"

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
const SHA256_FINGERPRINT_PREFIX = "SHA256:"
const SHA256_FINGERPRINT_RAW_BYTE_LENGTH = 32

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
      `Error: Invalid initial user ${formatCliValue(value)} — use "root" or a valid lowercase Linux username.`
    )
  }

  return normalizedValue === "root" ? { kind: "root" } : { kind: "admin", user: normalizedValue }
}

export function normalizeHost(value: string): string {
  return value.trim()
}

// R-0000125: Reject ASCII/C1 control characters and Unicode bidirectional
// formatting codepoints in hostnames. The shared
// `containsUnsafeCodepoint` predicate is reused for public-key comments
// (R-0000233) so both inputs reject the same codepoint ranges.
export function isValidHost(value: string): boolean {
  const normalizedValue = normalizeHost(value)
  if (normalizedValue.length === 0) return false
  if (/\s/v.test(normalizedValue)) return false
  if (containsUnsafeCodepoint(normalizedValue)) return false
  return true
}

export function validateHost(exitWithMessage: ExitWithMessage, value: string): string {
  const normalizedValue = normalizeHost(value)
  if (!isValidHost(normalizedValue)) {
    exitWithMessage(
      `Error: Invalid host ${formatCliValue(value)} — use a domain name, IPv4, or IPv6 address without spaces.`
    )
  }
  return normalizedValue
}

export function isValidExpectedHostFingerprint(value: string): boolean {
  if (!OPENSSH_SHA256_FINGERPRINT_PATTERN.test(value)) {
    return false
  }
  // R-0000737: a regex that matches 43 base64 characters is necessary
  // but not sufficient: `[A-Za-z0-9+/]{43}` accepts canonical-length
  // strings that decode to fewer than 32 raw bytes (e.g. when Node's
  // base64 decoder silently tolerates a malformed trailing group).
  // Decoding the payload and asserting exactly 32 bytes — and then
  // re-encoding to confirm the input is the canonical representation —
  // closes that gap so we cannot pin a fingerprint that does not round
  // trip to a real SHA-256 digest.
  const encoded = value.slice(SHA256_FINGERPRINT_PREFIX.length)
  const decoded = Buffer.from(encoded, "base64")
  if (decoded.length !== SHA256_FINGERPRINT_RAW_BYTE_LENGTH) {
    return false
  }
  // ssh-keygen prints the SHA256 fingerprint without trailing `=`
  // padding, so we compare against the stripped re-encoding to avoid
  // accidentally accepting an alternate canonical form.
  const canonical = decoded.toString("base64")
  let trimmedEnd = canonical.length
  while (trimmedEnd > 0 && canonical[trimmedEnd - 1] === "=") {
    trimmedEnd--
  }
  return canonical.slice(0, trimmedEnd) === encoded
}

export function validateExpectedHostFingerprint(
  exitWithMessage: ExitWithMessage,
  value: string
): string {
  if (!isValidExpectedHostFingerprint(value)) {
    exitWithMessage(
      `Error: Invalid expected host fingerprint ${formatCliValue(value)} — use an OpenSSH SHA256 fingerprint.`
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

// R-0000229: bound the validation retry loop so a closed stdin (EOF, piped
// `< /dev/null`) cannot keep us spinning indefinitely while emitting error
// messages. After MAX_PROMPT_ATTEMPTS rejected entries we abort with a
// CliExitError so the operator sees a deterministic failure mode. We detect
// EOF heuristically: readline.question returns "" (without throwing) once the
// input stream is closed, so the same empty value the validator already
// rejects also signals "no further input available" and we surface a clearer
// error message in that case.
export const MAX_PROMPT_ATTEMPTS = 5

export async function promptForHost(prompt: PromptFunction): Promise<string> {
  for (let attempt = 0; attempt < MAX_PROMPT_ATTEMPTS; attempt++) {
    // eslint-disable-next-line no-await-in-loop
    const rawAnswer = await prompt("Server host (domain or IP): ")
    const host = normalizeHost(rawAnswer)
    if (isValidHost(host)) {
      return host
    }
    if (rawAnswer === "") {
      // R-0000229: empty answer with no prior valid input strongly suggests
      // a closed stdin (EOF). Fail fast instead of looping until the limit.
      throw new CliExitError(
        "Error: No host provided — stdin is closed or empty. Pass --host <domain-or-ip>."
      )
    }
    console.error("Error: Please enter a domain name, IPv4, or IPv6 address without spaces.")
  }
  throw new CliExitError(
    `Error: Too many invalid host entries (${String(MAX_PROMPT_ATTEMPTS)}). Pass --host <domain-or-ip> instead.`
  )
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
  // R-0000734: distinguish between a truly missing argument (no token
  // follows the option) and a token that looks like another long flag
  // ("--something"). The previous implementation conflated both cases
  // and emitted the same "Missing value" message, which made it hard
  // for operators to spot whether they forgot the value entirely or
  // accidentally passed a flag where a value belonged.
  if (value == null) {
    parameters.exitWithMessage(`Error: Missing value for "${parameters.optionName}".`)
  }
  if (value.startsWith("--")) {
    parameters.exitWithMessage(
      `Error: Expected a value for "${parameters.optionName}" but got the flag "${value}". ` +
        `If the value really starts with "--", separate it from the option with "--" or quote it explicitly.`
    )
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
  exitWithMessage(`Error: Unknown option ${formatCliValue(argument)}.`)
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
