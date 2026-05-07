import type { InitialUserConfig } from "./templates.js"

import { escapeCliControlCharacters } from "./cliFormat.js"
import { promptForAdminPublicKey, promptForHost } from "./interactivePrompts.js"
import { readAdminPublicKeyFile, validateAdminPublicKey } from "./publicKeySelection.js"
import {
  parseCliArguments as parseScaffoldCliArguments,
  parseInitialUserConfig as parseScaffoldInitialUserConfig,
  validateExpectedHostFingerprint as validateScaffoldExpectedHostFingerprint,
  validateHost as validateScaffoldHost,
} from "./scaffoldConfig.js"

export function exitWithMessage(message: string): never {
  console.error(escapeCliControlCharacters(message))
  // eslint-disable-next-line node/no-process-exit
  process.exit(1)
}

export function parseCliArguments(argv: string[]): ReturnType<typeof parseScaffoldCliArguments> {
  return parseScaffoldCliArguments(argv, exitWithMessage)
}

export function parseInitialUserConfig(value: string): InitialUserConfig {
  return parseScaffoldInitialUserConfig(exitWithMessage, value)
}

export function validateHost(value: string): string {
  return validateScaffoldHost(exitWithMessage, value)
}

export function validateExpectedHostFingerprint(value: string): string {
  return validateScaffoldExpectedHostFingerprint(exitWithMessage, value)
}

export async function resolveCliOrPromptAdminPublicKey(parameters: {
  adminPublicKey: string | undefined
  adminPublicKeyFile: string | undefined
  allowPlaceholder?: boolean
}): Promise<string | undefined> {
  const { adminPublicKey, adminPublicKeyFile, allowPlaceholder = true } = parameters

  if (adminPublicKey !== undefined) {
    return validateAdminPublicKey(exitWithMessage, adminPublicKey)
  }

  if (adminPublicKeyFile !== undefined) {
    return readAdminPublicKeyFile(exitWithMessage, adminPublicKeyFile)
  }

  if (process.stdin.isTTY && process.stdout.isTTY) {
    return promptForAdminPublicKey(undefined, undefined, { allowPlaceholder })
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
