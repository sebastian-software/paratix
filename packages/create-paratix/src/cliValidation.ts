import type { InitialUserConfig } from "./templates.js"

import { CliExitError } from "./cliExitError.js"
import { escapeCliControlCharacters } from "./cliFormat.js"
import { promptForAdminPublicKey, promptForHost } from "./interactivePrompts.js"
import { readAdminPublicKeyFile, validateAdminPublicKey } from "./publicKeySelection.js"
import {
  parseCliArguments as parseScaffoldCliArguments,
  parseInitialUserConfig as parseScaffoldInitialUserConfig,
  validateExpectedHostFingerprint as validateScaffoldExpectedHostFingerprint,
  validateHost as validateScaffoldHost,
} from "./scaffoldConfig.js"

export { CliExitError } from "./cliExitError.js"

export function exitWithMessage(message: string): never {
  // R-0000189: keep emitting the user-visible error eagerly so callers and
  // tests observe `console.error` exactly as before. The follow-up cleanup
  // and exit-code assignment is centralised in `handleCliExit`.
  console.error(escapeCliControlCharacters(message))
  throw new CliExitError(message)
}

/**
 * R-0000189: shared cleanup hook so `main()` can reset interactive terminal
 * state (cursor visibility, raw mode) after a CliExitError was thrown from
 * an in-flight prompt. Kept as a small no-op-friendly default so the unit
 * tests can substitute their own implementation.
 */
export function restoreInteractiveTerminal(): void {
  if (process.stdout.isTTY) {
    // Make the cursor visible again. promptUi hides it before drawing the
    // arrow-key select; if exitWithMessage interrupts the render we never
    // reach the matching restore inside cleanupSelectInput.
    process.stdout.write("\x1B[?25h")
  }
  // setRawMode is only available on TTY streams. Reset to cooked mode so
  // the parent shell does not inherit a broken terminal.
  if (process.stdin.isTTY && typeof process.stdin.setRawMode === "function") {
    try {
      process.stdin.setRawMode(false)
    } catch {
      // Best effort: in some environments the call can fail even when
      // isTTY is true (e.g. a detached PTY).
    }
  }
}

/**
 * R-0000189: top-level handler that converts a thrown CliExitError into the
 * intended exit code while running interactive cleanup. Other thrown errors
 * are still surfaced as a generic CLI error. CliExitError already emits the
 * user-visible message via exitWithMessage, so this handler does not print
 * it a second time.
 *
 * @param error - The error caught from the CLI pipeline.
 */
export function handleCliExit(error: unknown): void {
  restoreInteractiveTerminal()
  if (error instanceof CliExitError) {
    process.exitCode = error.exitCode
    return
  }
  console.error(escapeCliControlCharacters(error instanceof Error ? error.message : String(error)))
  process.exitCode = 1
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
