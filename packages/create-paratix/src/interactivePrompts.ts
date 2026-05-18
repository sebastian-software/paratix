import { createInterface } from "node:readline/promises"

import type { InitialUserConfig } from "./templates.js"

import { CliExitError } from "./cliExitError.js"
import { escapeCliControlCharacters } from "./cliFormat.js"
import {
  type HostFingerprintScanResult,
  readHostFingerprintViaSsh2,
} from "./hostFingerprintBootstrap.js"
import { createTerminalSelect, type SelectFunction, type SelectOption } from "./promptUi.js"
import { promptForAdminPublicKey as promptForScaffoldAdminPublicKey } from "./publicKeySelection.js"
import {
  isValidInitialUserName,
  MAX_PROMPT_ATTEMPTS,
  normalizeInitialUserName,
  promptForHost as promptForScaffoldHost,
} from "./scaffoldConfig.js"

type PromptFunction = (question: string) => Promise<string>

const NOOP = (): void => undefined
// R-0000860: the fallback select handler is reached when a caller
// supplies a custom `prompt` but no `select` implementation, so the
// terminal-select helper cannot be constructed. The original handler
// threw a plain `Error`, which the CLI entry point would surface as an
// uncaught stack trace instead of a clean shell exit. Surface a
// `CliExitError` here so the failure mode matches the other prompt
// paths (e.g. `enforceInteractivePromptTty` and the prompt-session
// constructor), which already exit with code 1 and a structured
// message.
const INTERACTIVE_SELECTION_UNAVAILABLE =
  "Interactive selection is unavailable. Pass --initial-user <root|name> to skip the prompt."
const UNAVAILABLE_SELECT = (() => {
  throw new CliExitError(INTERACTIVE_SELECTION_UNAVAILABLE, 1)
}) as SelectFunction<"admin" | "root">

// R-0000664: refuse to run any prompt that drives `createTerminalSelect()`
// (or any other readline/setRawMode flow) outside an attached TTY.
// Previously the TTY check lived one level up in cliValidation.ts, so any
// caller that imported the prompts directly — or a CI runner whose
// `process.stdin.isTTY` returned `undefined` — would still try to flip
// stdin into raw mode and crash with `setRawMode is not a function`.
// Surfacing a CliExitError before the readline interface is ever opened
// keeps the failure mode deterministic and the terminal state intact.
//
// R-0000742: the same TTY gate appeared inline in
// `promptForInitialUserConfig` with a different remediation hint. Both
// callsites now go through `enforceInteractivePromptTty`, parameterised
// by the option-specific hint, so the gate logic stays in one place
// and a future remediation tweak does not have to be applied twice.
const GENERIC_NON_TTY_HINT =
  "Pass --admin-public-key/--admin-public-key-file and --expected-host-fingerprint " +
  "(or run create-paratix from an interactive shell) to skip the prompt."

const INITIAL_USER_NON_TTY_HINT =
  "Pass --initial-user <root|name> (or run create-paratix from an interactive shell) " +
  "to skip the prompt."

// `process.stdin.isTTY` and `process.stdout.isTTY` are typed `boolean`
// in the Node @types but at runtime are `undefined` for non-TTY streams.
function enforceInteractivePromptTty(remediationHint: string): void {
  if (process.stdin.isTTY && process.stdout.isTTY) return
  throw new CliExitError(`Interactive prompt requires a TTY. ${remediationHint}`, 1)
}

function ensureInteractivePromptTty(): void {
  enforceInteractivePromptTty(GENERIC_NON_TTY_HINT)
}

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

const HOST_FINGERPRINT_OPTIONS: Array<SelectOption<"placeholder" | "scan">> = [
  {
    description:
      "Read the currently presented host key from SSH port 22 via ssh2 and pin its fingerprint in server.ts.",
    label: "Scan host key",
    value: "scan",
  },
  {
    description:
      "Skip pinning now. The generated project will fail closed until known_hosts is prepared or a verified expectedHostFingerprint/PublicKey is added.",
    label: "Skip pinning",
    value: "placeholder",
  },
]

// R-0000122: after scanning the live host key we must not silently pin the
// fingerprint (blind TOFU). The operator confirms the scanned value out of
// band before it is written into server.ts.
const HOST_FINGERPRINT_CONFIRM_OPTIONS: Array<SelectOption<"discard" | "pin">> = [
  {
    description:
      "Skip pinning now. The generated project will fail closed until known_hosts is prepared or a verified host-key pin is added.",
    label: "Discard and skip",
    value: "discard",
  },
  {
    description:
      "Pin the scanned fingerprint into server.ts. Only choose this if the algorithm and fingerprint match an out-of-band reference (server console, provider dashboard, ssh-keyscan over a trusted network).",
    label: "Pin this fingerprint",
    value: "pin",
  },
]

// R-0000122: render the scanned host key on isolated lines so an operator
// can copy it cleanly for an out-of-band comparison.
function describeScanResult(host: string, result: HostFingerprintScanResult): string {
  const escapedHost = escapeCliControlCharacters(host)
  return [
    "",
    `Scanned SSH host key for ${escapedHost}:22`,
    `  algorithm:   ${escapeCliControlCharacters(result.algorithm)}`,
    `  fingerprint:`,
    `    ${escapeCliControlCharacters(result.fingerprint)}`,
    "",
    "Compare this value against an out-of-band reference before pinning it.",
    "",
  ].join("\n")
}

function createTerminalPrompt(): { close: () => void; prompt: PromptFunction } {
  const readline = createInterface({ input: process.stdin, output: process.stdout })
  return {
    close(): void {
      readline.close()
    },
    prompt: async (question: string): Promise<string> => readline.question(question),
  }
}

export type InitialUserPromptSession = {
  ask: PromptFunction
  chooseInitialUser: SelectFunction<"admin" | "root">
  closePrompt: () => void
  closeSelect: () => void
}

function createPromptSession(prompt?: PromptFunction): InitialUserPromptSession {
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

// R-0000229: bound the validation retry loop so a closed stdin (EOF, piped
// `< /dev/null`) cannot keep us spinning indefinitely while emitting error
// messages. After MAX_PROMPT_ATTEMPTS rejected entries we abort with a
// CliExitError so the operator sees a deterministic failure mode. An empty
// answer (readline.question on a closed stream returns "") short-circuits
// with a more informative EOF error instead of waiting for the limit.
async function promptForAdminUser(ask: PromptFunction): Promise<InitialUserConfig> {
  for (let attempt = 0; attempt < MAX_PROMPT_ATTEMPTS; attempt++) {
    // eslint-disable-next-line no-await-in-loop
    const rawAnswer = await ask("Admin username: ")
    const adminUser = normalizeInitialUserName(rawAnswer)
    if (isValidInitialUserName(adminUser) && adminUser !== "root") {
      return { kind: "admin", user: adminUser }
    }
    if (rawAnswer === "") {
      throw new CliExitError(
        "Error: No admin username provided — stdin is closed or empty. Pass --initial-user <root|name>."
      )
    }

    console.error(
      'Error: Invalid admin username. Use a valid lowercase Linux username other than "root".'
    )
  }
  throw new CliExitError(
    `Error: Too many invalid admin username entries (${String(MAX_PROMPT_ATTEMPTS)}). Pass --initial-user <root|name> instead.`
  )
}

export async function promptForHost(
  prompt?: PromptFunction,
  closePrompt: () => void = NOOP
): Promise<string> {
  if (prompt != null) {
    try {
      return await promptForScaffoldHost(prompt)
    } finally {
      closePrompt()
    }
  }

  // R-0000664: refuse non-TTY callers before `createTerminalPrompt()`
  // opens a readline interface on stdin. Tests and other consumers that
  // inject their own `prompt` argument bypass the terminal setup, so the
  // check only runs on the default path — mirroring the gate in
  // promptForAdminPublicKey and promptForHostFingerprint.
  ensureInteractivePromptTty()
  const terminalPrompt = createTerminalPrompt()
  try {
    return await promptForScaffoldHost(terminalPrompt.prompt)
  } finally {
    terminalPrompt.close()
  }
}

export async function promptForInitialUserConfig(
  prompt?: PromptFunction,
  select?: SelectFunction<"admin" | "root">,
  createSession: (prompt?: PromptFunction) => InitialUserPromptSession = createPromptSession
): Promise<InitialUserConfig> {
  // R-0000684: refuse non-TTY callers before `createPromptSession()` opens
  // a readline interface and `createTerminalSelect()` flips stdin into raw
  // mode. Without this guard a non-TTY caller crashed inside
  // `runTerminalSelect` with a generic Error that skipped the CliExit
  // cleanup and the `--initial-user` hint. Tests and other consumers that
  // inject a `createSession` factory bypass the terminal-select setup and
  // keep working unchanged. R-0000724: the gate keys off `prompt` and the
  // session factory only — the same shape as the sibling prompts that
  // only check the single injected handle. A caller that wires up a
  // custom prompt but lets `select` default would otherwise be denied
  // here even though the default-select code path is never reached.
  // R-0000742: the actual TTY check is shared with
  // `ensureInteractivePromptTty` via `enforceInteractivePromptTty`; we
  // only run it after the injection guard so consumers that wire up
  // their own prompt session continue to bypass the gate.
  if (prompt == null && createSession === createPromptSession) {
    enforceInteractivePromptTty(INITIAL_USER_NON_TTY_HINT)
  }
  const promptSession = createSession(prompt)
  const chooseInitialUser = select ?? promptSession.chooseInitialUser

  try {
    const initialUserType = await chooseInitialUser(
      "Which SSH user already works for the first connection to this server?",
      INITIAL_USER_OPTIONS
    )

    if (initialUserType === "root") {
      return { kind: "root" }
    }

    return await promptForAdminUser(promptSession.ask)
  } finally {
    // R-0000057: close the readline interface and the terminal-select
    // helper unconditionally so a thrown error inside the chooser or
    // promptForAdminUser (closed stdin, EPIPE, SIGINT) cannot leak open
    // handles. readline.close and terminalSelect.close are idempotent.
    promptSession.closeSelect()
    promptSession.closePrompt()
  }
}

export async function promptForAdminPublicKey(
  select?: SelectFunction<string>,
  publicKeys?: Array<{ key: string; label: string; path: string }>,
  options?: { allowPlaceholder?: boolean }
): Promise<string | undefined> {
  // R-0000664: refuse non-TTY callers before `createTerminalSelect()`
  // opens a readline interface and calls `setRawMode` on stdin. Tests
  // and other consumers that inject their own `select` argument bypass
  // both the TTY guard and the terminal-select setup, so the check only
  // runs on the default path.
  if (select == null) ensureInteractivePromptTty()
  const terminalSelect = select == null ? createTerminalSelect() : null
  const choose = select ?? terminalSelect?.select

  if (choose == null) {
    throw new Error(INTERACTIVE_SELECTION_UNAVAILABLE)
  }

  try {
    return await promptForScaffoldAdminPublicKey(choose, publicKeys, options)
  } finally {
    terminalSelect?.close()
  }
}

// R-0000128: explicit type for the host-fingerprint prompt so callers and
// tests can express any combination of select responses while keeping the
// internal call sites strongly typed.
type HostFingerprintSelectValue = "discard" | "pin" | "placeholder" | "scan"

async function scanHostFingerprint(host: string): Promise<HostFingerprintScanResult> {
  return readHostFingerprintViaSsh2(host, { allowSsh2HostKeyScan: true })
}

/**
 * Run a typed select on a chooser parameterised over a wider value set.
 * The chooser is contravariant in `TValue` for the options parameter, so
 * passing a narrow `Array<SelectOption<TNarrow>>` is sound, but the
 * returned `TWide` must be narrowed to `TNarrow` at runtime.
 *
 * R-0000231: validate the returned value against the offered options at
 * runtime before casting. A stubbed or buggy chooser that returns a value
 * outside the options array would otherwise let an unrelated branch run
 * (silent type-confusion). We surface a hard error so the failure mode is
 * obvious instead of masquerading as a different option.
 *
 * @param choose - The chooser parameterised over a wider value set.
 * @param prompt - The prompt text to display.
 * @param options - The options offered to the operator.
 * @returns The selected value, narrowed to `TNarrow`.
 */
async function chooseFrom<TWide extends string, TNarrow extends TWide>(
  choose: SelectFunction<TWide>,
  prompt: string,
  options: Array<SelectOption<TNarrow>>
): Promise<TNarrow> {
  const result = await choose(prompt, options)
  // R-0000231: runtime narrowing. A chooser that returns a value not present
  // in the offered options is treated as a programming error. We emit a
  // generic diagnostic so attacker-controlled labels cannot leak into the
  // message.
  const matchedOption = options.find((option) => option.value === result)
  if (matchedOption == null) {
    throw new Error(
      `Internal error: select returned an unexpected option for prompt ${JSON.stringify(prompt)}.`
    )
  }
  return matchedOption.value
}

function failAfterScanFailure(host: string, error: unknown): never {
  const reason = escapeCliControlCharacters(error instanceof Error ? error.message : String(error))
  const escapedHost = escapeCliControlCharacters(host)
  // R-0000128: word the failure as an explicit MITM-warning so an operator
  // does not dismiss it as a transient network glitch.
  console.error(
    [
      "",
      `Warning: failed to scan SSH host key for ${escapedHost}.`,
      `  reason: ${reason}`,
      "  This may indicate a man-in-the-middle attempt or a firewall blocking",
      "  the SSH handshake. Verify the host key out of band before pinning",
      "  any fingerprint into server.ts.",
      "",
    ].join("\n")
  )

  throw new Error(
    `Aborting scaffolding: host-key scan for ${escapedHost} failed (${reason}). ` +
      `Re-run create-paratix once the SSH handshake to ${escapedHost}:22 succeeds, ` +
      `or pass --expected-host-fingerprint with an out-of-band verified fingerprint.`
  )
}

/**
 * Run the scan-and-confirm flow for a host fingerprint.
 *
 * @param parameters - Scan flow parameters.
 * @param parameters.choose - Interactive select function.
 * @param parameters.host - The remote host to scan.
 * @param parameters.scanner - Implementation of the SSH host-key scan.
 * @returns The pinned fingerprint, or `undefined` when the operator
 *   declines to pin.
 */
async function scanAndConfirmFingerprint(parameters: {
  choose: SelectFunction<HostFingerprintSelectValue>
  host: string
  scanner: (host: string) => Promise<HostFingerprintScanResult>
}): Promise<string | undefined> {
  const { choose, host, scanner } = parameters

  let result: HostFingerprintScanResult
  try {
    result = await scanner(host)
  } catch (error) {
    // R-0000128: do not silently swallow scan failures. The helper
    // returns `never` and unconditionally throws (R-0000735 — no
    // second throw needed), so `result` is guaranteed to be assigned
    // for the remainder of the function.
    failAfterScanFailure(host, error)
  }

  // R-0000122: surface the scanned material on isolated lines so the
  // operator can copy and compare it against an out-of-band reference
  // before pinning it into server.ts.
  console.log(describeScanResult(host, result))

  const confirmation = await chooseFrom(
    choose,
    `Pin the scanned host fingerprint for ${escapeCliControlCharacters(host)}?`,
    HOST_FINGERPRINT_CONFIRM_OPTIONS
  )
  if (confirmation !== "pin") {
    const escapedHost = escapeCliControlCharacters(host)
    throw new Error(
      `Aborting scaffolding: scanned host fingerprint for ${escapedHost} was not pinned. ` +
        `Re-run create-paratix and pin a verified fingerprint, or pass --expected-host-fingerprint.`
    )
  }
  return result.fingerprint
}

export async function promptForHostFingerprint(
  host: string,
  select?: SelectFunction<HostFingerprintSelectValue>,
  scanner: (host: string) => Promise<HostFingerprintScanResult> = scanHostFingerprint
): Promise<string | undefined> {
  // R-0000664: refuse non-TTY callers before `createTerminalSelect()`
  // opens a readline interface and calls `setRawMode` on stdin. Tests
  // and other consumers that inject their own `select` argument bypass
  // both the TTY guard and the terminal-select setup, so the check only
  // runs on the default path.
  if (select == null) ensureInteractivePromptTty()
  const terminalSelect = select == null ? createTerminalSelect() : null
  const choose = select ?? terminalSelect?.select

  if (choose == null) {
    throw new Error(INTERACTIVE_SELECTION_UNAVAILABLE)
  }

  try {
    const hostKeyMode = await chooseFrom(
      choose,
      `How should create-paratix bootstrap the SSH host key for ${escapeCliControlCharacters(host)}?`,
      HOST_FINGERPRINT_OPTIONS
    )
    if (hostKeyMode !== "scan") {
      return undefined
    }

    return await scanAndConfirmFingerprint({ choose, host, scanner })
  } finally {
    terminalSelect?.close()
  }
}
