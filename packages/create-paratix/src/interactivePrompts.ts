import { createInterface } from "node:readline/promises"

import type { InitialUserConfig } from "./templates.js"

import { CliExitError } from "./cliExitError.js"
import {
  type HostFingerprintPromptOptions,
  type HostFingerprintScanner,
  type HostFingerprintSelectValue,
  selectHostFingerprint,
} from "./hostFingerprintPrompt.js"
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

export async function promptForHostFingerprint(
  host: string,
  select?: SelectFunction<HostFingerprintSelectValue>,
  options?: HostFingerprintPromptOptions | HostFingerprintScanner
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
    return await selectHostFingerprint(host, choose, options)
  } finally {
    terminalSelect?.close()
  }
}
