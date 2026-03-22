import { createInterface } from "node:readline/promises"

import type { InitialUserConfig } from "./templates.js"

import { readHostFingerprintViaSsh2 } from "./hostFingerprintBootstrap.js"
import { createTerminalSelect, type SelectFunction, type SelectOption } from "./promptUi.js"
import { promptForAdminPublicKey as promptForScaffoldAdminPublicKey } from "./publicKeySelection.js"
import {
  isValidInitialUserName,
  normalizeInitialUserName,
  promptForHost as promptForScaffoldHost,
} from "./scaffoldConfig.js"

type PromptFunction = (question: string) => Promise<string>

const NOOP = (): void => undefined
const INTERACTIVE_SELECTION_UNAVAILABLE = "Interactive selection is unavailable."
const UNAVAILABLE_SELECT = (() => {
  throw new Error(INTERACTIVE_SELECTION_UNAVAILABLE)
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

const HOST_FINGERPRINT_OPTIONS: Array<SelectOption<"placeholder" | "scan">> = [
  {
    description:
      "Read the currently presented host key from SSH port 22 via ssh2 and pin its fingerprint in server.ts.",
    label: "Scan host key",
    value: "scan",
  },
  {
    description:
      "Keep the expectedHostFingerprint placeholder in server.ts and verify the host key manually later.",
    label: "Keep placeholder",
    value: "placeholder",
  },
]

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
  for (;;) {
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

  const terminalPrompt = createTerminalPrompt()
  try {
    return await promptForScaffoldHost(terminalPrompt.prompt)
  } finally {
    terminalPrompt.close()
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

export async function promptForAdminPublicKey(
  select?: SelectFunction<string>,
  publicKeys?: Array<{ key: string; label: string; path: string }>
): Promise<string | undefined> {
  const terminalSelect = select == null ? createTerminalSelect() : null
  const choose = select ?? terminalSelect?.select

  if (choose == null) {
    throw new Error(INTERACTIVE_SELECTION_UNAVAILABLE)
  }

  try {
    return await promptForScaffoldAdminPublicKey(choose, publicKeys)
  } finally {
    terminalSelect?.close()
  }
}

export async function promptForHostFingerprint(
  host: string,
  select?: SelectFunction<"placeholder" | "scan">,
  scanner: (host: string) => Promise<string> = readHostFingerprintViaSsh2
): Promise<string | undefined> {
  const terminalSelect = select == null ? createTerminalSelect() : null
  const choose = select ?? terminalSelect?.select

  if (choose == null) {
    throw new Error(INTERACTIVE_SELECTION_UNAVAILABLE)
  }

  try {
    const hostKeyMode = await choose(
      `How should create-paratix bootstrap the SSH host key for ${host}?`,
      HOST_FINGERPRINT_OPTIONS
    )
    if (hostKeyMode !== "scan") {
      return undefined
    }

    try {
      return await scanner(host)
    } catch (error) {
      console.error(
        `${error instanceof Error ? error.message : String(error)} Keeping the expectedHostFingerprint placeholder in server.ts.`
      )
      return undefined
    }
  } finally {
    terminalSelect?.close()
  }
}
