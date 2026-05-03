import { createInterface } from "node:readline/promises"

import type { InitialUserConfig } from "./templates.js"

import {
  type HostFingerprintScanResult,
  readHostFingerprintViaSsh2,
} from "./hostFingerprintBootstrap.js"
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

// R-0000122: after scanning the live host key we must not silently pin the
// fingerprint (blind TOFU). The operator confirms the scanned value out of
// band before it is written into server.ts.
const HOST_FINGERPRINT_CONFIRM_OPTIONS: Array<SelectOption<"discard" | "pin">> = [
  {
    description:
      "Pin the scanned fingerprint into server.ts. Only choose this if the algorithm and fingerprint match an out-of-band reference (server console, provider dashboard, ssh-keyscan over a trusted network).",
    label: "Pin this fingerprint",
    value: "pin",
  },
  {
    description:
      "Keep the expectedHostFingerprint placeholder in server.ts. Choose this if you cannot verify the fingerprint right now.",
    label: "Discard and keep placeholder",
    value: "discard",
  },
]

// R-0000128: a failed scan can be a real network issue, but it can also be
// a man-in-the-middle that drops the SSH handshake to force a downgrade.
// We surface the failure as an explicit warning and require the operator
// to acknowledge it instead of silently returning undefined.
const HOST_FINGERPRINT_SCAN_FAILURE_OPTIONS: Array<SelectOption<"abort" | "continue">> = [
  {
    description:
      "Abort scaffolding now. Investigate the network path (TCP reachability, firewall, DNS) before retrying.",
    label: "Abort and investigate",
    value: "abort",
  },
  {
    description:
      "Keep the expectedHostFingerprint placeholder in server.ts and continue. Verify the host key out of band before the first paratix apply.",
    label: "Continue without pinning",
    value: "continue",
  },
]

// R-0000122: render the scanned host key on isolated lines so an operator
// can copy it cleanly for an out-of-band comparison.
function describeScanResult(host: string, result: HostFingerprintScanResult): string {
  return [
    "",
    `Scanned SSH host key for ${host}:22`,
    `  algorithm:   ${result.algorithm}`,
    `  fingerprint:`,
    `    ${result.fingerprint}`,
    "",
    "Compare this value against an out-of-band reference before pinning it.",
    "",
  ].join("\n")
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

async function promptForAdminUser(ask: PromptFunction): Promise<InitialUserConfig> {
  for (;;) {
    // eslint-disable-next-line no-await-in-loop
    const adminUser = normalizeInitialUserName(await ask("Admin username: "))
    if (isValidInitialUserName(adminUser) && adminUser !== "root") {
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

// R-0000128: explicit type for the host-fingerprint prompt so callers and
// tests can express any combination of select responses while keeping the
// internal call sites strongly typed.
type HostFingerprintSelectValue = "abort" | "continue" | "discard" | "pin" | "placeholder" | "scan"

async function confirmAfterScanFailure(
  choose: SelectFunction<HostFingerprintSelectValue>,
  host: string,
  error: unknown
): Promise<void> {
  const reason = error instanceof Error ? error.message : String(error)
  // R-0000128: word the failure as an explicit MITM-warning so an operator
  // does not dismiss it as a transient network glitch.
  console.error(
    [
      "",
      `Warning: failed to scan SSH host key for ${host}.`,
      `  reason: ${reason}`,
      "  This may indicate a man-in-the-middle attempt or a firewall blocking",
      "  the SSH handshake. Verify the host key out of band before pinning",
      "  any fingerprint into server.ts.",
      "",
    ].join("\n")
  )

  const decision = await (choose as SelectFunction<"abort" | "continue">)(
    `How should create-paratix proceed after the failed host-key scan for ${host}?`,
    HOST_FINGERPRINT_SCAN_FAILURE_OPTIONS
  )

  if (decision === "abort") {
    throw new Error(
      `Aborting scaffolding: host-key scan for ${host} failed (${reason}). ` +
        `Re-run create-paratix once the SSH handshake to ${host}:22 succeeds, ` +
        `or skip the scan by selecting "Keep placeholder".`
    )
  }
}

export async function promptForHostFingerprint(
  host: string,
  select?: SelectFunction<HostFingerprintSelectValue>,
  scanner: (host: string) => Promise<HostFingerprintScanResult> = readHostFingerprintViaSsh2
): Promise<string | undefined> {
  const terminalSelect = select == null ? createTerminalSelect() : null
  const choose = select ?? terminalSelect?.select

  if (choose == null) {
    throw new Error(INTERACTIVE_SELECTION_UNAVAILABLE)
  }

  try {
    const hostKeyMode = await (choose as SelectFunction<"placeholder" | "scan">)(
      `How should create-paratix bootstrap the SSH host key for ${host}?`,
      HOST_FINGERPRINT_OPTIONS
    )
    if (hostKeyMode !== "scan") {
      return undefined
    }

    let result: HostFingerprintScanResult
    try {
      result = await scanner(host)
    } catch (error) {
      // R-0000128: do not silently swallow scan failures. Surface a
      // possible-MITM warning and let the operator decide between aborting
      // and continuing without pinning. confirmAfterScanFailure throws
      // when the operator chooses to abort so the caller propagates a
      // non-zero exit instead of a quiet undefined.
      await confirmAfterScanFailure(choose, host, error)
      return undefined
    }

    // R-0000122: surface the scanned material on isolated lines so the
    // operator can copy and compare it against an out-of-band reference
    // before pinning it into server.ts.
    console.log(describeScanResult(host, result))

    const confirmation = await (choose as SelectFunction<"discard" | "pin">)(
      `Pin the scanned host fingerprint for ${host}?`,
      HOST_FINGERPRINT_CONFIRM_OPTIONS
    )
    if (confirmation !== "pin") {
      return undefined
    }
    return result.fingerprint
  } finally {
    terminalSelect?.close()
  }
}
