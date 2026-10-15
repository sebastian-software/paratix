import type { SecretRequest } from "./secretResolution.js"

import { getRunnerAbortSignal } from "../runnerAbortSignal.js"
import { promptTerminal } from "../terminal.js"
import { sanitizeTerminalText } from "../terminalSanitizer.js"

/** Optional display labels; source references are never used as prompt text. */
export type ManualSecretProviderOptions = {
  labels?: Readonly<Record<string, string>>
}

type PromptState = { busy: boolean }
const MANUAL_PROMPT_STATE_KEY = Symbol.for("paratix.secret.manualPrompt")

function isPromptState(value: unknown): value is PromptState {
  return (
    typeof value === "object" &&
    value !== null &&
    "busy" in value &&
    typeof value.busy === "boolean"
  )
}

function sharedPromptState(): PromptState {
  const registry = globalThis as Record<symbol, unknown>
  const existing = registry[MANUAL_PROMPT_STATE_KEY]
  if (existing === undefined) {
    const created = { busy: false }
    registry[MANUAL_PROMPT_STATE_KEY] = created
    return created
  }
  if (isPromptState(existing)) return existing
  throw new Error("Incompatible shared manual secret prompt state")
}

async function readManualSecret(label: string): Promise<string> {
  const abortSignal = getRunnerAbortSignal()
  abortSignal?.throwIfAborted()
  // Node types declare isTTY as boolean, while redirected streams expose undefined.
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-boolean-literal-compare -- require actual TTYs on both streams
  if (process.stdin.isTTY !== true || process.stderr.isTTY !== true) {
    throw new Error("Manual secret input requires a TTY on stdin and stderr")
  }
  const state = sharedPromptState()
  if (state.busy) throw new Error("Another manual secret prompt is already active")
  state.busy = true
  try {
    return await promptTerminal(`${sanitizeTerminalText(label)}: `, true, { abortSignal })
  } finally {
    state.busy = false
  }
}

/**
 * Each facade retains only opaque identities, never values or input promises.
 * @param labels - Copied display labels independent of source references.
 * @returns The facade's synchronous request preparation function.
 */
export function createManualRequestFactory(labels: ReadonlyMap<string, string>) {
  const identities = new Map<string, Map<string, symbol>>()
  return (name: string, reference: string, markedTotp: boolean): SecretRequest => {
    const label = labels.get(name) ?? name
    if (markedTotp) {
      return {
        name,
        reference,
        resolution: "per-access",
        resolve: async () => readManualSecret(label),
      }
    }
    let byReference = identities.get(name)
    if (byReference == null) {
      byReference = new Map()
      identities.set(name, byReference)
    }
    let cacheKey = byReference.get(reference)
    if (cacheKey == null) {
      cacheKey = Symbol("manual secret request")
      byReference.set(reference, cacheKey)
    }
    return {
      early: { cacheKey, load: async () => readManualSecret(label) },
      name,
      reference,
    }
  }
}
