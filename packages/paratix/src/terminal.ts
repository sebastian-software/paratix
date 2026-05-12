import { createInterface } from "node:readline"
import { Writable } from "node:stream"

function normalizePromptAbortReason(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error(String(reason))
}

// R-0000263: render the password prompt without echoing typed characters by
// supplying a custom Writable to readline rather than monkey-patching the
// internal `_writeToOutput`. The wrapper forwards the prompt question once
// (so the operator sees the question) and discards everything readline would
// otherwise echo back. This avoids the readline private-API dependency and
// the type-cast through `unknown`.
function createHiddenPromptOutput(question: string, target: NodeJS.WritableStream): Writable {
  return new Writable({
    write(chunk: Buffer | string, encoding, callback) {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8")
      if (text.includes(question)) target.write(text, encoding, callback)
      else callback()
    },
  })
}

function createPromptAbortHandler(parameters: {
  abortSignal?: AbortSignal
  cleanup: () => void
  hidden: boolean
  reject: (reason?: unknown) => void
  rl: ReturnType<typeof createInterface>
  setSettled: () => void
  settled: () => boolean
}): () => void {
  return () => {
    if (parameters.settled()) return
    parameters.setSettled()
    parameters.cleanup()
    parameters.rl.close()
    if (parameters.hidden) process.stderr.write("\n")
    parameters.reject(
      normalizePromptAbortReason(
        parameters.abortSignal?.reason ?? new Error("Terminal prompt aborted")
      )
    )
  }
}

/**
 * Prompt the user for input on the terminal.
 * When `hidden` is true the typed characters are not echoed (for passwords).
 *
 * @param question - The prompt text shown to the user.
 * @param hidden - Whether to suppress character echo (password mode).
 * @param options - Optional prompt behavior.
 * @param options.abortSignal - Optional abort signal that cancels the active prompt.
 * @returns The entered string.
 */
export async function promptTerminal(
  question: string,
  hidden = false,
  options?: { abortSignal?: AbortSignal }
): Promise<string> {
  const output = hidden ? createHiddenPromptOutput(question, process.stderr) : process.stderr
  const rl = createInterface({ input: process.stdin, output })
  const abortSignal = options?.abortSignal

  return new Promise((resolve, reject) => {
    let settled = false

    const rejectClosedPrompt = (): void => {
      if (settled) return
      settled = true
      cleanup()
      if (hidden) process.stderr.write("\n")
      reject(new Error("Terminal prompt closed before input was received"))
    }

    const cleanup = (): void => {
      abortSignal?.removeEventListener("abort", rejectPrompt)
      rl.removeListener("close", rejectClosedPrompt)
    }

    const resolvePrompt = (answer: string): void => {
      if (settled) return
      settled = true
      cleanup()
      rl.close()
      if (hidden) process.stderr.write("\n")
      resolve(answer)
    }

    const rejectPrompt = createPromptAbortHandler({
      abortSignal,
      cleanup,
      hidden,
      reject,
      rl,
      setSettled() {
        settled = true
      },
      settled: () => settled,
    })

    if (abortSignal?.aborted === true) {
      rejectPrompt()
      return
    }

    abortSignal?.addEventListener("abort", rejectPrompt, { once: true })
    rl.once("close", rejectClosedPrompt)

    rl.question(question, (answer) => {
      resolvePrompt(answer)
    })
  })
}
