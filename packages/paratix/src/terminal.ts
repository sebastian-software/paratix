import { createInterface } from "node:readline"

function normalizePromptAbortReason(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error(String(reason))
}

function installHiddenPromptOutput(rl: ReturnType<typeof createInterface>, question: string): void {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- readline internal API for password masking
  const rlInternal = rl as unknown as {
    _writeToOutput: (text: string) => void
    output: NodeJS.WritableStream
  }
  rlInternal._writeToOutput = (text: string) => {
    if (text.includes(question)) {
      rlInternal.output.write(text)
    }
  }
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
  const rl = createInterface({ input: process.stdin, output: process.stderr })
  const abortSignal = options?.abortSignal

  if (hidden) installHiddenPromptOutput(rl, question)

  return new Promise((resolve, reject) => {
    let settled = false
    let rejectClosedPrompt = (): void => {}

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

    rejectClosedPrompt = () => {
      if (settled) return
      settled = true
      cleanup()
      if (hidden) process.stderr.write("\n")
      reject(new Error("Terminal prompt closed before input was received"))
    }

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
