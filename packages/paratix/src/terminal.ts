import { createInterface } from "node:readline"
import { Writable } from "node:stream"

function normalizePromptAbortReason(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error(String(reason))
}

// Hidden prompts need a TTY-shaped output so readline keeps terminal-mode
// behavior, but all redraw/echo chunks must be discarded to avoid leaking
// typed secrets. Only the prompt question itself is forwarded once.
class HiddenPromptOutput extends Writable {
  public readonly columns: number | undefined
  public readonly rows: number | undefined

  private promptWritten = false

  public constructor(
    private readonly question: string,
    private readonly target: NodeJS.WriteStream
  ) {
    super()
    this.columns = target.columns
    this.rows = target.rows
    Object.defineProperty(this, "isTTY", { value: target.isTTY })
  }

  public override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8")
    if (!this.promptWritten && text.includes(this.question)) {
      this.promptWritten = true
      this.target.write(this.question, encoding, callback)
      return
    }

    callback()
  }

  public clearLine(...parameters: Parameters<NodeJS.WriteStream["clearLine"]>): boolean {
    return this.target.clearLine(...parameters)
  }

  public clearScreenDown(
    ...parameters: Parameters<NodeJS.WriteStream["clearScreenDown"]>
  ): boolean {
    return this.target.clearScreenDown(...parameters)
  }

  public cursorTo(...parameters: Parameters<NodeJS.WriteStream["cursorTo"]>): boolean {
    return this.target.cursorTo(...parameters)
  }

  public getColorDepth(...parameters: Parameters<NodeJS.WriteStream["getColorDepth"]>): number {
    return this.target.getColorDepth(...parameters)
  }

  public hasColors(...parameters: Parameters<NodeJS.WriteStream["hasColors"]>): boolean {
    return this.target.hasColors(...parameters)
  }

  public moveCursor(...parameters: Parameters<NodeJS.WriteStream["moveCursor"]>): boolean {
    return this.target.moveCursor(...parameters)
  }
}

function createHiddenPromptOutput(question: string, target: NodeJS.WriteStream): Writable {
  return new HiddenPromptOutput(question, target)
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
