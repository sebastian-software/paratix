import { createInterface } from "node:readline"
import { Writable } from "node:stream"

/** ASCII ESC byte (0x1B) used to start ANSI/VT100 control sequences. */
const ASCII_ESC = 0x1b

/** ANSI escape sequence to re-show the terminal cursor ("ESC [ ? 25 h"). */
const ANSI_SHOW_CURSOR = `${String.fromCharCode(ASCII_ESC)}[?25h`

function normalizePromptAbortReason(reason: unknown): Error {
  return reason instanceof Error ? reason : new Error(String(reason))
}

// Hidden prompts need a TTY-shaped output so readline keeps terminal-mode
// behavior, but all redraw/echo chunks must be discarded to avoid leaking
// typed secrets. The prompt text itself is written directly to the target
// stream by promptTerminal before rl.question is invoked, so _write
// suppresses every chunk readline would emit. Chunk-based detection of the
// prompt text is unreliable because readline may split the prompt across
// multiple _write invocations, in which case a substring check would
// suppress the chunk that actually carries the prompt.
class HiddenPromptOutput extends Writable {
  public readonly columns: number | undefined
  public readonly rows: number | undefined

  public constructor(private readonly target: NodeJS.WriteStream) {
    super()
    this.columns = target.columns
    this.rows = target.rows
    Object.defineProperty(this, "isTTY", { value: target.isTTY })
  }

  public override _write(
    _chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void
  ): void {
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

function createHiddenPromptOutput(target: NodeJS.WriteStream): Writable {
  return new HiddenPromptOutput(target)
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
  const output = hidden ? createHiddenPromptOutput(process.stderr) : process.stderr
  const rl = createInterface({ input: process.stdin, output })
  const abortSignal = options?.abortSignal

  // An interactive prompt (sudo password, host-key confirmation, `pause`
  // builtin) can run while the live module spinner in output.ts is active and
  // has hidden the cursor via "ESC [ ? 25 l". Re-show the cursor on the prompt
  // stream so the user always sees where their input goes. Only emit the
  // escape on a TTY so redirected/piped stderr stays clean. Both the hidden
  // and the visible path write their prompt to process.stderr, so writing here
  // covers both.
  if (process.stderr.isTTY) {
    process.stderr.write(ANSI_SHOW_CURSOR)
  }

  if (hidden) {
    // Write the prompt exactly once directly to stderr; readline's own
    // prompt emission is suppressed by HiddenPromptOutput._write because
    // chunk-based detection of the prompt text is unreliable when readline
    // splits the prompt across multiple writes.
    process.stderr.write(question)
  }

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
