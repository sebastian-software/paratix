import { createInterface } from "node:readline"

/**
 * Prompt the user for input on the terminal.
 * When `hidden` is true the typed characters are not echoed (for passwords).
 *
 * @param question - The prompt text shown to the user.
 * @param hidden - Whether to suppress character echo (password mode).
 * @returns The entered string.
 */
export async function promptTerminal(question: string, hidden = false): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr })

  if (hidden) {
    // Disable echo by overriding _writeToOutput (readline internal)
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

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close()
      if (hidden) process.stderr.write("\n")
      resolve(answer)
    })
  })
}
