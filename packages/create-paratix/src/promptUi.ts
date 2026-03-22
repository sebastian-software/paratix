import { emitKeypressEvents } from "node:readline"

export type SelectOption<TValue extends string> = {
  description: string
  label: string
  value: TValue
}

export type SelectFunction<TValue extends string> = (
  prompt: string,
  options: Array<SelectOption<TValue>>
) => Promise<TValue>

function createSelectLines<TValue extends string>(
  prompt: string,
  options: Array<SelectOption<TValue>>,
  selectedIndex: number
): string[] {
  return [
    prompt,
    "",
    "Use the arrow keys to choose how Paratix should connect on the very first run:",
    ...options.flatMap((option, index) => {
      const prefix = index === selectedIndex ? ">" : " "
      return [`${prefix} ${option.label}`, `   ${option.description}`]
    }),
    "",
    "Press Enter to confirm.",
  ]
}

function redrawSelect(lines: string[], renderedLines: number): number {
  if (renderedLines > 0) {
    for (let index = 0; index < renderedLines; index++) {
      process.stdout.write("\x1B[1A\x1B[2K")
    }
  }

  process.stdout.write(`${lines.join("\n")}\n`)
  return lines.length
}

function ensureInteractiveTerminal(): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error(
      "Interactive selection requires a TTY. Use --initial-user <root|name> in non-interactive environments."
    )
  }
}

function prepareSelectInput(): { previousRawMode: boolean | undefined } {
  emitKeypressEvents(process.stdin)
  const previousRawMode = process.stdin.isRaw
  process.stdin.setRawMode(true)
  process.stdin.resume()
  return { previousRawMode }
}

function cleanupSelectInput(previousRawMode: boolean | undefined): void {
  process.stdin.setRawMode(previousRawMode ?? false)
  process.stdout.write("\x1B[?25h")
}

function createSelectRenderer<TValue extends string>(
  prompt: string,
  options: Array<SelectOption<TValue>>
): {
  moveDown: () => void
  moveUp: () => void
  render: () => void
  selectedValue: () => TValue
} {
  let renderedLines = 0
  let selectedIndex = 0

  return {
    moveDown: (): void => {
      selectedIndex = (selectedIndex + 1) % options.length
    },
    moveUp: (): void => {
      selectedIndex = (selectedIndex - 1 + options.length) % options.length
    },
    render: (): void => {
      renderedLines = redrawSelect(createSelectLines(prompt, options, selectedIndex), renderedLines)
    },
    selectedValue: (): TValue => options[selectedIndex].value,
  }
}

function finishSelection<TValue>(
  cleanup: () => void,
  resolver: (value: TValue) => void,
  value: TValue
): void {
  cleanup()
  resolver(value)
}

function handleNavigationKey<TValue extends string>(
  keyName: string | undefined,
  renderer: ReturnType<typeof createSelectRenderer<TValue>>
): boolean {
  if (keyName === "down") {
    renderer.moveDown()
    renderer.render()
    return true
  }

  if (keyName === "up") {
    renderer.moveUp()
    renderer.render()
    return true
  }

  return false
}

function handleConfirmationKey<TValue extends string>(
  keyName: string | undefined,
  renderer: ReturnType<typeof createSelectRenderer<TValue>>,
  confirmSelection: (value: TValue) => void
): boolean {
  if (keyName !== "enter" && keyName !== "return") {
    return false
  }

  process.stdout.write("\n")
  confirmSelection(renderer.selectedValue())
  return true
}

function handleCancelKey(
  key: { ctrl?: boolean; name?: string },
  cleanup: () => void,
  reject: (reason?: unknown) => void
): void {
  if (key.ctrl && key.name === "c") {
    process.stdout.write("\n")
    cleanup()
    reject(new Error("Prompt cancelled."))
  }
}

async function runTerminalSelect<TValue extends string>(
  prompt: string,
  options: Array<SelectOption<TValue>>
): Promise<TValue> {
  ensureInteractiveTerminal()
  const { previousRawMode } = prepareSelectInput()
  const renderer = createSelectRenderer(prompt, options)

  return new Promise<TValue>((resolve, reject) => {
    const cleanup = (): void => {
      process.stdin.removeListener("keypress", onKeypress)
      cleanupSelectInput(previousRawMode)
    }

    const onKeypress = (_character: string, key: { ctrl?: boolean; name?: string }): void => {
      if (handleNavigationKey(key.name, renderer)) {
        return
      }

      if (
        handleConfirmationKey(key.name, renderer, (value) => {
          finishSelection(cleanup, resolve, value)
        })
      ) {
        return
      }

      handleCancelKey(key, cleanup, reject)
    }

    process.stdout.write("\x1B[?25l")
    renderer.render()
    process.stdin.on("keypress", onKeypress)
  })
}

/**
 * Creates a simple arrow-key driven terminal select prompt without adding an external dependency.
 *
 * @returns A select function and a no-op close hook for API symmetry with text prompts.
 */
export function createTerminalSelect(): {
  close: () => void
  select: <TValue extends string>(
    prompt: string,
    options: Array<SelectOption<TValue>>
  ) => Promise<TValue>
} {
  return {
    close: (): void => undefined,
    select: async <TValue extends string>(
      prompt: string,
      options: Array<SelectOption<TValue>>
    ): Promise<TValue> => runTerminalSelect(prompt, options),
  }
}
