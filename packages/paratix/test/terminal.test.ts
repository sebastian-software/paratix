import { EventEmitter } from "node:events"

import { afterEach, describe, expect, it, vi } from "vitest"

type QuestionCallback = (answer: string) => void
type MockReadline = EventEmitter & {
  close: ReturnType<typeof vi.fn>
  question: ReturnType<typeof vi.fn>
}

async function loadPromptTerminalWithMockedReadline() {
  vi.resetModules()

  const interfaces: MockReadline[] = []

  vi.doMock("node:readline", () => ({
    createInterface: vi.fn(() => {
      const rl = new EventEmitter() as MockReadline
      rl.close = vi.fn(() => {
        rl.emit("close")
      })
      rl.question = vi.fn()
      interfaces.push(rl)
      return rl
    }),
  }))

  const { promptTerminal } = await import("../src/terminal.js")
  return { interfaces, promptTerminal }
}

afterEach(() => {
  vi.doUnmock("node:readline")
  vi.resetModules()
  vi.restoreAllMocks()
})

describe("promptTerminal", () => {
  it("rejects when readline closes before an answer is received", async () => {
    const { interfaces, promptTerminal } = await loadPromptTerminalWithMockedReadline()
    const prompt = promptTerminal("Password: ")

    interfaces[0]?.emit("close")

    await expect(prompt).rejects.toThrow("Terminal prompt closed before input was received")
  })

  it("resolves once when the answer arrives before readline closes", async () => {
    const { interfaces, promptTerminal } = await loadPromptTerminalWithMockedReadline()
    const prompt = promptTerminal("Password: ")
    const questionCall = interfaces[0]?.question.mock.calls[0] as
      | [question: string, callback: QuestionCallback]
      | undefined

    questionCall?.[1]("secret")

    await expect(prompt).resolves.toBe("secret")
    expect(interfaces[0]?.close).toHaveBeenCalledOnce()
  })
})
