import { EventEmitter } from "node:events"
import { afterEach, describe, expect, it, vi } from "vitest"

type QuestionCallback = (answer: string) => void

class MockReadline extends EventEmitter {
  public close(): void {
    this.emit("close")
  }

  public question(_question: string, _callback: QuestionCallback): void {
    void _question
    void _callback
  }
}

async function loadPromptTerminalWithMockedReadline() {
  vi.resetModules()

  const interfaces: MockReadline[] = []
  const questionCallbacks: QuestionCallback[] = []
  const closeSpies: Array<ReturnType<typeof vi.spyOn>> = []

  vi.doMock("node:readline", () => ({
    createInterface: vi.fn(() => {
      const rl = new MockReadline()
      closeSpies.push(vi.spyOn(rl, "close"))
      vi.spyOn(rl, "question").mockImplementation((_question, callback) => {
        questionCallbacks.push(callback)
      })
      interfaces.push(rl)
      return rl
    }),
  }))

  const { promptTerminal } = await import("../src/terminal.js")
  return { closeSpies, interfaces, promptTerminal, questionCallbacks }
}

describe("promptTerminal", () => {
  afterEach(() => {
    vi.doUnmock("node:readline")
    vi.resetModules()
    vi.restoreAllMocks()
  })

  it("rejects when readline closes before an answer is received", async () => {
    const { interfaces, promptTerminal } = await loadPromptTerminalWithMockedReadline()
    const prompt = promptTerminal("Password: ")

    interfaces[0]?.emit("close")

    await expect(prompt).rejects.toThrow("Terminal prompt closed before input was received")
  })

  it("resolves once when the answer arrives before readline closes", async () => {
    const { closeSpies, promptTerminal, questionCallbacks } =
      await loadPromptTerminalWithMockedReadline()
    const prompt = promptTerminal("Password: ")

    questionCallbacks[0]?.("secret")

    await expect(prompt).resolves.toBe("secret")
    expect(closeSpies[0]).toHaveBeenCalledOnce()
  })
})
