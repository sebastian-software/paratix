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

  // R-0000263: hidden mode no longer monkey-patches readline internals; it
  // must instead hand a custom Writable to createInterface that forwards the
  // prompt question and discards the echoed input.
  it("uses a custom Writable as output when hidden mode is enabled", async () => {
    vi.resetModules()
    const createInterfaceSpy = vi.fn((args: { output: NodeJS.WritableStream }) => {
      const rl = new MockReadline()
      vi.spyOn(rl, "question").mockImplementation((_question, callback) => {
        queueMicrotask(() => {
          callback("secret")
        })
      })
      // Expose the output stream so the test can probe it.
      ;(rl as unknown as { __output: NodeJS.WritableStream }).__output = args.output
      return rl
    })
    vi.doMock("node:readline", () => ({ createInterface: createInterfaceSpy }))

    const { promptTerminal } = await import("../src/terminal.js")
    const answer = await promptTerminal("Password: ", true)

    expect(answer).toBe("secret")
    expect(createInterfaceSpy).toHaveBeenCalledOnce()
    const args = createInterfaceSpy.mock.calls[0]?.[0]
    expect(args?.output).not.toBe(process.stderr)
    expect(typeof (args?.output as NodeJS.WritableStream).write).toBe("function")
  })
})
