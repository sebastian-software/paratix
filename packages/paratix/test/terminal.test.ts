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

  it("uses a TTY-compatible Writable as output when hidden mode is enabled", async () => {
    vi.resetModules()
    let capturedOutput: NodeJS.WritableStream | undefined
    const createInterfaceSpy = vi.fn((arg: { output: NodeJS.WritableStream }) => {
      capturedOutput = arg.output
      const rl = new MockReadline()
      vi.spyOn(rl, "question").mockImplementation((_question, callback) => {
        queueMicrotask(() => {
          callback("secret")
        })
      })
      return rl
    })
    vi.doMock("node:readline", () => ({ createInterface: createInterfaceSpy }))

    const { promptTerminal } = await import("../src/terminal.js")
    const answer = await promptTerminal("Password: ", true)

    expect(answer).toBe("secret")
    expect(createInterfaceSpy).toHaveBeenCalledOnce()
    expect(capturedOutput).toBeDefined()
    expect(capturedOutput).not.toBe(process.stderr)
    expect(typeof capturedOutput?.write).toBe("function")
    expect(typeof (capturedOutput as { cursorTo?: unknown } | undefined)?.cursorTo).toBe("function")
  })

  it("does not leak hidden input through simulated readline output writes", async () => {
    vi.resetModules()
    const secret = "sudo-password-123"
    let capturedOutput: NodeJS.WritableStream | undefined
    const stderrWrites: string[] = []
    const stderrWriteSpy = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderrWrites.push(String(chunk))
      return true
    })
    const createInterfaceSpy = vi.fn((arg: { output: NodeJS.WritableStream }) => {
      capturedOutput = arg.output
      const rl = new MockReadline()
      vi.spyOn(rl, "question").mockImplementation((_question, callback) => {
        capturedOutput?.write(`Password: ${secret}`)
        capturedOutput?.write(secret)
        queueMicrotask(() => {
          callback(secret)
        })
      })
      return rl
    })
    vi.doMock("node:readline", () => ({ createInterface: createInterfaceSpy }))

    const { promptTerminal } = await import("../src/terminal.js")
    const answer = await promptTerminal("Password: ", true)

    expect(answer).toBe(secret)
    expect(stderrWriteSpy).toHaveBeenCalled()
    expect(stderrWrites.join("")).toContain("Password: ")
    expect(stderrWrites.join("")).not.toContain(secret)
  })
})
