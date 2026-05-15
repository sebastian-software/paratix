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
  const questionSpies: Array<ReturnType<typeof vi.spyOn>> = []

  vi.doMock("node:readline", () => ({
    createInterface: vi.fn(() => {
      const rl = new MockReadline()
      closeSpies.push(vi.spyOn(rl, "close"))
      const questionSpy = vi.spyOn(rl, "question").mockImplementation((_question, callback) => {
        questionCallbacks.push(callback)
      })
      questionSpies.push(questionSpy)
      interfaces.push(rl)
      return rl
    }),
  }))

  const { promptTerminal } = await import("../src/terminal.js")
  return { closeSpies, interfaces, promptTerminal, questionCallbacks, questionSpies }
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

  it("rejects an already aborted signal before asking the question", async () => {
    const { closeSpies, promptTerminal, questionSpies } =
      await loadPromptTerminalWithMockedReadline()
    const controller = new AbortController()
    const abortError = new Error("Prompt cancelled before start")
    controller.abort(abortError)
    const removeAbortListenerSpy = vi.spyOn(controller.signal, "removeEventListener")
    const addAbortListenerSpy = vi.spyOn(controller.signal, "addEventListener")

    await expect(
      promptTerminal("Password: ", false, { abortSignal: controller.signal })
    ).rejects.toBe(abortError)

    expect(addAbortListenerSpy).not.toHaveBeenCalled()
    expect(removeAbortListenerSpy).toHaveBeenCalledOnce()
    expect(closeSpies[0]).toHaveBeenCalledOnce()
    expect(questionSpies[0]).not.toHaveBeenCalled()
  })

  it("cleans up and ignores a late answer after aborting while question is pending", async () => {
    const { closeSpies, promptTerminal, questionCallbacks } =
      await loadPromptTerminalWithMockedReadline()
    const controller = new AbortController()
    const addAbortListenerSpy = vi.spyOn(controller.signal, "addEventListener")
    const removeAbortListenerSpy = vi.spyOn(controller.signal, "removeEventListener")
    const abortError = new Error("Prompt cancelled")

    const prompt = promptTerminal("Password: ", false, { abortSignal: controller.signal })
    controller.abort(abortError)

    await expect(prompt).rejects.toBe(abortError)
    questionCallbacks[0]?.("late answer")

    expect(addAbortListenerSpy).toHaveBeenCalledOnce()
    expect(removeAbortListenerSpy).toHaveBeenCalledOnce()
    expect(removeAbortListenerSpy.mock.calls[0]?.[1]).toBe(addAbortListenerSpy.mock.calls[0]?.[1])
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

  it("writes the hidden prompt newline once when aborted while question is pending", async () => {
    vi.resetModules()
    let capturedOutput: NodeJS.WritableStream | undefined
    let capturedCallback: QuestionCallback | undefined
    const stderrWrites: string[] = []
    const stderrWriteSpy = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderrWrites.push(String(chunk))
      return true
    })
    const closeSpies: Array<ReturnType<typeof vi.spyOn>> = []
    vi.doMock("node:readline", () => ({
      createInterface: vi.fn((arg: { output: NodeJS.WritableStream }) => {
        capturedOutput = arg.output
        const rl = new MockReadline()
        closeSpies.push(vi.spyOn(rl, "close"))
        vi.spyOn(rl, "question").mockImplementation((_question, callback) => {
          capturedCallback = callback
          capturedOutput?.write("Password: ")
        })
        return rl
      }),
    }))

    const { promptTerminal } = await import("../src/terminal.js")
    const controller = new AbortController()
    const addAbortListenerSpy = vi.spyOn(controller.signal, "addEventListener")
    const removeAbortListenerSpy = vi.spyOn(controller.signal, "removeEventListener")
    const abortError = new Error("Hidden prompt cancelled")

    const prompt = promptTerminal("Password: ", true, { abortSignal: controller.signal })
    controller.abort(abortError)

    await expect(prompt).rejects.toBe(abortError)
    capturedCallback?.("late secret")

    expect(addAbortListenerSpy).toHaveBeenCalledOnce()
    expect(removeAbortListenerSpy).toHaveBeenCalledOnce()
    expect(stderrWriteSpy).toHaveBeenCalled()
    expect(stderrWrites.join("")).toBe("Password: \n")
    expect(closeSpies[0]).toHaveBeenCalledOnce()
  })
})
