import { EventEmitter } from "node:events"
import { describe, expect, it } from "vitest"

import { collectStreamOutput, type StreamOutputParameters } from "../src/sshHelpers.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type MockChannel = { stderr: EventEmitter } & EventEmitter

function createMockChannel(): { stderr: EventEmitter; stream: MockChannel } {
  const stream = new EventEmitter() as MockChannel
  const stderr = new EventEmitter()
  stream.stderr = stderr
  return { stderr, stream }
}

type CollectResult = Promise<{ code: number; stderr: string; stdout: string }>

async function runCollect(
  overrides: {
    emitClose?: { code: number }
    emitStderr?: string
    emitStdout?: string
  } & Partial<StreamOutputParameters>
): CollectResult {
  const { emitClose = { code: 0 }, emitStderr, emitStdout, ...params } = overrides
  const { stderr, stream } = createMockChannel()

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      /* intentionally never fires in tests */
    }, 60_000)

    collectStreamOutput({
      command: "echo hello",
      options: { silent: true },
      reject,
      resolve,
      stream: stream as unknown as StreamOutputParameters["stream"],
      timer,
      ...params,
    })

    if (emitStdout !== undefined) stream.emit("data", Buffer.from(emitStdout))
    if (emitStderr !== undefined) stderr.emit("data", Buffer.from(emitStderr))
    stream.emit("close", emitClose.code)

    clearTimeout(timer)
  })
}

async function getErrorMessage(promise: Promise<unknown>): Promise<string> {
  try {
    await promise
    throw new Error("Expected promise to reject")
  } catch (error) {
    return (error as Error).message
  }
}

// ---------------------------------------------------------------------------
// maskSecrets (tested indirectly through collectStreamOutput error messages)
// ---------------------------------------------------------------------------

describe("maskSecrets (via collectStreamOutput error messages)", () => {
  it("masks a single secret in command, stdout, and stderr", async () => {
    const secret = "hunter2"
    const promise = runCollect({
      command: `echo ${secret}`,
      emitClose: { code: 1 },
      emitStderr: `error: ${secret}`,
      emitStdout: `output: ${secret}`,
      secrets: [secret],
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain(secret)
    expect(msg).toContain("***")
  })

  it("masks multiple distinct secrets", async () => {
    const password = "s3cr3t"
    const token = "tok-abc123"
    const promise = runCollect({
      command: `cmd ${password} ${token}`,
      emitClose: { code: 1 },
      emitStderr: `err ${token}`,
      emitStdout: `out ${password}`,
      secrets: [password, token],
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain(password)
    expect(msg).not.toContain(token)
  })

  it("leaves text unchanged when secrets list is empty", async () => {
    const visible = "plaintext"
    const promise = runCollect({
      command: `echo ${visible}`,
      emitClose: { code: 1 },
      emitStderr: visible,
      emitStdout: visible,
      secrets: [],
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toContain(visible)
  })

  it("ignores empty-string secrets so no infinite replacement occurs", async () => {
    const promise = runCollect({
      command: "echo hi",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: "hi",
      secrets: ["", ""],
    })

    // Should reject cleanly without hanging or throwing a RangeError
    await expect(promise).rejects.toThrow(/Command failed/v)
  })

  it("replaces all occurrences when a secret appears multiple times", async () => {
    const secret = "reusedpass"
    const promise = runCollect({
      command: `${secret} && ${secret}`,
      emitClose: { code: 1 },
      emitStderr: secret,
      emitStdout: `${secret} ${secret}`,
      secrets: [secret],
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain(secret)
    // Each occurrence was replaced with *** so at least three *** groups exist
    const occurrences = msg.match(/\*\*\*/gv)
    expect(occurrences).not.toBeNull()
    expect(occurrences).toHaveLength(5)
  })
})

// ---------------------------------------------------------------------------
// collectStreamOutput
// ---------------------------------------------------------------------------

describe("collectStreamOutput", () => {
  it("rejects with exit code and masked secrets when exit code is non-zero", async () => {
    const secret = "p@ssw0rd"
    const promise = runCollect({
      command: `sudo -S -p '' ${secret}`,
      emitClose: { code: 1 },
      emitStderr: `sudo: ${secret}: incorrect`,
      emitStdout: `sudo output ${secret}`,
      secrets: [secret],
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toMatch(/Command failed with exit code 1/v)
    expect(msg).not.toContain(secret)
    expect(msg).toContain("***")
  })

  it("resolves with stdout and stderr when exit code is 0", async () => {
    const result = await runCollect({
      command: "echo hello",
      emitClose: { code: 0 },
      emitStderr: "",
      emitStdout: "hello\n",
      secrets: ["shouldNotMatter"],
    })

    expect(result.code).toBe(0)
    expect(result.stdout).toBe("hello\n")
    expect(result.stderr).toBe("")
  })

  it("resolves without masking when secrets parameter is omitted", async () => {
    const result = await runCollect({
      command: "whoami",
      emitClose: { code: 0 },
      emitStdout: "deploy\n",
    })

    expect(result.code).toBe(0)
    expect(result.stdout).toBe("deploy\n")
  })

  it("rejects without masking when no secrets provided and exit code is non-zero", async () => {
    const promise = runCollect({
      command: "false",
      emitClose: { code: 2 },
      emitStderr: "some error",
      emitStdout: "some output",
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toMatch(/Command failed with exit code 2/v)
    expect(msg).toContain("some output")
    expect(msg).toContain("some error")
  })

  it("treats undefined exit code (ssh2 quirk) as 0 and resolves", async () => {
    const { stream } = createMockChannel()

    const result = await new Promise<{ code: number; stderr: string; stdout: string }>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          /* intentionally never fires in tests */
        }, 60_000)
        collectStreamOutput({
          command: "reboot",
          options: { silent: true },
          reject,
          resolve,
          stream: stream as unknown as StreamOutputParameters["stream"],
          timer,
        })
        // Simulate ssh2 sending undefined for the code
        stream.emit("close", undefined as unknown as number)
        clearTimeout(timer)
      }
    )

    expect(result.code).toBe(0)
  })

  it("does not reject when ignoreExitCode is true even on non-zero exit", async () => {
    const result = await runCollect({
      command: "false",
      emitClose: { code: 127 },
      emitStderr: "fail",
      emitStdout: "",
      options: { ignoreExitCode: true, silent: true },
    })

    expect(result.code).toBe(127)
    expect(result.stderr).toBe("fail")
  })

  it("rejects immediately with the stream error (regression: missing error handler)", async () => {
    const { stream } = createMockChannel()
    const streamError = new Error("ECONNRESET")

    const promise = new Promise<{ code: number; stderr: string; stdout: string }>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error("Timed out — stream error was not forwarded"))
        }, 5_000)
        collectStreamOutput({
          command: "cat /etc/hosts",
          options: { silent: true },
          reject,
          resolve,
          stream: stream as unknown as StreamOutputParameters["stream"],
          timer,
        })
        stream.emit("error", streamError)
      }
    )

    await expect(promise).rejects.toThrow("ECONNRESET")
  })
})
