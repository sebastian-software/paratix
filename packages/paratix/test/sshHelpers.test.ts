import type { Client } from "ssh2"

import { EventEmitter } from "node:events"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  collectStreamOutput,
  CommandError,
  createStreamMasker,
  maskSecrets,
  MAX_OUTPUT_LENGTH,
  shellQuote,
  type StreamOutputParameters,
  tryConnectOnPort,
  validateMode,
} from "../src/sshHelpers.js"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type MockChannel = { stderr: EventEmitter } & EventEmitter

type MockClient = {
  connect: Client["connect"]
  end: Client["end"]
} & Client &
  EventEmitter

function createMockChannel(): { stderr: EventEmitter; stream: MockChannel } {
  const stream = new EventEmitter() as MockChannel
  const stderr = new EventEmitter()
  stream.stderr = stderr
  return { stderr, stream }
}

function createMockClient(): MockClient {
  const client = new EventEmitter() as MockClient
  client.connect = () => client
  client.end = () => client
  vi.spyOn(client, "connect")
  vi.spyOn(client, "end")
  return client
}

type CollectResult = Promise<{ code: number; stderr: string; stdout: string }>

async function runCollect(
  overrides: {
    emitClose?: { code: null | number | undefined; signal?: string }
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
    stream.emit("close", emitClose.code, emitClose.signal)

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
// createStreamMasker
// ---------------------------------------------------------------------------

describe("createStreamMasker", () => {
  it("masks a secret that is fully contained in a single chunk after flush", () => {
    const output: string[] = []
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["hunter2"]
    )

    masker.push("hunter2")
    masker.flush()

    expect(output.join("")).not.toContain("hunter2")
    expect(output.join("")).toContain("[REDACTED]")
  })

  it("masks a secret split across two chunks ('hun' + 'ter2')", () => {
    const output: string[] = []
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["hunter2"]
    )

    masker.push("hun")
    masker.push("ter2")
    masker.flush()

    expect(output.join("")).not.toContain("hunter2")
    expect(output.join("")).toContain("[REDACTED]")
  })

  it("masks a secret split at chunk-end and chunk-start ('hunte' + 'r2')", () => {
    const output: string[] = []
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["hunter2"]
    )

    masker.push("hunte")
    masker.push("r2")
    masker.flush()

    expect(output.join("")).not.toContain("hunter2")
    expect(output.join("")).toContain("[REDACTED]")
  })

  it("masks multiple distinct secrets appearing in a single chunk", () => {
    const output: string[] = []
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["alpha", "beta"]
    )

    masker.push("prefix alpha and beta suffix")
    masker.flush()

    const combined = output.join("")
    expect(combined).not.toContain("alpha")
    expect(combined).not.toContain("beta")
    expect(combined).toContain("[REDACTED]")
  })

  it("produces no output when chunk is smaller than overlap, then flushes on flush()", () => {
    const output: string[] = []
    // Secret "hunter2" has length 7, so overlap = 6
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["hunter2"]
    )

    // A chunk shorter than overlap (6 chars) must not produce output yet
    masker.push("hello")

    expect(output).toHaveLength(0)

    masker.flush()

    // After flush the buffered text comes out unchanged (no secret present)
    expect(output.join("")).toBe("hello")
  })

  it("passes all text through unchanged when secrets array is empty", () => {
    const output: string[] = []
    const masker = createStreamMasker((t) => {
      output.push(t)
    }, [])

    masker.push("plain text")
    masker.flush()

    expect(output.join("")).toBe("plain text")
  })

  it("produces no output when flush() is called without any prior push", () => {
    const output: string[] = []
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["secret"]
    )

    masker.flush()

    expect(output).toHaveLength(0)
  })

  it("passes text unmodified when no secret matches any chunk", () => {
    const output: string[] = []
    const masker = createStreamMasker(
      (t) => {
        output.push(t)
      },
      ["hunter2"]
    )

    masker.push("hello world, nothing to see here")
    masker.flush()

    expect(output.join("")).toBe("hello world, nothing to see here")
  })
})

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
    expect(msg).toContain("[REDACTED]")
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
    // Each occurrence was replaced with [REDACTED] so at least five [REDACTED] groups exist
    const occurrences = msg.match(/\[REDACTED\]/gv)
    expect(occurrences).not.toBeNull()
    expect(occurrences).toHaveLength(5)
  })

  it("masks longer secrets first when a shorter secret is a substring of a longer one (regression)", async () => {
    // Bug: if "pass" is replaced before "password", "password" becomes "[REDACTED]word"
    const promise = runCollect({
      command: "echo test",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: "my password is pass",
      secrets: ["pass", "password"],
    })
    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain("pass")
    expect(msg).not.toContain("word")
  })
})

// ---------------------------------------------------------------------------
// maskSecrets — direct tests
// ---------------------------------------------------------------------------

describe("maskSecrets", () => {
  it("throws when a secret contains the redaction placeholder", () => {
    expect(() => maskSecrets("some text", ["my[REDACTED]secret"])).toThrow(/redaction placeholder/v)
  })

  it("does not throw for normal secrets", () => {
    expect(maskSecrets("the password is hunter2", ["hunter2"])).toBe("the password is [REDACTED]")
  })

  it("masks shell-quoted secret variants with apostrophes", () => {
    const secret = "it's complicated"
    const escapedSecret = shellQuote(secret)
    expect(maskSecrets(`command uses ${escapedSecret}`, [secret])).toBe("command uses [REDACTED]")
  })

  it("resolves lazy secret sources only when masking is needed", () => {
    const resolveSecret = vi.fn(() => "hunter2")

    const masker = createStreamMasker(() => {
      /* noop */
    }, [resolveSecret])

    expect(resolveSecret).not.toHaveBeenCalled()

    masker.push("plain text")

    expect(resolveSecret).toHaveBeenCalledOnce()
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
    expect(msg).toContain("[REDACTED]")
  })

  it("rejects with exit code and masks shell-quoted secrets in command/stdout/stderr", async () => {
    const secret = "don't leak me"
    const escapedSecret = shellQuote(secret)
    const promise = runCollect({
      command: `printf %s ${escapedSecret}`,
      emitClose: { code: 1 },
      emitStderr: `stderr ${escapedSecret}`,
      emitStdout: `stdout ${escapedSecret}`,
      secrets: [secret],
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain(secret)
    expect(msg).not.toContain(escapedSecret)
    expect(msg).toContain("[REDACTED]")
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

  it("rejects signal-closed streams even when exit codes are ignored", async () => {
    const promise = runCollect({
      emitClose: { code: null, signal: "SIGKILL" },
      emitStderr: "killed",
      options: { ignoreExitCode: true, silent: true },
    })

    await expect(promise).rejects.toThrow("Command failed with signal SIGKILL")
  })

  it("masks secrets in resolved stdout and stderr on successful exit (exit code 0)", async () => {
    const secret = "s3cr3tpassword"
    const result = await runCollect({
      command: "echo something",
      emitClose: { code: 0 },
      emitStderr: `warning: ${secret} detected`,
      emitStdout: `output: ${secret} here`,
      secrets: [secret],
    })

    expect(result.stdout).not.toContain(secret)
    expect(result.stdout).toContain("[REDACTED]")
    expect(result.stderr).not.toContain(secret)
    expect(result.stderr).toContain("[REDACTED]")
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
        }, 5000)
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

  it("rejects immediately with the stderr stream error", async () => {
    const { stderr, stream } = createMockChannel()
    const stderrError = new Error("stderr channel reset")

    const promise = new Promise<{ code: number; stderr: string; stdout: string }>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error("Timed out — stderr stream error was not forwarded"))
        }, 5000)
        collectStreamOutput({
          command: "cat /etc/hosts",
          options: { silent: true },
          reject,
          resolve,
          stream: stream as unknown as StreamOutputParameters["stream"],
          timer,
        })
        stderr.emit("error", stderrError)
      }
    )

    await expect(promise).rejects.toThrow("stderr channel reset")
  })
})

// ---------------------------------------------------------------------------
// Live-output masking (regression: maskSecrets must be applied to process.std{out,err}.write)
// ---------------------------------------------------------------------------

describe("live-output masking via process.stdout/stderr.write", () => {
  let stderrWrites: string[]
  let stdoutWrites: string[]

  beforeEach(() => {
    stderrWrites = []
    stdoutWrites = []
    vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      stdoutWrites.push(String(chunk))
      return true
    })
    vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
      stderrWrites.push(String(chunk))
      return true
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("masks secrets in process.stdout.write when silent is false", async () => {
    const secret = "supersecret"
    const { stderr, stream } = createMockChannel()

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        /* intentionally never fires in tests */
      }, 60_000)

      collectStreamOutput({
        command: "echo something",
        options: { silent: false },
        reject,
        resolve() {
          resolve()
        },
        secrets: [secret],
        stream: stream as unknown as StreamOutputParameters["stream"],
        timer,
      })

      stream.emit("data", Buffer.from(`output contains ${secret} here`))
      stderr.emit("data", Buffer.from("no secret here"))
      stream.emit("close", 0)
      clearTimeout(timer)
    })

    expect(stdoutWrites.join("")).not.toContain(secret)
    expect(stdoutWrites.join("")).toContain("[REDACTED]")
  })

  it("masks shell-quoted secrets split across stdout chunks when silent is false", async () => {
    const secret = "don't split me"
    const escapedSecret = shellQuote(secret)
    const { stderr, stream } = createMockChannel()

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        /* intentionally never fires in tests */
      }, 60_000)

      collectStreamOutput({
        command: "echo something",
        options: { silent: false },
        reject,
        resolve() {
          resolve()
        },
        secrets: [secret],
        stream: stream as unknown as StreamOutputParameters["stream"],
        timer,
      })

      stream.emit("data", Buffer.from(escapedSecret.slice(0, 8)))
      stream.emit("data", Buffer.from(escapedSecret.slice(8)))
      stderr.emit("data", Buffer.from(""))
      stream.emit("close", 0)
      clearTimeout(timer)
    })

    const stdoutOutput = stdoutWrites.join("")
    expect(stdoutOutput).not.toContain(secret)
    expect(stdoutOutput).not.toContain(escapedSecret)
    expect(stdoutOutput).toContain("[REDACTED]")
  })

  it("masks secrets in process.stderr.write when silent is false", async () => {
    const secret = "topsecrettoken"
    const { stderr, stream } = createMockChannel()

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        /* intentionally never fires in tests */
      }, 60_000)

      collectStreamOutput({
        command: "deploy",
        options: { silent: false },
        reject,
        resolve() {
          resolve()
        },
        secrets: [secret],
        stream: stream as unknown as StreamOutputParameters["stream"],
        timer,
      })

      stream.emit("data", Buffer.from("stdout without secret"))
      stderr.emit("data", Buffer.from(`error: ${secret} is invalid`))
      stream.emit("close", 0)
      clearTimeout(timer)
    })

    expect(stderrWrites.join("")).not.toContain(secret)
    expect(stderrWrites.join("")).toContain("[REDACTED]")
  })

  it("masks secrets in both stdout and stderr live-output simultaneously", async () => {
    const password = "mypassword"
    const token = "mytoken"
    const { stderr, stream } = createMockChannel()

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        /* intentionally never fires in tests */
      }, 60_000)

      collectStreamOutput({
        command: "run",
        options: { silent: false },
        reject,
        resolve() {
          resolve()
        },
        secrets: [password, token],
        stream: stream as unknown as StreamOutputParameters["stream"],
        timer,
      })

      stream.emit("data", Buffer.from(`using password ${password} done`))
      stderr.emit("data", Buffer.from(`token ${token} rejected`))
      stream.emit("close", 0)
      clearTimeout(timer)
    })

    const stdoutOutput = stdoutWrites.join("")
    const stderrOutput = stderrWrites.join("")

    expect(stdoutOutput).not.toContain(password)
    expect(stdoutOutput).toContain("[REDACTED]")
    expect(stderrOutput).not.toContain(token)
    expect(stderrOutput).toContain("[REDACTED]")
  })

  it("does not call process.stdout.write or process.stderr.write when silent is true", async () => {
    const secret = "silentsecret"
    const { stderr, stream } = createMockChannel()

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        /* intentionally never fires in tests */
      }, 60_000)

      collectStreamOutput({
        command: "run",
        options: { silent: true },
        reject,
        resolve() {
          resolve()
        },
        secrets: [secret],
        stream: stream as unknown as StreamOutputParameters["stream"],
        timer,
      })

      stream.emit("data", Buffer.from(`contains ${secret}`))
      stderr.emit("data", Buffer.from(`also ${secret}`))
      stream.emit("close", 0)
      clearTimeout(timer)
    })

    expect(stdoutWrites).toStrictEqual([])
    expect(stderrWrites).toStrictEqual([])
  })
})

// ---------------------------------------------------------------------------
// CommandError and stdout/stderr truncation
// ---------------------------------------------------------------------------

async function getCommandError(promise: Promise<unknown>): Promise<CommandError> {
  try {
    await promise
    throw new Error("Expected promise to reject")
  } catch (error) {
    return error as CommandError
  }
}

describe("CommandError and truncation", () => {
  it("rejected error is instanceof CommandError when exit code is non-zero", async () => {
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "some error",
      emitStdout: "some output",
    })

    const error = await getCommandError(promise)
    expect(error).toBeInstanceOf(CommandError)
  })

  it("CommandError has name 'CommandError'", async () => {
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "error",
      emitStdout: "output",
    })

    const error = await getCommandError(promise)
    expect(error.name).toBe("CommandError")
  })

  it("stdout longer than MAX_OUTPUT_LENGTH is truncated in the error message", async () => {
    const longStdout = "a".repeat(MAX_OUTPUT_LENGTH + 1)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: longStdout,
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toContain("…(truncated)")
    expect(msg).not.toContain(longStdout)
  })

  it("stderr longer than MAX_OUTPUT_LENGTH is truncated in the error message", async () => {
    const longStderr = "b".repeat(MAX_OUTPUT_LENGTH + 1)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: longStderr,
      emitStdout: "",
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toContain("…(truncated)")
    expect(msg).not.toContain(longStderr)
  })

  it("stdout exactly at MAX_OUTPUT_LENGTH is not truncated and has no hint", async () => {
    const exactStdout = "c".repeat(MAX_OUTPUT_LENGTH)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: exactStdout,
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain("…(truncated)")
    expect(msg).not.toContain("(use --verbose for full output)")
  })

  it("stderr exactly at MAX_OUTPUT_LENGTH is not truncated and has no hint", async () => {
    const exactStderr = "d".repeat(MAX_OUTPUT_LENGTH)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: exactStderr,
      emitStdout: "",
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain("…(truncated)")
    expect(msg).not.toContain("(use --verbose for full output)")
  })

  it("hint '(use --verbose for full output)' is appended when stdout is truncated", async () => {
    const longStdout = "e".repeat(MAX_OUTPUT_LENGTH + 1)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: longStdout,
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toContain("(use --verbose for full output)")
  })

  it("hint '(use --verbose for full output)' is appended when stderr is truncated", async () => {
    const longStderr = "f".repeat(MAX_OUTPUT_LENGTH + 1)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: longStderr,
      emitStdout: "",
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toContain("(use --verbose for full output)")
  })

  it("hint is absent when stdout and stderr are both within MAX_OUTPUT_LENGTH", async () => {
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "short error",
      emitStdout: "short output",
    })

    const msg = await getErrorMessage(promise)
    expect(msg).not.toContain("(use --verbose for full output)")
  })

  it("fullStdout contains the complete (untruncated) masked stdout", async () => {
    const longStdout = "g".repeat(MAX_OUTPUT_LENGTH + 50)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: longStdout,
    })

    const error = await getCommandError(promise)
    expect(error.fullStdout).toBe(longStdout)
    expect(error.fullStdout).toHaveLength(MAX_OUTPUT_LENGTH + 50)
  })

  it("fullStderr contains the complete (untruncated) masked stderr", async () => {
    const longStderr = "h".repeat(MAX_OUTPUT_LENGTH + 50)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: longStderr,
      emitStdout: "",
    })

    const error = await getCommandError(promise)
    expect(error.fullStderr).toBe(longStderr)
    expect(error.fullStderr).toHaveLength(MAX_OUTPUT_LENGTH + 50)
  })

  it("secrets are masked in fullStdout and fullStderr before truncation check", async () => {
    const secret = "mysecretvalue"
    const longStdout = `${secret} ${"x".repeat(MAX_OUTPUT_LENGTH)}`
    const longStderr = `${secret} ${"y".repeat(MAX_OUTPUT_LENGTH)}`
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: longStderr,
      emitStdout: longStdout,
      secrets: [secret],
    })

    const error = await getCommandError(promise)
    expect(error.fullStdout).not.toContain(secret)
    expect(error.fullStdout).toContain("[REDACTED]")
    expect(error.fullStderr).not.toContain(secret)
    expect(error.fullStderr).toContain("[REDACTED]")
  })

  it("truncated error message contains first MAX_OUTPUT_LENGTH characters of stdout", async () => {
    const prefix = "IMPORTANT"
    const longStdout = prefix + "z".repeat(MAX_OUTPUT_LENGTH)
    const promise = runCollect({
      command: "false",
      emitClose: { code: 1 },
      emitStderr: "",
      emitStdout: longStdout,
    })

    const msg = await getErrorMessage(promise)
    expect(msg).toContain(prefix)
  })
})

// ---------------------------------------------------------------------------
// tryConnectOnPort
// ---------------------------------------------------------------------------

describe("tryConnectOnPort", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it("removes connect-phase listeners after the client is ready", async () => {
    const client = createMockClient()
    const promise = tryConnectOnPort({
      client,
      host: "example.test",
      port: 22,
      username: "root",
    })

    expect(client.listenerCount("ready")).toBe(1)
    expect(client.listenerCount("error")).toBe(1)

    client.emit("ready")

    await expect(promise).resolves.toBeUndefined()
    expect(client.listenerCount("ready")).toBe(0)
    expect(client.listenerCount("error")).toBe(0)

    client.on("error", () => {
      /* runtime errors are handled by the active SSH session */
    })
    client.emit("error", new Error("runtime failure"))

    expect(client.end).not.toHaveBeenCalled()
  })

  it("cleans up the client when the connect-phase error fires before ready", async () => {
    const client = createMockClient()
    const error = new Error("Permission denied")
    const promise = tryConnectOnPort({
      client,
      host: "example.test",
      port: 22,
      username: "root",
    })

    client.emit("error", error)

    await expect(promise).rejects.toThrow("Permission denied")
    expect(client.end).toHaveBeenCalledOnce()
    expect(client.listenerCount("ready")).toBe(0)
    expect(client.listenerCount("error")).toBe(0)
  })

  it("cleans up the client when the connect attempt times out", async () => {
    vi.useFakeTimers()
    const client = createMockClient()
    const promise = tryConnectOnPort({
      client,
      host: "example.test",
      port: 2222,
      username: "root",
    })
    const rejection = promise.then(
      () => {
        throw new Error("Expected promise to reject")
      },
      (error: unknown) => error
    )

    await vi.advanceTimersByTimeAsync(10_000)

    await expect(rejection).resolves.toMatchObject({
      message: "Connection timeout on port 2222",
    })
    expect(client.end).toHaveBeenCalledOnce()
    expect(client.listenerCount("ready")).toBe(0)
    expect(client.listenerCount("error")).toBe(0)
  })

  it("cleans up the client and timer when the connect attempt is aborted", async () => {
    vi.useFakeTimers()
    const client = createMockClient()
    const abortController = new AbortController()
    const abortError = new Error("Interrupted by SIGINT")
    const promise = tryConnectOnPort({
      abortSignal: abortController.signal,
      client,
      host: "example.test",
      port: 2222,
      username: "root",
    })

    abortController.abort(abortError)

    await expect(promise).rejects.toThrow("Interrupted by SIGINT")
    expect(client.end).toHaveBeenCalledOnce()
    expect(client.listenerCount("ready")).toBe(0)
    expect(client.listenerCount("error")).toBe(0)
    expect(vi.getTimerCount()).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// validateMode
// ---------------------------------------------------------------------------

describe("validateMode", () => {
  it("accepts valid 3-digit octal mode (644)", () => {
    expect(() => {
      validateMode("644")
    }).not.toThrow()
  })

  it("accepts valid 4-digit octal mode (0755)", () => {
    expect(() => {
      validateMode("0755")
    }).not.toThrow()
  })

  it("accepts mode with all zeros (000)", () => {
    expect(() => {
      validateMode("000")
    }).not.toThrow()
  })

  it("accepts mode 0777", () => {
    expect(() => {
      validateMode("0777")
    }).not.toThrow()
  })

  it("throws for mode with digit 8 (888)", () => {
    expect(() => {
      validateMode("888")
    }).toThrow(/mode/v)
  })

  it("throws for mode with digit 9 (799)", () => {
    expect(() => {
      validateMode("799")
    }).toThrow(/mode/v)
  })

  it("throws for 2-digit mode (77)", () => {
    expect(() => {
      validateMode("77")
    }).toThrow(/mode/v)
  })

  it("throws for 5-digit mode (07550)", () => {
    expect(() => {
      validateMode("07550")
    }).toThrow(/mode/v)
  })

  it("throws for non-numeric mode (abc)", () => {
    expect(() => {
      validateMode("abc")
    }).toThrow(/mode/v)
  })

  it("throws for empty string", () => {
    expect(() => {
      validateMode("")
    }).toThrow(/mode/v)
  })
})
