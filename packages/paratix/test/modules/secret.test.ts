import { inspect } from "node:util"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Module, SecretInput } from "../../src/index.js"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { secret } from "../../src/modules/secret.js"
import { withRunnerAbortSignal } from "../../src/runnerAbortSignal.js"
import { withSecretPrewarmScope } from "../../src/secretPrewarm.js"
import {
  clearRegisteredSecrets,
  getRegisteredSecrets,
  withRunScopedSecrets,
} from "../../src/secretSink.js"
import { promptTerminal } from "../../src/terminal.js"

vi.mock("../../src/terminal.js", () => ({ promptTerminal: vi.fn() }))
const prompt = vi.mocked(promptTerminal)

function captureError(operation: () => unknown): unknown {
  try {
    operation()
  } catch (error) {
    return error
  }
  throw new Error("Expected the invalid configuration to fail")
}

async function environment(module: Module) {
  // eslint-disable-next-line prefer-spread -- Module.apply is a lifecycle method.
  const result = await module.apply(null, {})
  expect(result.status).toBe("ok")
  return mergeEnvironmentFromMeta({}, result.meta)
}

const originalStdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
const originalStderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY")
const originalStdoutTty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY")

describe("secret contract test context", () => {
  beforeEach(() => {
    prompt.mockReset().mockResolvedValue("synthetic-value")
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true })
    clearRegisteredSecrets()
  })
  afterEach(() => {
    if (originalStdinTty) Object.defineProperty(process.stdin, "isTTY", originalStdinTty)
    else Reflect.deleteProperty(process.stdin, "isTTY")
    if (originalStderrTty) Object.defineProperty(process.stderr, "isTTY", originalStderrTty)
    else Reflect.deleteProperty(process.stderr, "isTTY")
    if (originalStdoutTty) Object.defineProperty(process.stdout, "isTTY", originalStdoutTty)
    else Reflect.deleteProperty(process.stdout, "isTTY")
    vi.restoreAllMocks()
    clearRegisteredSecrets()
  })

  describe("manual secret facade", () => {
    it("snapshots labels and bindings without exposing opaque sources", async () => {
      const labels = { PASSWORD: "Database\u001b[31m password" }
      const facade = secret.provider("manual", { labels })
      const bindings: Record<string, SecretInput> = { PASSWORD: " op://private/source " }
      const module = facade.resolve(bindings)
      labels.PASSWORD = "changed"
      bindings.PASSWORD = "changed"
      prompt.mockResolvedValueOnce("  pasted ünicode  ")
      const env = await environment(module)
      await expect(resolveEnvironment(env, "PASSWORD")).resolves.toBe("  pasted ünicode  ")
      expect(prompt).toHaveBeenCalledWith("Database password: ", true, { abortSignal: undefined })
      expect(module.name).not.toContain("private")
      expect(module.local).toBe(true)
      expect(module._dryRunMetaProducer).toBe(true)
      await expect(module.check(null, {})).resolves.toBe("needs-apply")
      expect(getRegisteredSecrets()).toStrictEqual([])
    })

    it("accepts an empty source and empty input with the logical name as label", async () => {
      Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: false })
      prompt.mockResolvedValueOnce("")
      const env = await environment(secret.provider("manual").resolve({ PASSWORD: "" }))
      await expect(resolveEnvironment(env, "PASSWORD")).resolves.toBe("")
      expect(prompt).toHaveBeenCalledWith("PASSWORD: ", true, { abortSignal: undefined })
    })

    it("shares only identical facade/name/source requests within one run", async () => {
      const facade = secret.provider("manual", { labels: { A: "same", B: "same" } })
      const same = facade.resolve({ A: "source" })
      const repeated = facade.resolve({ A: "source" })
      const distinct = [
        facade.resolve({ A: " source" }),
        facade.resolve({ B: "source" }),
        secret.provider("manual").resolve({ A: "source" }),
      ]
      await withSecretPrewarmScope(async () => {
        await same._prewarmSecrets?.()
        expect(getRegisteredSecrets()).toStrictEqual([])
        await withRunScopedSecrets(async () => {
          await environment(repeated)
          expect(getRegisteredSecrets()).toContain("synthetic-value")
        })
        for (const module of distinct) {
          // eslint-disable-next-line no-await-in-loop -- Distinct interactive prompts must run sequentially.
          await environment(module)
        }
        expect(prompt).toHaveBeenCalledTimes(4)
      })
      await withSecretPrewarmScope(async () => environment(same))
      await environment(same)
      await environment(same)
      expect(prompt).toHaveBeenCalledTimes(7)
      expect(getRegisteredSecrets()).toStrictEqual([])
    })

    it.each([
      { stderr: true, stdin: false },
      { stderr: true, stdin: undefined },
      { stderr: false, stdin: true },
      { stderr: undefined, stdin: true },
      { stderr: false, stdin: false },
    ])(
      "rejects early and late input before reading for stdin=$stdin stderr=$stderr",
      async ({ stderr, stdin }) => {
        Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: stdin })
        Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: stderr })
        const facade = secret.provider("manual")
        await expect(
          facade.resolve({ VALUE: "private-source" })._prewarmSecrets?.()
        ).rejects.toThrow("TTY on stdin and stderr")
        const env = await environment(facade.resolve({ CODE: secret.totp("private-source") }))
        await expect(resolveEnvironment(env, "CODE")).rejects.toThrow("TTY on stdin and stderr")
        expect(prompt).not.toHaveBeenCalled()
      }
    )

    it("passes the runner signal, releases the guard after abort, and rejects an already aborted signal", async () => {
      const controller = new AbortController()
      prompt.mockImplementationOnce(
        async (_question, _hidden, options) =>
          new Promise((_resolve, reject) => {
            options?.abortSignal?.addEventListener(
              "abort",
              () => {
                reject(new Error("cancelled"))
              },
              {
                once: true,
              }
            )
          })
      )
      const facade = secret.provider("manual")
      await withRunnerAbortSignal(controller.signal, async () => {
        const env = await environment(facade.resolve({ CODE: secret.totp("source") }))
        const pending = resolveEnvironment(env, "CODE")
        await vi.waitFor(() => {
          expect(prompt).toHaveBeenCalledOnce()
        })
        controller.abort()
        await expect(pending).rejects.toThrow("cancelled")
        await expect(resolveEnvironment(env, "CODE")).rejects.toThrow(Error)
        expect(prompt).toHaveBeenCalledOnce()
      })
      await environment(facade.resolve({ PASSWORD: "source" }))
      expect(prompt).toHaveBeenCalledTimes(2)
    })

    it.each(["tiny", "synthetic-long-secret"])(
      "redacts an observed %s value from all prewarm error surfaces",
      async (value) => {
        const source = "opaque-sensitive-reference"
        const original = new Error(`failure ${value} ${source}`, {
          cause: new Error(`nested ${value}`),
        })
        original.stack = `stack ${value} ${source}`
        prompt.mockResolvedValueOnce(value).mockRejectedValueOnce(original)
        const module = secret.provider("manual").resolve({ FIRST: "first-source", SECOND: source })
        let caught: unknown
        try {
          await module._prewarmSecrets?.()
        } catch (error) {
          caught = error
        }
        expect(caught).toBeInstanceOf(Error)
        const diagnostic = inspect(caught, { depth: 8 })
        expect(diagnostic).not.toContain(value)
        expect(diagnostic).not.toContain(source)
        expect(original.message).toContain(value)
        expect(getRegisteredSecrets()).toStrictEqual([])
      }
    )
  })

  describe("manual delayed failure masking", () => {
    it.each(["tiny", "synthetic-long-secret"])(
      "redacts an earlier observed %s value when a late resolver fails",
      async (value) => {
        prompt.mockResolvedValueOnce(value)
        const env = await environment(
          secret
            .provider("manual")
            .resolve({ CODE: secret.totp("code-source"), PASSWORD: "source" })
        )
        const original = new Error(`late failure ${value}`, { cause: new Error(`nested ${value}`) })
        original.stack = `late stack ${value}`
        prompt.mockRejectedValueOnce(original)
        let caught: unknown
        try {
          await resolveEnvironment(env, "CODE")
        } catch (error) {
          caught = error
        }
        expect(caught).toBeInstanceOf(Error)
        expect(inspect(caught, { depth: 8 })).not.toContain(value)
        expect(original.message).toContain(value)
        expect(getRegisteredSecrets()).toStrictEqual([])
      }
    )
  })

  describe("manual marked codes", () => {
    it("does no early work, coalesces only an open access, then requests a new code", async () => {
      const descriptor = { kind: "totp" as const, reference: "source" }
      const module = secret
        .provider("manual")
        .resolve({ CODE: descriptor, UNUSED: secret.totp("other") })
      descriptor.reference = "mutated"
      await module._prewarmSecrets?.()
      const env = await environment(module)
      expect(prompt).not.toHaveBeenCalled()
      const pending = Promise.withResolvers<string>()
      prompt.mockReturnValueOnce(pending.promise)
      const first = resolveEnvironment(env, "CODE")
      const second = resolveEnvironment(env, "CODE")
      await vi.waitFor(() => {
        expect(prompt).toHaveBeenCalledOnce()
      })
      pending.resolve("001234")
      await expect(Promise.all([first, second])).resolves.toStrictEqual(["001234", "001234"])
      prompt.mockResolvedValueOnce("009876")
      await expect(resolveEnvironment(env, "CODE")).resolves.toBe("009876")
      expect(prompt).toHaveBeenCalledTimes(2)
      expect(getRegisteredSecrets()).toStrictEqual([])
    })

    it("never shares a pending code between apply calls or runs and recovers after rejection", async () => {
      const module = secret.provider("manual").resolve({ CODE: secret.totp("source") })
      const [firstEnv, secondEnv] = await Promise.all([
        withSecretPrewarmScope(async () => environment(module)),
        withSecretPrewarmScope(async () => environment(module)),
      ])
      const pending = Promise.withResolvers<string>()
      prompt.mockReturnValueOnce(pending.promise)
      const first = resolveEnvironment(firstEnv, "CODE")
      await vi.waitFor(() => {
        expect(prompt).toHaveBeenCalledOnce()
      })
      await expect(resolveEnvironment(secondEnv, "CODE")).rejects.toThrow("already active")
      pending.resolve("111111")
      await expect(first).resolves.toBe("111111")
      prompt.mockResolvedValueOnce("222222")
      await expect(resolveEnvironment(secondEnv, "CODE")).resolves.toBe("222222")
      expect(prompt).toHaveBeenCalledTimes(2)
    })

    it("keeps ordinary values separate from marked codes with the same identity", async () => {
      const facade = secret.provider("manual")
      await withSecretPrewarmScope(async () => {
        prompt.mockResolvedValueOnce("ordinary-value").mockResolvedValueOnce("123456")
        const ordinary = await environment(facade.resolve({ VALUE: "same-source" }))
        const marked = await environment(facade.resolve({ VALUE: secret.totp("same-source") }))
        await expect(resolveEnvironment(ordinary, "VALUE")).resolves.toBe("ordinary-value")
        await expect(resolveEnvironment(marked, "VALUE")).resolves.toBe("123456")
        expect(prompt).toHaveBeenCalledTimes(2)
      })
    })
  })

  describe("secret facade validation", () => {
    it.each(
      [
        {},
        [],
        null,
        { "bad name": "hidden" },
        { constructor: "hidden" },
        { VALUE: 123 },
        { VALUE: { kind: "totp", reference: 123 } },
        { VALUE: { extra: true, kind: "totp", reference: "hidden" } },
      ].map((bindings) => ({ bindings }))
    )("rejects invalid bindings synchronously without displaying values %#", ({ bindings }) => {
      expect(() => secret.provider("manual").resolve(bindings as never)).toThrow(Error)
      const error = captureError(() => secret.provider("manual").resolve(bindings as never))
      expect(String(error)).not.toContain("hidden")
      expect(prompt).not.toHaveBeenCalled()
    })
    it("rejects invalid providers, options and references before any I/O", () => {
      expect(() => secret.provider("hidden" as never)).toThrow("Unknown secret provider")
      expect(() => secret.provider("manual", { labels: { VALUE: 123 } } as never)).toThrow(Error)
      expect(() => {
        // @ts-expect-error -- Runtime validation must reject options that typed callers cannot supply.
        secret.provider("1password", {})
      }).toThrow(Error)
      expect(() => secret.provider("1password").resolve({ VALUE: "hidden" })).toThrow(Error)
      expect(() => secret.totp(123 as never)).toThrow(Error)
      expect(prompt).not.toHaveBeenCalled()
    })
  })
})
