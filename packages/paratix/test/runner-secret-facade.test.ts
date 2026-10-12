import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import type { Environment, Module, ModuleResult, ServerDefinition } from "../src/types.js"

import { applyModuleFilter } from "../src/moduleFilter.js"
import { getSignalBus, installRunnerTestHooks, makeMockSshClass } from "./helpers/runnerMocks.js"

installRunnerTestHooks()
const originalStdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
const originalStderrTty = Object.getOwnPropertyDescriptor(process.stderr, "isTTY")

async function harness() {
  const chronology: string[] = []
  const prompt = vi.fn<() => Promise<string>>().mockImplementation(async () => {
    chronology.push("prompt")
    await Promise.resolve()
    return "synthetic-secret"
  })
  const connect = vi.fn().mockImplementation(async () => {
    chronology.push("connect")
    await Promise.resolve()
    return null
  })
  vi.doMock("../src/terminal.js", () => ({ promptTerminal: prompt }))
  vi.doMock("../src/ssh.js", () => ({
    shellQuote: (value: string) => `'${value}'`,
    SshConnectionImpl: makeMockSshClass([], { connect, lifecycle: "permissive" }),
  }))
  const [
    { runPlaybook },
    { secret },
    { when },
    { recipe },
    { resolveEnvironment },
    { getRegisteredSecrets },
  ] = await Promise.all([
    import("../src/runner.js"),
    import("../src/modules/secret.js"),
    import("../src/builtins.js"),
    import("../src/recipe.js"),
    import("../src/environment.js"),
    import("../src/secretSink.js"),
  ])
  return {
    chronology,
    connect,
    getRegisteredSecrets,
    prompt,
    recipe,
    resolveEnvironment,
    runPlaybook,
    secret,
    when,
  }
}
function definition(run: Module[], signals?: Module[]): ServerDefinition {
  return {
    host: "127.0.0.1",
    name: "synthetic-secret-run",
    run,
    signals,
    ssh: { ports: [22], privateKey: "~/.ssh/id", user: "root" },
  }
}
function probe(
  name: string,
  check: (env: Environment) => Promise<"needs-apply" | "ok">,
  apply?: (env: Environment) => Promise<ModuleResult>
): Module {
  return {
    apply: async (_ssh, env) => apply?.(env) ?? { status: "ok" },
    check: async (_ssh, env) => check(env),
    name,
  }
}

describe("secret contract test context", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.spyOn(console, "log").mockImplementation(() => {
      /* Output is captured by assertions instead. */
    })
    vi.spyOn(console, "error").mockImplementation(() => {
      /* Output is captured by assertions instead. */
    })
    Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: true })
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true })
  })
  afterEach(() => {
    vi.doUnmock("../src/terminal.js")
    vi.doUnmock("../src/ssh.js")
    vi.restoreAllMocks()
    if (originalStdinTty) Object.defineProperty(process.stdin, "isTTY", originalStdinTty)
    else Reflect.deleteProperty(process.stdin, "isTTY")
    if (originalStderrTty) Object.defineProperty(process.stderr, "isTTY", originalStderrTty)
    else Reflect.deleteProperty(process.stderr, "isTTY")
    process.exitCode = 0
  })

  describe("runner secret facade lifecycle", () => {
    it.each([false, true])(
      "prewarms ordinary input before connect and exposes meta only at its nested module position; dryRun=%s",
      async (dryRun) => {
        const h = await harness()
        const secrets = h.secret.provider("manual").resolve({ PASSWORD: "opaque-source" })
        const before = probe("before", async (env) => {
          expect(env.PASSWORD).toBeUndefined()
          await Promise.resolve()
          return "ok"
        })
        const after = probe("after", async (env) => {
          await expect(h.resolveEnvironment(env, "PASSWORD")).resolves.toBe("synthetic-secret")
          return "ok"
        })
        await h.runPlaybook(
          definition([
            before,
            h.recipe("outer", [h.when(() => true, h.recipe("inner", [secrets]))]),
            after,
          ]),
          { dryRun }
        )
        expect(h.chronology).toStrictEqual(["prompt", "connect"])
        expect(h.prompt).toHaveBeenCalledOnce()
        expect(h.getRegisteredSecrets()).toStrictEqual([])
      }
    )

    it("does not prompt for marked codes hidden by a condition, a filter or an untriggered signal", async () => {
      const h = await harness()
      const facade = h.secret.provider("manual")
      const code = () => facade.resolve({ CODE: h.secret.totp("source") })
      const keep = probe("keep", async () => {
        await Promise.resolve()
        return "ok"
      })
      const guarded = h.when(() => false, code())
      const run = applyModuleFilter(
        [guarded, h.recipe("filtered", [code()]), keep],
        new Set([guarded.name, keep.name])
      )
      await h.runPlaybook(definition(run, [h.recipe("unused-signal", [code()])]))
      expect(h.prompt).not.toHaveBeenCalled()
      expect(h.chronology).toStrictEqual(["connect"])
    })

    it("keeps marked policy through nested recipe and condition meta and refreshes between check, apply and signal", async () => {
      const h = await harness()
      h.prompt
        .mockResolvedValueOnce("111111")
        .mockResolvedValueOnce("222222")
        .mockResolvedValueOnce("333333")
      const observed: unknown[] = []
      const consumer = probe(
        "consumer",
        async (env) => {
          observed.push(await h.resolveEnvironment(env, "CODE"))
          return "needs-apply"
        },
        async (env) => {
          observed.push(await h.resolveEnvironment(env, "CODE"))
          return { status: "changed" }
        }
      )
      const signal = probe(
        "signal-consumer",
        async () => {
          await Promise.resolve()
          return "ok"
        },
        async (env) => {
          observed.push(await h.resolveEnvironment(env, "CODE"))
          return { status: "ok" }
        }
      )
      const codes = h.secret.provider("manual").resolve({ CODE: h.secret.totp("source") })
      await h.runPlaybook(
        definition(
          [h.recipe("outer", [h.when(() => true, h.recipe("inner", [codes]))]), consumer],
          [signal]
        )
      )
      expect(observed).toStrictEqual(["111111", "222222", "333333"])
      expect(h.prompt).toHaveBeenCalledTimes(3)
      expect(h.chronology[0]).toBe("connect")
      expect(h.getRegisteredSecrets()).toStrictEqual([])
    })

    it("runs a late code prompt during a dry-run check only when that check consumes it", async () => {
      const h = await harness()
      const codes = h.secret.provider("manual").resolve({ CODE: h.secret.totp("source") })
      let applied = false
      const consumer = probe(
        "consumer",
        async (env) => {
          await h.resolveEnvironment(env, "CODE")
          return "needs-apply"
        },
        async () => {
          applied = true
          await Promise.resolve()
          return { status: "changed" }
        }
      )
      await h.runPlaybook(definition([codes, consumer]), { dryRun: true })
      expect(h.chronology).toStrictEqual(["connect", "prompt"])
      expect(applied).toBe(false)
    })

    it("prevents connection on early TTY failure and stops later work on late TTY failure", async () => {
      const h = await harness()
      Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: false })
      const facade = h.secret.provider("manual")
      await expect(
        h.runPlaybook(definition([facade.resolve({ PASSWORD: "source" })]))
      ).rejects.toThrow("TTY")
      expect(h.connect).not.toHaveBeenCalled()
      let earlier = false
      let later = false
      const before = probe("before", async () => {
        earlier = true
        await Promise.resolve()
        return "ok"
      })
      const consumer = probe("consumer", async (env) => {
        await h.resolveEnvironment(env, "CODE")
        return "ok"
      })
      const after = probe("after", async () => {
        later = true
        await Promise.resolve()
        return "ok"
      })
      await h.runPlaybook(
        definition([facade.resolve({ CODE: h.secret.totp("source") }), before, consumer, after])
      )
      expect(earlier).toBe(true)
      expect(later).toBe(false)
      expect(h.connect).toHaveBeenCalledOnce()
      expect(process.exitCode).toBe(1)
      expect(h.prompt).not.toHaveBeenCalled()
    })

    it.each(["SIGINT", "SIGTERM"] as const)(
      "aborts an active late prompt on %s and releases the prompt guard",
      async (signal) => {
        const h = await harness()
        const promptStarted = Promise.withResolvers<undefined>()
        h.prompt.mockImplementationOnce(
          async (...args: unknown[]) =>
            new Promise<string>((_resolve, reject) => {
              const options = args[2] as { abortSignal: AbortSignal }
              options.abortSignal.addEventListener(
                "abort",
                () => {
                  reject(new Error("cancelled"))
                },
                {
                  once: true,
                }
              )
              promptStarted.resolve(undefined)
            })
        )
        const facade = h.secret.provider("manual")
        const consumer = probe("consumer", async (env) => {
          await h.resolveEnvironment(env, "CODE")
          return "ok"
        })
        const run = h.runPlaybook(
          definition([facade.resolve({ CODE: h.secret.totp("source") }), consumer])
        )
        await promptStarted.promise
        getSignalBus().emit(signal)
        await run
        expect(process.exitCode).not.toBe(0)
        expect(h.getRegisteredSecrets()).toStrictEqual([])
        // eslint-disable-next-line prefer-spread -- A subsequent direct apply proves the guard was released.
        const recovered = await facade.resolve({ PASSWORD: "source" }).apply(null, {})
        expect(recovered.status).toBe("ok")
      }
    )
  })
})
