import { describe, expect, it, vi } from "vitest"

import type { Environment, Module } from "../src/types.js"

import { assert, debug, fail, pause, when } from "../src/builtins.js"

const emptyEnv: Environment = {}

function makeAlwaysOkModule(): Module {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply() {
      return { status: "ok" }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check() {
      return "ok"
    },
    name: "always-ok",
  }
}

function makeNeedsApplyModule(applyStatus: "changed" | "failed" | "ok" = "changed"): Module {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply() {
      return { status: applyStatus }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check() {
      return "needs-apply"
    },
    name: "needs-apply-module",
  }
}

describe("assert", () => {
  it("check returns ok when condition is true", async () => {
    const mod = assert(() => true, "condition must be true")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when condition is false", async () => {
    const mod = assert(() => false, "condition must be true")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns ok when condition is true", async () => {
    const mod = assert(() => true, "condition must be true")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("apply returns failed when condition is false", async () => {
    const mod = assert(() => false, "condition must be true")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("passes env to the condition function", async () => {
    const env: Environment = { ready: "true" }
    const mod = assert((e) => e.ready === "true", "must be ready")
    const result = await mod.check(null, env)
    expect(result).toBe("ok")
  })
})

describe("debug", () => {
  it("check always returns needs-apply", async () => {
    // eslint-disable-next-line testing-library/no-debugging-utils -- paratix debug module, not testing-library debug
    const mod = debug("some debug message")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply always returns ok", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {
      /* noop */
    })
    // eslint-disable-next-line testing-library/no-debugging-utils -- paratix debug module, not testing-library debug
    const mod = debug("some debug message")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("ok")
    consoleSpy.mockRestore()
  })
})

describe("fail", () => {
  it("check always returns needs-apply", async () => {
    const mod = fail("something went wrong")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply always returns failed", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    const mod = fail("something went wrong")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    consoleSpy.mockRestore()
  })
})

describe("pause", () => {
  it("check always returns needs-apply", async () => {
    const mod = pause()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply calls process.stdin.pause() after the data event resolves the promise", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    let capturedCallback: (() => void) | undefined
    const onceSpy = vi
      .spyOn(process.stdin, "once")
      .mockImplementation((_event: string | symbol, callback: (...args: unknown[]) => void) => {
        capturedCallback = callback as () => void
        return process.stdin
      })
    const stdinPauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)

    const mod = pause()
    // eslint-disable-next-line prefer-spread
    const applyPromise = mod.apply(null, emptyEnv)

    // Emit the data event so the promise can resolve
    expect(capturedCallback).toBeDefined()
    capturedCallback!()

    await applyPromise

    expect(stdinPauseSpy).toHaveBeenCalledOnce()

    stdoutSpy.mockRestore()
    onceSpy.mockRestore()
    stdinPauseSpy.mockRestore()
  })
})

describe("when", () => {
  it("check returns ok when condition is false (modules are skipped)", async () => {
    const innerModule = makeNeedsApplyModule()
    const mod = when(() => false, innerModule)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns ok when condition is true and all inner modules are ok", async () => {
    const innerModule = makeAlwaysOkModule()
    const mod = when(() => true, innerModule)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("check returns needs-apply when condition is true and an inner module needs apply", async () => {
    const innerModule = makeNeedsApplyModule()
    const mod = when(() => true, innerModule)
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns skipped when condition is false", async () => {
    const innerModule = makeNeedsApplyModule()
    const mod = when(() => false, innerModule)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("skipped")
  })

  it("apply executes inner modules and returns changed when condition is true and module changed", async () => {
    const innerModule = makeNeedsApplyModule("changed")
    const mod = when(() => true, innerModule)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("apply returns ok when condition is true and all inner modules are already ok", async () => {
    const innerModule = makeAlwaysOkModule()
    const mod = when(() => true, innerModule)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("apply returns failed when an inner module returns failed", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {
      /* noop */
    })
    const innerModule = makeNeedsApplyModule("failed")
    const mod = when(() => true, innerModule)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    consoleSpy.mockRestore()
  })

  // Bug #13 regression: when().check() must copy the environment before passing it to inner modules
  it("check does not mutate the caller's environment object", async () => {
    const receivedEnvs: Environment[] = []
    const snoopModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply(_ssh, env) {
        return { meta: env, status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(_ssh, env) {
        receivedEnvs.push(env)
        // Mutate the received env to verify the caller's object is not affected
        Object.assign(env, { injected: "yes" })
        return "ok"
      },
      name: "snoop",
    }

    const callerEnv: Environment = { original: "value" }
    const mod = when(() => true, snoopModule)
    await mod.check(null, callerEnv)

    // The inner module received a copy, not the original object
    expect(receivedEnvs[0]).not.toBe(callerEnv)
    // The caller's env must be unchanged
    expect(callerEnv).not.toHaveProperty("injected")
  })

  // Bug: applyConditionalModules returns { status: aggregatedStatus } without a meta field,
  // so meta values produced by inner modules are silently dropped.
  it("apply returns meta values from inner modules in the result", async () => {
    const metaModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { meta: { RESOLVED_IP: "1.2.3.4" }, status: "changed" as const }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "meta-producing-module",
    }

    const mod = when(() => true, metaModule)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)

    expect(result.status).toBe("changed")
    expect(result.meta).toBeDefined()
    expect(result.meta).toMatchObject({ RESOLVED_IP: "1.2.3.4" })
  })

  it("check passes the same copied environment to all inner modules", async () => {
    const envsSeenBySecond: Environment[] = []
    const firstModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(_ssh, env) {
        // Mutate the env copy to test that inner modules share the same copied env
        Object.assign(env, { fromFirst: "mutated" })
        return "ok"
      },
      name: "first",
    }
    const secondModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(_ssh, env) {
        envsSeenBySecond.push({ ...env })
        return "needs-apply"
      },
      name: "second",
    }

    const mod = when(() => true, firstModule, secondModule)
    await mod.check(null, { original: "value" })

    // The second module's env should reflect the first module's mutation
    // because the inner copy is shared between inner modules
    expect(envsSeenBySecond[0]).toHaveProperty("fromFirst", "mutated")
  })
})
