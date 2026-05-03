import { describe, expect, it, vi } from "vitest"

import type { Environment, Module } from "../src/types.js"

import {
  assert,
  debug,
  fail,
  firstRun,
  pause,
  setPauseAbortSignal,
  signals,
  when,
} from "../src/builtins.js"
import { resolveEnvironment } from "../src/environment.js"
import { mergeEnvironmentFromMeta, meta } from "../src/meta.js"
import { createMockSsh } from "./helpers/mockSsh.js"

const emptyEnv: Environment = {}
const DPKG_STATUS_LITERAL = ["${", "Status}"].join("")
const DPKG_UFW_INSTALLED = `dpkg-query -W -f='${DPKG_STATUS_LITERAL}' 'ufw' 2>/dev/null | grep -q 'install ok installed'`

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

function makeFailedModule(errorMessage: string): Module {
  return {
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async apply() {
      return { error: new Error(errorMessage), status: "failed" as const }
    },
    // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
    async check() {
      return "needs-apply"
    },
    name: `failed-module: ${errorMessage}`,
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
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toBe("[assert] condition must be true")
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
    const mod = fail("something went wrong")
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toBe("[fail] something went wrong")
  })
})

describe("pause", () => {
  it("check always returns needs-apply", async () => {
    const mod = pause()
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply calls process.stdin.pause() after Enter resolves the promise", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    let capturedCallback: ((chunk: Buffer) => void) | undefined
    const onSpy = vi
      .spyOn(process.stdin, "on")
      .mockImplementation((_event: string | symbol, callback: (...args: unknown[]) => void) => {
        capturedCallback = callback as (chunk: Buffer) => void
        return process.stdin
      })
    const removeSpy = vi
      .spyOn(process.stdin, "removeListener")
      .mockImplementation(() => process.stdin)
    const stdinPauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)

    const mod = pause()
    // eslint-disable-next-line prefer-spread
    const applyPromise = mod.apply(null, emptyEnv)

    // Emit Enter so the promise can resolve.
    expect(capturedCallback).toBeDefined()
    capturedCallback!(Buffer.from("\n"))

    await applyPromise

    expect(stdinPauseSpy).toHaveBeenCalledOnce()

    stdoutSpy.mockRestore()
    onSpy.mockRestore()
    removeSpy.mockRestore()
    stdinPauseSpy.mockRestore()
  })

  it("ignores non-Enter data events while waiting for pause confirmation", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    let capturedCallback: ((chunk: Buffer) => void) | undefined
    const onSpy = vi
      .spyOn(process.stdin, "on")
      .mockImplementation((_event: string | symbol, callback: (...args: unknown[]) => void) => {
        capturedCallback = callback as (chunk: Buffer) => void
        return process.stdin
      })
    const removeSpy = vi
      .spyOn(process.stdin, "removeListener")
      .mockImplementation(() => process.stdin)
    const stdinPauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)

    const mod = pause()
    // eslint-disable-next-line prefer-spread
    const applyPromise = mod.apply(null, emptyEnv)

    expect(capturedCallback).toBeDefined()
    capturedCallback!(Buffer.from("x"))

    await Promise.resolve()

    expect(stdinPauseSpy).not.toHaveBeenCalled()
    expect(removeSpy).not.toHaveBeenCalled()

    capturedCallback!(Buffer.from("\r"))
    await applyPromise

    expect(stdinPauseSpy).toHaveBeenCalledOnce()

    stdoutSpy.mockRestore()
    onSpy.mockRestore()
    removeSpy.mockRestore()
    stdinPauseSpy.mockRestore()
  })

  it("rejects the apply promise and removes the stdin data listener when the abort signal fires", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    let capturedCallback: ((...args: unknown[]) => void) | undefined
    const onSpy = vi
      .spyOn(process.stdin, "on")
      .mockImplementation((_event: string | symbol, callback: (...args: unknown[]) => void) => {
        capturedCallback = callback
        return process.stdin
      })
    const removedListeners: Array<{ callback: unknown; event: string | symbol }> = []
    const removeListenerSpy = vi
      .spyOn(process.stdin, "removeListener")
      .mockImplementation((event: string | symbol, listener: (...args: unknown[]) => void) => {
        removedListeners.push({ callback: listener, event })
        return process.stdin
      })
    const stdinPauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)

    const controller = new AbortController()
    setPauseAbortSignal(controller.signal)

    try {
      const mod = pause()
      // eslint-disable-next-line prefer-spread
      const applyPromise = mod.apply(null, emptyEnv)

      // Listener was attached before we abort.
      expect(capturedCallback).toBeDefined()

      controller.abort(new Error("Terminal prompt interrupted by SIGINT"))

      await expect(applyPromise).rejects.toThrow(/SIGINT/v)

      // The stdin "data" listener was removed; the abort path also pauses stdin.
      expect(removedListeners).toContainEqual({ callback: capturedCallback, event: "data" })
      expect(stdinPauseSpy).toHaveBeenCalled()
    } finally {
      setPauseAbortSignal(undefined)
      stdoutSpy.mockRestore()
      onSpy.mockRestore()
      removeListenerSpy.mockRestore()
      stdinPauseSpy.mockRestore()
    }
  })

  it("rejects synchronously when the abort signal is already aborted at the start of pause", async () => {
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)
    const onSpy = vi.spyOn(process.stdin, "on")
    const stdinPauseSpy = vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin)

    const controller = new AbortController()
    controller.abort(new Error("aborted before pause"))
    setPauseAbortSignal(controller.signal)

    try {
      const mod = pause()
      // eslint-disable-next-line prefer-spread
      await expect(mod.apply(null, emptyEnv)).rejects.toThrow(/aborted before pause/v)

      // stdin "data" listener is never installed when the signal is already aborted.
      expect(onSpy).not.toHaveBeenCalled()
    } finally {
      setPauseAbortSignal(undefined)
      stdoutSpy.mockRestore()
      onSpy.mockRestore()
      stdinPauseSpy.mockRestore()
    }
  })
})

describe("firstRun.stop", () => {
  it("check returns needs-apply when PARATIX_FIRST_RUN=true", async () => {
    const mod = firstRun.stop("stop after bootstrap")
    const result = await mod.check(null, { PARATIX_FIRST_RUN: "true" })
    expect(result).toBe("needs-apply")
  })

  it("check returns ok outside first-run", async () => {
    const mod = firstRun.stop("stop after bootstrap")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("apply returns a successful stop marker during first-run", async () => {
    const mod = firstRun.stop("stop after bootstrap")
    const applyModule = mod.apply
    const result = await applyModule(null, { PARATIX_FIRST_RUN: "true" })
    expect(result.status).toBe("ok")
    expect(result._stopRun).toBe(true)
    expect(result._dryRunDetail).toBe("(first-run stop)")
  })

  it("apply is a no-op outside first-run", async () => {
    const mod = firstRun.stop("stop after bootstrap")
    const applyModule = mod.apply
    const result = await applyModule(null, emptyEnv)
    expect(result).toStrictEqual({ status: "ok" })
  })
})

describe("signals.flush", () => {
  it("check always returns needs-apply", async () => {
    const mod = signals.flush("before hardening boundary")
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("apply returns a successful flush marker", async () => {
    const mod = signals.flush("before hardening boundary")
    const applyModule = mod.apply
    const result = await applyModule(null, emptyEnv)
    expect(result.status).toBe("ok")
    expect(result._flushSignals).toBe(true)
    expect(result._dryRunDetail).toBe("(dry-run, pending signals not executed)")
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

  it("apply propagates error details when an inner module returns failed", async () => {
    const innerModule = makeFailedModule("inner module exploded")
    const mod = when(() => true, innerModule)
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toBe("inner module exploded")
  })

  it("apply propagates nested when child errors without overwriting them", async () => {
    const nestedFailingModule = makeFailedModule("nested child failure")
    const nestedWhen = when(() => true, nestedFailingModule)
    const mod = when(() => true, nestedWhen)

    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(Error)
    expect(result.error?.message).toBe("nested child failure")
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
        return { meta: [meta.env("RESOLVED_IP", "1.2.3.4")], status: "changed" as const }
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
    const environment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(environment, "RESOLVED_IP")).resolves.toBe("1.2.3.4")
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

  // R-0000087 regression: when(...).apply must hand inner modules an environment
  // without `Object.prototype` on the prototype chain. The previous spread-based
  // copy (`{ ...environment }`) silently dropped the null-prototype hardening
  // established by R-0000069/R-0000070/R-0000074.
  it("apply hands the first inner module a null-prototype environment", async () => {
    let receivedEnv: Environment | undefined
    const captureModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply(_ssh, env) {
        receivedEnv = env
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check() {
        return "needs-apply"
      },
      name: "capture-module",
    }

    const nullProtoEnv: Environment = Object.create(null)
    nullProtoEnv.EXISTING = "value"

    const mod = when(() => true, captureModule)
    // eslint-disable-next-line prefer-spread
    await mod.apply(null, nullProtoEnv)

    expect(receivedEnv).toBeDefined()
    expect(Object.getPrototypeOf(receivedEnv)).toBeNull()
    expect(receivedEnv?.EXISTING).toBe("value")
  })

  // R-0000087 regression: same guarantee for the check-side traversal.
  it("check hands the first inner module a null-prototype environment", async () => {
    let receivedEnv: Environment | undefined
    const captureModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async apply() {
        return { status: "ok" }
      },
      // eslint-disable-next-line @typescript-eslint/require-await -- Interface requires async
      async check(_ssh, env) {
        receivedEnv = env
        return "ok"
      },
      name: "capture-module",
    }

    const nullProtoEnv: Environment = Object.create(null)
    nullProtoEnv.EXISTING = "value"

    const mod = when(() => true, captureModule)
    await mod.check(null, nullProtoEnv)

    expect(receivedEnv).toBeDefined()
    expect(Object.getPrototypeOf(receivedEnv)).toBeNull()
    expect(receivedEnv?.EXISTING).toBe("value")
  })

  it("packageInstalled runs inner modules when the package is present", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "which apt-get": { code: 0 },
    })
    const mod = when.packageInstalled("ufw", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("packageAbsent skips inner modules when the package is present", async () => {
    const ssh = createMockSsh({
      [DPKG_UFW_INSTALLED]: { code: 0 },
      "which apt-get": { code: 0 },
    })
    // eslint-disable-next-line @typescript-eslint/require-await -- Promise-returning mock function
    const innerCheck = vi.fn(async () => "needs-apply" as const)
    const innerModule: Module = {
      // eslint-disable-next-line @typescript-eslint/require-await -- Promise-returning module method
      async apply() {
        return { status: "changed" as const }
      },
      check: async () => innerCheck(),
      name: "inner",
    }

    const mod = when.packageAbsent("ufw", innerModule)
    const result = await mod.check(ssh, emptyEnv)

    expect(result).toBe("ok")
    expect(innerCheck).not.toHaveBeenCalled()
  })

  it("commandExists checks command presence on the host", async () => {
    const ssh = createMockSsh({
      "command -v 'docker' >/dev/null 2>&1": { code: 0 },
    })
    const mod = when.commandExists("docker", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("commandMissing skips apply when the command exists", async () => {
    const ssh = createMockSsh({
      "command -v 'docker' >/dev/null 2>&1": { code: 0 },
    })
    const mod = when.commandMissing("docker", makeNeedsApplyModule())
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("skipped")
  })

  it("fileExists checks for regular files only", async () => {
    const ssh = createMockSsh({
      "test -f '/etc/app.conf'": { code: 0 },
    })
    const mod = when.fileExists("/etc/app.conf", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("fileMissing skips when a regular file exists", async () => {
    const ssh = createMockSsh({
      "test -f '/etc/app.conf'": { code: 0 },
    })
    const mod = when.fileMissing("/etc/app.conf", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("pathExists checks for directories only", async () => {
    const ssh = createMockSsh({
      "test -d '/etc/myapp'": { code: 0 },
    })
    const mod = when.pathExists("/etc/myapp", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("pathMissing skips when a directory exists", async () => {
    const ssh = createMockSsh({
      "test -d '/etc/myapp'": { code: 0 },
    })
    const mod = when.pathMissing("/etc/myapp", makeNeedsApplyModule())
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("skipped")
  })

  it("symlinkExists checks for symlinks only", async () => {
    const ssh = createMockSsh({
      "test -L '/etc/myapp/current'": { code: 0 },
    })
    const mod = when.symlinkExists("/etc/myapp/current", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("symlinkMissing skips when a symlink exists", async () => {
    const ssh = createMockSsh({
      "test -L '/etc/myapp/current'": { code: 0 },
    })
    const mod = when.symlinkMissing("/etc/myapp/current", makeNeedsApplyModule())
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("skipped")
  })

  it("socketExists checks for unix sockets only", async () => {
    const ssh = createMockSsh({
      "test -S '/run/docker.sock'": { code: 0 },
    })
    const mod = when.socketExists("/run/docker.sock", makeNeedsApplyModule())
    const result = await mod.check(ssh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("socketMissing skips when a unix socket exists", async () => {
    const ssh = createMockSsh({
      "test -S '/run/docker.sock'": { code: 0 },
    })
    const mod = when.socketMissing("/run/docker.sock", makeNeedsApplyModule())
    const result = await mod.apply(ssh, emptyEnv)
    expect(result.status).toBe("skipped")
  })
})
