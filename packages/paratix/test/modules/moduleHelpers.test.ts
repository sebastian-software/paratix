import { describe, expect, it } from "vitest"

import {
  applyWithFlagLock,
  FLAGS_DIRECTORY,
  hasFlag,
  setFlag,
  setVersionedFlag,
} from "../../src/modules/moduleHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolvePromise: (() => void) | undefined
  const promise = new Promise<void>((resolve) => {
    resolvePromise = resolve
  })
  return {
    promise,
    resolve() {
      resolvePromise?.()
    },
  }
}

function createSharedFlagMockSsh(flagName: string): ReturnType<typeof createMockSsh> {
  const base = createMockSsh(
    {},
    {
      defaultExecResult: { code: 0 },
      defaultOutputResult: "",
      defaultTestResult: false,
    }
  )
  let flagExists = false
  let lockExists = false
  const waiters: Array<() => void> = []

  function resolveWaiters(): void {
    for (const resolve of waiters.splice(0)) resolve()
  }

  const flagTestCommand = `[ -f ${FLAGS_DIRECTORY}/'${flagName}' ]`
  const lockMkdirCommand = `mkdir ${FLAGS_DIRECTORY}/'${flagName}.lock'`
  const lockRmdirCommand = `rmdir ${FLAGS_DIRECTORY}/'${flagName}.lock'`
  const touchFlagCommand = `touch ${FLAGS_DIRECTORY}/'${flagName}'`

  return {
    ...base,
    async exec(command, options) {
      base.calls.push(command)
      base.execCalls.push({ command, options })
      if (command === lockMkdirCommand) {
        if (lockExists) return { code: 1, stderr: "", stdout: "" }
        lockExists = true
        return { code: 0, stderr: "", stdout: "" }
      }
      if (command === lockRmdirCommand) {
        lockExists = false
        resolveWaiters()
        return { code: 0, stderr: "", stdout: "" }
      }
      if (command === touchFlagCommand) {
        flagExists = true
        resolveWaiters()
        return { code: 0, stderr: "", stdout: "" }
      }
      if (command.startsWith("i=0; while [ -d")) {
        if (!flagExists && lockExists) {
          await new Promise<void>((resolve) => {
            waiters.push(resolve)
          })
        }
        return { code: 0, stderr: "", stdout: "" }
      }
      return { code: 0, stderr: "", stdout: "" }
    },
    async test(command) {
      await Promise.resolve()
      base.calls.push(command)
      return command === flagTestCommand && flagExists
    },
  }
}

describe("hasFlag – empty string validation", () => {
  it("throws when flagName is an empty string", async () => {
    // An empty flagName produces shellQuote("") === "''" which expands the
    // glob pattern to match all flags, causing silent data-loss or wrong results.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "")).rejects.toThrow(/flagName must match/v)
  })

  it("does not throw for a valid flagName", async () => {
    const ssh = createMockSsh({
      "[ -f /var/lib/paratix/flags/'valid-flag' ]": { code: 0 },
    })
    await expect(hasFlag(ssh, "valid-flag")).resolves.not.toThrow()
  })
})

describe("setVersionedFlag – empty string validation", () => {
  it("throws when flagName is an empty string", async () => {
    // shellQuote("") === "''" – touch would create a file literally named "''"
    // instead of the intended versioned flag.
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await expect(setVersionedFlag(ssh, "", "valid-prefix-")).rejects.toThrow(/flagName must match/v)
  })

  it("throws when flagPrefix is an empty string", async () => {
    // shellQuote("") === "''" – the find -name glob becomes "''"* which in bash
    // expands to * and would delete ALL flags on the target system.
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await expect(setVersionedFlag(ssh, "valid-flag-1.0", "")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("does not throw for valid flagName and flagPrefix", async () => {
    const flagPrefix = "valid-prefix-"
    const flagName = "valid-prefix-1.0"
    const ssh = createMockSsh({
      [`find ${FLAGS_DIRECTORY} -maxdepth 1 -name '${flagPrefix}*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'${flagName}'`]:
        {
          code: 0,
        },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await expect(setVersionedFlag(ssh, flagName, flagPrefix)).resolves.not.toThrow()
  })

  it("calls find with the correct prefix glob to replace old versioned flags", async () => {
    const flagPrefix = "myapp-"
    const flagName = "myapp-2.0"
    const expectedCommand = `find ${FLAGS_DIRECTORY} -maxdepth 1 -name '${flagPrefix}*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'${flagName}'`
    const ssh = createMockSsh({
      [expectedCommand]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    await setVersionedFlag(ssh, flagName, flagPrefix)
    expect(ssh.calls).toContain(expectedCommand)
  })
})

describe("hasFlag – rejects path-traversal-like names", () => {
  it("rejects flagName equal to '..' (would resolve to parent directory)", async () => {
    // [ -f /var/lib/paratix/flags/.. ] would always be true, masking missing flags.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "..")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName with a leading dot", async () => {
    // Hidden-style names like ".foo" are not permitted; they collide with the
    // directory-traversal exclusion and complicate reasoning about flag files.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, ".foo")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName containing a path separator", async () => {
    // A `/` would let a flag name escape the flags directory entirely.
    const ssh = createMockSsh()
    await expect(hasFlag(ssh, "foo/bar")).rejects.toThrow(/flagName must match/v)
  })
})

describe("setFlag – rejects path-traversal-like names", () => {
  it("rejects flagName equal to '..'", async () => {
    const ssh = createMockSsh()
    await expect(setFlag(ssh, "..")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName with a leading dot", async () => {
    const ssh = createMockSsh()
    await expect(setFlag(ssh, ".foo")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName containing a path separator", async () => {
    const ssh = createMockSsh()
    await expect(setFlag(ssh, "foo/bar")).rejects.toThrow(/flagName must match/v)
  })

  it("does not throw for a valid flagName", async () => {
    const flagName = "valid-flag"
    const ssh = createMockSsh({
      [`touch ${FLAGS_DIRECTORY}/'${flagName}'`]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })

    await expect(setFlag(ssh, flagName)).resolves.not.toThrow()
  })
})

describe("applyWithFlagLock", () => {
  it("skips apply when a direct apply call finds an existing flag", async () => {
    const flagName = "apply-once"
    const ssh = createMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'${flagName}' ]`]: { code: 0 },
    })
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        await Promise.resolve()
        applyCalls += 1
        return { status: "changed" }
      },
      flagName,
    })

    expect(result).toStrictEqual({ status: "ok" })
    expect(applyCalls).toBe(0)
    expect(ssh.calls).not.toContain(`mkdir ${FLAGS_DIRECTORY}/'${flagName}.lock'`)
  })

  it("runs apply once while a parallel caller waits for the flag", async () => {
    const flagName = "parallel-apply"
    const ssh = createSharedFlagMockSsh(flagName)
    const firstApplyStarted = deferred()
    const finishFirstApply = deferred()
    let applyCalls = 0

    const first = applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        firstApplyStarted.resolve()
        await finishFirstApply.promise
        await setFlag(ssh, flagName)
        return { status: "changed" }
      },
      flagName,
    })

    await firstApplyStarted.promise

    const second = applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await setFlag(ssh, flagName)
        return { status: "changed" }
      },
      flagName,
    })

    finishFirstApply.resolve()
    const results = await Promise.all([first, second])

    expect(results).toStrictEqual([{ status: "changed" }, { status: "ok" }])
    expect(applyCalls).toBe(1)
    expect(ssh.calls).toContain(`mkdir ${FLAGS_DIRECTORY}/'${flagName}.lock'`)
  })
})

describe("setVersionedFlag – rejects path-traversal-like names", () => {
  it("rejects flagPrefix equal to '..'", async () => {
    // A `..` prefix would let `find -name '..*' -delete` target paths outside
    // the flags directory hierarchy on some find implementations.
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", "..")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagPrefix with a leading dot", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", ".hidden-")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagPrefix containing a path separator", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", "foo/bar")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagName equal to '..'", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "..", "valid-prefix-")).rejects.toThrow(
      /flagName must match/v
    )
  })
})

describe("setVersionedFlag – rejects shell-special characters", () => {
  it("rejects flagPrefix containing spaces and parentheses", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "valid-flag", "my prefix (v2)")).rejects.toThrow(
      /flagPrefix must match/v
    )
  })

  it("rejects flagName containing semicolons (command injection attempt)", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "safe; rm -rf /; #1.0", "safe-")).rejects.toThrow(
      /flagName must match/v
    )
  })

  it("rejects flagName containing backticks (command substitution attempt)", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "`id`1.0", "valid-")).rejects.toThrow(/flagName must match/v)
  })

  it("rejects flagName containing $() (command substitution attempt)", async () => {
    const ssh = createMockSsh()
    await expect(setVersionedFlag(ssh, "$(id)1.0", "valid-")).rejects.toThrow(
      /flagName must match/v
    )
  })
})
