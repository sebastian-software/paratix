import { describe, expect, it } from "vitest"

import type { ExecOptions, ExecResult } from "../../src/types.js"

import {
  applyWithFlagLock,
  FLAGS_DIRECTORY,
  hasFlag,
  setFlag,
  setVersionedFlag,
  withMutexLock,
} from "../../src/modules/moduleHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"
import {
  isFlagLockInternalSuccessCommand,
  makeIsVerifiedReleaseCall,
  MOCK_FLAG_LOCK_HOLDER_TOKEN,
} from "../helpers/mockSshFlagLock.js"

const createMockSsh: typeof createBaseMockSsh = (responses, options) =>
  createBaseMockSsh(responses, options)

function expectLockExecOptions(options: ExecOptions | undefined): void {
  expect(options).toStrictEqual({ ignoreExitCode: true, silent: true })
}

function nonZeroLockExecResult(command: string, options: ExecOptions | undefined): ExecResult {
  const result = { code: 1, stderr: "", stdout: "" }
  if (options?.ignoreExitCode !== true) {
    throw new Error(
      `Command failed with exit code ${String(result.code)}: ${command}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`
    )
  }
  expectLockExecOptions(options)
  return result
}

/**
 * R-0000634: assert that a command is the verified-release shell statement
 * for the given lock. Tests use this instead of a plain `rmdir` match
 * because release is now a single atomic shell statement. The predicate is
 * built via the shared helper so the test never composes the
 * prefix/suffix check inline (eslint-plugin-vitest forbids logical
 * operators in tests).
 *
 * @param call - The recorded shell command to inspect.
 * @param lockName - The validated lock identifier (without quotes).
 * @returns `true` when `call` is the verified-release command for `lockName`.
 */
function isVerifiedReleaseCall(call: string, lockName: string): boolean {
  return makeIsVerifiedReleaseCall(lockName)(call)
}

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
      allowUnstubbedDefaults: true,
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
  const lockRmdirCommand = `rmdir -- ${FLAGS_DIRECTORY}/'${flagName}.lock'`
  const touchFlagCommand = `touch ${FLAGS_DIRECTORY}/'${flagName}'`
  // R-0000634: release is a single atomic shell statement combining the
  // ownership check, marker removal and `rmdir`. The mock recognises the
  // deterministic token returned by the holder-readback `output` stub.
  // R-0000749: production code now emits the `--` separator before path
  // arguments in awk / rm / rmdir invocations.
  const markerPath = `${FLAGS_DIRECTORY}/'${flagName}.lock'/holder`
  const lockPath = `${FLAGS_DIRECTORY}/'${flagName}.lock'`
  // R-0000803: awk now receives the marker as a single shell-quoted token.
  const awkMarkerPath = `'${FLAGS_DIRECTORY}/${flagName}.lock/holder'`
  // R-0000758: release captures the awk readback in `$awk_token` and uses
  // the POSIX `x`-prefix comparison so unusual awk output cannot collide
  // with `[` operator syntax.
  const verifiedReleaseCommand =
    `awk_token=$(awk 'NR==1{print $1}' -- ${awkMarkerPath} 2>/dev/null); awk_status=$?; ` +
    `[ "$awk_status" = 0 ] && ` +
    `[ "x$awk_token" = 'x${MOCK_FLAG_LOCK_HOLDER_TOKEN}' ] && ` +
    `rm -f -- ${markerPath} && ` +
    `rmdir -- ${lockPath}`
  const markerAwkReadCommand = `awk 'NR==1{print $1}' -- ${awkMarkerPath}`

  return {
    ...base,
    async exec(command, options) {
      base.calls.push(command)
      base.execCalls.push({ command, options })
      if (command === lockMkdirCommand) {
        if (lockExists) return nonZeroLockExecResult(command, options)
        expectLockExecOptions(options)
        lockExists = true
        return { code: 0, stderr: "", stdout: "" }
      }
      if (command === lockRmdirCommand || command === verifiedReleaseCommand) {
        expectLockExecOptions(options)
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
        expectLockExecOptions(options)
        return { code: 0, stderr: "", stdout: "" }
      }
      if (isFlagLockInternalSuccessCommand(command)) return { code: 0, stderr: "", stdout: "" }
      throw new Error(`unexpected shared flag lock exec command: ${command}`)
    },
    // R-0000670: writeFlagLockHolderMarker reads the `pid@hostname` token
    // back via `ssh.output` and now fails the acquire if the readback is
    // empty. Return the shared deterministic token so the lock is acquired
    // normally and the release path matches `verifiedReleaseCommand`.
    async output(command) {
      base.calls.push(command)
      if (command === markerAwkReadCommand) return MOCK_FLAG_LOCK_HOLDER_TOKEN
      return base.output(command)
    },
    async test(command) {
      await Promise.resolve()
      base.calls.push(command)
      if (command === flagTestCommand) return flagExists
      throw new Error(`unexpected shared flag lock test command: ${command}`)
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
      [`find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name '${flagPrefix}*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'${flagName}'`]:
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
    const expectedCommand = `find ${FLAGS_DIRECTORY} -maxdepth 1 -type f -name '${flagPrefix}*' ! -name '*.lock' -delete && touch ${FLAGS_DIRECTORY}/'${flagName}'`
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
  it("shared flag lock mock rejects unexpected exec commands", async () => {
    const ssh = createSharedFlagMockSsh("parallel-apply")

    await expect(ssh.exec("echo unexpected")).rejects.toThrow(
      "unexpected shared flag lock exec command: echo unexpected"
    )
  })

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

type StaleLockMockState = {
  flagExists: boolean
  lockExists: boolean
  staleReclaimCalls: number
}

const LOCK_COMMAND_KIND = {
  flagTest: "flag-test",
  lockMkdir: "lock-mkdir",
  lockRmdir: "lock-rmdir",
  lockWait: "lock-wait",
  other: "other",
  staleReclaim: "stale-reclaim",
  touchFlag: "touch-flag",
} as const

type LockCommandKind = (typeof LOCK_COMMAND_KIND)[keyof typeof LOCK_COMMAND_KIND]

function classifyLockCommand(command: string, flagName: string): LockCommandKind {
  // R-0000749: production code emits `rmdir --` to defend against path
  // arguments that begin with `-`.
  const lockMkdirCommand = `mkdir ${FLAGS_DIRECTORY}/'${flagName}.lock'`
  const lockRmdirCommand = `rmdir -- ${FLAGS_DIRECTORY}/'${flagName}.lock'`
  const touchFlagCommand = `touch ${FLAGS_DIRECTORY}/'${flagName}'`
  const flagTestCommand = `[ -f ${FLAGS_DIRECTORY}/'${flagName}' ]`
  if (command === lockMkdirCommand) return LOCK_COMMAND_KIND.lockMkdir
  if (command === lockRmdirCommand) return LOCK_COMMAND_KIND.lockRmdir
  if (command === touchFlagCommand) return LOCK_COMMAND_KIND.touchFlag
  if (command === flagTestCommand) return LOCK_COMMAND_KIND.flagTest
  if (command.startsWith("i=0; while [ -d")) return LOCK_COMMAND_KIND.lockWait
  if (command.startsWith("if [ -d ") && command.includes("-mmin")) {
    return LOCK_COMMAND_KIND.staleReclaim
  }
  return LOCK_COMMAND_KIND.other
}

function createStaleLockSsh(
  flagName: string,
  reclaim: "fresh" | "stale"
): {
  ssh: ReturnType<typeof createMockSsh>
  state: StaleLockMockState
} {
  const base = createMockSsh(
    {},
    {
      allowUnstubbedDefaults: true,
      defaultExecResult: { code: 0 },
      defaultOutputResult: "",
      defaultTestResult: false,
    }
  )
  const state: StaleLockMockState = {
    flagExists: false,
    lockExists: true, // simulate a lock left behind by a crashed holder
    staleReclaimCalls: 0,
  }

  function handleStaleReclaim(command: string, options: ExecOptions | undefined): ExecResult {
    state.staleReclaimCalls += 1
    if (reclaim === "fresh") return nonZeroLockExecResult(command, options)
    expectLockExecOptions(options)
    state.lockExists = false
    return { code: 0, stderr: "", stdout: "" }
  }

  function handleLockMkdir(command: string, options: ExecOptions | undefined): ExecResult {
    if (state.lockExists) return nonZeroLockExecResult(command, options)
    expectLockExecOptions(options)
    state.lockExists = true
    return { code: 0, stderr: "", stdout: "" }
  }

  function handleCommand(command: string, options: ExecOptions | undefined): ExecResult {
    const kind = classifyLockCommand(command, flagName)
    switch (kind) {
      case LOCK_COMMAND_KIND.flagTest: {
        return { code: state.flagExists ? 0 : 1, stderr: "", stdout: "" }
      }
      case LOCK_COMMAND_KIND.lockMkdir: {
        return handleLockMkdir(command, options)
      }
      case LOCK_COMMAND_KIND.lockRmdir: {
        expectLockExecOptions(options)
        state.lockExists = false
        return { code: 0, stderr: "", stdout: "" }
      }
      case LOCK_COMMAND_KIND.lockWait: {
        return nonZeroLockExecResult(command, options)
      }
      case LOCK_COMMAND_KIND.other: {
        if (isFlagLockInternalSuccessCommand(command)) return { code: 0, stderr: "", stdout: "" }
        throw new Error(`unexpected stale flag lock command: ${command}`)
      }
      case LOCK_COMMAND_KIND.staleReclaim: {
        return handleStaleReclaim(command, options)
      }
      case LOCK_COMMAND_KIND.touchFlag: {
        state.flagExists = true
        return { code: 0, stderr: "", stdout: "" }
      }
    }
  }

  // R-0000749: production code now emits the `--` separator before the
  // awk path argument.
  // R-0000803: awk now receives the marker as a single shell-quoted token.
  const markerAwkReadCommand = `awk 'NR==1{print $1}' -- '${FLAGS_DIRECTORY}/${flagName}.lock/holder'`

  const ssh: typeof base = {
    ...base,
    async exec(command, options) {
      base.calls.push(command)
      base.execCalls.push({ command, options })
      await Promise.resolve()
      return handleCommand(command, options)
    },
    // R-0000670: the acquire path now fails fast if the holder-marker
    // readback yields an empty token. Return the shared deterministic
    // token so the stale-lock recovery test keeps the lock acquired after
    // reclaim succeeded.
    async output(command) {
      base.calls.push(command)
      if (command === markerAwkReadCommand) return MOCK_FLAG_LOCK_HOLDER_TOKEN
      return base.output(command)
    },
    async test(command) {
      await Promise.resolve()
      base.calls.push(command)
      const isFlagTest = classifyLockCommand(command, flagName) === "flag-test"
      if (isFlagTest) return state.flagExists
      throw new Error(`unexpected stale flag lock test command: ${command}`)
    },
  }

  return { ssh, state }
}

describe("applyWithFlagLock – stale lock recovery", () => {
  it("stale lock mock rejects unexpected exec commands", async () => {
    const { ssh } = createStaleLockSsh("stale-lock-flag", "stale")

    await expect(ssh.exec("echo unexpected")).rejects.toThrow(
      "unexpected stale flag lock command: echo unexpected"
    )
  })

  it("returns the flag directory creation failure without entering the contention loop", async () => {
    const flagName = "lock-dir-failure"
    const ssh = createMockSsh({
      [`[ -f ${FLAGS_DIRECTORY}/'${flagName}' ]`]: { code: 1 },
      "mkdir -p /var/lib/paratix/flags": {
        code: 1,
        stderr: "mkdir: cannot create directory '/var/lib/paratix/flags': Permission denied\n",
      },
    })
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await Promise.resolve()
        return { status: "changed" }
      },
      flagName,
      waitSeconds: 1,
    })

    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining("failed to create /var/lib/paratix/flags"),
      }),
      status: "failed",
    })
    expect(applyCalls).toBe(0)
    expect(ssh.calls).not.toContain(`mkdir ${FLAGS_DIRECTORY}/'${flagName}.lock'`)
    expect(ssh.calls.some((call) => call.startsWith("i=0; while [ -d"))).toBe(false)
  })

  it("reclaims a stale lock after the wait window expires and reruns apply", async () => {
    const flagName = "stale-lock-flag"
    const { ssh, state } = createStaleLockSsh(flagName, "stale")
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await setFlag(ssh, flagName)
        return { status: "changed" }
      },
      flagName,
      staleSeconds: 60,
      waitSeconds: 1,
    })

    expect(result).toStrictEqual({ status: "changed" })
    expect(state.staleReclaimCalls).toBe(1)
    expect(applyCalls).toBe(1)
  })

  // R-0000671: the reclaim shell statement must capture the stale holder
  // token via `STALE_TOKEN="$(awk ...)"` before the `find -mmin` check and
  // re-compare it against the marker contents before running `rm/rmdir`.
  // Without that gate, a holder that became active again — or a fresh
  // acquirer racing through the same window — would have its marker
  // destroyed.
  it("R-0000671: stale-lock reclaim verifies the holder token before removing the marker", async () => {
    const flagName = "stale-lock-token-verified"
    const { ssh } = createStaleLockSsh(flagName, "stale")

    await applyWithFlagLock(ssh, {
      async apply() {
        await setFlag(ssh, flagName)
        return { status: "changed" }
      },
      flagName,
      staleSeconds: 60,
      waitSeconds: 1,
    })

    const lockPath = `${FLAGS_DIRECTORY}/'${flagName}.lock'`
    const markerPath = `${lockPath}/holder`
    // R-0000803: awk now receives the marker as a single shell-quoted token.
    const awkMarkerPath = `'${FLAGS_DIRECTORY}/${flagName}.lock/holder'`
    const reclaimCallCandidates = ssh.calls.filter((call) => call.startsWith("if [ -d "))
    const reclaimCall = reclaimCallCandidates.find((call) => call.includes(`STALE_TOKEN=`))
    expect(reclaimCall).toBeDefined()
    expect(reclaimCall).toContain(
      `STALE_TOKEN="$(awk 'NR==1{print $1}' -- ${awkMarkerPath} 2>/dev/null)"`
    )
    expect(reclaimCall).toContain(
      `[ "$(awk 'NR==1{print $1}' -- ${awkMarkerPath} 2>/dev/null)" = "$STALE_TOKEN" ] && rm -f -- ${markerPath} && rmdir -- ${lockPath}`
    )
  })

  it("returns failedCommand when the lock is held but not stale", async () => {
    const flagName = "fresh-lock-flag"
    const { ssh } = createStaleLockSsh(flagName, "fresh")
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await Promise.resolve()
        return { status: "changed" }
      },
      flagName,
      staleSeconds: 60,
      waitSeconds: 1,
    })

    expect(result.status).toBe("failed")
    expect(applyCalls).toBe(0)
  })

  it("writes a holder marker after acquiring the lock", async () => {
    const flagName = "marker-flag"
    const ssh = createSharedFlagMockSsh(flagName)

    await applyWithFlagLock(ssh, {
      async apply() {
        await setFlag(ssh, flagName)
        return { status: "changed" }
      },
      flagName,
    })

    const markerPathFragment = `${FLAGS_DIRECTORY}/'${flagName}.lock'/holder`
    const markerWrite = ssh.calls.find((call) => isHolderMarkerWrite(call, markerPathFragment))
    expect(markerWrite).toBeDefined()
  })
})

function isHolderMarkerWrite(call: string, markerPathFragment: string): boolean {
  return call.startsWith("printf ") && call.includes(markerPathFragment)
}

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

// R-0000634: the shared mutex mock fakes a holder marker so the verified
// release path can run end-to-end. The marker `awk` readback (via
// `ssh.output`) returns this token, and the combined release command (the
// single shell statement that performs the ownership check, marker removal
// and `rmdir`) is recognised against the same token.
const FAKE_HOLDER_TOKEN = "12345@mockhost"

function createSharedMutexMockSsh(lockName: string): ReturnType<typeof createMockSsh> {
  const base = createMockSsh(
    {},
    {
      allowUnstubbedDefaults: true,
      defaultExecResult: { code: 0 },
      defaultOutputResult: "",
      defaultTestResult: false,
    }
  )
  let lockExists = false
  const waiters: Array<() => void> = []

  function resolveWaiters(): void {
    for (const resolve of waiters.splice(0)) resolve()
  }

  // R-0000749: production code now emits the `--` separator before path
  // arguments in awk / rm / rmdir invocations.
  // R-0000758: release captures the awk readback in `$awk_token` and uses
  // the POSIX `x`-prefix comparison.
  const lockMkdirCommand = `mkdir ${FLAGS_DIRECTORY}/'${lockName}'`
  // R-0000803: awk now receives the marker as a single shell-quoted token.
  const awkMarkerPath = `'${FLAGS_DIRECTORY}/${lockName}/holder'`
  const markerAwkReadCommand = `awk 'NR==1{print $1}' -- ${awkMarkerPath}`
  const verifiedReleaseCommand =
    `awk_token=$(awk 'NR==1{print $1}' -- ${awkMarkerPath} 2>/dev/null); awk_status=$?; ` +
    `[ "$awk_status" = 0 ] && ` +
    `[ "x$awk_token" = 'x${FAKE_HOLDER_TOKEN}' ] && ` +
    `rm -f -- ${FLAGS_DIRECTORY}/'${lockName}'/holder && ` +
    `rmdir -- ${FLAGS_DIRECTORY}/'${lockName}'`

  return {
    ...base,
    async exec(command, options) {
      base.calls.push(command)
      base.execCalls.push({ command, options })
      if (command === lockMkdirCommand) {
        if (lockExists) return nonZeroLockExecResult(command, options)
        expectLockExecOptions(options)
        lockExists = true
        return { code: 0, stderr: "", stdout: "" }
      }
      if (command === verifiedReleaseCommand) {
        expectLockExecOptions(options)
        lockExists = false
        resolveWaiters()
        return { code: 0, stderr: "", stdout: "" }
      }
      if (command.startsWith("i=0; while [ -d")) {
        if (lockExists) {
          await new Promise<void>((resolve) => {
            waiters.push(resolve)
          })
        }
        expectLockExecOptions(options)
        return { code: 0, stderr: "", stdout: "" }
      }
      if (isFlagLockInternalSuccessCommand(command)) return { code: 0, stderr: "", stdout: "" }
      throw new Error(`unexpected shared mutex exec command: ${command}`)
    },
    // R-0000634: `writeFlagLockHolderMarker` calls `ssh.output` to read the
    // marker's `pid@hostname` token back after writing. Returning a
    // deterministic token here lets the subsequent verified-release
    // command match `verifiedReleaseCommand` above.
    async output(command) {
      base.calls.push(command)
      if (command === markerAwkReadCommand) {
        return FAKE_HOLDER_TOKEN
      }
      return base.output(command)
    },
  }
}

describe("withMutexLock", () => {
  it("shared mutex mock rejects unexpected exec commands", async () => {
    const ssh = createSharedMutexMockSsh("etc-hosts-mutex")

    await expect(ssh.exec("echo unexpected")).rejects.toThrow(
      "unexpected shared mutex exec command: echo unexpected"
    )
  })

  it("returns a structured failure when the flag directory cannot be created", async () => {
    // R-0000757: `withMutexLock` no longer throws on lock-acquire failures
    // — it returns `{ kind: "failed", failure }` carrying a typed
    // `failed` ModuleResult so callers can propagate it without try/catch.
    const lockName = "mutex-dir-failure"
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": {
        code: 1,
        stderr: "mkdir: cannot create directory '/var/lib/paratix/flags': Permission denied\n",
      },
    })
    let sectionCalls = 0

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] failed to acquire mutex",
      lockName,
      async section() {
        sectionCalls += 1
        await Promise.resolve()
      },
    })

    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message: expect.stringMatching(
            /\[test\] failed to acquire mutex: .*failed to create \/var\/lib\/paratix\/flags/v
          ),
        }),
        status: "failed",
      },
      kind: "failed",
    })
    expect(sectionCalls).toBe(0)
    expect(ssh.calls).not.toContain(`mkdir ${FLAGS_DIRECTORY}/'${lockName}'`)
    expect(ssh.calls.some((call) => call.startsWith("i=0; while [ -d"))).toBe(false)
  })

  it("acquires the lock, runs the section and releases the lock", async () => {
    const lockName = "etc-hosts-mutex"
    const ssh = createSharedMutexMockSsh(lockName)
    let sectionCalls = 0

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex section failed",
      lockName,
      async section() {
        await Promise.resolve()
        sectionCalls += 1
        return "value" as const
      },
    })

    expect(result).toStrictEqual({ kind: "ok", value: "value" })
    expect(sectionCalls).toBe(1)
    expect(ssh.calls).toContain(`mkdir ${FLAGS_DIRECTORY}/'${lockName}'`)
    // R-0000634: release is now a single shell statement that runs the
    // ownership check, marker removal and `rmdir` atomically.
    expect(ssh.calls.some((call) => isVerifiedReleaseCall(call, lockName))).toBe(true)
  })

  it("converts a section throw into a structured failure and still releases the lock", async () => {
    // R-0000757: by default, section throws are captured and surfaced as a
    // typed `failed` ModuleResult so callers can drop their try/catch
    // wrappers. The lock release still runs in the `finally` path.
    const lockName = "etc-hosts-mutex"
    const ssh = createSharedMutexMockSsh(lockName)

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex section failed",
      lockName,
      async section() {
        await Promise.resolve()
        throw new Error("boom")
      },
    })

    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message: "[test] mutex section failed: boom",
        }),
        status: "failed",
      },
      kind: "failed",
    })
    // R-0000634: release is now a single shell statement that runs the
    // ownership check, marker removal and `rmdir` atomically.
    expect(ssh.calls.some((call) => isVerifiedReleaseCall(call, lockName))).toBe(true)
  })

  it("rethrows section errors when propagateSectionThrows is set, after releasing the lock", async () => {
    // R-0000757: callers that own reconnect/recovery (e.g. `sshd.port`) can
    // opt into the legacy propagation semantics so the upstream apply path
    // keeps seeing the underlying transport error verbatim.
    const lockName = "etc-hosts-mutex"
    const ssh = createSharedMutexMockSsh(lockName)
    const error = new Error("transport boom")

    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] should not be used",
        lockName,
        propagateSectionThrows: true,
        async section() {
          await Promise.resolve()
          throw error
        },
      })
    ).rejects.toBe(error)

    expect(ssh.calls.some((call) => isVerifiedReleaseCall(call, lockName))).toBe(true)
  })

  it("serialises two parallel callers competing for the same mutex", async () => {
    const lockName = "etc-fstab-mutex"
    const ssh = createSharedMutexMockSsh(lockName)
    const firstStarted = deferred()
    const finishFirst = deferred()
    const ordering: string[] = []

    const first = withMutexLock(ssh, {
      failureMessage: "[test] mutex section failed",
      lockName,
      async section() {
        ordering.push("first-enter")
        firstStarted.resolve()
        await finishFirst.promise
        ordering.push("first-leave")
        return 1
      },
    })

    await firstStarted.promise

    const second = withMutexLock(ssh, {
      failureMessage: "[test] mutex section failed",
      lockName,
      async section() {
        ordering.push("second-enter")
        await Promise.resolve()
        ordering.push("second-leave")
        return 2
      },
    })

    finishFirst.resolve()
    const results = await Promise.all([first, second])

    expect(results).toStrictEqual([
      { kind: "ok", value: 1 },
      { kind: "ok", value: 2 },
    ])
    expect(ordering).toStrictEqual(["first-enter", "first-leave", "second-enter", "second-leave"])
  })

  it("rejects an invalid lockName", async () => {
    // Validation errors are programmer mistakes and stay as synchronous
    // throws — only runtime failures (acquire/wait/section-throw) are
    // converted into the structured `MutexLockResult` shape.
    const ssh = createMockSsh()
    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex section failed",
        lockName: "bad lock",
        async section() {
          await Promise.resolve()
          return null
        },
      })
    ).rejects.toThrow(/lockName must match/v)
  })
})

// R-0000273: setFlag, setVersionedFlag and ensureFlagsDirectory must surface
// EROFS/EPERM/ENOSPC failures as a typed `ModuleResult` instead of throwing.
// Apply paths invoke these helpers AFTER convergence already happened, so a
// roh throw would mask the successful state change behind an uncaught
// exception.
describe("setFlag – persist failures surface as ModuleResult", () => {
  it("returns a failed ModuleResult when touch fails with ENOSPC", async () => {
    const flagName = "persist-failure"
    const ssh = createMockSsh({
      [`touch /var/lib/paratix/flags/'${flagName}'`]: {
        code: 1,
        stderr:
          "touch: cannot touch '/var/lib/paratix/flags/persist-failure': No space left on device\n",
      },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const result = await setFlag(ssh, flagName)
    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining("failed to persist flag"),
      }),
      status: "failed",
    })
  })

  it("returns a failed ModuleResult when mkdir -p fails with EROFS", async () => {
    const flagName = "persist-failure-rofs"
    const ssh = createMockSsh({
      "mkdir -p /var/lib/paratix/flags": {
        code: 1,
        stderr: "mkdir: cannot create directory '/var/lib/paratix/flags': Read-only file system\n",
      },
    })
    const result = await setFlag(ssh, flagName)
    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining("failed to create /var/lib/paratix/flags"),
      }),
      status: "failed",
    })
  })

  it("returns null when touch succeeds", async () => {
    const flagName = "persist-success"
    const ssh = createMockSsh({
      [`touch /var/lib/paratix/flags/'${flagName}'`]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const result = await setFlag(ssh, flagName)
    expect(result).toBeNull()
  })
})

describe("setVersionedFlag – persist failures surface as ModuleResult", () => {
  it("returns a failed ModuleResult when find/touch fails with EPERM", async () => {
    const flagName = "versioned-flag-1.0"
    const flagPrefix = "versioned-flag-"
    const findCommand = `find /var/lib/paratix/flags -maxdepth 1 -type f -name '${flagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${flagName}'`
    const ssh = createMockSsh({
      [findCommand]: {
        code: 1,
        stderr:
          "touch: cannot touch '/var/lib/paratix/flags/versioned-flag-1.0': Permission denied\n",
      },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const result = await setVersionedFlag(ssh, flagName, flagPrefix)
    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining("failed to persist versioned flag versioned-flag-1.0"),
      }),
      status: "failed",
    })
  })

  it("returns null when find/touch succeeds", async () => {
    const flagName = "versioned-flag-2.0"
    const flagPrefix = "versioned-flag-"
    const findCommand = `find /var/lib/paratix/flags -maxdepth 1 -type f -name '${flagPrefix}*' ! -name '*.lock' -delete && touch /var/lib/paratix/flags/'${flagName}'`
    const ssh = createMockSsh({
      [findCommand]: { code: 0 },
      "mkdir -p /var/lib/paratix/flags": { code: 0 },
    })
    const result = await setVersionedFlag(ssh, flagName, flagPrefix)
    expect(result).toBeNull()
  })
})

// R-0000670: when the holder marker write fails (printf non-zero) or the
// readback yields an empty token, acquireFlagLock now removes the lock
// directory immediately and surfaces a structured failure. Without this,
// the caller would enter the critical section with an unverifiable empty
// holder token and the lock would sit untouched until the four-hour stale
// threshold expired.
describe("acquireFlagLock – holder marker write failures (R-0000670)", () => {
  function buildHolderMarkerFailureSsh(
    lockDirectoryName: string,
    printfBehaviour: "fail" | "succeed-but-empty-readback"
  ): ReturnType<typeof createMockSsh> {
    const lockPath = `${FLAGS_DIRECTORY}/'${lockDirectoryName}'`
    const markerPath = `${lockPath}/holder`
    const printfFailureStderr = "printf: write error: No space left on device\n"
    // R-0000749: production code now emits `rm -f --` / `rmdir --` so path
    // arguments are never mis-parsed as options.
    const mkdirCommand = `mkdir ${lockPath}`
    const rmdirCommand = `rmdir -- ${lockPath}`
    const rmMarkerCommand = `rm -f -- ${markerPath}`
    const printfPattern = /^printf '%s@%s %s\\n' "\$\$" [^"]+ "\$\(date \+%s\)" > \S+\/holder$/v
    return createMockSsh(
      {},
      {
        allowUnstubbedDefaults: true,
        defaultExecResult: { code: 0 },
        defaultOutputResult: "",
        defaultTestResult: false,
        responseStubs: [
          { command: "mkdir -p /var/lib/paratix/flags", result: { code: 0 } },
          { command: mkdirCommand, result: { code: 0 } },
          {
            command: printfPattern,
            result:
              printfBehaviour === "fail"
                ? { code: 1, stderr: printfFailureStderr, stdout: "" }
                : { code: 0, stderr: "", stdout: "" },
          },
          { command: rmMarkerCommand, result: { code: 0 } },
          { command: rmdirCommand, result: { code: 0 } },
        ],
      }
    )
  }

  it("returns a failed ModuleResult and removes the lock when printf fails", async () => {
    const flagName = "marker-write-failure"
    const lockDirectoryName = `${flagName}.lock`
    const ssh = buildHolderMarkerFailureSsh(lockDirectoryName, "fail")
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await Promise.resolve()
        return { status: "changed" }
      },
      flagName,
    })

    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining(
          `failed to write flag lock holder marker for ${lockDirectoryName}`
        ),
      }),
      status: "failed",
    })
    expect(applyCalls).toBe(0)
    expect(ssh.calls).toContain(`rmdir -- ${FLAGS_DIRECTORY}/'${lockDirectoryName}'`)
  })

  it("returns a failed ModuleResult and removes the lock when readback is empty", async () => {
    const flagName = "marker-readback-empty"
    const lockDirectoryName = `${flagName}.lock`
    // defaultOutputResult is "" so the holder-readback returns an empty
    // token even though printf reported success.
    const ssh = buildHolderMarkerFailureSsh(lockDirectoryName, "succeed-but-empty-readback")
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await Promise.resolve()
        return { status: "changed" }
      },
      flagName,
    })

    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining(
          `flag lock holder marker for ${lockDirectoryName} is empty after write`
        ),
      }),
      status: "failed",
    })
    expect(applyCalls).toBe(0)
    expect(ssh.calls).toContain(`rm -f -- ${FLAGS_DIRECTORY}/'${lockDirectoryName}'/holder`)
    expect(ssh.calls).toContain(`rmdir -- ${FLAGS_DIRECTORY}/'${lockDirectoryName}'`)
  })

  it("withMutexLock surfaces the marker-write failure instead of running the section", async () => {
    // R-0000757: lock-acquire failures (holder-marker write rejection) now
    // surface as `{ kind: "failed", failure }` rather than a thrown error.
    const lockName = "marker-write-failure-mutex"
    // withMutexLock uses `lockName` directly as the lock directory name
    // (no `.lock` suffix), so the helper must be wired with the bare name.
    const ssh = buildHolderMarkerFailureSsh(lockName, "fail")
    let sectionCalls = 0

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex acquire failed",
      lockName,
      async section() {
        sectionCalls += 1
        await Promise.resolve()
      },
    })

    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message: expect.stringMatching(/failed to write flag lock holder marker/v),
        }),
        status: "failed",
      },
      kind: "failed",
    })
    expect(sectionCalls).toBe(0)
    expect(ssh.calls).toContain(`rmdir -- ${FLAGS_DIRECTORY}/'${lockName}'`)
  })
})
