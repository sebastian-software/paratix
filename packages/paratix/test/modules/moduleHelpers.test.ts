import { describe, expect, it, onTestFinished, vi } from "vitest"

import type { ExecOptions, ExecResult } from "../../src/types.js"

import { describeFlagLockHolder, flagLockRefreshGuard } from "../../src/modules/flagLockRefresh.js"
import { flagLockAgeThreshold } from "../../src/modules/flagLockScripts.js"
import {
  applyWithFlagLock,
  FLAG_LOCK_STALE_SECONDS,
  FLAGS_DIRECTORY,
  hasFlag,
  type MutexLockWaitFailureContext,
  setFlag,
  setVersionedFlag,
  withMutexLock,
} from "../../src/modules/moduleHelpers.js"
import { createMockSsh as createBaseMockSsh } from "../helpers/mockSsh.js"
import {
  isFlagLockInternalSuccessCommand,
  isFlagLockReclaimProbe,
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

/**
 * R-0000840 helper for the flag-lock mocks below. Returns the canonical
 * mock response for the holder-marker readback (now routed through
 * ssh.exec instead of ssh.output) and the bulk of the
 * mutex-bookkeeping commands; returns `undefined` when the command is
 * not a known internal flag-lock call, so callers can fall through to
 * their own dispatch.
 *
 * Extracted because inlining both branches into each mock pushed the
 * surrounding `exec` past the project-wide ESLint complexity limit
 * (R-0000840 added an extra branch on top of the historical
 * `isFlagLockInternalSuccessCommand` check).
 *
 * @param command - The shell command intercepted by the mock.
 * @param markerAwkReadCommand - The exact awk readback string the mock
 *   should treat as a holder-marker probe.
 * @returns A canned `ExecResult` for known flag-lock internal commands,
 *   or `undefined` when the caller should keep dispatching.
 */
function handleFlagLockInternalCommand(
  command: string,
  markerAwkReadCommand: string
): { code: number; stderr: string; stdout: string } | undefined {
  if (command === markerAwkReadCommand) {
    return { code: 0, stderr: "", stdout: MOCK_FLAG_LOCK_HOLDER_TOKEN }
  }
  if (isFlagLockInternalSuccessCommand(command)) {
    return { code: 0, stderr: "", stdout: "" }
  }
  // Issue #224: a contended acquirer tries one stale reclaim before its first
  // poll. The lock these shared mocks hold is always fresh, so it refuses.
  if (isFlagLockReclaimProbe(command)) return { code: 1, stderr: "", stdout: "" }
  return undefined
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
    `awk_token=$(awk 'NR==1{print $1}' ${awkMarkerPath} 2>/dev/null); awk_status=$?; ` +
    `[ "$awk_status" = 0 ] && ` +
    `[ "x$awk_token" = 'x${MOCK_FLAG_LOCK_HOLDER_TOKEN}' ] && ` +
    `rm -f -- ${markerPath} && ` +
    `rmdir -- ${lockPath}`
  const markerAwkReadCommand = `awk 'NR==1{print $1}' ${awkMarkerPath}`

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
      // R-0000840 + R-0000634 internal-default handler — see helper above.
      const internal = handleFlagLockInternalCommand(command, markerAwkReadCommand)
      if (internal) return internal
      throw new Error(`unexpected shared flag lock exec command: ${command}`)
    },
    // R-0000634: kept for callers that exercise the helper through
    // ssh.output directly (the production path moved to ssh.exec under
    // R-0000840).
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
  const markerAwkReadCommand = `awk 'NR==1{print $1}' '${FLAGS_DIRECTORY}/${flagName}.lock/holder'`

  const ssh: typeof base = {
    ...base,
    async exec(command, options) {
      base.calls.push(command)
      base.execCalls.push({ command, options })
      await Promise.resolve()
      // R-0000840: the production code now reads the holder marker via
      // ssh.exec (was ssh.output) so the readback's exit code can be
      // inspected. Intercept the readback at the exec layer with the
      // shared deterministic token so the acquire proceeds and the
      // stale-lock recovery test keeps the lock acquired after reclaim.
      if (command === markerAwkReadCommand) {
        return { code: 0, stderr: "", stdout: MOCK_FLAG_LOCK_HOLDER_TOKEN }
      }
      return handleCommand(command, options)
    },
    // R-0000670: kept for callers that exercise the helper through
    // ssh.output directly (the production path moved to ssh.exec under
    // R-0000840).
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

  it("reclaims a stale lock before the first poll and reruns apply", async () => {
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
    // Issue #224: the first contended result tries the reclaim right away, so
    // no poll round is spent on a lock that is already stale.
    expect(ssh.calls.some((call) => call.startsWith("i=0; while [ -d"))).toBe(false)
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
      `STALE_TOKEN="$(awk 'NR==1{print $1}' ${awkMarkerPath} 2>/dev/null)"`
    )
    expect(reclaimCall).toContain(
      `[ "$(awk 'NR==1{print $1}' ${awkMarkerPath} 2>/dev/null)" = "$STALE_TOKEN" ] && rm -f -- ${markerPath} && rmdir -- ${lockPath}`
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
  const markerAwkReadCommand = `awk 'NR==1{print $1}' ${awkMarkerPath}`
  const verifiedReleaseCommand =
    `awk_token=$(awk 'NR==1{print $1}' ${awkMarkerPath} 2>/dev/null); awk_status=$?; ` +
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
      // R-0000840: writeFlagLockHolderMarker now reads the marker via
      // ssh.exec (was ssh.output) so the readback's exit code is
      // observable. Return the deterministic token so the subsequent
      // verified-release command can match `verifiedReleaseCommand`.
      if (command === markerAwkReadCommand) {
        return { code: 0, stderr: "", stdout: FAKE_HOLDER_TOKEN }
      }
      const internal = handleFlagLockInternalCommand(command, markerAwkReadCommand)
      if (internal) return internal
      throw new Error(`unexpected shared mutex exec command: ${command}`)
    },
    // R-0000634: kept for callers that still issue the awk readback via
    // ssh.output. The production code path (writeFlagLockHolderMarker)
    // routes through ssh.exec post-R-0000840; this handler protects mocks
    // that exercise the helper in isolation.
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
    // defaultExecResult is { code: 0 } with empty stdout so the holder
    // readback (R-0000840: now an `ssh.exec`) returns an empty token even
    // though printf reported success.
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
          `flag lock holder marker for ${lockDirectoryName} is readable but empty`
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

// Issue #224: scripted mutex mock for the bounded wait, the lock handle and
// the heartbeat. Every lock command is dispatched to a test-controlled
// handler; anything unexpected throws so the strict call shape stays visible.
type ScriptedMutexHandlers = {
  diagnostics?: () => string
  mkdir: () => boolean
  poll: (seconds: number) => boolean
  readbackToken?: string
  reclaim: () => boolean
  refresh?: () => number | Promise<number>
}

type ScriptedMutexSsh = ReturnType<typeof createMockSsh> & {
  pollSeconds: number[]
  reclaimCalls: () => number
}

const POLL_SECONDS_PATTERN = /-lt (?<seconds>\d+) \]/v

function parsePollSeconds(command: string): number {
  return Number(POLL_SECONDS_PATTERN.exec(command)?.groups?.seconds ?? Number.NaN)
}

function scriptedMutexResult(code: number, stdout = ""): ExecResult {
  return { code, stderr: "", stdout }
}

function createScriptedMutexSsh(
  lockName: string,
  handlers: ScriptedMutexHandlers
): ScriptedMutexSsh {
  const base = createMockSsh(
    {},
    {
      allowUnstubbedDefaults: true,
      defaultExecResult: { code: 0 },
      defaultOutputResult: "",
      defaultTestResult: false,
    }
  )
  const pollSeconds: number[] = []
  let reclaims = 0
  const prefixHandlers: Array<{
    handle: (command: string) => ExecResult | Promise<ExecResult>
    matches: (command: string) => boolean
  }> = [
    {
      handle(command) {
        const seconds = parsePollSeconds(command)
        pollSeconds.push(seconds)
        return scriptedMutexResult(handlers.poll(seconds) ? 0 : 1)
      },
      matches: (command) => command.startsWith("i=0; while [ -d"),
    },
    {
      handle() {
        reclaims += 1
        return scriptedMutexResult(handlers.reclaim() ? 0 : 1)
      },
      matches: (command) => command.startsWith("if [ -d ") && command.includes("-mmin"),
    },
    {
      async handle() {
        const refresh = handlers.refresh ?? (() => 0)
        return scriptedMutexResult(await refresh())
      },
      matches: (command) => isGuardCall(command) && handlers.refresh !== undefined,
    },
    {
      handle: () => scriptedMutexResult(0, handlers.diagnostics?.() ?? ""),
      matches: (command) => command.startsWith("if [ ! -d ") && handlers.diagnostics !== undefined,
    },
    {
      handle: () => scriptedMutexResult(0),
      matches: (command) => command.startsWith("awk_token="),
    },
  ]
  const lockMkdirCommand = `mkdir ${FLAGS_DIRECTORY}/'${lockName}'`
  const markerAwkReadCommand = `awk 'NR==1{print $1}' '${FLAGS_DIRECTORY}/${lockName}/holder'`
  const markerWritePrefix = "printf '%s"
  const exactResults = new Map<string, () => ExecResult>([
    ["mkdir -p /var/lib/paratix/flags", () => scriptedMutexResult(0)],
    [`rm -f -- ${FLAGS_DIRECTORY}/'${lockName}'/holder`, () => scriptedMutexResult(0)],
    [`rmdir -- ${FLAGS_DIRECTORY}/'${lockName}'`, () => scriptedMutexResult(0)],
    [lockMkdirCommand, () => scriptedMutexResult(handlers.mkdir() ? 0 : 1)],
    [
      markerAwkReadCommand,
      () => scriptedMutexResult(0, handlers.readbackToken ?? MOCK_FLAG_LOCK_HOLDER_TOKEN),
    ],
  ])
  return {
    ...base,
    async exec(command, options) {
      await Promise.resolve()
      base.calls.push(command)
      base.execCalls.push({ command, options })
      const exact = exactResults.get(command)
      if (exact) return exact()
      if (command.startsWith(markerWritePrefix)) return scriptedMutexResult(0)
      const prefixed = prefixHandlers.find((handler) => handler.matches(command))
      if (prefixed) return prefixed.handle(command)
      throw new Error(`unexpected scripted mutex exec command: ${command}`)
    },
    pollSeconds,
    reclaimCalls: () => reclaims,
  }
}

function sequence<TValue>(values: TValue[], fallback: TValue): () => TValue {
  let index = 0
  return () => {
    const value = values[index] ?? fallback
    index += 1
    return value
  }
}

/**
 * Issue #224: a refresh handler that calls `onReached` on its `count`-th call.
 *
 * @param count - The call that triggers `onReached`.
 * @param onReached - Called once on the `count`-th call.
 * @param code - The exit code every call returns.
 * @returns The refresh handler and its call counter.
 */
function countingRefresh(
  count: number,
  onReached: () => void,
  code: number
): { calls: () => number; refresh: () => number } {
  let calls = 0
  return {
    calls: () => calls,
    refresh() {
      calls += 1
      if (calls === count) onReached()
      return code
    },
  }
}

function isGuardCall(call: string): boolean {
  return call.startsWith("{ [ -d ")
}

function sum(values: number[]): number {
  return values.reduce((total, value) => total + value, 0)
}

const FLAG_LOCK_EXEC_TIMEOUT_SECONDS = 120
const FLAG_LOCK_WAIT_SECONDS_DEFAULT = 300

describe("withMutexLock – bounded wait (issue #224)", () => {
  it("scripted mutex mock rejects unexpected exec commands", async () => {
    const ssh = createScriptedMutexSsh("bounded-mutex", {
      mkdir: () => true,
      poll: () => true,
      reclaim: () => false,
    })

    await expect(ssh.exec("echo unexpected")).rejects.toThrow(
      "unexpected scripted mutex exec command: echo unexpected"
    )
  })

  it("never runs a wait exec of 120 s or longer and fails structurally at the default deadline", async () => {
    const ssh = createScriptedMutexSsh("bounded-mutex", {
      mkdir: () => false,
      poll: () => false,
      reclaim: () => false,
    })
    let sectionCalls = 0

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex busy",
      lockName: "bounded-mutex",
      async section() {
        sectionCalls += 1
        await Promise.resolve()
      },
    })

    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message: "[test] mutex busy: timed out waiting for mutex lock bounded-mutex",
        }),
        status: "failed",
      },
      kind: "failed",
    })
    expect(sectionCalls).toBe(0)
    expect(ssh.pollSeconds).toStrictEqual([60, 60, 60, 60, 60])
    expect(Math.max(...ssh.pollSeconds)).toBeLessThan(FLAG_LOCK_EXEC_TIMEOUT_SECONDS)
    expect(sum(ssh.pollSeconds)).toBe(FLAG_LOCK_WAIT_SECONDS_DEFAULT)
    // One stale-reclaim attempt before the first poll, then one after every
    // still-held round.
    expect(ssh.reclaimCalls()).toBe(6)
  })

  it("reclaims an already stale lock before the first poll", async () => {
    const ssh = createScriptedMutexSsh("bounded-mutex", {
      mkdir: sequence([false], true),
      poll: () => false,
      reclaim: () => true,
    })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex busy",
      lockName: "bounded-mutex",
      async section() {
        await Promise.resolve()
        return "entered"
      },
    })

    expect(result).toStrictEqual({ kind: "ok", value: "entered" })
    // No poll round was spent on a lock that was already reclaimable.
    expect(ssh.pollSeconds).toStrictEqual([])
    expect(ssh.reclaimCalls()).toBe(1)
  })

  it("reclaims a stale lock in a later round and then runs the section", async () => {
    const ssh = createScriptedMutexSsh("bounded-mutex", {
      mkdir: sequence([false], true),
      poll: () => false,
      // Before the first poll, after round 1, after round 2.
      reclaim: sequence([false, false], true),
    })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex busy",
      lockName: "bounded-mutex",
      async section() {
        await Promise.resolve()
        return "entered"
      },
    })

    expect(result).toStrictEqual({ kind: "ok", value: "entered" })
    expect(ssh.pollSeconds).toStrictEqual([60, 60])
    expect(ssh.reclaimCalls()).toBe(3)
  })

  it("retries a lost re-acquire race within the same deadline", async () => {
    const ssh = createScriptedMutexSsh("bounded-mutex", {
      mkdir: sequence([false, false, false], true),
      poll: () => true,
      reclaim: () => false,
    })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex busy",
      lockName: "bounded-mutex",
      async section() {
        await Promise.resolve()
        return 1
      },
      waitSeconds: 10,
    })

    expect(result).toStrictEqual({ kind: "ok", value: 1 })
    // Each lost race charges the shared budget instead of restarting it.
    expect(ssh.pollSeconds).toStrictEqual([10, 9, 8])
    // Only the first contended result tries a reclaim before polling; the
    // released rounds after it need none.
    expect(ssh.reclaimCalls()).toBe(1)
  })

  it("does not restart the full wait after repeatedly losing the re-acquire race", async () => {
    const ssh = createScriptedMutexSsh("bounded-mutex", {
      mkdir: () => false,
      poll: () => true,
      reclaim: () => false,
    })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex busy",
      lockName: "bounded-mutex",
      async section() {
        await Promise.resolve()
      },
      waitSeconds: 5,
    })

    expect(result.kind).toBe("failed")
    expect(ssh.pollSeconds).toStrictEqual([5, 4, 3, 2, 1])
  })

  it("builds a custom wait-failure message from the holder diagnostics", async () => {
    const lockName = "bounded-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      diagnostics: () => "paratix-lock marker 1000 880\nhost=controller pid=42\nentry=run-abc\n",
      mkdir: () => false,
      poll: () => false,
      reclaim: () => false,
    })
    const contexts: MutexLockWaitFailureContext[] = []

    const result = await withMutexLock(ssh, {
      describeWaitFailure(context) {
        contexts.push(context)
        return describeFlagLockHolder(context)
      },
      failureMessage: "[test] destination busy",
      lockName,
      async section() {
        await Promise.resolve()
      },
      staleSeconds: 600,
      waitSeconds: 60,
    })

    expect(contexts).toStrictEqual([
      {
        diagnostics: {
          ageSeconds: 120,
          kind: "held",
          markerPresent: true,
          ownerLines: ["host=controller pid=42", "entry=run-abc"],
        },
        lockName,
        lockPath: `/var/lib/paratix/flags/${lockName}`,
        staleThreshold: { effectiveAgeSeconds: 540, mminMinutes: 9 },
        waitSeconds: 60,
      },
    ])
    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message:
            "[test] destination busy: lock /var/lib/paratix/flags/bounded-mutex is held " +
            "(owner: host=controller pid=42; entry=run-abc), marker age 120 s, " +
            "reclaimable once older than 540 s (in about 421 s)",
        }),
      },
      kind: "failed",
    })
  })
})

describe("applyWithFlagLock – bounded wait (issue #224)", () => {
  it("polls in rounds of at most 60 s with a reclaim before the first poll and per round and fails at the default deadline", async () => {
    const flagName = "bounded-flag"
    const { ssh, state } = createStaleLockSsh(flagName, "fresh")
    let applyCalls = 0

    const result = await applyWithFlagLock(ssh, {
      async apply() {
        applyCalls += 1
        await Promise.resolve()
        return { status: "changed" }
      },
      flagName,
      staleSeconds: 60,
    })

    const waitCalls = ssh.calls.filter((call) => call.startsWith("i=0; while [ -d"))
    expect(result).toMatchObject({
      error: expect.objectContaining({
        message: expect.stringContaining(`timed out waiting for flag lock ${flagName}.lock`),
      }),
      status: "failed",
    })
    expect(applyCalls).toBe(0)
    expect(waitCalls.map((call) => parsePollSeconds(call))).toStrictEqual([60, 60, 60, 60, 60])
    // One reclaim before the first poll, then one per still-held round.
    expect(state.staleReclaimCalls).toBe(6)
  })
})

const CUSTOM_HOLDER_TOKEN = "0123456789abcdef0123456789abcdef"

describe("describeFlagLockHolder (issue #224)", () => {
  it("says that an absent lock was released only after the wait ran out", () => {
    expect(
      describeFlagLockHolder({
        diagnostics: { kind: "absent" },
        lockName: "bounded-mutex",
        staleThreshold: flagLockAgeThreshold(600),
      })
    ).toBe("lock /var/lib/paratix/flags/bounded-mutex was released only after the wait ran out")
  })
})

describe("withMutexLock – caller-supplied holder and lock handle (issue #224)", () => {
  it("writes the token as marker line 1 followed by the owner lines", async () => {
    const lockName = "holder-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      readbackToken: CUSTOM_HOLDER_TOKEN,
      reclaim: () => false,
    })
    const tokens: string[] = []

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      holder: {
        ownerLines: ["host=controller pid=42", "started=2026-10-01T20:17:26Z"],
        token: CUSTOM_HOLDER_TOKEN,
      },
      lockName,
      async section(handle) {
        await Promise.resolve()
        tokens.push(handle.token)
        return handle.lockPath
      },
    })

    expect(result).toStrictEqual({ kind: "ok", value: `/var/lib/paratix/flags/${lockName}` })
    expect(tokens).toStrictEqual([CUSTOM_HOLDER_TOKEN])
    expect(ssh.calls).toContain(
      `printf '%s\\n' '${CUSTOM_HOLDER_TOKEN}' 'host=controller pid=42' 'started=2026-10-01T20:17:26Z' > ${FLAGS_DIRECTORY}/'${lockName}'/holder`
    )
    // No hostname lookup is needed for a caller-supplied holder.
    expect(ssh.calls).not.toContain("hostname")
    expect(ssh.calls).toContain(
      `awk_token=$(awk 'NR==1{print $1}' '${FLAGS_DIRECTORY}/${lockName}/holder' 2>/dev/null); awk_status=$?; ` +
        `[ "$awk_status" = 0 ] && [ "x$awk_token" = 'x${CUSTOM_HOLDER_TOKEN}' ] && ` +
        `rm -f -- ${FLAGS_DIRECTORY}/'${lockName}'/holder && rmdir -- ${FLAGS_DIRECTORY}/'${lockName}'`
    )
  })

  it("fails without running the section when the readback does not carry the supplied token", async () => {
    const lockName = "holder-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      readbackToken: "someone-else-token",
      reclaim: () => false,
    })
    let sectionCalls = 0

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      holder: { token: CUSTOM_HOLDER_TOKEN },
      lockName,
      async section() {
        sectionCalls += 1
        await Promise.resolve()
      },
    })

    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message: expect.stringContaining("does not carry the supplied token"),
        }),
      },
      kind: "failed",
    })
    expect(sectionCalls).toBe(0)
    // The marker carries another holder's token, so neither the marker nor
    // the lock directory is touched: removing them would evict that holder.
    expect(ssh.calls).not.toContain(`rm -f -- ${FLAGS_DIRECTORY}/'${lockName}'/holder`)
    expect(ssh.calls).not.toContain(`rmdir -- ${FLAGS_DIRECTORY}/'${lockName}'`)
    expect(ssh.calls.some((call) => isVerifiedReleaseCall(call, lockName))).toBe(false)
  })

  it("removes the lock eagerly when the readback for a supplied token is empty", async () => {
    const lockName = "holder-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      readbackToken: "",
      reclaim: () => false,
    })
    let sectionCalls = 0

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      holder: { token: CUSTOM_HOLDER_TOKEN },
      lockName,
      async section() {
        sectionCalls += 1
        await Promise.resolve()
      },
    })

    expect(result).toMatchObject({
      failure: {
        error: expect.objectContaining({
          message: `[test] mutex: [moduleHelpers] flag lock holder marker for ${lockName} is readable but empty`,
        }),
      },
      kind: "failed",
    })
    expect(sectionCalls).toBe(0)
    // An unverifiable marker is still cleaned up so the next acquirer is not blocked.
    expect(ssh.calls).toContain(`rm -f -- ${FLAGS_DIRECTORY}/'${lockName}'/holder`)
    expect(ssh.calls).toContain(`rmdir -- ${FLAGS_DIRECTORY}/'${lockName}'`)
  })

  it.each([
    ["a token with a space", { token: "abc def ghijkl" }],
    ["a token with a quote", { token: "abcdefgh'ij" }],
    ["a too short token", { token: "abc" }],
    ["an owner line with a newline", { ownerLines: ["a\nb"], token: CUSTOM_HOLDER_TOKEN }],
    ["an owner line with a quote", { ownerLines: ["it's"], token: CUSTOM_HOLDER_TOKEN }],
    ["an owner line with $", { ownerLines: ["$(id)"], token: CUSTOM_HOLDER_TOKEN }],
  ])("rejects %s before any remote command", async (_label, holder) => {
    const ssh = createMockSsh()

    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        holder,
        lockName: "holder-mutex",
        async section() {
          await Promise.resolve()
        },
      })
    ).rejects.toThrow(/flag lock (?:holder token|owner line)/v)
    expect(ssh.calls).toStrictEqual([])
  })

  it("refreshes through the guard exec and latches the handle as lost on refusal", async () => {
    const lockName = "holder-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      readbackToken: CUSTOM_HOLDER_TOKEN,
      reclaim: () => false,
      refresh: sequence([0, 1, 0], 0),
    })
    const observed: unknown[] = []

    await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      holder: { token: CUSTOM_HOLDER_TOKEN },
      lockName,
      refreshGuardSeconds: 360,
      async section(handle) {
        observed.push(await handle.refresh(), handle.isLost(), handle.lostReason())
        observed.push(await handle.refresh(), handle.isLost(), handle.lostReason())
        observed.push(await handle.refresh(), handle.isLost(), handle.lostReason())
        return null
      },
      staleSeconds: 600,
    })

    const guardCalls = ssh.calls.filter((call) => call.startsWith("{ [ -d "))
    expect(observed).toStrictEqual([
      true,
      false,
      undefined,
      false,
      true,
      { kind: "refused" },
      false,
      true,
      { kind: "refused" },
    ])
    // The latched handle does not contact the host again.
    expect(guardCalls).toStrictEqual([
      flagLockRefreshGuard({ guardSeconds: 360, lockName, token: CUSTOM_HOLDER_TOKEN }),
      flagLockRefreshGuard({ guardSeconds: 360, lockName, token: CUSTOM_HOLDER_TOKEN }),
    ])
    expect(guardCalls[0]).toContain("! -mmin +5 ")
  })

  it("latches the handle as lost when the refresh exec throws", async () => {
    const lockName = "holder-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      reclaim: () => false,
      refresh() {
        throw new Error("channel closed")
      },
    })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      lockName,
      async section(handle) {
        return [await handle.refresh(), handle.isLost(), handle.lostReason()]
      },
    })

    // The reason keeps the error apart from a refusal: the lock may still be held.
    expect(result).toStrictEqual({
      kind: "ok",
      value: [false, true, { kind: "error", message: "channel closed" }],
    })
  })

  it("uses the stale threshold as the default guard threshold", async () => {
    const lockName = "holder-mutex"
    const ssh = createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      reclaim: () => false,
      refresh: () => 0,
    })

    await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      lockName,
      async section(handle) {
        return handle.refresh()
      },
      staleSeconds: 600,
    })

    expect(ssh.calls.find((call) => call.startsWith("{ [ -d "))).toContain("! -mmin +9 ")
  })

  it("supports the opt-in internal defaults for the archive lock name and a custom holder", async () => {
    const lockName = "archive-extract-lock-0123456789abcdef"
    const ssh = createMockSsh({}, { allowFlagLockInternalDefaults: true })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      holder: { ownerLines: ["host=controller pid=42"], token: MOCK_FLAG_LOCK_HOLDER_TOKEN },
      lockName,
      async section(handle) {
        return handle.refresh()
      },
    })

    expect(result).toStrictEqual({ kind: "ok", value: true })
  })
})

/**
 * Issue #224: run the heartbeat timer on a fake clock for the current test,
 * so no assertion depends on real timing.
 */
function useFakeHeartbeatClock(): void {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] })
  onTestFinished(() => {
    vi.useRealTimers()
  })
}

describe("withMutexLock – heartbeat (issue #224)", () => {
  /** The heartbeat interval of these tests, on the fake clock. */
  const intervalMilliseconds = 1000
  /** How far past the section's end the clock runs to catch a late refresh. */
  const afterwardMilliseconds = 10 * intervalMilliseconds

  function heartbeatSsh(
    lockName: string,
    refresh: () => number | Promise<number>
  ): ReturnType<typeof createScriptedMutexSsh> {
    return createScriptedMutexSsh(lockName, {
      mkdir: () => true,
      poll: () => true,
      readbackToken: CUSTOM_HOLDER_TOKEN,
      reclaim: () => false,
      refresh,
    })
  }

  /**
   * Issue #224: advance the fake clock one heartbeat interval at a time until
   * `done` holds.
   *
   * @param done - The condition to reach.
   * @param remainingSteps - How many intervals may pass before giving up.
   */
  async function advanceUntil(done: () => boolean, remainingSteps = 100): Promise<void> {
    if (done()) return
    if (remainingSteps === 0) throw new Error("condition not reached on the fake clock")
    await vi.advanceTimersByTimeAsync(intervalMilliseconds)
    await advanceUntil(done, remainingSteps - 1)
  }

  /**
   * Issue #224: settle a pending lock run on the fake clock.
   *
   * @param pending - The `withMutexLock` call.
   * @returns How it settled.
   */
  async function settleOnFakeClock<TValue>(
    pending: Promise<TValue>
  ): Promise<PromiseSettledResult<TValue>> {
    let settled = false
    const outcome = Promise.allSettled([pending]).then(([result]) => {
      settled = true
      return result
    })
    await advanceUntil(() => settled)
    return outcome
  }

  it("refreshes periodically while the section runs and stops before the release", async () => {
    useFakeHeartbeatClock()
    const lockName = "heartbeat-mutex"
    const refreshedTwice = deferred()
    const counter = countingRefresh(2, refreshedTwice.resolve, 0)
    const ssh = heartbeatSsh(lockName, counter.refresh)

    const outcome = await settleOnFakeClock(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        heartbeat: { intervalMilliseconds },
        holder: { token: CUSTOM_HOLDER_TOKEN },
        lockName,
        async section(handle) {
          await refreshedTwice.promise
          return handle.isLost()
        },
      })
    )
    const callsAtReturn = ssh.calls.length
    await vi.advanceTimersByTimeAsync(afterwardMilliseconds)

    const releaseIndex = ssh.calls.findIndex((call) => call.startsWith("awk_token="))
    const lastGuardIndex = ssh.calls.findLastIndex((call) => isGuardCall(call))
    expect(outcome).toStrictEqual({ status: "fulfilled", value: { kind: "ok", value: false } })
    expect(counter.calls()).toBe(2)
    expect(lastGuardIndex).toBeLessThan(releaseIndex)
    // Many intervals after the release, no refresh ran any more.
    expect(ssh.calls).toHaveLength(callsAtReturn)
  })

  it("stops refreshing once a refresh failed and reports the lost lock to the section", async () => {
    useFakeHeartbeatClock()
    const lockName = "heartbeat-mutex"
    const refused = deferred()
    const finishSection = deferred()
    const ssh = heartbeatSsh(lockName, countingRefresh(1, refused.resolve, 1).refresh)

    const pending = withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      heartbeat: { intervalMilliseconds },
      holder: { token: CUSTOM_HOLDER_TOKEN },
      lockName,
      async section(handle) {
        await refused.promise
        await finishSection.promise
        return handle.isLost()
      },
    })
    let refusedSeen = false
    void refused.promise.then(() => {
      refusedSeen = true
    })
    await advanceUntil(() => refusedSeen)
    // The section keeps running for many more intervals after the refusal.
    await vi.advanceTimersByTimeAsync(afterwardMilliseconds)
    const guardCallsWhileRunning = ssh.calls.filter((call) => isGuardCall(call)).length
    finishSection.resolve()
    const outcome = await settleOnFakeClock(pending)

    expect(guardCallsWhileRunning).toBe(1)
    expect(outcome).toStrictEqual({ status: "fulfilled", value: { kind: "ok", value: true } })
    expect(ssh.calls.filter((call) => isGuardCall(call))).toHaveLength(1)
  })

  it("never starts a refresh once the section has returned", async () => {
    useFakeHeartbeatClock()
    const lockName = "heartbeat-mutex"
    const ssh = heartbeatSsh(lockName, () => 0)

    const outcome = await settleOnFakeClock(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        heartbeat: { intervalMilliseconds },
        holder: { token: CUSTOM_HOLDER_TOKEN },
        lockName,
        async section() {
          await Promise.resolve()
          return "done"
        },
      })
    )
    await vi.advanceTimersByTimeAsync(afterwardMilliseconds)

    expect(outcome).toStrictEqual({ status: "fulfilled", value: { kind: "ok", value: "done" } })
    expect(ssh.calls.filter((call) => isGuardCall(call))).toStrictEqual([])
    expect(ssh.calls.at(-1)).toMatch(/^awk_token=/v)
  })

  it("waits for an in-flight refresh before releasing the lock", async () => {
    useFakeHeartbeatClock()
    const lockName = "heartbeat-mutex"
    const refreshStarted = deferred()
    const finishRefresh = deferred()
    const ssh = heartbeatSsh(lockName, async () => {
      refreshStarted.resolve()
      await finishRefresh.promise
      return 0
    })

    const pending = withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      heartbeat: { intervalMilliseconds },
      holder: { token: CUSTOM_HOLDER_TOKEN },
      lockName,
      async section() {
        await refreshStarted.promise
        return "done"
      },
    })
    let refreshSeen = false
    void refreshStarted.promise.then(() => {
      refreshSeen = true
    })
    await advanceUntil(() => refreshSeen)
    // The section has returned; however long the refresh takes, the release
    // waits for it.
    await vi.advanceTimersByTimeAsync(afterwardMilliseconds)
    const releasedWhileRefreshing = ssh.calls.some((call) => call.startsWith("awk_token="))
    finishRefresh.resolve()
    const outcome = await settleOnFakeClock(pending)

    expect(releasedWhileRefreshing).toBe(false)
    expect(outcome).toStrictEqual({ status: "fulfilled", value: { kind: "ok", value: "done" } })
    expect(ssh.calls.at(-1)).toMatch(/^awk_token=/v)
  })

  it("keeps propagateSectionThrows working with a running heartbeat", async () => {
    useFakeHeartbeatClock()
    const lockName = "heartbeat-mutex"
    const refreshed = deferred()
    const ssh = heartbeatSsh(lockName, countingRefresh(1, refreshed.resolve, 0).refresh)
    const error = new Error("transport boom")

    const outcome = await settleOnFakeClock(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        heartbeat: { intervalMilliseconds },
        holder: { token: CUSTOM_HOLDER_TOKEN },
        lockName,
        propagateSectionThrows: true,
        async section() {
          await refreshed.promise
          throw error
        },
      })
    )
    const callsAfterThrow = ssh.calls.length
    await vi.advanceTimersByTimeAsync(afterwardMilliseconds)

    expect(outcome).toStrictEqual({ reason: error, status: "rejected" })
    expect(ssh.calls.filter((call) => isGuardCall(call))).toHaveLength(1)
    expect(ssh.calls.at(-1)).toMatch(/^awk_token=/v)
    expect(ssh.calls).toHaveLength(callsAfterThrow)
  })

  it("rejects a non-positive heartbeat interval", async () => {
    const ssh = createMockSsh()

    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        heartbeat: { intervalMilliseconds: 0 },
        lockName: "heartbeat-mutex",
        async section() {
          await Promise.resolve()
        },
      })
    ).rejects.toThrow(/heartbeat\.intervalMilliseconds/v)
  })

  it("rejects a heartbeat interval that is not below the effective guard age before any remote command", async () => {
    const ssh = createMockSsh()

    // A 360 s guard refuses markers older than 300 s (`-mmin +5`).
    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        heartbeat: { intervalMilliseconds: 300_000 },
        lockName: "heartbeat-mutex",
        refreshGuardSeconds: 360,
        async section() {
          await Promise.resolve()
        },
        staleSeconds: 600,
      })
    ).rejects.toThrow(
      "heartbeat.intervalMilliseconds must stay below the effective refresh guard age: 300 s is not below 300 s"
    )
    expect(ssh.calls).toStrictEqual([])
  })

  it("rejects the default heartbeat interval against a guard whose effective age is one minute", async () => {
    const ssh = createMockSsh()

    // The guard defaults to the stale threshold: 120 s means `-mmin +1`, 60 s.
    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        heartbeat: {},
        lockName: "heartbeat-mutex",
        async section() {
          await Promise.resolve()
        },
        staleSeconds: 120,
      })
    ).rejects.toThrow(/60 s is not below 60 s/v)
    expect(ssh.calls).toStrictEqual([])
  })

  it("accepts a heartbeat interval just below the effective guard age", async () => {
    const ssh = createScriptedMutexSsh("heartbeat-mutex", {
      mkdir: () => true,
      poll: () => true,
      reclaim: () => false,
    })

    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      heartbeat: { intervalMilliseconds: 299_999 },
      lockName: "heartbeat-mutex",
      refreshGuardSeconds: 360,
      async section() {
        await Promise.resolve()
        return "entered"
      },
      staleSeconds: 600,
    })

    expect(result).toStrictEqual({ kind: "ok", value: "entered" })
  })
})

describe("withMutexLock – threshold validation (issue #224)", () => {
  it("rejects a refresh guard whose effective age exceeds the effective reclaim age before any remote command", async () => {
    const ssh = createMockSsh()

    // 660 s means `-mmin +10` (600 s), 600 s means `-mmin +9` (540 s).
    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        lockName: "threshold-mutex",
        refreshGuardSeconds: 660,
        async section() {
          await Promise.resolve()
        },
        staleSeconds: 600,
      })
    ).rejects.toThrow(
      "refreshGuardSeconds must not accept a marker older than the stale threshold: effective guard age 600 s exceeds effective reclaim age 540 s"
    )
    expect(ssh.calls).toStrictEqual([])
  })

  it("compares the effective ages, not the configured seconds", async () => {
    const ssh = createScriptedMutexSsh("threshold-mutex", {
      mkdir: () => true,
      poll: () => true,
      reclaim: () => false,
    })

    // 600 s and 541 s both mean `-mmin +9`, so the guard is not above the reclaim age.
    const result = await withMutexLock(ssh, {
      failureMessage: "[test] mutex",
      lockName: "threshold-mutex",
      refreshGuardSeconds: 600,
      async section() {
        await Promise.resolve()
        return "entered"
      },
      staleSeconds: 541,
    })

    expect(result).toStrictEqual({ kind: "ok", value: "entered" })
  })

  it("rejects a negative stale threshold before any remote command", async () => {
    const ssh = createMockSsh()

    await expect(
      withMutexLock(ssh, {
        failureMessage: "[test] mutex",
        lockName: "threshold-mutex",
        async section() {
          await Promise.resolve()
        },
        staleSeconds: -1,
      })
    ).rejects.toThrow(/flag lock age threshold must be a finite number/v)
    expect(ssh.calls).toStrictEqual([])
  })
})

describe("flagLockAgeThreshold (issue #224)", () => {
  it.each([
    [600, { effectiveAgeSeconds: 540, mminMinutes: 9 }],
    [360, { effectiveAgeSeconds: 300, mminMinutes: 5 }],
    [FLAG_LOCK_STALE_SECONDS, { effectiveAgeSeconds: 14_340, mminMinutes: 239 }],
    [61, { effectiveAgeSeconds: 60, mminMinutes: 1 }],
    [60, { effectiveAgeSeconds: 0, mminMinutes: 0 }],
    [0, { effectiveAgeSeconds: 0, mminMinutes: 0 }],
  ])("maps %i s to the find -mmin threshold %o", (seconds, expected) => {
    expect(flagLockAgeThreshold(seconds)).toStrictEqual(expected)
  })

  it("rejects negative and non-finite ages", () => {
    expect(() => flagLockAgeThreshold(-1)).toThrow(/finite number/v)
    expect(() => flagLockAgeThreshold(Number.NaN)).toThrow(/finite number/v)
  })

  it("keeps the shared 4 h stale reclaim at -mmin +239", async () => {
    const flagName = "stale-threshold-flag"
    const { ssh } = createStaleLockSsh(flagName, "fresh")

    await applyWithFlagLock(ssh, {
      async apply() {
        await Promise.resolve()
        return { status: "changed" }
      },
      flagName,
      waitSeconds: 1,
    })

    expect(ssh.calls.find((call) => call.startsWith("if [ -d "))).toContain("-mmin +239 ")
  })
})
