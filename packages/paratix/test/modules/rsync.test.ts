import { spawn } from "node:child_process"
import { randomUUID } from "node:crypto"
import { unlinkSync, writeFileSync } from "node:fs"
import { EventEmitter, Readable } from "node:stream"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { rsync } from "../../src/modules/rsync.js"
import { setRunnerAbortSignal } from "../../src/runnerAbortSignal.js"
import { CommandError } from "../../src/sshHelpers.js"
import { createMockSsh } from "../helpers/mockSsh.js"

const KNOWN_HOSTS_TEST_UUID = vi.hoisted<ReturnType<typeof randomUUID>>(
  () => "00000000-0000-4000-8000-000000000000"
)

vi.mock("node:crypto", () => ({
  randomUUID: vi.fn().mockReturnValue(KNOWN_HOSTS_TEST_UUID),
}))

vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}))

vi.mock("node:fs", () => ({
  unlinkSync: vi.fn(),
  writeFileSync: vi.fn(),
}))

const emptyEnv = {}
const mockSpawn = vi.mocked(spawn)
const mockRandomUUID = vi.mocked(randomUUID)
const mockUnlinkSync = vi.mocked(unlinkSync)
const mockWriteFileSync = vi.mocked(writeFileSync)

// ---------------------------------------------------------------------------
// Helpers — centralize mock setup to avoid repetitive eslint-disable lines
// ---------------------------------------------------------------------------

const noopRead = (): void => {
  /* readable is push-based in this fake; pull is a no-op */
}

/**
 * Build a fake child process that emits the configured stdout/stderr chunks
 * and then closes with the given exit code. R-0000040: tests must drive a
 * spawn-based runner instead of execFile, and stdout can be arbitrarily
 * large because the runner streams it line-by-line.
 *
 * @param parameters - Configuration for the simulated rsync child.
 * @param parameters.code - Exit code to emit on close. Defaults to 0.
 * @param parameters.stderr - Stderr payload split into chunks for emission.
 * @param parameters.stderrChunks - Optional explicit chunk array overriding stderr.
 * @param parameters.stdout - Stdout payload split into chunks for emission.
 * @param parameters.stdoutChunks - Optional explicit chunk array overriding stdout.
 * @param parameters.spawnError - When provided, the process emits an `error` event.
 * @returns The fake child-process object compatible with the runner.
 */
function makeFakeRsyncChild(parameters: {
  code?: null | number
  spawnError?: Error
  stderr?: string
  stderrChunks?: string[]
  stdout?: string
  stdoutChunks?: string[]
}): { stderr: Readable; stdout: Readable } & EventEmitter {
  const child = new EventEmitter() as {
    stderr: Readable
    stdout: Readable
  } & EventEmitter
  child.stdout = new Readable({ read: noopRead })
  child.stderr = new Readable({ read: noopRead })

  const stdoutChunks =
    parameters.stdoutChunks ?? (parameters.stdout == null ? [] : [parameters.stdout])
  const stderrChunks =
    parameters.stderrChunks ?? (parameters.stderr == null ? [] : [parameters.stderr])

  setImmediate(() => {
    for (const chunk of stdoutChunks) child.stdout.push(chunk)
    child.stdout.push(null)
    for (const chunk of stderrChunks) child.stderr.push(chunk)
    child.stderr.push(null)
    if (parameters.spawnError != null) {
      child.emit("error", parameters.spawnError)
      return
    }
    child.emit("close", parameters.code ?? 0)
  })

  return child
}

function makeHangingRsyncChild(): {
  child: {
    kill: (signal: NodeJS.Signals) => boolean
    stderr: Readable
    stdout: Readable
  } & EventEmitter
  killCalls: NodeJS.Signals[]
} {
  const killCalls: NodeJS.Signals[] = []
  const child = new EventEmitter() as {
    kill: (signal: NodeJS.Signals) => boolean
    stderr: Readable
    stdout: Readable
  } & EventEmitter
  child.stdout = new Readable({ read: noopRead })
  child.stderr = new Readable({ read: noopRead })
  Object.defineProperty(child, "exitCode", { value: null })
  child.kill = (signal: NodeJS.Signals): boolean => {
    killCalls.push(signal)
    return true
  }
  return { child, killCalls }
}

function mockSuccess(stdout = ""): void {
  mockSpawn.mockImplementation(() => makeFakeRsyncChild({ code: 0, stdout }) as never)
}

function resolveFailureCode(rawCode: number | string | undefined): number {
  if (typeof rawCode === "number") return rawCode
  if (typeof rawCode === "string") return Number.parseInt(rawCode, 10)
  return 1
}

function mockFailureWithStderr(
  parameters: { code?: number | string; stderr?: string; stdout?: string } = {}
): void {
  const code = resolveFailureCode(parameters.code)
  mockSpawn.mockImplementation(
    () =>
      makeFakeRsyncChild({
        code,
        stderr: parameters.stderr,
        stdout: parameters.stdout,
      }) as never
  )
}

function getArgs(): string[] {
  return mockSpawn.mock.calls[0][1] as string[]
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("rsync.sync — check", () => {
  beforeEach(() => {
    mockSpawn.mockReset()
  })

  it("returns needs-apply when ssh is null", async () => {
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply when dry-run shows changes (stdout not empty)", async () => {
    mockSuccess(">f+++++++++ file.txt\n")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns ok when dry-run shows no changes (stdout empty)", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok when dry-run only emits whitespace", async () => {
    mockSuccess(" \n\t\n")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.check(mockSsh, emptyEnv)
    expect(result).toBe("ok")
  })

  it("throws a descriptive error when the rsync dry-run command fails", async () => {
    mockFailureWithStderr({ code: 23, stderr: "Permission denied (publickey)." })
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(
      "[rsync.sync] check failed for /local/src -> /remote/dest (exit code 23)\nPermission denied (publickey)."
    )
  })

  it("passes correct args to rsync", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.check(mockSsh, emptyEnv)

    expect(mockSpawn).toHaveBeenCalledOnce()
    const [cmd] = mockSpawn.mock.calls[0]
    expect(cmd).toBe("rsync")
    const args = getArgs()
    expect(args).toContain("/local/src")
    expect(args).toContain("root@1.2.3.4:'/remote/dest'")
  })

  it("includes --dry-run flag", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.check(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--dry-run")
  })
})

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

describe("rsync.sync — apply", () => {
  beforeEach(() => {
    mockSpawn.mockReset()
  })

  afterEach(() => {
    setRunnerAbortSignal(undefined)
    vi.useRealTimers()
  })

  it("returns failed when ssh is null", async () => {
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    // eslint-disable-next-line prefer-spread
    const result = await mod.apply(null, emptyEnv)
    expect(result.status).toBe("failed")
  })

  it("returns changed when rsync transfers files", async () => {
    mockSuccess(">f+++++++++ file.txt\n")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns ok when destination is already in sync", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns ok when rsync only emits whitespace", async () => {
    mockSuccess(" \n\t\n")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("ok")
  })

  it("returns changed when rsync stdout has no trailing newline", async () => {
    mockSuccess(">f+++++++++ file.txt")
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("changed")
  })

  it("returns failed when rsync command fails", async () => {
    mockFailureWithStderr({ code: 12, stderr: "rsync: connection unexpectedly closed" })
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)
    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error?.message).toContain(
      "[rsync.sync] apply failed for /local/src -> /remote/dest (exit code 12)"
    )
    expect(result.error).toMatchObject({
      fullStderr: "rsync: connection unexpectedly closed",
      fullStdout: "",
    })
  })

  it("bounds captured stdout when rsync emits large output before failing", async () => {
    const stdout = ">f+++++++++ assets/image-XXXXXX.png\n".repeat(10_000)
    mockFailureWithStderr({ code: 23, stdout })
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect(result.error).toMatchObject({
      fullStderr: "",
    })
    expect((result.error as CommandError).fullStdout.length).toBeLessThan(stdout.length)
    expect((result.error as CommandError).fullStdout).toContain("rsync stdout truncated")
  })

  it("bounds captured stderr when rsync emits large error output", async () => {
    const stderr = "rsync: repeated permission error\n".repeat(10_000)
    mockFailureWithStderr({ code: 23, stderr })
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error).toBeInstanceOf(CommandError)
    expect((result.error as CommandError).fullStderr.length).toBeLessThan(stderr.length)
    expect((result.error as CommandError).fullStderr).toContain("rsync stderr truncated")
  })

  it("does NOT include --dry-run flag", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).not.toContain("--dry-run")
  })

  it("passes correct args to rsync", async () => {
    mockSuccess()
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(mockSpawn).toHaveBeenCalledOnce()
    const [cmd] = mockSpawn.mock.calls[0]
    expect(cmd).toBe("rsync")
    const args = getArgs()
    expect(args).toContain("/local/src")
    expect(args).toContain("root@1.2.3.4:'/remote/dest'")
  })

  it("succeeds even when rsync produces multi-megabyte stdout (R-0000040 regression)", async () => {
    // R-0000040: the previous execFile-based runner used Node's default
    // 1 MiB stdout buffer. With --itemize-changes, a sync of tens of
    // thousands of files easily exceeds that limit and the runner would
    // surface ERR_CHILD_PROCESS_STDIO_MAXBUFFER even though rsync itself
    // succeeded. The spawn-based streaming runner handles this case.
    // 80 KiB-aligned realistic itemize lines * 60 000 lines = ~2.16 MiB,
    // comfortably above the 1 MiB execFile default that the previous
    // implementation used.
    const lineCount = 60_000
    const itemizeLine = ">f+++++++++ assets/image-XXXXXX.png\n"
    const totalBytes = itemizeLine.length * lineCount
    expect(totalBytes).toBeGreaterThan(1024 * 1024)

    // Stream the output in 256 KiB chunks so the runner sees realistic
    // multi-event delivery rather than a single push.
    const chunkSize = 256 * 1024
    const stdoutChunks: string[] = []
    let assembled = ""
    for (let i = 0; i < lineCount; i += 1) assembled += itemizeLine
    for (let offset = 0; offset < assembled.length; offset += chunkSize) {
      stdoutChunks.push(assembled.slice(offset, offset + chunkSize))
    }

    mockSpawn.mockImplementation(() => makeFakeRsyncChild({ code: 0, stdoutChunks }) as never)

    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    const result = await mod.apply(mockSsh, emptyEnv)

    expect(result.status).toBe("changed")
  })

  it("kills and fails a hanging rsync child when the timeout expires", async () => {
    vi.useFakeTimers()
    const { child, killCalls } = makeHangingRsyncChild()
    mockSpawn.mockReturnValue(child as never)
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src", timeout: 25 })

    const resultPromise = mod.apply(mockSsh, emptyEnv)
    let resolved = false
    void resultPromise.then(() => {
      resolved = true
    })
    await vi.advanceTimersByTimeAsync(25)

    expect(resolved).toBe(false)
    expect(killCalls).toStrictEqual(["SIGTERM"])

    await vi.advanceTimersByTimeAsync(1000)
    expect(killCalls).toStrictEqual(["SIGTERM", "SIGKILL"])

    child.emit("close", 137)
    const result = await resultPromise
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("rsync timed out after 25ms")
  })

  it("kills and fails a hanging rsync child when the runner abort signal fires", async () => {
    vi.useFakeTimers()
    const { child, killCalls } = makeHangingRsyncChild()
    mockSpawn.mockReturnValue(child as never)
    const controller = new AbortController()
    setRunnerAbortSignal(controller.signal)
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src", timeout: 10_000 })

    const resultPromise = mod.apply(mockSsh, emptyEnv)
    let resolved = false
    void resultPromise.then(() => {
      resolved = true
    })
    controller.abort()

    await vi.advanceTimersByTimeAsync(0)
    expect(resolved).toBe(false)
    expect(killCalls).toStrictEqual(["SIGTERM"])

    await vi.advanceTimersByTimeAsync(1000)
    expect(killCalls).toStrictEqual(["SIGTERM", "SIGKILL"])

    child.emit("close", 143)
    const result = await resultPromise
    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("rsync aborted")
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("rsync.sync — name", () => {
  it("has correct name format: rsync.sync: <src> -> <dest>", () => {
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    expect(mod.name).toBe("rsync.sync: /local/src -> /remote/dest")
  })
})

describe("rsync.sync — path validation", () => {
  it("R-0000179: rejects newline characters in dest", () => {
    expect(() => {
      rsync.sync({ dest: "/remote/dest\nbreak", src: "/local/src" })
    }).toThrow(/dest must not contain ASCII control characters/v)
  })

  it("R-0000179: rejects newline characters in src", () => {
    expect(() => {
      rsync.sync({ dest: "/remote/dest", src: "/local/src\nbreak" })
    }).toThrow(/src must not contain ASCII control characters/v)
  })

  it("R-0000179: rejects NUL byte in dest", () => {
    expect(() => {
      rsync.sync({ dest: "/remote/dest\0nul", src: "/local/src" })
    }).toThrow(/dest must not contain ASCII control characters/v)
  })

  it("R-0000179: rejects DEL byte in src", () => {
    expect(() => {
      rsync.sync({ dest: "/remote/dest", src: "/local/src\x7fbreak" })
    }).toThrow(/src must not contain ASCII control characters/v)
  })

  it("R-0000179: rejects empty dest", () => {
    expect(() => {
      rsync.sync({ dest: "", src: "/local/src" })
    }).toThrow(/dest must not be empty/v)
  })
})

// ---------------------------------------------------------------------------
// Argument building
// ---------------------------------------------------------------------------

describe("rsync.sync — argument building", () => {
  beforeEach(() => {
    mockSpawn.mockReset()
    mockSuccess()
    mockRandomUUID.mockReturnValue(KNOWN_HOSTS_TEST_UUID)
    mockUnlinkSync.mockReset()
    mockWriteFileSync.mockReset()
  })

  it("includes -az and --itemize-changes as base flags", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    expect(args).toContain("-az")
    expect(args).toContain("--itemize-changes")
  })

  it("includes SSH transport with correct port, key, and StrictHostKeyChecking=yes", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    expect(eIdx).toBeGreaterThanOrEqual(0)
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("ssh")
    expect(transportArg).toContain("-p 22")
    expect(transportArg).toContain("-i '~/.ssh/id'")
    expect(transportArg).toContain("-o StrictHostKeyChecking=yes")
  })

  // R-0000247 regression: the verified known_hosts file is created in the
  // shared OS tmpdir; opening with `wx` (O_WRONLY | O_CREAT | O_EXCL) causes
  // the create step to refuse following a pre-existing symlink, defending
  // against a symlink-replacement attack on hosts without a sticky-bit /tmp.
  it("uses a temporary verified known_hosts file for a pinned session host key", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
      verifiedHostPublicKey: "ssh-ed25519 AAAAPINNEDKEY",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src", strictHostKeyChecking: "no" })

    await mod.apply(mockSsh, emptyEnv)

    expect(mockWriteFileSync).toHaveBeenCalledWith(
      expect.stringContaining(`/paratix-rsync-known-hosts-${KNOWN_HOSTS_TEST_UUID}`),
      "1.2.3.4 ssh-ed25519 AAAAPINNEDKEY\n",
      { flag: "wx", mode: 0o600 }
    )
    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("UserKnownHostsFile='")
    expect(transportArg).toContain(`paratix-rsync-known-hosts-${KNOWN_HOSTS_TEST_UUID}`)
    expect(transportArg).toContain("-o GlobalKnownHostsFile=/dev/null")
    expect(transportArg).toContain("-o StrictHostKeyChecking=yes")
    expect(mockUnlinkSync).toHaveBeenCalledWith(
      expect.stringContaining(`/paratix-rsync-known-hosts-${KNOWN_HOSTS_TEST_UUID}`)
    )
  })

  it("wraps privateKeyPath with single quotes to prevent shell expansion of special characters", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "$HOME/.ssh/deploy key",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    expect(eIdx).toBeGreaterThanOrEqual(0)
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-i '$HOME/.ssh/deploy key'")
    expect(transportArg).not.toContain('-i "$HOME/.ssh/deploy key"')
  })

  it.each(["accept-new", "no", "off", "yes"] as const)(
    "uses custom StrictHostKeyChecking=%s when provided",
    async (strictHostKeyChecking) => {
      const mockSsh = createMockSsh()
      const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src", strictHostKeyChecking })
      await mod.apply(mockSsh, emptyEnv)

      const args = getArgs()
      const eIdx = args.indexOf("-e")
      const transportArg = args[eIdx + 1]
      expect(transportArg).toContain(`-o StrictHostKeyChecking=${strictHostKeyChecking}`)
    }
  )

  it("rejects invalid StrictHostKeyChecking strings at module construction", () => {
    expect(() =>
      rsync.sync({
        dest: "/remote/dest",
        src: "/local/src",
        strictHostKeyChecking: "maybe" as never,
      })
    ).toThrow(
      '[rsync.sync] strictHostKeyChecking must be one of "accept-new", "no", "off", or "yes"'
    )
  })

  it("rejects non-string StrictHostKeyChecking values at module construction", () => {
    expect(() =>
      rsync.sync({
        dest: "/remote/dest",
        src: "/local/src",
        strictHostKeyChecking: false as never,
      })
    ).toThrow(
      '[rsync.sync] strictHostKeyChecking must be one of "accept-new", "no", "off", or "yes"'
    )
  })

  it("does not rely on a local known_hosts entry when the session exports a verified host key", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "fresh-host.example",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
      verifiedHostPublicKey: "ssh-ed25519 AAAAFRESHKEY",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })

    await mod.check(mockSsh, emptyEnv)

    expect(mockWriteFileSync).toHaveBeenCalledWith(
      expect.stringContaining(`/paratix-rsync-known-hosts-${KNOWN_HOSTS_TEST_UUID}`),
      "fresh-host.example ssh-ed25519 AAAAFRESHKEY\n",
      { flag: "wx", mode: 0o600 }
    )
    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("UserKnownHostsFile='")
    expect(transportArg).toContain(`paratix-rsync-known-hosts-${KNOWN_HOSTS_TEST_UUID}`)
    expect(transportArg).toContain("-o GlobalKnownHostsFile=/dev/null")
  })

  it("passes StrictHostKeyChecking=yes to ssh transport when set to yes", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({
      dest: "/remote/dest",
      src: "/local/src",
      strictHostKeyChecking: "yes",
    })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o StrictHostKeyChecking=yes")
  })

  it("adds --include before --exclude patterns", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({
      dest: "/remote/dest",
      exclude: ["*.log"],
      include: ["*.conf"],
      src: "/local/src",
    })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const includeIdx = args.indexOf("--include")
    const excludeIdx = args.indexOf("--exclude")
    expect(includeIdx).toBeGreaterThanOrEqual(0)
    expect(excludeIdx).toBeGreaterThanOrEqual(0)
    expect(args[includeIdx + 1]).toBe("*.conf")
    expect(args[excludeIdx + 1]).toBe("*.log")
    expect(includeIdx).toBeLessThan(excludeIdx)
  })

  it("adds --delete when delete option is true", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ delete: true, dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--delete")
  })

  it("does not add --delete when delete option is false", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ delete: false, dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).not.toContain("--delete")
  })

  it("does not add --delete when delete option is undefined", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).not.toContain("--delete")
  })

  it("adds --chown=owner:owner when only owner is set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", owner: "deploy", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chown=deploy:deploy")
  })

  it("adds --chown=:group when only group is set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/remote/dest", group: "www-data", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chown=:www-data")
  })

  it("adds --chown=owner:group when both are set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({
      dest: "/remote/dest",
      group: "www-data",
      owner: "deploy",
      src: "/local/src",
    })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chown=deploy:www-data")
  })

  it("adds --chmod when chmod option is set", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ chmod: "644", dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("--chmod=644")
  })

  it("builds correct remote destination as user@host:quoted-dest", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/var/www/html", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("root@1.2.3.4:'/var/www/html'")
  })

  it("quotes remote destinations that contain shell metacharacters", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/var/www/releases/app $(date); touch bad", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("root@1.2.3.4:'/var/www/releases/app $(date); touch bad'")
  })

  it("escapes embedded single quotes in remote destinations using the '\\'' pattern", async () => {
    const mockSsh = createMockSsh()
    const mod = rsync.sync({ dest: "/var/www/it's", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("root@1.2.3.4:'/var/www/it'\\''s'")
  })

  it("builds IPv6 remote destination in bracketed form", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "2001:db8::10",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/var/www/html", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    expect(getArgs()).toContain("root@[2001:db8::10]:'/var/www/html'")
  })
})

// ---------------------------------------------------------------------------
// SSH auth — agent socket vs private key vs none
// ---------------------------------------------------------------------------

describe("rsync.sync — SSH auth method in transport flag", () => {
  beforeEach(() => {
    mockSpawn.mockReset()
    mockSuccess()
  })

  it("sets -o IdentityAgent=<socket> when agentSocket is provided", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/run/user/1000/gnupg/S.gpg-agent.ssh",
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    expect(eIdx).toBeGreaterThanOrEqual(0)
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o IdentityAgent='/run/user/1000/gnupg/S.gpg-agent.ssh'")
    expect(transportArg).not.toContain("-i ")
  })

  it("wraps agentSocket with single quotes to prevent shell expansion", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/tmp/ssh-agent $USER.sock",
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-o IdentityAgent='/tmp/ssh-agent $USER.sock'")
    expect(transportArg).not.toContain('-o IdentityAgent="/tmp/ssh-agent $USER.sock"')
  })

  it("prefers privateKeyPath over agentSocket when both are present", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/run/user/1000/gnupg/S.gpg-agent.ssh",
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/deploy_key",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-i '~/.ssh/deploy_key'")
    expect(transportArg).not.toContain("-o IdentityAgent=")
  })

  it("sets -i <keypath> when only privateKeyPath is provided (backwards compatibility)", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).toContain("-i '~/.ssh/id'")
    expect(transportArg).not.toContain("-o IdentityAgent=")
  })

  it("regression: appends -o IdentitiesOnly=yes whenever privateKeyPath is set", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      privateKeyPath: "~/.ssh/id",
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    // Both the -i flag and IdentitiesOnly=yes must be present, so rsync only
    // ever uses the configured key and never silently picks an agent identity.
    expect(transportArg).toContain("-i '~/.ssh/id'")
    expect(transportArg).toContain("-o IdentitiesOnly=yes")
  })

  it("regression: does not append IdentitiesOnly=yes when only agentSocket is provided", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      agentSocket: "/run/user/1000/ssh-agent.sock",
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    // IdentitiesOnly=yes is only meaningful in combination with -i; with an
    // agent-only fallback the option would over-restrict identity selection.
    expect(transportArg).toContain("-o IdentityAgent='/run/user/1000/ssh-agent.sock'")
    expect(transportArg).not.toContain("-o IdentitiesOnly=yes")
  })

  it("includes no identity flag when neither privateKeyPath nor agentSocket is provided", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })
    await mod.apply(mockSsh, emptyEnv)

    const args = getArgs()
    const eIdx = args.indexOf("-e")
    const transportArg = args[eIdx + 1]
    expect(transportArg).not.toContain("-i ")
    expect(transportArg).not.toContain("-o IdentityAgent=")
  })

  it("throws a clear error for password-authenticated sessions", async () => {
    const mockSsh = createMockSsh()
    vi.spyOn(mockSsh, "getConnectionInfo").mockReturnValue({
      authMethod: "password",
      configuredPorts: [22],
      host: "1.2.3.4",
      port: 22,
      user: "root",
    })
    const mod = rsync.sync({ dest: "/remote/dest", src: "/local/src" })

    await expect(mod.check(mockSsh, emptyEnv)).rejects.toThrow(
      "[rsync.sync] check requires agent or private-key SSH authentication; password fallback sessions are not supported"
    )

    expect(mockSpawn).not.toHaveBeenCalled()
  })
})
