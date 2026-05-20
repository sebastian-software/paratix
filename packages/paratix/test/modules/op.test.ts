import type * as childProcess from "node:child_process"

import { EventEmitter } from "node:events"
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { op } from "../../src/modules/op.js"
import { OP_OUTPUT_CAPTURE_LIMIT_BYTES } from "../../src/modules/opOutputCapture.js"
import { setRunnerAbortSignal } from "../../src/runnerAbortSignal.js"
import { clearRegisteredSecrets, getRegisteredSecrets } from "../../src/secretSink.js"

type MockStdin = {
  end: Mock
  once: Mock
} & EventEmitter

type MockChildProcess = { stdin: MockStdin } & EventEmitter

function createMockChild(stdout: string, exitCode = 0, stderr = ""): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess
  const stdoutEmitter = new EventEmitter()
  const stderrEmitter = new EventEmitter()
  Object.defineProperty(child, "stdout", { value: stdoutEmitter })
  Object.defineProperty(child, "stderr", { value: stderrEmitter })
  child.stdin = Object.assign(new EventEmitter(), {
    end: vi.fn(),
    once: vi.fn(function once(
      this: EventEmitter,
      eventName: string,
      listener: (...arguments_: unknown[]) => void
    ) {
      EventEmitter.prototype.once.call(this, eventName, listener)
      return this
    }),
  })

  // Emit data and close asynchronously so listeners are registered first
  queueMicrotask(() => {
    stdoutEmitter.emit("data", Buffer.from(stdout))
    if (stderr.length > 0) {
      stderrEmitter.emit("data", Buffer.from(stderr))
    }
    child.emit("close", exitCode)
  })

  return child
}

function createHangingMockChild(killCalls: NodeJS.Signals[]): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess
  Object.defineProperty(child, "stdout", { value: new EventEmitter() })
  Object.defineProperty(child, "stderr", { value: new EventEmitter() })
  Object.defineProperty(child, "exitCode", { value: null })
  Object.defineProperty(child, "signalCode", { value: null })
  Object.defineProperty(child, "killed", { value: false })
  ;(child as unknown as { kill: (signal: NodeJS.Signals) => void }).kill = (
    signal: NodeJS.Signals
  ) => {
    killCalls.push(signal)
  }
  child.stdin = Object.assign(new EventEmitter(), {
    end: vi.fn(),
    once: vi.fn(function once(
      this: EventEmitter,
      eventName: string,
      listener: (...arguments_: unknown[]) => void
    ) {
      EventEmitter.prototype.once.call(this, eventName, listener)
      return this
    }),
  })

  return child
}

type SpawnCall = { args: string[]; command: string }

let spawnCalls: SpawnCall[] = []

function trackSpawn(command: string, args: readonly string[]): void {
  spawnCalls.push({ args: [...args], command })
}

function mockSpawnWith(output: string, exitCode = 0, stderr = ""): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    trackSpawn(command, args ?? [])
    return createMockChild(output, exitCode, stderr) as never
  })
}

function createEnoentMockChild(): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess
  const stdoutEmitter = new EventEmitter()
  const stderrEmitter = new EventEmitter()
  Object.defineProperty(child, "stdout", { value: stdoutEmitter })
  Object.defineProperty(child, "stderr", { value: stderrEmitter })
  child.stdin = Object.assign(new EventEmitter(), {
    end: vi.fn(),
    once: vi.fn(function once(
      this: EventEmitter,
      eventName: string,
      listener: (...arguments_: unknown[]) => void
    ) {
      EventEmitter.prototype.once.call(this, eventName, listener)
      return this
    }),
  })

  queueMicrotask(() => {
    const enoent = Object.assign(new Error("spawn op ENOENT"), { code: "ENOENT" })
    child.emit("error", enoent)
  })
  return child
}

function mockSpawnWithSpawnError(): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    trackSpawn(command, args ?? [])
    return createEnoentMockChild() as never
  })
}

function mockSpawnWithStdinError(error: Error, killCalls: NodeJS.Signals[]): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    trackSpawn(command, args ?? [])
    const child = createHangingMockChild(killCalls)
    child.stdin.end.mockImplementationOnce(() => {
      queueMicrotask(() => {
        child.stdin.emit("error", error)
      })
    })
    return child as never
  })
}

function mockSpawnByReference(outputs: Record<string, string>): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    const argsList = args ?? []
    trackSpawn(command, argsList)
    // R-0000643: the op invocation is `op read -- <reference>`; the
    // end-of-options separator sits at args[1] so the reference is at args[2].
    const reference = argsList[2] ?? ""
    const output = outputs[reference] ?? ""
    return createMockChild(output) as never
  })
}

vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}))

const { spawn: mockedSpawn } = await vi.importMock<typeof childProcess>("node:child_process")
const mockedSpawnFn = vi.mocked(mockedSpawn)

const emptyEnv = {}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("op.resolve — check", () => {
  it("is marked as a dry-run meta producer", () => {
    const module_ = op.resolve({})
    expect(module_._dryRunMetaProducer).toBe(true)
  })

  it("always returns needs-apply", async () => {
    const module_ = op.resolve({})
    const result = await module_.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })

  it("returns needs-apply regardless of references", async () => {
    const module_ = op.resolve({ password: "op://vault/item/password" })
    const result = await module_.check(null, emptyEnv)
    expect(result).toBe("needs-apply")
  })
})

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

describe("op.resolve — apply", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    clearRegisteredSecrets()
    spawnCalls = []
    mockSpawnWith("")
  })

  afterEach(() => {
    clearRegisteredSecrets()
  })

  it("resolves regular secrets via op read and returns them as meta", async () => {
    mockSpawnWith("secret123\n")

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "password")).resolves.toBe("secret123")
  })

  it("preserves JSON-special characters in regular secrets", async () => {
    const resolvedValue = 'quoted "value" with backslash \\ and newline\nsecond line'
    mockSpawnWith(`${resolvedValue}\n`)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "password")).resolves.toBe(resolvedValue)
  })

  it("resolves OTP fields via op read and returns lazy functions as meta", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "token")).resolves.toMatch(/^\d{6}$/v)
  })

  it("calls the lazy OTP function and returns a 6-digit string", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    const code = await resolveEnvironment(metaEnvironment, "token")
    expect(code).toMatch(/^\d{6}$/v)
  })

  // R-0000576: the otpauth URI carrying the shared `secret=` is registered
  // in the secret sink while `apply` is resolving values so a third-party
  // error renderer cannot leak it. R-0001011: direct module.apply calls own a
  // run-scoped cleanup boundary, so the URI must not remain registered after
  // apply returns.
  it("releases the direct-apply otpauth URI after resolving OTP meta", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    const code = await resolveEnvironment(metaEnvironment, "token")

    expect(code).toMatch(/^\d{6}$/v)
    expect(getRegisteredSecrets()).not.toContain(otpauthUri)
    expect(getRegisteredSecrets()).not.toContain(code)
  })

  it("does not persist direct-apply 8-digit OTP codes after resolving OTP meta", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=8"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    const code = await resolveEnvironment(metaEnvironment, "token")

    expect(code).toMatch(/^\d{8}$/v)
    expect(getRegisteredSecrets()).not.toContain(otpauthUri)
    expect(getRegisteredSecrets()).not.toContain(code)
  })

  it("recognises OTP fields by /one-time-password suffix", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "token")).resolves.toMatch(/^\d{6}$/v)
    // Regular reference resolution must not run for OTP-only references.
    const injectCalls = spawnCalls.filter((c) => c.args[0] === "inject")
    expect(injectCalls).toHaveLength(0)
  })

  it("recognises OTP fields by /otp suffix", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/otp" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "token")).resolves.toMatch(/^\d{6}$/v)
  })

  it("returns { status: 'failed' } when op read throws for a regular reference", async () => {
    mockSpawnWith("", 1)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Failed to resolve 1Password references")
  })

  it("returns failed when op stdin emits an error", async () => {
    const killCalls: NodeJS.Signals[] = []
    mockSpawnWithStdinError(new Error("write EPIPE"), killCalls)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("write EPIPE")
    expect(killCalls).toContain("SIGTERM")
  })

  it("returns { status: 'failed' } when op read throws", async () => {
    mockSpawnWith("", 1)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Failed to resolve 1Password references")
  })

  it("calls op read once for each regular reference", async () => {
    mockSpawnByReference({
      "op://vault/item/api-key": "key123\n",
      "op://vault/item/db-password": "db456\n",
    })

    const module_ = op.resolve({
      apiKey: "op://vault/item/api-key",
      dbPassword: "op://vault/item/db-password",
    })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    expect(spawnCalls).toHaveLength(2)
    expect(spawnCalls.map((call) => call.args)).toStrictEqual([
      ["read", "--", "op://vault/item/api-key"],
      ["read", "--", "op://vault/item/db-password"],
    ])
  })

  // R-0000643: defense-in-depth alignment with package.ts and git.ts — even
  // though `validateReferences` enforces an op:// prefix today, the explicit
  // end-of-options separator keeps the CLI invocation safe if validation is
  // ever relaxed. Assert the separator on both the regular-secret and OTP
  // paths.
  it("R-0000643: passes -- before the regular reference argument", async () => {
    mockSpawnWith("secret123\n")

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    expect(spawnCalls).toHaveLength(1)
    expect(spawnCalls[0].args).toStrictEqual(["read", "--", "op://vault/item/password"])
  })

  it("R-0000643: passes -- before the OTP reference argument", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    expect(spawnCalls).toHaveLength(1)
    expect(spawnCalls[0].args).toStrictEqual(["read", "--", "op://vault/item/one-time-password"])
  })

  it("does not call op read for regular references when only OTP fields are present", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({
      token: "op://vault/item/one-time-password",
    })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    const injectCalls = spawnCalls.filter((c) => c.args[0] === "inject")
    expect(injectCalls).toHaveLength(0)
  })

  it("works with an empty references object", async () => {
    const module_ = op.resolve({})
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(await mergeEnvironmentFromMeta({}, result.meta)).toStrictEqual({})
    expect(spawnCalls).toHaveLength(0)
  })

  it("merges regular and OTP meta into a single result", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"

    mockSpawnByReference({
      "op://vault/item/one-time-password": `${otpauthUri}\n`,
      "op://vault/item/password": "secret123\n",
    })

    const module_ = op.resolve({
      password: "op://vault/item/password",
      token: "op://vault/item/one-time-password",
    })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "password")).resolves.toBe("secret123")
    await expect(resolveEnvironment(metaEnvironment, "token")).resolves.toMatch(/^\d{6}$/v)
  })
})

// ---------------------------------------------------------------------------
// error masking
// ---------------------------------------------------------------------------

describe("op.resolve — error masking", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    clearRegisteredSecrets()
    spawnCalls = []
  })

  afterEach(() => {
    clearRegisteredSecrets()
  })

  it("masks reference strings echoed in op stderr from the failure message", async () => {
    const reference = "op://prod-vault/database/password"
    mockSpawnWith("", 1, `error: item ${reference} not found in prod-vault`)

    const module_ = op.resolve({ password: reference })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain(reference)
    expect(result.error?.message).not.toContain("prod-vault/database/password")
  })

  // R-0000165: when an OTP resolve fails AFTER a regular secret has already
  // been read, the resolved regular value must already be in the secret sink
  // so any subsequent stack trace, unhandled rejection, or shared logger
  // trap masks it. Without immediate registration the regular value would
  // only land in the sink on the post-loop pass, leaving a window where the
  // OTP failure could leak it in plaintext.
  it("masks regular secrets before a later OTP resolve throws without retaining them", async () => {
    const resolvedValue = "early-registered-secret-value"
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild(`${resolvedValue}\n`)
    }) as never)
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild("", 1, "otp resolve crashed")
    }) as never)

    const module_ = op.resolve({
      password: "op://vault/item/password",
      token: "op://vault/item/one-time-password",
    })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain(resolvedValue)
    expect(getRegisteredSecrets()).not.toContain(resolvedValue)
  })

  it("masks the resolved regular secret value when it leaks into op stderr", async () => {
    const resolvedValue = "super-secret-resolved-value-12345"
    // Two op calls: the first op read succeeds and resolves the secret, the
    // second op read for the OTP fails with stderr that contains the
    // already-resolved value (e.g. via a stack trace or echoing).
    const stderrLeak = `connection failed; last value=${resolvedValue}`
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild(`${resolvedValue}\n`)
    }) as never)
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild("", 1, stderrLeak)
    }) as never)

    const module_ = op.resolve({
      password: "op://vault/item/password",
      token: "op://vault/item/one-time-password",
    })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain(resolvedValue)
  })

  it("masks the resolved otpauth URI when it leaks into a later op error message", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    const otpStdout = `${otpauthUri}\n`
    const stderrLeak = `tls error reading ${otpauthUri}`
    // First reference resolves successfully (returning the otpauth URI);
    // a second OTP reference fails with stderr containing that URI.
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild(otpStdout)
    }) as never)
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild("", 1, stderrLeak)
    }) as never)

    const module_ = op.resolve({
      first: "op://vault/item/one-time-password",
      second: "op://vault/item2/otp",
    })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain(otpauthUri)
    expect(result.error?.message).not.toContain("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
  })

  it("explains the install path when op is not on PATH (ENOENT)", async () => {
    mockSpawnWithSpawnError()

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("not installed")
    expect(result.error?.message).toContain("https://1password.com/downloads/command-line/")
  })

  it("explains how to sign in when op stderr indicates an auth failure", async () => {
    mockSpawnWith("", 1, "[ERROR] You are not signed in to a 1Password account.")

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("op signin")
  })

  it("does not append the signin hint for unrelated op errors", async () => {
    mockSpawnWith("", 1, "[ERROR] item could not be retrieved due to a transient error.")

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain("op signin")
  })

  // R-0000589 + R-0000588: the captured stderr is now treated as a secret
  // and its prefixes are redacted by `maskKnownSecretPrefixes`. The
  // truncation marker is therefore covered by the masked prefix, but the
  // remaining authentication hint (which sits after the masked prefix) and
  // the overall length bound must still hold.
  it("bounds large op stderr while preserving the authentication hint", async () => {
    const largeStderr = `[ERROR] You are not signed in to a 1Password account.\n${"x".repeat(
      OP_OUTPUT_CAPTURE_LIMIT_BYTES * 2
    )}`
    mockSpawnWith("", 1, largeStderr)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("op signin")
    expect(result.error?.message).toContain("[REDACTED]")
    expect(result.error?.message.length).toBeLessThan(OP_OUTPUT_CAPTURE_LIMIT_BYTES + 500)
  })

  it("fails instead of returning a truncated secret when op stdout is too large", async () => {
    const largeSecret = `secret-${"s".repeat(OP_OUTPUT_CAPTURE_LIMIT_BYTES * 2)}`
    mockSpawnWith(`${largeSecret}\n`)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("refusing to return a truncated secret")
    expect(result.error?.message).not.toContain(largeSecret.slice(0, 32))
  })

  it("masks known secret prefixes when stderr truncation cuts through a secret", async () => {
    const resolvedValue = `boundary-secret-${"z".repeat(80)}`
    const stderrPrelude = "failure "
    const capturedSecretPrefixLength = 48
    const stderrBeforeSecret = `${stderrPrelude}${"x".repeat(
      OP_OUTPUT_CAPTURE_LIMIT_BYTES - stderrPrelude.length - capturedSecretPrefixLength
    )}`
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild(`${resolvedValue}\n`)
    }) as never)
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild("", 1, `${stderrBeforeSecret}${resolvedValue}`)
    }) as never)

    const module_ = op.resolve({
      password: "op://vault/item/password",
      token: "op://vault/item/one-time-password",
    })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    // R-0000589 + R-0000588: the captured stderr (which now carries the
    // truncated secret prefix) is treated as a secret. The truncation
    // marker is therefore covered by the redacted prefix; the test still
    // asserts that the resolved secret is masked.
    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain(resolvedValue.slice(0, capturedSecretPrefixLength))
    expect(result.error?.message).toContain("[REDACTED]")
  })
})

// ---------------------------------------------------------------------------
// input validation
// ---------------------------------------------------------------------------

describe("op.resolve — input validation", () => {
  it("throws when a reference does not start with op://", () => {
    expect(() => op.resolve({ password: "not-a-valid-ref" })).toThrow(/must start with "op:\/\/"/v)
  })

  it("accepts references starting with op://", () => {
    expect(() => op.resolve({ password: "op://vault/item/password" })).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// name
// ---------------------------------------------------------------------------

describe("op.resolve — name", () => {
  it("includes all keys in the name", () => {
    const module_ = op.resolve({
      apiKey: "op://vault/item/api-key",
      password: "op://vault/item/password",
    })
    expect(module_.name).toContain("apiKey")
    expect(module_.name).toContain("password")
  })

  it("shows empty name for empty references", () => {
    const module_ = op.resolve({})
    expect(module_.name).toBe("op.resolve: ")
  })

  it("shows single key in name", () => {
    const module_ = op.resolve({ token: "op://vault/item/token" })
    expect(module_.name).toBe("op.resolve: token")
  })
})

// ---------------------------------------------------------------------------
// local
// ---------------------------------------------------------------------------

describe("op.resolve — local", () => {
  it("has local set to true", () => {
    const module_ = op.resolve({})
    expect(module_.local).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// R-0000641: null stdin terminates the orphaned op child
// ---------------------------------------------------------------------------

describe("op.resolve — null stdin (R-0000641)", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    clearRegisteredSecrets()
    spawnCalls = []
  })

  afterEach(() => {
    clearRegisteredSecrets()
  })

  it("kills the op child via SIGTERM when stdin is null and rejects", async () => {
    const killCalls: NodeJS.Signals[] = []
    const child = new EventEmitter() as MockChildProcess
    Object.defineProperty(child, "stdout", { value: new EventEmitter() })
    Object.defineProperty(child, "stderr", { value: new EventEmitter() })
    Object.defineProperty(child, "exitCode", { value: null })
    Object.defineProperty(child, "signalCode", { value: null })
    Object.defineProperty(child, "stdin", { value: null })
    ;(child as unknown as { kill: (signal: NodeJS.Signals) => void }).kill = (
      signal: NodeJS.Signals
    ) => {
      killCalls.push(signal)
    }
    mockedSpawnFn.mockImplementation((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return child as never
    })

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread -- Module.apply, not Function.prototype.apply
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("stdin unavailable")
    // Without an explicit kill the spawned ChildProcess would outlive the
    // rejected promise; the fix sends SIGTERM as part of the escalation.
    expect(killCalls).toContain("SIGTERM")
  })

  // R-0000678: when `child.stdin.end(input)` throws synchronously (e.g. the
  // child exited between the null check and the write so the pipe is gone)
  // rejectOnce settles the promise but leaves the underlying ChildProcess
  // running. The catch block must call killChildEscalating before rejecting,
  // mirroring the null-stdin path.
  it("kills the op child via SIGTERM when stdin.end throws synchronously", async () => {
    const killCalls: NodeJS.Signals[] = []
    const child = new EventEmitter() as MockChildProcess
    Object.defineProperty(child, "stdout", { value: new EventEmitter() })
    Object.defineProperty(child, "stderr", { value: new EventEmitter() })
    Object.defineProperty(child, "exitCode", { value: null })
    Object.defineProperty(child, "signalCode", { value: null })
    Object.defineProperty(child, "killed", { value: false })
    ;(child as unknown as { kill: (signal: NodeJS.Signals) => void }).kill = (
      signal: NodeJS.Signals
    ) => {
      killCalls.push(signal)
    }
    const stdinEnd = vi.fn(() => {
      throw new Error("write EPIPE")
    })
    child.stdin = Object.assign(new EventEmitter(), {
      end: stdinEnd,
      once: vi.fn(function once(
        this: EventEmitter,
        eventName: string,
        listener: (...arguments_: unknown[]) => void
      ) {
        EventEmitter.prototype.once.call(this, eventName, listener)
        return this
      }),
    })
    mockedSpawnFn.mockImplementation((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return child as never
    })

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread -- Module.apply, not Function.prototype.apply
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("write EPIPE")
    // Without the killChildEscalating call the orphaned op CLI process
    // would outlive the rejected promise.
    expect(killCalls).toContain("SIGTERM")
  })
})

// ---------------------------------------------------------------------------
// R-0000220: abort signal coupling + timeout
// ---------------------------------------------------------------------------

describe("op.resolve — runner abort and timeout (R-0000220)", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    clearRegisteredSecrets()
    spawnCalls = []
  })

  afterEach(() => {
    vi.useRealTimers()
    setRunnerAbortSignal(undefined)
    clearRegisteredSecrets()
  })

  it("rejects immediately when the runner abort signal is already aborted before spawn", async () => {
    const controller = new AbortController()
    controller.abort()
    setRunnerAbortSignal(controller.signal)
    // Even if spawn would succeed, apply must fail before spawning. Track that
    // the mocked spawn was never invoked.
    mockSpawnWith("secret123\n")

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread -- Module.apply, not Function.prototype.apply
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("aborted before spawn")
    expect(spawnCalls).toHaveLength(0)
  })

  it("kills the op child and rejects when the runner abort signal fires mid-call", async () => {
    const killCalls: NodeJS.Signals[] = []
    const child = new EventEmitter() as MockChildProcess
    Object.defineProperty(child, "stdout", { value: new EventEmitter() })
    Object.defineProperty(child, "stderr", { value: new EventEmitter() })
    Object.defineProperty(child, "exitCode", { value: null })
    Object.defineProperty(child, "signalCode", { value: null })
    Object.defineProperty(child, "killed", { value: false })
    ;(child as unknown as { kill: (signal: NodeJS.Signals) => void }).kill = (
      signal: NodeJS.Signals
    ) => {
      killCalls.push(signal)
    }
    child.stdin = Object.assign(new EventEmitter(), {
      end: vi.fn(),
      once: vi.fn(function once(
        this: EventEmitter,
        eventName: string,
        listener: (...arguments_: unknown[]) => void
      ) {
        EventEmitter.prototype.once.call(this, eventName, listener)
        return this
      }),
    })
    mockedSpawnFn.mockImplementation((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return child as never
    })

    const controller = new AbortController()
    setRunnerAbortSignal(controller.signal)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread -- Module.apply, not Function.prototype.apply
    const applyPromise = module_.apply(null, emptyEnv)
    // Trigger abort while the child is still hanging (no `close` emitted).
    queueMicrotask(() => {
      controller.abort()
    })
    const result = await applyPromise

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("aborted")
    expect(killCalls).toContain("SIGTERM")
  })

  it("kills the op child and fails when a call times out without runner abort", async () => {
    vi.useFakeTimers()
    const killCalls: NodeJS.Signals[] = []
    const child = new EventEmitter() as MockChildProcess
    Object.defineProperty(child, "stdout", { value: new EventEmitter() })
    Object.defineProperty(child, "stderr", { value: new EventEmitter() })
    Object.defineProperty(child, "exitCode", { value: null })
    Object.defineProperty(child, "signalCode", { value: null })
    Object.defineProperty(child, "killed", { value: false })
    ;(child as unknown as { kill: (signal: NodeJS.Signals) => void }).kill = (
      signal: NodeJS.Signals
    ) => {
      killCalls.push(signal)
    }
    child.stdin = Object.assign(new EventEmitter(), {
      end: vi.fn(),
      once: vi.fn(function once(
        this: EventEmitter,
        eventName: string,
        listener: (...arguments_: unknown[]) => void
      ) {
        EventEmitter.prototype.once.call(this, eventName, listener)
        return this
      }),
    })
    mockedSpawnFn.mockImplementation((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return child as never
    })

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread -- Module.apply, not Function.prototype.apply
    const applyPromise = module_.apply(null, emptyEnv)
    await vi.advanceTimersByTimeAsync(60_000)
    const result = await applyPromise

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Failed to resolve 1Password references")
    expect(result.error?.message).toContain("op timed out after 60000ms")
    expect(killCalls).toContain("SIGTERM")
  })

  it("escalates to SIGKILL after SIGTERM when the child has not exited", async () => {
    vi.useFakeTimers()
    const killCalls: NodeJS.Signals[] = []
    let killed = false
    const child = new EventEmitter() as MockChildProcess
    Object.defineProperty(child, "stdout", { value: new EventEmitter() })
    Object.defineProperty(child, "stderr", { value: new EventEmitter() })
    Object.defineProperty(child, "exitCode", { value: null })
    Object.defineProperty(child, "signalCode", { value: null })
    Object.defineProperty(child, "killed", {
      get() {
        return killed
      },
    })
    ;(child as unknown as { kill: (signal: NodeJS.Signals) => void }).kill = (
      signal: NodeJS.Signals
    ) => {
      killCalls.push(signal)
      killed = true
    }
    child.stdin = Object.assign(new EventEmitter(), {
      end: vi.fn(),
      once: vi.fn(function once(
        this: EventEmitter,
        eventName: string,
        listener: (...arguments_: unknown[]) => void
      ) {
        EventEmitter.prototype.once.call(this, eventName, listener)
        return this
      }),
    })
    mockedSpawnFn.mockImplementation((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return child as never
    })

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread -- Module.apply, not Function.prototype.apply
    const applyPromise = module_.apply(null, emptyEnv)
    await vi.advanceTimersByTimeAsync(60_000)
    const result = await applyPromise
    await vi.advanceTimersByTimeAsync(1000)

    expect(result.status).toBe("failed")
    expect(killCalls).toStrictEqual(["SIGTERM", "SIGKILL"])
  })
})
