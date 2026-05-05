import type * as childProcess from "node:child_process"

import { EventEmitter } from "node:events"
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest"

import { resolveEnvironment } from "../../src/environment.js"
import { mergeEnvironmentFromMeta } from "../../src/meta.js"
import { op } from "../../src/modules/op.js"
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

function mockSpawnWithStdinError(error: Error): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    trackSpawn(command, args ?? [])
    const child = createMockChild("", 0)
    child.stdin.end.mockImplementationOnce(() => {
      child.stdin.emit("error", error)
    })
    return child as never
  })
}

function mockSpawnBySubcommand(outputs: Record<string, string>): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    const argsList = args ?? []
    trackSpawn(command, argsList)
    const subcommand = argsList[0] ?? ""
    const output = outputs[subcommand] ?? ""
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

  it("resolves regular secrets via op inject and returns them as meta", async () => {
    mockSpawnWith(JSON.stringify({ password: "secret123" }))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    const metaEnvironment = await mergeEnvironmentFromMeta({}, result.meta)
    await expect(resolveEnvironment(metaEnvironment, "password")).resolves.toBe("secret123")
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

  it("registers each generated OTP code in the secret sink", async () => {
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
    expect(getRegisteredSecrets()).toContain(code)
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
    // op inject must NOT have been called for OTP-only references
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

  it("returns { status: 'failed' } when op inject throws", async () => {
    mockSpawnWith("", 1)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Failed to resolve 1Password references")
  })

  it("returns failed when op stdin emits an error", async () => {
    mockSpawnWithStdinError(new Error("write EPIPE"))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("write EPIPE")
  })

  it("returns { status: 'failed' } when op read throws", async () => {
    mockSpawnWith("", 1)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("Failed to resolve 1Password references")
  })

  it("calls op inject only once for multiple regular references (batch)", async () => {
    mockSpawnWith(JSON.stringify({ apiKey: "key123", dbPassword: "db456" }))

    const module_ = op.resolve({
      apiKey: "op://vault/item/api-key",
      dbPassword: "op://vault/item/db-password",
    })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    expect(spawnCalls).toHaveLength(1)
    expect(spawnCalls[0].args).toStrictEqual(["inject"])
  })

  it("does not call op inject when only OTP fields are present", async () => {
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

    mockSpawnBySubcommand({
      inject: JSON.stringify({ password: "secret123" }),
      read: `${otpauthUri}\n`,
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
// JSON validation
// ---------------------------------------------------------------------------

describe("op.resolve — JSON validation", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    clearRegisteredSecrets()
    spawnCalls = []
  })

  afterEach(() => {
    clearRegisteredSecrets()
  })

  it("returns failed when op inject returns an array", async () => {
    mockSpawnWith(JSON.stringify(["not", "an", "object"]))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("unexpected non-object JSON")
  })

  it("returns failed when op inject returns non-string values", async () => {
    mockSpawnWith(JSON.stringify({ password: 42 }))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).toContain("non-string values")
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

  it("masks the resolved regular secret value when it leaks into op stderr", async () => {
    const resolvedValue = "super-secret-resolved-value-12345"
    // Two op calls: the first inject succeeds and resolves the secret, the
    // second op read for the OTP fails with stderr that contains the
    // already-resolved value (e.g. via a stack trace or echoing).
    const stderrLeak = `connection failed; last value=${resolvedValue}`
    mockSpawnBySubcommand({})
    mockedSpawnFn.mockImplementationOnce(((command: string, args: readonly string[]) => {
      trackSpawn(command, args)
      return createMockChild(JSON.stringify({ password: resolvedValue }))
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

  it("does not include raw stdout in the failure message when JSON parsing fails", async () => {
    const sneakySecret = "super-secret-resolved-value"
    // Invalid JSON: `op` produced raw secret-like output instead of JSON.
    mockSpawnWith(sneakySecret, 0)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
    expect(result.error?.message).not.toContain(sneakySecret)
    expect(result.error?.message).toContain("invalid JSON")
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
