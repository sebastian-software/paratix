import type * as childProcess from "node:child_process"

import { EventEmitter } from "node:events"
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest"

import { op } from "../../src/modules/op.js"

type MockChildProcess = { stdin: { end: Mock } } & EventEmitter

function createMockChild(stdout: string, exitCode = 0): MockChildProcess {
  const child = new EventEmitter() as MockChildProcess
  const stdoutEmitter = new EventEmitter()
  const stderrEmitter = new EventEmitter()
  Object.defineProperty(child, "stdout", { value: stdoutEmitter })
  Object.defineProperty(child, "stderr", { value: stderrEmitter })
  child.stdin = { end: vi.fn() }

  // Emit data and close asynchronously so listeners are registered first
  queueMicrotask(() => {
    stdoutEmitter.emit("data", Buffer.from(stdout))
    child.emit("close", exitCode)
  })

  return child
}

type SpawnCall = { args: string[]; command: string }

let spawnCalls: SpawnCall[] = []

function trackSpawn(command: string, args: readonly string[]): void {
  spawnCalls.push({ args: [...args], command })
}

function mockSpawnWith(output: string, exitCode = 0): void {
  mockedSpawnFn.mockImplementation((command: string, args?: readonly string[]) => {
    trackSpawn(command, args ?? [])
    return createMockChild(output, exitCode) as never
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
    spawnCalls = []
    mockSpawnWith("")
  })

  it("resolves regular secrets via op inject and returns them as meta", async () => {
    mockSpawnWith(JSON.stringify({ password: "secret123" }))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta).toStrictEqual({ password: "secret123" })
  })

  it("resolves OTP fields via op read and returns lazy functions as meta", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(typeof result.meta?.token).toBe("function")
  })

  it("calls the lazy OTP function and returns a 6-digit string", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    const lazyFunction = result.meta?.token as () => string
    const code = lazyFunction()
    expect(code).toMatch(/^\d{6}$/v)
  })

  it("recognises OTP fields by /one-time-password suffix", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockSpawnWith(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta?.token).toBeTypeOf("function")
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
    expect(result.meta?.token).toBeTypeOf("function")
  })

  it("returns { status: 'failed' } when op inject throws", async () => {
    mockSpawnWith("", 1)

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("returns { status: 'failed' } when op read throws", async () => {
    mockSpawnWith("", 1)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
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
    expect(result.meta).toStrictEqual({})
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
    expect(result.meta?.password).toBe("secret123")
    expect(result.meta?.token).toBeTypeOf("function")
  })
})

// ---------------------------------------------------------------------------
// JSON validation
// ---------------------------------------------------------------------------

describe("op.resolve — JSON validation", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    spawnCalls = []
  })

  it("returns failed when op inject returns an array", async () => {
    mockSpawnWith(JSON.stringify(["not", "an", "object"]))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("returns failed when op inject returns non-string values", async () => {
    mockSpawnWith(JSON.stringify({ password: 42 }))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
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
// error logging (bug: catch ohne Logging)
// ---------------------------------------------------------------------------

describe("op.resolve — error logging on failure", () => {
  beforeEach(() => {
    vi.resetAllMocks()
    spawnCalls = []
  })

  it("logs the error before returning { status: 'failed' } when op inject throws", async () => {
    // Arrange: op inject schlaegt fehl (exit code 1)
    mockSpawnWith("", 1)
    const consoleSpy = vi.spyOn(console, "error")

    const module_ = op.resolve({ password: "op://vault/item/password" })

    // Act
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    // Assert: Fehler muss geloggt werden BEVOR { status: 'failed' } zurueckgegeben wird.
    // Generische Meldung ohne sensitive Details aus stderr.
    expect(result.status).toBe("failed")
    expect(consoleSpy).toHaveBeenCalledWith("Failed to resolve 1Password references")
  })

  it("logs the error before returning { status: 'failed' } when op read throws", async () => {
    // Arrange: op read schlaegt fehl (exit code 1)
    mockSpawnWith("", 1)
    const consoleSpy = vi.spyOn(console, "error")

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })

    // Act
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    // Assert: Fehler muss geloggt werden.
    // Generische Meldung ohne sensitive Details aus stderr.
    expect(result.status).toBe("failed")
    expect(consoleSpy).toHaveBeenCalledWith("Failed to resolve 1Password references")
  })
})
