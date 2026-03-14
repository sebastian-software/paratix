import { execFileSync } from "node:child_process"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { op } from "../../src/modules/op.js"

vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
}))

const emptyEnv = {}

const mockedExecFileSync = vi.mocked(execFileSync)

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

describe("op.resolve — check", () => {
  it("always returns ok", async () => {
    const module_ = op.resolve({})
    const result = await module_.check(null, emptyEnv)
    expect(result).toBe("ok")
  })

  it("returns ok regardless of references", async () => {
    const module_ = op.resolve({ password: "op://vault/item/password" })
    const result = await module_.check(null, emptyEnv)
    expect(result).toBe("ok")
  })
})

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

describe("op.resolve — apply", () => {
  beforeEach(() => {
    vi.resetAllMocks()
  })

  it("resolves regular secrets via op inject and returns them as meta", async () => {
    mockedExecFileSync.mockReturnValue(JSON.stringify({ password: "secret123" }))

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta).toStrictEqual({ password: "secret123" })
  })

  it("resolves OTP fields via op read and returns lazy functions as meta", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockedExecFileSync.mockReturnValue(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(typeof result.meta?.token).toBe("function")
  })

  it("calls the lazy OTP function and returns a 6-digit string", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockedExecFileSync.mockReturnValue(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion -- test assertion on known mock shape
    const lazyFunction = result.meta?.token as () => string
    const code = lazyFunction()
    expect(code).toMatch(/^\d{6}$/v)
  })

  it("recognises OTP fields by /one-time-password suffix", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockedExecFileSync.mockReturnValue(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta?.token).toBeTypeOf("function")
    // op inject must NOT have been called for OTP-only references
    expect(mockedExecFileSync).not.toHaveBeenCalledWith("op", ["inject"], expect.anything())
  })

  it("recognises OTP fields by /otp suffix", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockedExecFileSync.mockReturnValue(`${otpauthUri}\n`)

    const module_ = op.resolve({ token: "op://vault/item/otp" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta?.token).toBeTypeOf("function")
  })

  it("returns { status: 'failed' } when op inject throws", async () => {
    mockedExecFileSync.mockImplementation(() => {
      throw new Error("op inject failed")
    })

    const module_ = op.resolve({ password: "op://vault/item/password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("returns { status: 'failed' } when op read throws", async () => {
    mockedExecFileSync.mockImplementation(() => {
      throw new Error("op read failed")
    })

    const module_ = op.resolve({ token: "op://vault/item/one-time-password" })
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("failed")
  })

  it("calls op inject only once for multiple regular references (batch)", async () => {
    mockedExecFileSync.mockReturnValue(JSON.stringify({ apiKey: "key123", dbPassword: "db456" }))

    const module_ = op.resolve({
      apiKey: "op://vault/item/api-key",
      dbPassword: "op://vault/item/db-password",
    })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    expect(mockedExecFileSync).toHaveBeenCalledTimes(1)
    expect(mockedExecFileSync).toHaveBeenCalledWith("op", ["inject"], expect.anything())
  })

  it("does not call op inject when only OTP fields are present", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"
    mockedExecFileSync.mockReturnValue(`${otpauthUri}\n`)

    const module_ = op.resolve({
      token: "op://vault/item/one-time-password",
    })
    // eslint-disable-next-line prefer-spread
    await module_.apply(null, emptyEnv)

    expect(mockedExecFileSync).not.toHaveBeenCalledWith("op", ["inject"], expect.anything())
  })

  it("works with an empty references object", async () => {
    const module_ = op.resolve({})
    // eslint-disable-next-line prefer-spread
    const result = await module_.apply(null, emptyEnv)

    expect(result.status).toBe("ok")
    expect(result.meta).toStrictEqual({})
    expect(mockedExecFileSync).not.toHaveBeenCalled()
  })

  it("merges regular and OTP meta into a single result", async () => {
    const otpauthUri =
      "otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6"

    // op inject is called first (regular secrets), then op read (OTP)
    mockedExecFileSync.mockReturnValueOnce(JSON.stringify({ password: "secret123" }))
    mockedExecFileSync.mockReturnValueOnce(`${otpauthUri}\n`)

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
