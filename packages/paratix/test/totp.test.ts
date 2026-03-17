import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { generateTotpCode } from "../src/totp.js"

// RFC 6238 Appendix B test secret (ASCII "12345678901234567890") encoded as Base32
const RFC_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// ---------------------------------------------------------------------------
// RFC 6238 test vectors
// ---------------------------------------------------------------------------

describe("generateTotpCode — RFC 6238 test vectors", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("produces 287082 at unix time 59 (counter=1, SHA1, 6 digits)", () => {
    vi.setSystemTime(59 * 1000)
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(uri)).toBe("287082")
  })

  it("produces 081804 at unix time 1111111109 (counter=37037037)", () => {
    vi.setSystemTime(1_111_111_109 * 1000)
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(uri)).toBe("081804")
  })

  it("produces 050471 at unix time 1111111111 (counter=37037037)", () => {
    vi.setSystemTime(1_111_111_111 * 1000)
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(uri)).toBe("050471")
  })

  it("produces 005924 at unix time 1234567890 (counter=41152263)", () => {
    vi.setSystemTime(1_234_567_890 * 1000)
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(uri)).toBe("005924")
  })
})

// ---------------------------------------------------------------------------
// URI parameter support
// ---------------------------------------------------------------------------

describe("generateTotpCode — URI parameters", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(59 * 1000)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("defaults to period=30 when not specified in URI", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    // counter at t=59 with period=30 is floor(59/30)=1 → code 287082
    expect(generateTotpCode(uri)).toBe("287082")
  })

  it("respects a custom period from the URI", () => {
    // period=60 → counter at t=59 is floor(59/60)=0 → different code than period=30
    const uriPeriod30 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&period=30`
    const uriPeriod60 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&period=60`

    const codePeriod30 = generateTotpCode(uriPeriod30)
    const codePeriod60 = generateTotpCode(uriPeriod60)

    // The two counters differ (1 vs 0), so the codes must differ
    expect(codePeriod30).not.toBe(codePeriod60)
  })

  it("defaults to 6 digits when not specified in URI", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(uri)).toHaveLength(6)
  })

  it("respects custom digits from the URI (8 digits)", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&digits=8`
    const code = generateTotpCode(uri)
    expect(code).toHaveLength(8)
  })

  it("zero-pads codes shorter than the requested digit length", () => {
    // Set time so the truncated value produces a short number.
    // We use a known vector where the 6-digit code starts with "0": t=1234567890 → "005924"
    vi.setSystemTime(1_234_567_890 * 1000)
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    const code = generateTotpCode(uri)
    expect(code).toBe("005924")
    expect(code).toHaveLength(6)
  })
})

// ---------------------------------------------------------------------------
// Base32 decoding
// ---------------------------------------------------------------------------

describe("generateTotpCode — Base32 decoding", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(59 * 1000)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("accepts lower-case Base32 secrets", () => {
    const lowerUri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32.toLowerCase()}`
    const upperUri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(lowerUri)).toBe(generateTotpCode(upperUri))
  })

  it("ignores padding characters (=) in the secret", () => {
    const paddedUri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}====`
    const plainUri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    expect(generateTotpCode(paddedUri)).toBe(generateTotpCode(plainUri))
  })

  it("throws on invalid Base32 characters in the secret", () => {
    const invalidUri = "otpauth://totp/Test?secret=INVALID!@#$"
    expect(() => generateTotpCode(invalidUri)).toThrow(/Invalid Base32 character/v)
  })
})

// ---------------------------------------------------------------------------
// algorithm parameter
// ---------------------------------------------------------------------------

describe("generateTotpCode — algorithm parameter", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(59 * 1000)
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it("defaults to SHA1 when algorithm is not specified", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    // RFC 6238 Appendix B vector: t=59, SHA1, 6 digits → 287082
    expect(generateTotpCode(uri)).toBe("287082")
  })

  it("produces a different code with algorithm=SHA256 than with SHA1", () => {
    const uriSha1 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    const uriSha256 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=SHA256`
    expect(generateTotpCode(uriSha1)).not.toBe(generateTotpCode(uriSha256))
  })

  it("produces a different code with algorithm=SHA512 than with SHA1 and SHA256", () => {
    const uriSha1 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}`
    const uriSha256 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=SHA256`
    const uriSha512 = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=SHA512`
    const codeSha1 = generateTotpCode(uriSha1)
    const codeSha256 = generateTotpCode(uriSha256)
    const codeSha512 = generateTotpCode(uriSha512)
    expect(codeSha512).not.toBe(codeSha1)
    expect(codeSha512).not.toBe(codeSha256)
  })

  it("is case-insensitive (sha256 works like SHA256)", () => {
    const uriLower = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=sha256`
    const uriUpper = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=SHA256`
    expect(generateTotpCode(uriLower)).toBe(generateTotpCode(uriUpper))
  })

  it("accepts mixed case (Sha256)", () => {
    const uriMixed = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=Sha256`
    const uriUpper = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=SHA256`
    expect(generateTotpCode(uriMixed)).toBe(generateTotpCode(uriUpper))
  })
})

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("generateTotpCode — error handling", () => {
  it("throws when the secret parameter is missing", () => {
    const uri = "otpauth://totp/Test"
    expect(() => generateTotpCode(uri)).toThrow(/secret/v)
  })

  it("throws when the secret parameter is an empty string", () => {
    const uri = "otpauth://totp/Test?secret="
    expect(() => generateTotpCode(uri)).toThrow(/secret/v)
  })

  // period validation
  it("throws when period=0", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&period=0`
    expect(() => generateTotpCode(uri)).toThrow(/period/v)
  })

  it("throws when period=-1", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&period=-1`
    expect(() => generateTotpCode(uri)).toThrow(/period/v)
  })

  it("throws when period is non-numeric (NaN)", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&period=abc`
    expect(() => generateTotpCode(uri)).toThrow(/period/v)
  })

  // digits validation
  it("throws when digits=0", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&digits=0`
    expect(() => generateTotpCode(uri)).toThrow(/digits/v)
  })

  it("throws when digits=-1", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&digits=-1`
    expect(() => generateTotpCode(uri)).toThrow(/digits/v)
  })

  it("throws when digits=11 (exceeds maximum of 10)", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&digits=11`
    expect(() => generateTotpCode(uri)).toThrow(/digits/v)
  })

  it("throws when digits is non-numeric (NaN)", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&digits=abc`
    expect(() => generateTotpCode(uri)).toThrow(/digits/v)
  })

  // algorithm validation
  it("throws when algorithm is unsupported", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=MD5`
    expect(() => generateTotpCode(uri)).toThrow(/algorithm/v)
  })

  it("throws when algorithm is empty string", () => {
    const uri = `otpauth://totp/Test?secret=${RFC_SECRET_BASE32}&algorithm=`
    expect(() => generateTotpCode(uri)).toThrow(/algorithm/v)
  })
})
