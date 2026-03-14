import { createHmac } from "node:crypto"

/** Number of bits per Base32 character. */
const BASE32_BITS_PER_CHAR = 5

/** Number of bits per byte. */
const BITS_PER_BYTE = 8

/** Size of the HMAC counter buffer in bytes (64-bit big-endian). */
const COUNTER_BUFFER_SIZE = 8

/** Bitmask to extract the lower 4 bits for the HMAC offset. */
const OFFSET_MASK = 0x0f

/** Bitmask to clear the sign bit on the first truncated byte. */
const SIGN_BIT_MASK = 0x7f

/** Bitmask for a full byte. */
const BYTE_MASK = 0xff

/** Bit shift for the first byte in the truncated 32-bit value. */
const SHIFT_24 = 24

/** Bit shift for the second byte in the truncated 32-bit value. */
const SHIFT_16 = 16

/** Byte offset constants for dynamic truncation. */
const TRUNCATION_BYTE_1 = 1
const TRUNCATION_BYTE_2 = 2
const TRUNCATION_BYTE_3 = 3

/** Milliseconds per second. */
const MILLISECONDS_PER_SECOND = 1000

/** Base for decimal digit extraction. */
const DECIMAL_BASE = 10

/** Default TOTP period in seconds. */
const DEFAULT_PERIOD = 30

/** Default number of TOTP digits. */
const DEFAULT_DIGITS = 6

/**
 * Decode a Base32-encoded string (RFC 4648) into a Buffer.
 *
 * Padding characters (`=`) and whitespace are stripped before decoding.
 * The alphabet used is `A–Z` and `2–7` (standard Base32, not Base32hex).
 *
 * @param encoded - The Base32 string to decode (case-insensitive, padding optional).
 * @returns A Buffer containing the decoded bytes.
 * @throws {Error} If the string contains a character outside the Base32 alphabet.
 */
function decodeBase32(encoded: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const stripped = encoded.toUpperCase().replaceAll(/[=\s]/gv, "")

  let bits = ""
  for (const character of stripped) {
    const index = alphabet.indexOf(character)
    if (index === -1) {
      throw new Error(`Invalid Base32 character: ${character}`)
    }
    bits += index.toString(2).padStart(BASE32_BITS_PER_CHAR, "0")
  }

  const bytes: number[] = []
  for (let index = 0; index + BITS_PER_BYTE <= bits.length; index += BITS_PER_BYTE) {
    bytes.push(Number.parseInt(bits.slice(index, index + BITS_PER_BYTE), 2))
  }

  return Buffer.from(bytes)
}

/**
 * Perform HMAC-SHA1 dynamic truncation on the digest to produce a numeric code.
 *
 * @param hmacDigest - The raw HMAC-SHA1 digest buffer.
 * @param digits - Number of digits for the output code.
 * @returns The zero-padded TOTP code string.
 */
function truncateHmac(hmacDigest: Buffer, digits: number): string {
  const offset = (hmacDigest.at(-1) ?? 0) & OFFSET_MASK
  const binaryCode =
    (((hmacDigest.at(offset) ?? 0) & SIGN_BIT_MASK) << SHIFT_24) |
    (((hmacDigest.at(offset + TRUNCATION_BYTE_1) ?? 0) & BYTE_MASK) << SHIFT_16) |
    (((hmacDigest.at(offset + TRUNCATION_BYTE_2) ?? 0) & BYTE_MASK) << BITS_PER_BYTE) |
    ((hmacDigest.at(offset + TRUNCATION_BYTE_3) ?? 0) & BYTE_MASK)

  const otp = binaryCode % DECIMAL_BASE ** digits
  return otp.toString().padStart(digits, "0")
}

/**
 * Generate a TOTP code from an `otpauth://totp/...` URI according to RFC 6238.
 *
 * The URI is parsed for `secret`, `period` (default 30), and `digits` (default 6).
 * Uses HMAC-SHA1 with dynamic truncation to produce a numeric one-time password.
 *
 * @param otpauthUri - A fully-qualified `otpauth://totp/...` URI containing at
 *   least a `secret` query parameter with a Base32-encoded shared secret.
 * @returns The zero-padded TOTP code as a string (length determined by `digits`).
 * @throws {Error} If the URI is missing the `secret` parameter.
 * @throws {Error} If the `secret` contains characters outside the Base32 alphabet.
 * @see {@link https://datatracker.ietf.org/doc/html/rfc6238 RFC 6238 – TOTP}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc4226 RFC 4226 – HOTP}
 */
export function generateTotpCode(otpauthUri: string): string {
  const url = new URL(otpauthUri)

  const secret = url.searchParams.get("secret")
  if (secret == null || secret === "") {
    throw new Error("TOTP URI is missing the 'secret' parameter")
  }

  const period = Number.parseInt(
    url.searchParams.get("period") ?? String(DEFAULT_PERIOD),
    DECIMAL_BASE
  )
  const digits = Number.parseInt(
    url.searchParams.get("digits") ?? String(DEFAULT_DIGITS),
    DECIMAL_BASE
  )

  const key = decodeBase32(secret)

  // Calculate the time-based counter
  const counter = Math.floor(Date.now() / MILLISECONDS_PER_SECOND / period)

  // Encode counter as big-endian 8-byte buffer
  const counterBuffer = Buffer.alloc(COUNTER_BUFFER_SIZE)
  counterBuffer.writeBigUInt64BE(BigInt(counter))

  // Compute HMAC-SHA1 and apply dynamic truncation
  const hmacDigest = createHmac("sha1", key).update(counterBuffer).digest()
  return truncateHmac(hmacDigest, digits)
}
