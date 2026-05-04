import { createPublicKey } from "node:crypto"

type ReadResult<T> = {
  nextOffset: number
  value: T
}

const UINT32_BYTE_LENGTH = 4
const ED25519_PUBLIC_KEY_BYTE_LENGTH = 32
const NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH = 65
const NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH = 97
const NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH = 133
const MPINT_SIGN_BIT = 0x80
const UNCOMPRESSED_EC_POINT_PREFIX = 0x04
const MINIMUM_RSA_MODULUS_BITS = 2048
const MINIMUM_RSA_EXPONENT = 3n
const BITS_PER_BYTE = 8

const ecdsaCurveNames = new Map([
  ["ecdsa-sha2-nistp256", "nistp256"],
  ["ecdsa-sha2-nistp384", "nistp384"],
  ["ecdsa-sha2-nistp521", "nistp521"],
  ["sk-ecdsa-sha2-nistp256@openssh.com", "nistp256"],
])

const ecdsaPointLengths = new Map([
  ["nistp256", NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH],
  ["nistp384", NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH],
  ["nistp521", NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH],
])

const ecdsaJwkCurveNames = new Map([
  ["nistp256", "P-256"],
  ["nistp384", "P-384"],
  ["nistp521", "P-521"],
])

function readUint32(value: Buffer, offset: number): null | ReadResult<number> {
  if (offset + UINT32_BYTE_LENGTH > value.length) return null
  return {
    nextOffset: offset + UINT32_BYTE_LENGTH,
    value: value.readUInt32BE(offset),
  }
}

function readWireString(value: Buffer, offset: number): null | ReadResult<Buffer> {
  const lengthResult = readUint32(value, offset)
  if (lengthResult == null) return null

  const endOffset = lengthResult.nextOffset + lengthResult.value
  if (endOffset > value.length) return null

  return {
    nextOffset: endOffset,
    value: value.subarray(lengthResult.nextOffset, endOffset),
  }
}

function readWireStringUtf8(value: Buffer, offset: number): null | ReadResult<string> {
  const result = readWireString(value, offset)
  return result == null
    ? null
    : {
        nextOffset: result.nextOffset,
        value: result.value.toString("utf8"),
      }
}

function readMpint(value: Buffer, offset: number): null | ReadResult<Buffer> {
  const result = readWireString(value, offset)
  if (result == null || result.value.length === 0) return null
  return result
}

function isAtEnd(value: Buffer, offset: number): boolean {
  return offset === value.length
}

function isPositiveMpint(value: Buffer): boolean {
  return value[0] < MPINT_SIGN_BIT
}

function removeMpintSignPadding(value: Buffer): Buffer {
  let offset = 0
  while (offset < value.length - 1 && value[offset] === 0) {
    offset++
  }
  return value.subarray(offset)
}

function mpintToBigInt(value: Buffer): bigint {
  const normalizedValue = removeMpintSignPadding(value)
  let result = 0n
  for (const byte of normalizedValue) {
    result = (result << 8n) + BigInt(byte)
  }
  return result
}

function getMpintBitLength(value: Buffer): number {
  const normalizedValue = removeMpintSignPadding(value)
  const firstByte = normalizedValue[0]
  if (firstByte === 0) return 0

  return (normalizedValue.length - 1) * BITS_PER_BYTE + firstByte.toString(2).length
}

function hasValidRsaExponent(value: Buffer): boolean {
  const exponent = mpintToBigInt(value)
  return exponent >= MINIMUM_RSA_EXPONENT && (exponent & 1n) === 1n
}

function hasValidRsaModulus(value: Buffer): boolean {
  return getMpintBitLength(value) >= MINIMUM_RSA_MODULUS_BITS
}

function validateRsaWireKey(value: Buffer, offset: number): boolean {
  const exponent = readMpint(value, offset)
  if (
    exponent == null ||
    !isPositiveMpint(exponent.value) ||
    !hasValidRsaExponent(exponent.value)
  ) {
    return false
  }

  const modulus = readMpint(value, exponent.nextOffset)
  return (
    modulus != null &&
    isPositiveMpint(modulus.value) &&
    hasValidRsaModulus(modulus.value) &&
    isAtEnd(value, modulus.nextOffset)
  )
}

function hasValidEcdsaPoint(
  point: null | ReadResult<Buffer>,
  expectedPointLength: number | undefined
): point is ReadResult<Buffer> {
  if (point == null) return false
  return (
    point.value.length === expectedPointLength && point.value[0] === UNCOMPRESSED_EC_POINT_PREFIX
  )
}

function toBase64Url(value: Buffer): string {
  return value.toString("base64url")
}

function hasCryptographicallyValidEcdsaPoint(point: Buffer, curveName: string): boolean {
  const jwkCurveName = ecdsaJwkCurveNames.get(curveName)
  if (jwkCurveName == null) return false

  const coordinateLength = (point.length - 1) / 2
  const x = point.subarray(1, 1 + coordinateLength)
  const y = point.subarray(1 + coordinateLength)

  try {
    createPublicKey({
      format: "jwk",
      key: {
        crv: jwkCurveName,
        kty: "EC",
        x: toBase64Url(x),
        y: toBase64Url(y),
      },
    })
    return true
  } catch {
    return false
  }
}

function validateEcdsaWireKey(value: Buffer, offset: number, algorithm: string): boolean {
  const expectedCurveName = ecdsaCurveNames.get(algorithm)
  if (expectedCurveName == null) return false

  const curveName = readWireStringUtf8(value, offset)
  if (curveName?.value !== expectedCurveName) return false

  const point = readWireString(value, curveName.nextOffset)
  const expectedPointLength = ecdsaPointLengths.get(curveName.value)
  if (!hasValidEcdsaPoint(point, expectedPointLength)) return false
  if (!hasCryptographicallyValidEcdsaPoint(point.value, curveName.value)) return false

  if (algorithm !== "sk-ecdsa-sha2-nistp256@openssh.com") {
    return isAtEnd(value, point.nextOffset)
  }

  const application = readWireString(value, point.nextOffset)
  if (application?.value.length === undefined || application.value.length === 0) return false
  return isAtEnd(value, application.nextOffset)
}

function validateEd25519WireKey(value: Buffer, offset: number, algorithm: string): boolean {
  const publicKey = readWireString(value, offset)
  if (publicKey?.value.length !== ED25519_PUBLIC_KEY_BYTE_LENGTH) return false

  if (algorithm !== "sk-ssh-ed25519@openssh.com") {
    return isAtEnd(value, publicKey.nextOffset)
  }

  const application = readWireString(value, publicKey.nextOffset)
  if (application?.value.length === undefined || application.value.length === 0) return false
  return isAtEnd(value, application.nextOffset)
}

export function hasValidOpenSshPublicKeyWireBlob(algorithm: string, encodedKey: string): boolean {
  const decodedKey = Buffer.from(encodedKey, "base64")
  const wireAlgorithm = readWireStringUtf8(decodedKey, 0)

  if (wireAlgorithm?.value !== algorithm) return false

  if (algorithm === "ssh-rsa") return validateRsaWireKey(decodedKey, wireAlgorithm.nextOffset)
  if (algorithm.startsWith("ecdsa-") || algorithm.startsWith("sk-ecdsa-")) {
    return validateEcdsaWireKey(decodedKey, wireAlgorithm.nextOffset, algorithm)
  }
  if (algorithm === "ssh-ed25519" || algorithm === "sk-ssh-ed25519@openssh.com") {
    return validateEd25519WireKey(decodedKey, wireAlgorithm.nextOffset, algorithm)
  }

  return false
}
