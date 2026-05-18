import { createPublicKey } from "node:crypto"

const SSH_WIRE_LENGTH_FIELD_BYTES = 4
const ED25519_PUBLIC_KEY_BYTE_LENGTH = 32
const NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH = 65
const NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH = 97
const NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH = 133
const UNCOMPRESSED_EC_POINT_PREFIX = 0x04
const PRINTABLE_ASCII_MIN = 0x20
const PRINTABLE_ASCII_MAX = 0x7e

const ECDSA_CURVE_NAMES = new Map([
  ["ecdsa-sha2-nistp256", "nistp256"],
  ["ecdsa-sha2-nistp384", "nistp384"],
  ["ecdsa-sha2-nistp521", "nistp521"],
])

const ECDSA_POINT_LENGTHS = new Map([
  ["nistp256", NISTP256_UNCOMPRESSED_POINT_BYTE_LENGTH],
  ["nistp384", NISTP384_UNCOMPRESSED_POINT_BYTE_LENGTH],
  ["nistp521", NISTP521_UNCOMPRESSED_POINT_BYTE_LENGTH],
])

const ECDSA_JWK_CURVE_NAMES = new Map([
  ["nistp256", "P-256"],
  ["nistp384", "P-384"],
  ["nistp521", "P-521"],
])

type WireReadResult = {
  nextOffset: number
  value: Buffer
}

function readWireString(value: Buffer, offset: number): null | WireReadResult {
  if (offset + SSH_WIRE_LENGTH_FIELD_BYTES > value.length) return null
  const length = value.readUInt32BE(offset)
  const start = offset + SSH_WIRE_LENGTH_FIELD_BYTES
  const end = start + length
  if (end > value.length) return null
  return { nextOffset: end, value: value.subarray(start, end) }
}

function throwInvalidHostKeyBlob(algorithm: string, detail: string): never {
  throw new Error(
    `Refusing to capture host fingerprint: malformed "${algorithm}" host key blob (${detail}). ` +
      `This may indicate a man-in-the-middle attack or a broken SSH peer.`
  )
}

function isPrintableAsciiByte(byte: number): boolean {
  return byte >= PRINTABLE_ASCII_MIN && byte <= PRINTABLE_ASCII_MAX
}

function validateEd25519HostKeyBlob(keyBuffer: Buffer, offset: number, algorithm: string): void {
  const publicKey = readWireString(keyBuffer, offset)
  if (publicKey == null) {
    throwInvalidHostKeyBlob(algorithm, "missing or truncated public-key field")
  }
  if (publicKey.value.length !== ED25519_PUBLIC_KEY_BYTE_LENGTH) {
    throwInvalidHostKeyBlob(
      algorithm,
      `expected ${String(ED25519_PUBLIC_KEY_BYTE_LENGTH)}-byte public key, got ${String(publicKey.value.length)}`
    )
  }
  if (publicKey.nextOffset !== keyBuffer.length) {
    throwInvalidHostKeyBlob(algorithm, "trailing data after public key")
  }
}

function assertEcdsaPointIsOnCurve(point: Buffer, curveName: string, algorithm: string): void {
  const jwkCurveName = ECDSA_JWK_CURVE_NAMES.get(curveName)
  if (jwkCurveName == null) {
    throwInvalidHostKeyBlob(algorithm, `unknown ECDSA curve "${curveName}"`)
  }

  const coordinateLength = (point.length - 1) / 2
  const x = point.subarray(1, 1 + coordinateLength)
  const y = point.subarray(1 + coordinateLength)

  try {
    createPublicKey({
      format: "jwk",
      key: {
        crv: jwkCurveName,
        kty: "EC",
        x: x.toString("base64url"),
        y: y.toString("base64url"),
      },
    })
  } catch {
    throwInvalidHostKeyBlob(algorithm, "EC point is not on the expected curve")
  }
}

type EcdsaCurveNameReadParameters = {
  algorithm: string
  expectedCurveName: string
  keyBuffer: Buffer
  offset: number
}

function readEcdsaCurveName(parameters: EcdsaCurveNameReadParameters): WireReadResult {
  const { algorithm, expectedCurveName, keyBuffer, offset } = parameters
  const curveName = readWireString(keyBuffer, offset)
  if (curveName == null) {
    throwInvalidHostKeyBlob(algorithm, "missing or truncated curve identifier")
  }
  for (const byte of curveName.value) {
    if (!isPrintableAsciiByte(byte)) {
      throwInvalidHostKeyBlob(algorithm, "curve identifier contains non-printable bytes")
    }
  }
  const curveNameValue = curveName.value.toString("ascii")
  if (curveNameValue !== expectedCurveName) {
    throwInvalidHostKeyBlob(
      algorithm,
      `curve identifier "${curveNameValue}" does not match "${expectedCurveName}"`
    )
  }
  return curveName
}

type EcdsaPointReadParameters = {
  algorithm: string
  expectedPointLength: number
  keyBuffer: Buffer
  offset: number
}

function readEcdsaPoint(parameters: EcdsaPointReadParameters): WireReadResult {
  const { algorithm, expectedPointLength, keyBuffer, offset } = parameters
  const point = readWireString(keyBuffer, offset)
  if (point == null) {
    throwInvalidHostKeyBlob(algorithm, "missing or truncated EC point field")
  }
  if (point.value.length !== expectedPointLength) {
    throwInvalidHostKeyBlob(
      algorithm,
      `expected ${String(expectedPointLength)}-byte EC point, got ${String(point.value.length)}`
    )
  }
  if (point.value[0] !== UNCOMPRESSED_EC_POINT_PREFIX) {
    throwInvalidHostKeyBlob(algorithm, "EC point is not in uncompressed form")
  }
  if (point.nextOffset !== keyBuffer.length) {
    throwInvalidHostKeyBlob(algorithm, "trailing data after EC point")
  }
  return point
}

function validateEcdsaHostKeyBlob(keyBuffer: Buffer, offset: number, algorithm: string): void {
  const expectedCurveName = ECDSA_CURVE_NAMES.get(algorithm)
  const expectedPointLength =
    expectedCurveName == null ? undefined : ECDSA_POINT_LENGTHS.get(expectedCurveName)
  if (expectedCurveName == null || expectedPointLength === undefined) {
    throwInvalidHostKeyBlob(algorithm, "no curve mapping for algorithm")
  }

  const curveName = readEcdsaCurveName({
    algorithm,
    expectedCurveName,
    keyBuffer,
    offset,
  })
  const point = readEcdsaPoint({
    algorithm,
    expectedPointLength,
    keyBuffer,
    offset: curveName.nextOffset,
  })
  assertEcdsaPointIsOnCurve(point.value, expectedCurveName, algorithm)
}

/**
 * Validate the OpenSSH SSH wire blob behind a host-key algorithm label.
 *
 * R-0000128: an algorithm label alone proves nothing — a MITM can ship
 * arbitrary bytes after the label. Rejecting malformed wire payloads
 * (truncated, wrong curve, point off-curve) before pinning a fingerprint
 * keeps create-paratix from anchoring trust to garbage.
 *
 * @param keyBuffer - Raw host-key wire blob as received from ssh2.
 * @param algorithm - Algorithm label already validated against the allowlist.
 * @throws {Error} When the blob does not match the algorithm's expected structure.
 */
export function validateHostKeyBlob(
  keyBuffer: Buffer,
  algorithm: string,
  payloadOffsetHint?: number
): void {
  // R-0000732: derive the payload offset from the wire format itself
  // rather than re-deriving it from the algorithm string. The previous
  // implementation computed `payloadOffset = 4 + Buffer.byteLength(algorithm)`
  // which assumes the wire-encoded algorithm length matches the
  // expected algorithm name. A peer could place a longer algorithm
  // string on the wire (e.g. padded with trailing bytes) and still
  // bypass the algorithm check upstream if it normalises differently.
  // Parsing the leading wire string here and comparing it byte-for-byte
  // against the expected algorithm closes that gap and gives us the
  // authoritative offset for the remainder of the payload.
  //
  // R-0000733: when the caller already parsed the algorithm wire field
  // (extractHostKeyAlgorithm in hostFingerprintBootstrap), it threads
  // the resulting nextOffset in via payloadOffsetHint. We still parse
  // the algorithm field locally to guarantee fail-closed behaviour for
  // direct callers, and assert that the hint matches the parsed
  // offset so the two callsites cannot drift.
  const algorithmField = readWireString(keyBuffer, 0)
  if (algorithmField == null) {
    throwInvalidHostKeyBlob(algorithm, "missing or truncated algorithm field")
  }
  const wireAlgorithm = algorithmField.value.toString("ascii")
  if (wireAlgorithm !== algorithm) {
    throwInvalidHostKeyBlob(
      algorithm,
      `algorithm field "${wireAlgorithm}" does not match expected "${algorithm}"`
    )
  }
  const payloadOffset = algorithmField.nextOffset
  if (payloadOffsetHint !== undefined && payloadOffsetHint !== payloadOffset) {
    throwInvalidHostKeyBlob(
      algorithm,
      `payload offset hint ${String(payloadOffsetHint)} does not match parsed offset ${String(payloadOffset)}`
    )
  }

  if (algorithm === "ssh-ed25519") {
    validateEd25519HostKeyBlob(keyBuffer, payloadOffset, algorithm)
    return
  }
  if (
    algorithm === "ecdsa-sha2-nistp256" ||
    algorithm === "ecdsa-sha2-nistp384" ||
    algorithm === "ecdsa-sha2-nistp521"
  ) {
    validateEcdsaHostKeyBlob(keyBuffer, payloadOffset, algorithm)
    return
  }

  // assertSupportedHostKeyAlgorithm guarantees we never reach this branch,
  // but keep an explicit fail-closed to defend against future allowlist
  // edits that forget to extend this switch.
  throwInvalidHostKeyBlob(algorithm, "no validator registered for algorithm")
}
