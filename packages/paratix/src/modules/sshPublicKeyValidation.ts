import { extractAlgoFromKey } from "../knownHosts.js"

const UINT32_SIZE = 4
const ED25519_PUBLIC_KEY_SIZE = 32
const SK_ECDSA_SHA2_NISTP256_ALGORITHM = "sk-ecdsa-sha2-nistp256@openssh.com"
const SK_SSH_ED25519_ALGORITHM = "sk-ssh-ed25519@openssh.com"
const SSH_ED25519_ALGORITHM = "ssh-ed25519"
const STRICT_BASE64_PATTERN = /^[A-Za-z0-9+\/]+=*$/v
const AUTHORIZED_KEY_ALGORITHMS = new Set([
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  SK_ECDSA_SHA2_NISTP256_ALGORITHM,
  SK_SSH_ED25519_ALGORITHM,
  SSH_ED25519_ALGORITHM,
  "ssh-rsa",
])

type SshStringField = {
  nextOffset: number
  value: Buffer
}

function readSshStringField(buffer: Buffer, offset: number): SshStringField {
  if (offset + UINT32_SIZE > buffer.length) throw new Error("truncated SSH string length")
  const length = buffer.readUInt32BE(offset)
  const valueStart = offset + UINT32_SIZE
  const valueEnd = valueStart + length
  if (valueEnd > buffer.length) throw new Error("truncated SSH string value")
  return { nextOffset: valueEnd, value: buffer.subarray(valueStart, valueEnd) }
}

function assertNoTrailingKeyBlobData(buffer: Buffer, offset: number): void {
  if (offset !== buffer.length) throw new Error("unexpected trailing key data")
}

function assertEd25519KeyBlobShape(algorithm: string, keyBuffer: Buffer, offset: number): void {
  const keyField = readSshStringField(keyBuffer, offset)
  if (keyField.value.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`${algorithm} key payload must be ${ED25519_PUBLIC_KEY_SIZE} bytes`)
  }
  const nextOffset =
    algorithm === SK_SSH_ED25519_ALGORITHM
      ? readSshStringField(keyBuffer, keyField.nextOffset).nextOffset
      : keyField.nextOffset
  assertNoTrailingKeyBlobData(keyBuffer, nextOffset)
}

function assertEcdsaKeyBlobShape(algorithm: string, keyBuffer: Buffer, offset: number): void {
  const curveField = readSshStringField(keyBuffer, offset)
  const keyField = readSshStringField(keyBuffer, curveField.nextOffset)
  if (curveField.value.length === 0 || keyField.value.length === 0) {
    throw new Error(`${algorithm} key payload is incomplete`)
  }
  const nextOffset = algorithm.startsWith("sk-ecdsa-sha2-")
    ? readSshStringField(keyBuffer, keyField.nextOffset).nextOffset
    : keyField.nextOffset
  assertNoTrailingKeyBlobData(keyBuffer, nextOffset)
}

function assertRsaKeyBlobShape(algorithm: string, keyBuffer: Buffer, offset: number): void {
  const exponentField = readSshStringField(keyBuffer, offset)
  const modulusField = readSshStringField(keyBuffer, exponentField.nextOffset)
  if (exponentField.value.length === 0 || modulusField.value.length === 0) {
    throw new Error(`${algorithm} key payload is incomplete`)
  }
  assertNoTrailingKeyBlobData(keyBuffer, modulusField.nextOffset)
}

function assertEncodedAlgorithm(algorithm: string, encodedAlgorithm: string): void {
  if (encodedAlgorithm !== algorithm) {
    throw new Error(
      `algorithm ${algorithm} does not match encoded key algorithm ${encodedAlgorithm}`
    )
  }
}

function assertAuthorizedKeyBlobShape(algorithm: string, keyBuffer: Buffer): void {
  const firstField = readSshStringField(keyBuffer, 0)
  assertEncodedAlgorithm(algorithm, firstField.value.toString("ascii"))
  if (algorithm === SSH_ED25519_ALGORITHM || algorithm === SK_SSH_ED25519_ALGORITHM) {
    assertEd25519KeyBlobShape(algorithm, keyBuffer, firstField.nextOffset)
    return
  }
  if (algorithm.startsWith("ecdsa-sha2-") || algorithm.startsWith("sk-ecdsa-sha2-")) {
    assertEcdsaKeyBlobShape(algorithm, keyBuffer, firstField.nextOffset)
    return
  }
  assertRsaKeyBlobShape(algorithm, keyBuffer, firstField.nextOffset)
}

function parseAuthorizedKeyParts(value: string): [string, string] {
  const parts = value.trim().split(/\s+/v)
  if (parts.length < 2) {
    throw new Error(
      "ssh.authorizedKeys requires a full public key in the format '<algorithm> <base64>'"
    )
  }
  return [parts[0], parts[1]]
}

export function assertAuthorizedKeyValue(value: string): void {
  if (value.length === 0) throw new Error("ssh.authorizedKeys: key must not be empty")
  if (/[\n\r]/v.test(value)) {
    throw new Error(`ssh.authorizedKeys: key must not contain newlines: ${JSON.stringify(value)}`)
  }
  const [algorithm, base64Key] = parseAuthorizedKeyParts(value)
  if (!AUTHORIZED_KEY_ALGORITHMS.has(algorithm)) {
    throw new Error(`ssh.authorizedKeys: unsupported public key algorithm: ${algorithm}`)
  }
  if (!STRICT_BASE64_PATTERN.test(base64Key)) {
    throw new Error("ssh.authorizedKeys: key field must be strict base64")
  }
  const keyBuffer = Buffer.from(base64Key, "base64")
  try {
    extractAlgoFromKey(keyBuffer)
    assertAuthorizedKeyBlobShape(algorithm, keyBuffer)
  } catch (error) {
    throw new Error("ssh.authorizedKeys: key field is not a valid OpenSSH public key", {
      cause: error,
    })
  }
}
