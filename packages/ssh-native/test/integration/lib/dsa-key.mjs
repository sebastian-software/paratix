// DSA private keys for the UNSUPPORTED_KEY test, built without
// `ssh-keygen -t dsa` (newer OpenSSH builds, e.g. on macOS 15, no longer
// generate DSA keys). Node generates the key; this module writes it as
// PKCS#8 PEM and as a hand-built `openssh-key-v1` file, the format
// `ssh-keygen -t dsa` used to produce.
import { generateKeyPairSync, randomBytes } from "node:crypto"

const TAG_INTEGER = 0x02
const TAG_OCTET_STRING = 0x04
const TAG_SEQUENCE = 0x30
const LONG_LENGTH = 0x80
const OPENSSH_BLOCK_SIZE = 8
const PEM_LINE_LENGTH = 70
const HIGH_BIT = 0x80

/**
 * @typedef {object} Tlv
 * @property {number} tag DER tag
 * @property {Buffer} value content octets
 * @property {number} end offset after the element
 */

/**
 * Reads one DER element.
 *
 * @param der the encoding
 * @param offset where the element starts
 * @returns tag, content and end offset
 */
function readTlv(der, offset) {
  const tag = der[offset]
  let length = der[offset + 1]
  let start = offset + 2
  if (length >= LONG_LENGTH) {
    const octets = length - LONG_LENGTH
    length = der.readUIntBE(start, octets)
    start += octets
  }
  return { end: start + length, tag, value: der.subarray(start, start + length) }
}

/**
 * Reads the elements of a constructed DER value.
 *
 * @param der content of a SEQUENCE
 * @returns its elements
 */
function readSequence(der) {
  /** @type {Tlv[]} */
  const elements = []
  for (let offset = 0; offset < der.length;) {
    const element = readTlv(der, offset)
    elements.push(element)
    offset = element.end
  }
  return elements
}

/**
 * @param tlv a DER element
 * @param tag the expected tag
 * @returns the content, after checking the tag
 */
function expectTag(tlv, tag) {
  if (tlv.tag !== tag) throw new Error(`unexpected DER tag ${tlv.tag}, expected ${tag}`)
  return tlv.value
}

/**
 * @param value a non-negative integer
 * @returns its SSH mpint content (big-endian, leading zero if the high bit is set)
 */
function mpintBytes(value) {
  let hex = value.toString(16)
  if (hex.length % 2 === 1) hex = `0${hex}`
  const bytes = Buffer.from(hex, "hex")
  return bytes[0] >= HIGH_BIT ? Buffer.concat([Buffer.from([0]), bytes]) : bytes
}

/**
 * @param bytes big-endian magnitude (DER INTEGER content of a positive value)
 * @returns the integer
 */
function toBigInt(bytes) {
  return BigInt(`0x${bytes.toString("hex")}`)
}

/**
 * @param base the number to raise
 * @param exponent the power, non-negative
 * @param modulus the DSA prime p
 * @returns base^exponent mod modulus
 */
function modPow(base, exponent, modulus) {
  const prime = BigInt(modulus)
  let result = 1n
  let factor = BigInt(base) % prime
  for (let rest = BigInt(exponent); rest > 0n; rest >>= 1n) {
    if (rest & 1n) result = (result * factor) % prime
    factor = (factor * factor) % prime
  }
  return result
}

/**
 * @param buffer content
 * @returns the SSH wire string
 */
function sshString(buffer) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(buffer.length)
  return Buffer.concat([length, buffer])
}

/**
 * @param value a 32-bit unsigned integer
 * @returns its wire encoding
 */
function uint32(value) {
  const bytes = Buffer.alloc(4)
  bytes.writeUInt32BE(value)
  return bytes
}

/**
 * Extracts p, q, g and x from a PKCS#8 DSA key and derives y = g^x mod p.
 *
 * @param pkcs8 DER of the PrivateKeyInfo
 * @returns the DSA parameters as SSH mpint contents
 */
function dsaParameters(pkcs8) {
  const [, algorithm, privateKey] = readSequence(expectTag(readTlv(pkcs8, 0), TAG_SEQUENCE))
  const [, parameters] = readSequence(expectTag(algorithm, TAG_SEQUENCE))
  const [p, q, g] = readSequence(expectTag(parameters, TAG_SEQUENCE)).map((element) =>
    expectTag(element, TAG_INTEGER)
  )
  const x = expectTag(readTlv(expectTag(privateKey, TAG_OCTET_STRING), 0), TAG_INTEGER)
  const y = modPow(toBigInt(g), toBigInt(x), toBigInt(p))
  return { g, p, q, x, y: mpintBytes(y) }
}

/**
 * @param section the private section of an openssh-key-v1 key
 * @returns it padded with 1, 2, 3, ... to a multiple of the block size
 */
function padded(section) {
  const padding = []
  for (let pad = 1; (section.length + padding.length) % OPENSSH_BLOCK_SIZE !== 0; pad += 1) {
    padding.push(pad)
  }
  return Buffer.concat([section, Buffer.from(padding)])
}

/**
 * @param parameters the DSA parameters
 * @returns the unencrypted `openssh-key-v1` PEM
 */
function opensshPem(parameters) {
  const { g, p, q, x, y } = parameters
  const type = sshString(Buffer.from("ssh-dss"))
  const publicBlob = Buffer.concat([type, ...[p, q, g, y].map((value) => sshString(value))])
  const check = randomBytes(4).readUInt32BE()
  const privatePart = [uint32(check), uint32(check), type]
  privatePart.push(...[p, q, g, y, x].map((value) => sshString(value)))
  privatePart.push(sshString(Buffer.from("ssh-native-it-dsa")))
  const section = padded(Buffer.concat(privatePart))
  const none = sshString(Buffer.from("none"))
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0"),
    none,
    none,
    sshString(Buffer.alloc(0)),
    uint32(1),
    sshString(publicBlob),
    sshString(section),
  ])
  const base64 = body.toString("base64")
  const lines = base64.match(new RegExp(`.{1,${PEM_LINE_LENGTH}}`, "gv")) ?? []
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`
}

/**
 * Generates one DSA key in two encodings.
 *
 * @returns `openssh` (openssh-key-v1) and `pkcs8` (PEM) of the same key
 */
export function generateDsaKey() {
  const { privateKey } = generateKeyPairSync("dsa", { divisorLength: 160, modulusLength: 1024 })
  const der = /** @type {Buffer} */ (privateKey.export({ format: "der", type: "pkcs8" }))
  const pkcs8 = /** @type {string} */ (privateKey.export({ format: "pem", type: "pkcs8" }))
  return { openssh: opensshPem(dsaParameters(der)), pkcs8 }
}
