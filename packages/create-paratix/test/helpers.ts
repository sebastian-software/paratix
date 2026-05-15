import type { Client, ConnectConfig } from "ssh2"

import { generateKeyPairSync } from "node:crypto"
import { readFileSync } from "node:fs"
import { expect, vi } from "vitest"

const UINT32_BYTE_LENGTH = 4
const BITS_PER_BYTE = 8
const ED25519_KEY_BYTES = 32
const MPINT_SIGN_BIT = 0x80
const UNCOMPRESSED_EC_POINT_PREFIX = 0x04
const INVALID_NISTP256_COORDINATE_BYTES = 64

export function createWireString(value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value
  const lengthPrefix = Buffer.alloc(UINT32_BYTE_LENGTH)
  lengthPrefix.writeUInt32BE(bytes.length, 0)
  return Buffer.concat([lengthPrefix, bytes])
}

export function readCreateParatixPackageVersion(): string {
  const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8")
  const parsed = JSON.parse(raw) as { version?: unknown }
  if (typeof parsed.version !== "string") {
    throw new TypeError("create-paratix package.json must contain a version string.")
  }

  return parsed.version
}

export function createEd25519PublicKey(
  comment: string,
  keyMaterial = Buffer.alloc(ED25519_KEY_BYTES, 1)
): string {
  const encodedKey = Buffer.concat([
    createWireString("ssh-ed25519"),
    createWireString(keyMaterial),
  ]).toString("base64")
  return `ssh-ed25519 ${encodedKey} ${comment}`
}

export function createMpint(value: Buffer): Buffer {
  return createWireString(value)
}

export function createRsaPublicKey(comment: string, exponent: Buffer, modulus: Buffer): string {
  const encodedKey = Buffer.concat([
    createWireString("ssh-rsa"),
    createMpint(exponent),
    createMpint(modulus),
  ]).toString("base64")
  return `ssh-rsa ${encodedKey} ${comment}`
}

export function createRsaModulus(bitLength: number): Buffer {
  const byteLength = Math.ceil(bitLength / BITS_PER_BYTE)
  const modulus = Buffer.alloc(byteLength, 0)
  const leadingBit = (bitLength - 1) % BITS_PER_BYTE
  modulus[0] = 1 << leadingBit

  return modulus[0] >= MPINT_SIGN_BIT ? Buffer.concat([Buffer.from([0]), modulus]) : modulus
}

function decodeBase64Url(value: string): Buffer {
  return Buffer.from(value, "base64url")
}

function encodePositiveMpint(value: Buffer): Buffer {
  return value[0] >= MPINT_SIGN_BIT ? Buffer.concat([Buffer.from([0]), value]) : value
}

export function createGeneratedRsa2048PublicKey(comment: string): string {
  const { publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x1_00_01,
  })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.e !== "string" || typeof jwk.n !== "string") {
    throw new TypeError("Generated RSA key did not export public parameters.")
  }

  return createRsaPublicKey(
    comment,
    encodePositiveMpint(decodeBase64Url(jwk.e)),
    encodePositiveMpint(decodeBase64Url(jwk.n))
  )
}

export function createEcdsaNistp256PublicKey(comment: string): string {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError("Generated P-256 key did not export coordinates.")
  }

  const point = Buffer.concat([
    Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
    decodeBase64Url(jwk.x),
    decodeBase64Url(jwk.y),
  ])
  const encodedKey = Buffer.concat([
    createWireString("ecdsa-sha2-nistp256"),
    createWireString("nistp256"),
    createWireString(point),
  ]).toString("base64")
  return `ecdsa-sha2-nistp256 ${encodedKey} ${comment}`
}

export function createSecurityKeyEcdsaNistp256PublicKey(comment: string): string {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError("Generated P-256 key did not export coordinates.")
  }

  const point = Buffer.concat([
    Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
    decodeBase64Url(jwk.x),
    decodeBase64Url(jwk.y),
  ])
  const encodedKey = Buffer.concat([
    createWireString("sk-ecdsa-sha2-nistp256@openssh.com"),
    createWireString("nistp256"),
    createWireString(point),
    createWireString("ssh:"),
  ]).toString("base64")
  return `sk-ecdsa-sha2-nistp256@openssh.com ${encodedKey} ${comment}`
}

export function createInvalidEcdsaNistp256PublicKey(comment: string): string {
  const encodedKey = Buffer.concat([
    createWireString("ecdsa-sha2-nistp256"),
    createWireString("nistp256"),
    createWireString(
      Buffer.concat([
        Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
        Buffer.alloc(INVALID_NISTP256_COORDINATE_BYTES, 0),
      ])
    ),
  ]).toString("base64")
  return `ecdsa-sha2-nistp256 ${encodedKey} ${comment}`
}

export const TEST_ADMIN_PUBLIC_KEY = createEd25519PublicKey("generated@test")
export const TEST_HOST_FINGERPRINT = "SHA256:MYVLAwRUnY5x4jwQ1SPUJoYXVb/fB/L3kFjCi5WxfYA"

export function buildEd25519HostKeyBuffer(
  publicKey: Buffer = Buffer.alloc(ED25519_KEY_BYTES, 1)
): Buffer {
  return Buffer.concat([createWireString("ssh-ed25519"), createWireString(publicKey)])
}

export type EcdsaHostKeyFixtureSpec = {
  algorithm: "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521"
  curveName: "nistp256" | "nistp384" | "nistp521"
  jwkCurveName: "P-256" | "P-384" | "P-521"
  pointByteLength: number
}

export function buildEcdsaHostKeyBuffer(spec: EcdsaHostKeyFixtureSpec): Buffer {
  const { algorithm, curveName, jwkCurveName, pointByteLength } = spec
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: jwkCurveName })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError(`Generated ${jwkCurveName} key did not export coordinates.`)
  }
  const coordinateLength = (pointByteLength - 1) / 2
  const x = decodeBase64Url(jwk.x)
  const y = decodeBase64Url(jwk.y)
  // Left-pad coordinates to the curve's coordinate length so the encoded
  // point matches the OpenSSH wire format's fixed-width uncompressed layout.
  const paddedX = Buffer.concat([Buffer.alloc(coordinateLength - x.length, 0), x])
  const paddedY = Buffer.concat([Buffer.alloc(coordinateLength - y.length, 0), y])
  const point = Buffer.concat([Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]), paddedX, paddedY])
  return Buffer.concat([
    createWireString(algorithm),
    createWireString(curveName),
    createWireString(point),
  ])
}

export function buildEcdsaPointFromGeneratedKey(jwkCurveName: "P-256" | "P-384" | "P-521"): Buffer {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: jwkCurveName })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError(`Generated ${jwkCurveName} key did not export coordinates.`)
  }
  return Buffer.concat([
    Buffer.from([UNCOMPRESSED_EC_POINT_PREFIX]),
    decodeBase64Url(jwk.x),
    decodeBase64Url(jwk.y),
  ])
}

export type FakeHostKeyClient = {
  connect: ReturnType<typeof vi.fn>
  end: ReturnType<typeof vi.fn>
  handlers: Record<string, (error?: Error) => void>
  on: ReturnType<typeof vi.fn>
  removeAllListeners: ReturnType<typeof vi.fn>
}

export function createFakeHostKeyClient(
  connectImplementation: (config: ConnectConfig, client: FakeHostKeyClient) => void
): FakeHostKeyClient {
  const fakeClient = {
    connect: vi.fn((config: ConnectConfig) => {
      connectImplementation(config, fakeClient)
      return fakeClient as unknown as Client
    }),
    end: vi.fn(() => fakeClient as unknown as Client),
    handlers: {} as Record<string, (error?: Error) => void>,
    on: vi.fn((event: string, handler: (error?: Error) => void) => {
      fakeClient.handlers[event] = handler
      return fakeClient as unknown as Client
    }),
    removeAllListeners: vi.fn(() => fakeClient as unknown as Client),
  }

  return fakeClient
}

export function useFakeHostKeyClient(fakeClient: FakeHostKeyClient): Client {
  return fakeClient as unknown as Client
}

export function callHostVerifier(config: ConnectConfig, key: Buffer): boolean | undefined {
  const hostVerifier = config.hostVerifier as ((key: Buffer) => boolean | undefined) | undefined
  const verdict = hostVerifier?.(key)
  return typeof verdict === "boolean" ? verdict : undefined
}

export async function expectProcessExit(
  callback: () => Promise<void> | void,
  expectedCode = 1
): Promise<void> {
  // R-0000189: exitWithMessage now throws a CliExitError instead of calling
  // process.exit synchronously. Tests that previously asserted on process.exit
  // assert on the thrown CliExitError so terminal cleanup remains observable.
  let caught: unknown
  try {
    await Promise.resolve().then(callback)
  } catch (error) {
    caught = error
  }

  const cliExitError = caught as { exitCode?: unknown; name?: string } | undefined
  expect(cliExitError?.name).toBe("CliExitError")
  expect(cliExitError?.exitCode).toBe(expectedCode)
}

/**
 * Test stub for `exitWithMessage`.
 *
 * Unlike the production implementation, this stub intentionally skips
 * `escapeCliControlCharacters` so test bodies can assert on the raw,
 * un-escaped message. Callers that do not silence `console.error`
 * themselves will see the message leak to stderr, so most test bodies
 * should `vi.spyOn(console, "error").mockImplementation(() => {})` before
 * triggering the stub.
 *
 * @param message - The raw error message to emit and throw.
 */
export function throwExitError(message: string): never {
  console.error(message)
  throw new Error(message)
}

type ProcessWithHandles = {
  _getActiveHandles?: () => unknown[]
}

function restorePropertyDescriptor(
  target: object,
  property: string,
  descriptor: PropertyDescriptor | undefined
): void {
  if (descriptor === undefined) {
    Reflect.deleteProperty(target, property)
    return
  }
  Object.defineProperty(target, property, descriptor)
}

export function setProcessTtyForTest(stdinIsTty: boolean, stdoutIsTty: boolean): () => void {
  const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
  const stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY")
  Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: stdinIsTty })
  Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: stdoutIsTty })
  return () => {
    restorePropertyDescriptor(process.stdin, "isTTY", stdinTty)
    restorePropertyDescriptor(process.stdout, "isTTY", stdoutTty)
  }
}

export function countActiveHandles(): number {
  const proc = process as unknown as ProcessWithHandles
  const handles = proc._getActiveHandles?.()
  return handles?.length ?? 0
}
