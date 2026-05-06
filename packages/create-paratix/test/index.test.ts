import type { Client, ConnectConfig } from "ssh2"

import { generateKeyPairSync } from "node:crypto"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { readHostFingerprintViaSsh2 } from "../src/hostFingerprintBootstrap.js"
import {
  deriveParatixDependencyRange,
  isDirectExecution,
  isValidExpectedHostFingerprint,
  isValidHost,
  isValidInitialUserName,
  isValidProjectName,
  normalizeHost,
  normalizeProjectName,
  parseCliArguments,
  parseInitialUserConfig,
  promptForAdminPublicKey,
  promptForHost,
  promptForHostFingerprint,
  promptForInitialUserConfig,
  resolveCliOrPromptHost,
  scaffoldProject,
  validateExpectedHostFingerprint,
  validateHost,
  writeProjectFiles,
} from "../src/index.js"
import { createSelectLines } from "../src/promptUi.js"
import {
  discoverLocalPublicKeys,
  isValidAdminPublicKey,
  readAdminPublicKeyFile,
  validateAdminPublicKey,
} from "../src/publicKeySelection.js"
import {
  AUTO_UPGRADES_20_TEMPLATE,
  createAdminNopasswdSudoersContent,
  createServerTemplate,
  UNATTENDED_UPGRADES_50_TEMPLATE,
} from "../src/templates.js"

function createWireString(value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value
  const lengthPrefix = Buffer.alloc(4)
  lengthPrefix.writeUInt32BE(bytes.length, 0)
  return Buffer.concat([lengthPrefix, bytes])
}

function readCreateParatixPackageVersion(): string {
  const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8")
  const parsed = JSON.parse(raw) as { version?: unknown }
  if (typeof parsed.version !== "string") {
    throw new TypeError("create-paratix package.json must contain a version string.")
  }

  return parsed.version
}

function createEd25519PublicKey(comment: string, keyMaterial = Buffer.alloc(32, 1)): string {
  const encodedKey = Buffer.concat([
    createWireString("ssh-ed25519"),
    createWireString(keyMaterial),
  ]).toString("base64")
  return `ssh-ed25519 ${encodedKey} ${comment}`
}

function createMpint(value: Buffer): Buffer {
  return createWireString(value)
}

function createRsaPublicKey(comment: string, exponent: Buffer, modulus: Buffer): string {
  const encodedKey = Buffer.concat([
    createWireString("ssh-rsa"),
    createMpint(exponent),
    createMpint(modulus),
  ]).toString("base64")
  return `ssh-rsa ${encodedKey} ${comment}`
}

function createRsaModulus(bitLength: number): Buffer {
  const byteLength = Math.ceil(bitLength / 8)
  const modulus = Buffer.alloc(byteLength, 0)
  const leadingBit = (bitLength - 1) % 8
  modulus[0] = 1 << leadingBit

  return modulus[0] >= 0x80 ? Buffer.concat([Buffer.from([0]), modulus]) : modulus
}

function decodeBase64Url(value: string): Buffer {
  return Buffer.from(value, "base64url")
}

function encodePositiveMpint(value: Buffer): Buffer {
  return value[0] >= 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value
}

function createGeneratedRsa2048PublicKey(comment: string): string {
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

function createEcdsaNistp256PublicKey(comment: string): string {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError("Generated P-256 key did not export coordinates.")
  }

  const point = Buffer.concat([Buffer.from([0x04]), decodeBase64Url(jwk.x), decodeBase64Url(jwk.y)])
  const encodedKey = Buffer.concat([
    createWireString("ecdsa-sha2-nistp256"),
    createWireString("nistp256"),
    createWireString(point),
  ]).toString("base64")
  return `ecdsa-sha2-nistp256 ${encodedKey} ${comment}`
}

function createSecurityKeyEcdsaNistp256PublicKey(comment: string): string {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  const jwk = publicKey.export({ format: "jwk" })
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new TypeError("Generated P-256 key did not export coordinates.")
  }

  const point = Buffer.concat([Buffer.from([0x04]), decodeBase64Url(jwk.x), decodeBase64Url(jwk.y)])
  const encodedKey = Buffer.concat([
    createWireString("sk-ecdsa-sha2-nistp256@openssh.com"),
    createWireString("nistp256"),
    createWireString(point),
    createWireString("ssh:"),
  ]).toString("base64")
  return `sk-ecdsa-sha2-nistp256@openssh.com ${encodedKey} ${comment}`
}

function createInvalidEcdsaNistp256PublicKey(comment: string): string {
  const encodedKey = Buffer.concat([
    createWireString("ecdsa-sha2-nistp256"),
    createWireString("nistp256"),
    createWireString(Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0)])),
  ]).toString("base64")
  return `ecdsa-sha2-nistp256 ${encodedKey} ${comment}`
}

const TEST_ADMIN_PUBLIC_KEY = createEd25519PublicKey("generated@test")
const TEST_HOST_FINGERPRINT = "SHA256:MYVLAwRUnY5x4jwQ1SPUJoYXVb/fB/L3kFjCi5WxfYA"
let TEST_DIR = ""

type FakeHostKeyClient = {
  connect: ReturnType<typeof vi.fn>
  end: ReturnType<typeof vi.fn>
  handlers: Record<string, (error?: Error) => void>
  on: ReturnType<typeof vi.fn>
  removeAllListeners: ReturnType<typeof vi.fn>
}

function createFakeHostKeyClient(
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

function useFakeHostKeyClient(fakeClient: FakeHostKeyClient): Client {
  return fakeClient as unknown as Client
}

function callHostVerifier(config: ConnectConfig, key: Buffer): boolean | undefined {
  const hostVerifier = config.hostVerifier as ((key: Buffer) => boolean | undefined) | undefined
  const verdict = hostVerifier?.(key)
  return typeof verdict === "boolean" ? verdict : undefined
}

async function expectProcessExit(
  callback: () => Promise<void> | void,
  expectedCode = 1
): Promise<void> {
  const exitError = new Error(`process.exit:${expectedCode}`)
  const exitSpy = vi.spyOn(process, "exit").mockImplementation((code) => {
    throw code === expectedCode ? exitError : new Error(`process.exit:${String(code)}`)
  })

  await expect(Promise.resolve().then(callback)).rejects.toThrow(exitError.message)
  expect(exitSpy).toHaveBeenCalledWith(expectedCode)
}

function throwExitError(message: string): never {
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

function setProcessTtyForTest(stdinIsTty: boolean, stdoutIsTty: boolean): () => void {
  const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, "isTTY")
  const stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY")
  Object.defineProperty(process.stdin, "isTTY", { configurable: true, value: stdinIsTty })
  Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: stdoutIsTty })
  return () => {
    restorePropertyDescriptor(process.stdin, "isTTY", stdinTty)
    restorePropertyDescriptor(process.stdout, "isTTY", stdoutTty)
  }
}

/**
 * Read the number of active handles from `process._getActiveHandles()`,
 * or fall back to `0` when the API is missing on the current Node build.
 * Used by the R-0000057 regression tests to ensure that
 * `promptForInitialUserConfig` does not leak readline / select handles
 * when an error propagates out of the prompt.
 *
 * @returns The number of active handles known to the runtime.
 */
function countActiveHandles(): number {
  const proc = process as unknown as ProcessWithHandles
  const handles = proc._getActiveHandles?.()
  return handles?.length ?? 0
}

describe("isValidProjectName", () => {
  // These tests document that invalid project names must be rejected.
  // Currently no validation exists in main() beyond a falsy-check, so
  // isValidProjectName is not yet exported. All tests in this block will
  // fail until the validation function is implemented and exported.

  it("accepts a simple lowercase name", () => {
    expect(isValidProjectName("my-project")).toBe(true)
  })

  it("accepts a name with numbers and hyphens", () => {
    expect(isValidProjectName("project-42")).toBe(true)
  })

  it("rejects a name containing spaces", () => {
    // Spaces are invalid in directory names used as npm package names and
    // would silently produce a broken package.json "name" field.
    expect(isValidProjectName("my project")).toBe(false)
  })

  it("rejects a name containing special characters", () => {
    // Characters like @ and ! are invalid in npm package names (unless
    // scoped with a leading @) and as unquoted directory names.
    expect(isValidProjectName("my@project!")).toBe(false)
  })

  it("rejects path traversal sequences", () => {
    // "../../etc" would resolve to an arbitrary directory outside the
    // current working directory, allowing an attacker to overwrite files.
    expect(isValidProjectName("../../etc")).toBe(false)
  })

  it("rejects names containing uppercase letters", () => {
    // npm package names must be lowercase. An uppercase name would be
    // written into package.json and cause npm publish/install errors.
    expect(isValidProjectName("MyProject")).toBe(false)
  })

  it("rejects a string that is blank after trimming", () => {
    // A name consisting only of whitespace passes the current falsy-check
    // in main() and would create a directory with a whitespace name.
    expect(isValidProjectName("   ")).toBe(false)
  })
})

describe("normalizeProjectName", () => {
  it("trims padded input before scaffolding uses it", () => {
    expect(normalizeProjectName(" my-server ")).toBe("my-server")
  })
})

describe("isDirectExecution (process.argv[1] regression)", () => {
  it("returns false when argv1 is null without throwing", () => {
    // Regression: previously index.ts called process.argv[1].replaceAll() without a null-check,
    // causing a TypeError when argv[1] is undefined (e.g. in a REPL or certain test runners).
    // null and undefined are both guarded by the != null check.
    expect(isDirectExecution("file:///some/module.js", null)).toBe(false)
  })

  it("returns false when the module URL does not match argv1", () => {
    expect(isDirectExecution("file:///project/src/index.js", "/other/script.js")).toBe(false)
  })

  it("returns true when the module URL resolves to argv1", () => {
    expect(isDirectExecution("file:///project/src/index.js", "/project/src/index.js")).toBe(true)
  })

  it("returns true when the module URL contains URL-encoded path characters", () => {
    expect(
      isDirectExecution(
        "file:///tmp/create-paratix%20dir/%23hash/%25percent/dist/index.js",
        "/tmp/create-paratix dir/#hash/%percent/dist/index.js"
      )
    ).toBe(true)
  })
})

describe("parseCliArguments", () => {
  it("uses interactive initial-user selection by default", () => {
    expect(parseCliArguments(["my-server"])).toStrictEqual({
      adminPublicKey: undefined,
      adminPublicKeyFile: undefined,
      expectedHostFingerprint: undefined,
      host: undefined,
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit host value", () => {
    expect(parseCliArguments(["my-server", "--host", "example.com"])).toStrictEqual({
      adminPublicKey: undefined,
      adminPublicKeyFile: undefined,
      expectedHostFingerprint: undefined,
      host: "example.com",
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit root initial user", () => {
    expect(parseCliArguments(["my-server", "--initial-user", "root"])).toStrictEqual({
      adminPublicKey: undefined,
      adminPublicKeyFile: undefined,
      expectedHostFingerprint: undefined,
      host: undefined,
      initialUser: "root",
      projectName: "my-server",
    })
  })

  it("supports an explicit admin initial user", () => {
    expect(parseCliArguments(["my-server", "--initial-user", "deploy"])).toStrictEqual({
      adminPublicKey: undefined,
      adminPublicKeyFile: undefined,
      expectedHostFingerprint: undefined,
      host: undefined,
      initialUser: "deploy",
      projectName: "my-server",
    })
  })

  it("supports an explicit admin public key", () => {
    expect(
      parseCliArguments([
        "my-server",
        "--admin-public-key",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest generated@test",
      ])
    ).toStrictEqual({
      adminPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest generated@test",
      adminPublicKeyFile: undefined,
      expectedHostFingerprint: undefined,
      host: undefined,
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit admin public key file", () => {
    expect(
      parseCliArguments(["my-server", "--admin-public-key-file", "/tmp/admin.pub"])
    ).toStrictEqual({
      adminPublicKey: undefined,
      adminPublicKeyFile: "/tmp/admin.pub",
      expectedHostFingerprint: undefined,
      host: undefined,
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("supports an explicit expected host fingerprint", () => {
    expect(
      parseCliArguments(["my-server", "--expected-host-fingerprint", TEST_HOST_FINGERPRINT])
    ).toStrictEqual({
      adminPublicKey: undefined,
      adminPublicKeyFile: undefined,
      expectedHostFingerprint: TEST_HOST_FINGERPRINT,
      host: undefined,
      initialUser: undefined,
      projectName: "my-server",
    })
  })

  it("rejects an invalid expected host fingerprint", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments([
        "my-server",
        "--expected-host-fingerprint",
        "SHA256:trusted-host-fingerprint",
      ])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid expected host fingerprint "SHA256:trusted-host-fingerprint" — use an OpenSSH SHA256 fingerprint.'
    )
  })

  it("escapes control bytes in invalid expected host fingerprint errors", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--expected-host-fingerprint", `SHA256:bad${escapeByte}`])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid expected host fingerprint "SHA256:bad\\u{001B}" — use an OpenSSH SHA256 fingerprint.'
    )
    expect(String(vi.mocked(console.error).mock.calls[0]?.[0])).not.toContain(escapeByte)
  })

  it("rejects passing both admin public key flags together", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments([
        "my-server",
        "--admin-public-key",
        "ssh-ed25519 AAAA test",
        "--admin-public-key-file",
        "/tmp/admin.pub",
      ])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Use either "--admin-public-key" or "--admin-public-key-file", not both.'
    )
  })

  it("rejects the removed bootstrap-root flag with a migration hint", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--bootstrap-root"])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: "--bootstrap-root" was removed. Use "--initial-user root" instead.'
    )
  })

  it("escapes control bytes in unknown option errors", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", `--bad${escapeByte}option`])
    })

    expect(console.error).toHaveBeenCalledWith('Error: Unknown option "--bad\\u{001B}option".')
    expect(String(vi.mocked(console.error).mock.calls[0]?.[0])).not.toContain(escapeByte)
  })

  // R-0000129: An empty or whitespace-only argument value would silently
  // disable downstream validation (e.g. `--host ""` would later present as
  // a missing host) and must therefore fail closed at the parser boundary.
  it("rejects an empty argument value (R-0000129)", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--host", ""])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Empty value for "--host" — provide a non-empty value.'
    )
  })

  it("rejects a whitespace-only argument value (R-0000129)", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--initial-user", "   "])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Empty value for "--initial-user" — provide a non-empty value.'
    )
  })

  // R-0000129: A value carrying CR/LF characters lets an attacker smuggle a
  // second line into log output or any file derived from the option
  // (header injection into the generated server.ts, sudoers, etc.). Reject
  // both \r and \n as well as the combined \r\n sequence at the parser
  // boundary.
  it("rejects an argument value containing LF (R-0000129)", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--admin-public-key", "first-line\nsecond-line"])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Multi-line value for "--admin-public-key" — provide a single-line value.'
    )
  })

  it("rejects an argument value containing CR (R-0000129)", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--admin-public-key-file", "/tmp/admin.pub\rextra"])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Multi-line value for "--admin-public-key-file" — provide a single-line value.'
    )
  })

  it("rejects an argument value containing CRLF (R-0000129)", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--host", "example.com\r\nrm -rf /"])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Multi-line value for "--host" — provide a single-line value.'
    )
  })

  it("rejects a multi-line expected host fingerprint value", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseCliArguments(["my-server", "--expected-host-fingerprint", "SHA256:good\nbad"])
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Multi-line value for "--expected-host-fingerprint" — provide a single-line value.'
    )
  })
})

describe("admin public key validation", () => {
  beforeEach(() => {
    TEST_DIR = mkdtempSync(join(tmpdir(), "create-paratix-test-"))
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    rmSync(TEST_DIR, { force: true, recursive: true })
    TEST_DIR = ""
  })

  it("accepts a valid OpenSSH public key", () => {
    expect(isValidAdminPublicKey(createEd25519PublicKey("user@example"))).toBe(true)
  })

  it("rejects public keys with embedded carriage returns", () => {
    expect(isValidAdminPublicKey(createEd25519PublicKey("user\rexample"))).toBe(false)
  })

  it("accepts a valid 2048-bit RSA public key", () => {
    expect(isValidAdminPublicKey(createGeneratedRsa2048PublicKey("rsa@example"))).toBe(true)
  })

  it("accepts a valid ECDSA nistp256 public key", () => {
    expect(isValidAdminPublicKey(createEcdsaNistp256PublicKey("ecdsa@example"))).toBe(true)
  })

  it("accepts a valid security-key ECDSA nistp256 public key", () => {
    expect(isValidAdminPublicKey(createSecurityKeyEcdsaNistp256PublicKey("sk@example"))).toBe(true)
  })

  it("rejects values without a supported OpenSSH algorithm prefix", () => {
    expect(isValidAdminPublicKey("not-a-key")).toBe(false)
    expect(isValidAdminPublicKey("ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxv2sz0YF80")).toBe(false)
  })

  it("rejects invalid base64 payloads", () => {
    expect(isValidAdminPublicKey("ssh-ed25519 not-base64!! user@example")).toBe(false)
  })

  it("rejects base64 payloads that are not OpenSSH wire blobs", () => {
    expect(isValidAdminPublicKey("ssh-ed25519 YWJj user@example")).toBe(false)
  })

  it("rejects public keys whose wire algorithm does not match the prefix", () => {
    const encodedRsaPrefixEd25519Body = Buffer.concat([
      createWireString("ssh-rsa"),
      createWireString(Buffer.from([0x01, 0x00, 0x01])),
      createWireString(Buffer.from([0x01, 0x23, 0x45])),
    ]).toString("base64")

    expect(isValidAdminPublicKey(`ssh-ed25519 ${encodedRsaPrefixEd25519Body} user@example`)).toBe(
      false
    )
  })

  it("rejects public keys with trailing data after the wire blob", () => {
    const encodedKey = Buffer.concat([
      createWireString("ssh-ed25519"),
      createWireString(Buffer.alloc(32, 1)),
      Buffer.from([0]),
    ]).toString("base64")

    expect(isValidAdminPublicKey(`ssh-ed25519 ${encodedKey} user@example`)).toBe(false)
  })

  it("rejects RSA public keys with a modulus smaller than 2048 bits", () => {
    expect(
      isValidAdminPublicKey(
        createRsaPublicKey(
          "tiny-rsa@example",
          Buffer.from([0x01, 0x00, 0x01]),
          createRsaModulus(1024)
        )
      )
    ).toBe(false)
  })

  it("rejects RSA public keys with an invalid exponent", () => {
    expect(
      isValidAdminPublicKey(
        createRsaPublicKey("bad-exponent@example", Buffer.from([0x02]), createRsaModulus(2048))
      )
    ).toBe(false)
  })

  it("rejects ECDSA public keys with a point outside the declared curve", () => {
    expect(isValidAdminPublicKey(createInvalidEcdsaNistp256PublicKey("bad-ecdsa@example"))).toBe(
      false
    )
  })

  it("rejects syntactically broken single-line values", () => {
    expect(isValidAdminPublicKey("ssh-ed25519")).toBe(false)
    expect(isValidAdminPublicKey("ssh-ed25519 ")).toBe(false)
  })

  it("fails closed for invalid direct admin public keys", () => {
    expect(() => {
      validateAdminPublicKey(throwExitError, "invalid-key")
    }).toThrow(
      'Error: Invalid value for "--admin-public-key" — provide a valid single-line OpenSSH public key.'
    )

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid value for "--admin-public-key" — provide a valid single-line OpenSSH public key.'
    )
  })

  it("fails closed for invalid admin public key files", () => {
    const invalidKeyFile = join(TEST_DIR, "invalid-admin.pub")
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(invalidKeyFile, "invalid-key\n")

    expect(() => {
      readAdminPublicKeyFile(throwExitError, invalidKeyFile)
    }).toThrow(
      'Error: Invalid value for "--admin-public-key-file" — provide a valid single-line OpenSSH public key.'
    )

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid value for "--admin-public-key-file" — provide a valid single-line OpenSSH public key.'
    )
  })

  it("fails closed for admin public key files with embedded carriage returns", () => {
    const invalidKeyFile = join(TEST_DIR, "cr-admin.pub")
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(invalidKeyFile, `${createEd25519PublicKey("user\rexample")}\n`)

    expect(() => {
      readAdminPublicKeyFile(throwExitError, invalidKeyFile)
    }).toThrow(
      'Error: Invalid value for "--admin-public-key-file" — provide a valid single-line OpenSSH public key.'
    )
  })

  // R-0000126: validateAdminPublicKey must hard-reject any value containing a
  // private-key PEM marker so a leaked private key cannot be embedded into
  // the scaffolded server.ts via either CLI flag.
  it("rejects an OpenSSH private key embed via --admin-public-key", () => {
    const privateKey = [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
      "-----END OPENSSH PRIVATE KEY-----",
    ].join("\n")

    expect(() => {
      validateAdminPublicKey(throwExitError, privateKey)
    }).toThrow(
      'Error: "--admin-public-key" contains a private key marker. Provide the matching OpenSSH public key (.pub) instead.'
    )

    expect(console.error).toHaveBeenCalledWith(
      'Error: "--admin-public-key" contains a private key marker. Provide the matching OpenSSH public key (.pub) instead.'
    )
  })

  it("rejects an RSA private key embed via --admin-public-key", () => {
    const privateKey = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEpAIBAAKCAQEA1234567890abcdef",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n")

    expect(() => {
      validateAdminPublicKey(throwExitError, privateKey)
    }).toThrow(/contains a private key marker/v)
  })

  it("rejects an EC private key embed via --admin-public-key", () => {
    const privateKey = [
      "-----BEGIN EC PRIVATE KEY-----",
      "MHcCAQEEIBexampleeexampleeexampleeexampleeexample",
      "-----END EC PRIVATE KEY-----",
    ].join("\n")

    expect(() => {
      validateAdminPublicKey(throwExitError, privateKey)
    }).toThrow(/contains a private key marker/v)
  })

  it("rejects a private key embed loaded from --admin-public-key-file", () => {
    const privateKeyFile = join(TEST_DIR, "private-admin.pub")
    mkdirSync(TEST_DIR, { recursive: true })
    writeFileSync(
      privateKeyFile,
      [
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
        "-----END OPENSSH PRIVATE KEY-----",
        "",
      ].join("\n")
    )

    expect(() => {
      readAdminPublicKeyFile(throwExitError, privateKeyFile)
    }).toThrow(
      'Error: "--admin-public-key-file" contains a private key marker. Provide the matching OpenSSH public key (.pub) instead.'
    )
  })

  // R-0000126: relative paths supplied on the CLI must be resolved against the
  // current working directory before they are read so that operators can pass
  // paths like `./id_ed25519.pub` without relying on shell expansion.
  it("resolves a relative admin public key file path against the current working directory", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const publicKey = createEd25519PublicKey("user@example")
    const absoluteKeyFile = join(TEST_DIR, "relative-admin.pub")
    writeFileSync(absoluteKeyFile, `${publicKey}\n`)

    const originalCwd = process.cwd()
    try {
      process.chdir(TEST_DIR)
      expect(readAdminPublicKeyFile(throwExitError, "./relative-admin.pub")).toBe(publicKey)
    } finally {
      process.chdir(originalCwd)
    }
  })

  // R-0000126: read failures must not leak filesystem details — only a
  // generic message is exposed to the operator.
  it("emits a neutral error message when the admin public key file cannot be read", () => {
    const missingPath = join(TEST_DIR, "does-not-exist.pub")

    expect(() => {
      readAdminPublicKeyFile(throwExitError, missingPath)
    }).toThrow("Error: Failed to read admin public key file.")

    expect(console.error).toHaveBeenCalledWith("Error: Failed to read admin public key file.")
  })

  it("emits a neutral error message when the admin public key file is a directory", () => {
    const directoryPath = join(TEST_DIR, "directory.pub")
    mkdirSync(directoryPath, { recursive: true })

    expect(() => {
      readAdminPublicKeyFile(throwExitError, directoryPath)
    }).toThrow("Error: Failed to read admin public key file.")

    expect(console.error).toHaveBeenCalledWith("Error: Failed to read admin public key file.")
  })

  it("emits a neutral error message when the admin public key file is too large", () => {
    const oversizedPath = join(TEST_DIR, "oversized.pub")
    writeFileSync(oversizedPath, Buffer.alloc(16 * 1024 + 1, "x"))

    expect(() => {
      readAdminPublicKeyFile(throwExitError, oversizedPath)
    }).toThrow("Error: Failed to read admin public key file.")

    expect(console.error).toHaveBeenCalledWith("Error: Failed to read admin public key file.")
  })

  it("omits discovered local public keys with embedded carriage returns", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const validKey = createEd25519PublicKey("user@example")
    writeFileSync(join(TEST_DIR, "id_ed25519.pub"), `${validKey}\n`)
    writeFileSync(
      join(TEST_DIR, "id_ed25519_cr.pub"),
      `${createEd25519PublicKey("user\rexample")}\n`
    )

    expect(discoverLocalPublicKeys(TEST_DIR)).toStrictEqual([
      {
        key: validKey,
        label: "id_ed25519.pub",
        path: join(TEST_DIR, "id_ed25519.pub"),
      },
    ])
  })

  it("skips discovered public key entries that are directories or too large", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    mkdirSync(join(TEST_DIR, "directory.pub"))
    writeFileSync(join(TEST_DIR, "oversized.pub"), Buffer.alloc(16 * 1024 + 1, "x"))

    const validKey = createEd25519PublicKey("user@example")
    writeFileSync(join(TEST_DIR, "id_ed25519.pub"), `${validKey}\n`)

    expect(discoverLocalPublicKeys(TEST_DIR)).toStrictEqual([
      {
        key: validKey,
        label: "id_ed25519.pub",
        path: join(TEST_DIR, "id_ed25519.pub"),
      },
    ])
  })
})

describe("initial user parsing", () => {
  it("accepts valid lowercase Linux usernames", () => {
    expect(isValidInitialUserName("deploy")).toBe(true)
    expect(isValidInitialUserName("admin_user")).toBe(true)
    expect(isValidInitialUserName("root")).toBe(true)
  })

  it("rejects invalid initial usernames", () => {
    expect(isValidInitialUserName("Admin")).toBe(false)
    expect(isValidInitialUserName("bad name")).toBe(false)
    expect(isValidInitialUserName("")).toBe(false)
  })

  it("escapes control bytes in invalid initial user errors", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      parseInitialUserConfig(`deploy${escapeByte}root`)
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid initial user "deploy\\u{001B}root" — use "root" or a valid lowercase Linux username.'
    )
    expect(String(vi.mocked(console.error).mock.calls[0]?.[0])).not.toContain(escapeByte)
  })

  it("maps root to the explicit root config", () => {
    expect(parseInitialUserConfig(" root ")).toStrictEqual({ kind: "root" })
  })

  it("maps other valid users to the admin config", () => {
    expect(parseInitialUserConfig(" deploy ")).toStrictEqual({ kind: "admin", user: "deploy" })
  })
})

describe("host parsing", () => {
  it("trims padded hosts", () => {
    expect(normalizeHost(" example.com ")).toBe("example.com")
  })

  it("accepts a domain, IPv4, and IPv6 literal", () => {
    expect(isValidHost("example.com")).toBe(true)
    expect(isValidHost("203.0.113.10")).toBe(true)
    expect(isValidHost("2001:db8::10")).toBe(true)
  })

  it("rejects empty or whitespace-containing hosts", () => {
    expect(isValidHost("")).toBe(false)
    expect(isValidHost("bad host")).toBe(false)
  })

  it("rejects hosts containing ASCII control characters (R-0000125)", () => {
    expect(isValidHost(`evil${String.fromCharCode(0)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCharCode(0x0d)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCharCode(0x0a)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCharCode(0x09)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCharCode(0x1b)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCharCode(0x7f)}.example.com`)).toBe(false)
  })

  it("rejects hosts containing C1 control characters (R-0000125)", () => {
    expect(isValidHost(`evil${String.fromCharCode(0x80)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCharCode(0x9f)}.example.com`)).toBe(false)
  })

  it("rejects hosts containing Unicode bidi override codepoints (R-0000125)", () => {
    expect(isValidHost(`evil${String.fromCodePoint(0x20_2e)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCodePoint(0x20_2d)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCodePoint(0x20_0e)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCodePoint(0x20_0f)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCodePoint(0x20_66)}.example.com`)).toBe(false)
    expect(isValidHost(`evil${String.fromCodePoint(0x20_69)}.example.com`)).toBe(false)
  })

  it("rejects shell-metachar payloads via whitespace or NUL framing (R-0000125)", () => {
    expect(isValidHost("evil.example.com;rm -rf /")).toBe(false)
    expect(isValidHost(`evil.example.com${String.fromCharCode(0)};rm -rf /`)).toBe(false)
  })

  it("validates a trimmed host", () => {
    expect(validateHost(" example.com ")).toBe("example.com")
  })

  it("keeps string-literal special characters for later safe serialization", () => {
    expect(validateHost('example".com')).toBe('example".com')
    expect(validateHost(String.raw`example\host`)).toBe(String.raw`example\host`)
  })

  it("exits for invalid hosts", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      validateHost("bad host")
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid host "bad host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )
  })

  it("escapes control bytes in invalid host errors", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      validateHost(`bad${escapeByte}host`)
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid host "bad\\u{001B}host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )
    expect(String(vi.mocked(console.error).mock.calls[0]?.[0])).not.toContain(escapeByte)
  })
})

describe("expected host fingerprint parsing", () => {
  it("accepts an OpenSSH SHA256 fingerprint", () => {
    expect(isValidExpectedHostFingerprint(TEST_HOST_FINGERPRINT)).toBe(true)
    expect(validateExpectedHostFingerprint(TEST_HOST_FINGERPRINT)).toBe(TEST_HOST_FINGERPRINT)
  })

  it("rejects fingerprints with the wrong digest prefix", () => {
    expect(
      isValidExpectedHostFingerprint("MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")
    ).toBe(false)
  })

  it("rejects padded or non-base64 SHA256 fingerprints", () => {
    expect(isValidExpectedHostFingerprint(`${TEST_HOST_FINGERPRINT}=`)).toBe(false)
    expect(isValidExpectedHostFingerprint("SHA256:trusted-host-fingerprint")).toBe(false)
  })

  it("exits for invalid expected host fingerprints", async () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      validateExpectedHostFingerprint("SHA256:trusted-host-fingerprint")
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid expected host fingerprint "SHA256:trusted-host-fingerprint" — use an OpenSSH SHA256 fingerprint.'
    )
  })

  it("escapes control bytes in direct expected host fingerprint validation errors", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    await expectProcessExit(() => {
      validateExpectedHostFingerprint(`SHA256:bad${escapeByte}`)
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid expected host fingerprint "SHA256:bad\\u{001B}" — use an OpenSSH SHA256 fingerprint.'
    )
    expect(String(vi.mocked(console.error).mock.calls[0]?.[0])).not.toContain(escapeByte)
  })
})

describe("promptForInitialUserConfig", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("supports the interactive root flow", async () => {
    const prompt = vi.fn()
    const select = vi.fn().mockResolvedValueOnce("root")

    await expect(promptForInitialUserConfig(prompt, select)).resolves.toStrictEqual({
      kind: "root",
    })
    expect(prompt).not.toHaveBeenCalled()
    expect(select).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenCalledWith(
      "Which SSH user already works for the first connection to this server?",
      [
        {
          description:
            "Fresh server with SSH access only as root. Paratix bootstraps a dedicated admin user first.",
          label: "Root user",
          value: "root",
        },
        {
          description:
            "A named admin user already exists. Paratix connects directly as that user and skips root bootstrap.",
          label: "Admin user",
          value: "admin",
        },
      ]
    )
  })

  it("supports the interactive admin flow with a concrete username", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("deploy")
    const select = vi.fn().mockResolvedValueOnce("admin")

    await expect(promptForInitialUserConfig(prompt, select)).resolves.toStrictEqual({
      kind: "admin",
      user: "deploy",
    })
    expect(select).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenCalledTimes(1)
    expect(prompt).toHaveBeenNthCalledWith(1, "Admin username: ")
  })

  // R-0000057 regression: a throw inside promptForAdminUser (closed stdin,
  // EPIPE, SIGINT) must not leak the readline interface. The cleanup is
  // guarded by a finally block, so the underlying close hook fires
  // regardless of whether the success path ran. We verify it indirectly
  // here by counting active handles before and after, and by re-running
  // the function with a fresh throw to confirm no handle accumulates.
  it("cleans up open handles when an error propagates from the admin prompt", async () => {
    const select = vi.fn().mockResolvedValueOnce("admin")
    const prompt = vi.fn().mockRejectedValueOnce(new Error("stdin closed"))

    // Snapshot the active-handle count before invoking the function.
    const handlesBefore = countActiveHandles()

    await expect(promptForInitialUserConfig(prompt, select)).rejects.toThrow("stdin closed")

    // After the rejection, no extra handle must remain. Allow the event
    // loop to drain so the readline close completes.
    await new Promise<void>((resolve) => {
      setImmediate(resolve)
    })
    const handlesAfter = countActiveHandles()
    expect(handlesAfter).toBeLessThanOrEqual(handlesBefore)
  })

  it("cleans up open handles when the chooser itself throws", async () => {
    const select = vi.fn().mockRejectedValueOnce(new Error("chooser cancelled"))
    const prompt = vi.fn()

    const handlesBefore = countActiveHandles()

    await expect(promptForInitialUserConfig(prompt, select)).rejects.toThrow("chooser cancelled")

    await new Promise<void>((resolve) => {
      setImmediate(resolve)
    })
    const handlesAfter = countActiveHandles()
    expect(handlesAfter).toBeLessThanOrEqual(handlesBefore)
  })
})

describe("promptForHost", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("accepts a valid interactive host", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("example.com")

    await expect(promptForHost(prompt)).resolves.toBe("example.com")
    expect(prompt).toHaveBeenCalledWith("Server host (domain or IP): ")
  })

  it("closes the host prompt session after a successful prompt run", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("example.com")
    const closePrompt = vi.fn()

    await expect(promptForHost(prompt, () => void closePrompt())).resolves.toBe("example.com")
    expect(closePrompt).toHaveBeenCalledTimes(1)
  })

  it("retries until a valid host is entered", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("bad host").mockResolvedValueOnce("203.0.113.10")

    await expect(promptForHost(prompt)).resolves.toBe("203.0.113.10")
    expect(console.error).toHaveBeenCalledWith(
      "Error: Please enter a domain name, IPv4, or IPv6 address without spaces."
    )
  })

  it("also closes the host prompt session after retries", async () => {
    const prompt = vi.fn().mockResolvedValueOnce("bad host").mockResolvedValueOnce("203.0.113.10")
    const closePrompt = vi.fn()

    await expect(promptForHost(prompt, () => void closePrompt())).resolves.toBe("203.0.113.10")
    expect(closePrompt).toHaveBeenCalledTimes(1)
  })
})

describe("resolveCliOrPromptHost", () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("uses the provided --host without prompting", async () => {
    const prompt = vi.fn().mockResolvedValue("prompted.example.com")

    await expect(resolveCliOrPromptHost("example.com", prompt)).resolves.toBe("example.com")
    expect(prompt).not.toHaveBeenCalled()
  })

  it("fails fast without --host in non-interactive environments", async () => {
    const prompt = vi.fn().mockResolvedValue("prompted.example.com")
    const restoreTty = setProcessTtyForTest(false, false)
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    try {
      await expectProcessExit(async () => {
        await resolveCliOrPromptHost(undefined, prompt)
      })

      expect(console.error).toHaveBeenCalledWith(
        "Missing --host in non-interactive environment. Pass --host <domain-or-ip>."
      )
      expect(prompt).not.toHaveBeenCalled()
    } finally {
      restoreTty()
    }
  })
})

describe("promptForAdminPublicKey", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("keeps the placeholder when the user declines local key reuse", async () => {
    const select = vi.fn().mockResolvedValueOnce("placeholder")

    await expect(promptForAdminPublicKey(select)).resolves.toBeUndefined()
    expect(select).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenNthCalledWith(
      1,
      "How should create-paratix configure the admin SSH public key?",
      [
        {
          description:
            "Read a public key from ~/.ssh and embed it directly into server.ts for the bootstrap admin user.",
          label: "Use local public key",
          value: "local",
        },
        {
          description:
            "Keep the placeholder in server.ts and paste your public key manually before the first apply.",
          label: "Keep placeholder",
          value: "placeholder",
        },
      ]
    )
  })

  it("does not offer the placeholder for root bootstrap admin key selection", async () => {
    const select = vi
      .fn()
      .mockResolvedValueOnce("local")
      .mockResolvedValueOnce("/tmp/id_ed25519.pub")

    await expect(
      promptForAdminPublicKey(
        select,
        [
          {
            key: "ssh-ed25519 AAAA example-ed25519",
            label: "id_ed25519.pub",
            path: "/tmp/id_ed25519.pub",
          },
        ],
        { allowPlaceholder: false }
      )
    ).resolves.toBe("ssh-ed25519 AAAA example-ed25519")
    expect(select).toHaveBeenNthCalledWith(
      1,
      "How should create-paratix configure the admin SSH public key?",
      [
        {
          description:
            "Read a public key from ~/.ssh and embed it directly into server.ts for the bootstrap admin user.",
          label: "Use local public key",
          value: "local",
        },
      ]
    )
  })

  it("selects from multiple local public keys via the cursor flow", async () => {
    const select = vi
      .fn()
      .mockResolvedValueOnce("local")
      .mockResolvedValueOnce("/tmp/id_ed25519.pub")

    await expect(
      promptForAdminPublicKey(select, [
        {
          key: "ssh-rsa AAAA example-rsa",
          label: "id_rsa.pub",
          path: "/tmp/id_rsa.pub",
        },
        {
          key: "ssh-ed25519 AAAA example-ed25519",
          label: "id_ed25519.pub",
          path: "/tmp/id_ed25519.pub",
        },
      ])
    ).resolves.toBe("ssh-ed25519 AAAA example-ed25519")
    expect(select).toHaveBeenCalledTimes(2)
  })

  it("falls back to the placeholder when no readable local public keys exist", async () => {
    const select = vi.fn().mockResolvedValueOnce("local")

    await expect(promptForAdminPublicKey(select, [])).resolves.toBeUndefined()
    expect(console.error).toHaveBeenCalledWith(
      "No readable public keys were found in ~/.ssh. Keeping the placeholder in server.ts."
    )
  })

  it("does not claim placeholder fallback for root bootstrap when no local keys exist", async () => {
    const select = vi.fn().mockResolvedValueOnce("local")

    await expect(
      promptForAdminPublicKey(select, [], { allowPlaceholder: false })
    ).resolves.toBeUndefined()
    expect(console.error).toHaveBeenCalledWith(
      "No readable public keys were found in ~/.ssh. Root bootstrap requires an admin public key."
    )
  })
})

describe("createSelectLines", () => {
  it("escapes unsafe terminal characters in prompt and option text", () => {
    const escapeByte = String.fromCharCode(0x1b)
    const bidiOverride = String.fromCodePoint(0x20_2e)
    const rendered = createSelectLines(
      `Select${escapeByte} public key:`,
      [
        {
          description: `/tmp/${bidiOverride}id_ed25519.pub`,
          label: `id${escapeByte}_ed25519.pub`,
          value: `/tmp/${escapeByte}${bidiOverride}id_ed25519.pub`,
        },
      ],
      0
    ).join("\n")

    expect(rendered).toContain("Select\\u{001B} public key:")
    expect(rendered).toContain("> id\\u{001B}_ed25519.pub")
    expect(rendered).toContain("/tmp/\\u{202E}id_ed25519.pub")
    expect(rendered).not.toContain(escapeByte)
    expect(rendered).not.toContain(bidiOverride)
  })
})

describe("promptForHostFingerprint", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
    vi.spyOn(console, "log").mockImplementation((...args) => {
      void args
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("keeps the placeholder when the user declines host-key scanning", async () => {
    const select = vi.fn().mockResolvedValueOnce("placeholder")
    const scanner = vi.fn()

    await expect(promptForHostFingerprint("example.com", select, scanner)).resolves.toBeUndefined()
    expect(scanner).not.toHaveBeenCalled()
    expect(select).toHaveBeenCalledWith(
      "How should create-paratix bootstrap the SSH host key for example.com?",
      [
        {
          description:
            "Read the currently presented host key from SSH port 22 via ssh2 and pin its fingerprint in server.ts.",
          label: "Scan host key",
          value: "scan",
        },
        {
          description:
            "Skip pinning now. The generated project will fail closed until known_hosts is prepared or a verified expectedHostFingerprint/PublicKey is added.",
          label: "Skip pinning",
          value: "placeholder",
        },
      ]
    )
  })

  // R-0000122: a single "scan" choice must NOT pin the fingerprint silently.
  // Operators have to confirm out-of-band before the value reaches server.ts.
  it("pins the scanned host fingerprint only after explicit confirmation", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("pin")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await expect(promptForHostFingerprint("example.com", select, scanner)).resolves.toBe(
      "SHA256:scanned-fingerprint"
    )
    expect(scanner).toHaveBeenCalledWith("example.com")
    expect(select).toHaveBeenCalledTimes(2)
    expect(select).toHaveBeenNthCalledWith(2, "Pin the scanned host fingerprint for example.com?", [
      {
        description: expect.stringContaining("fail closed"),
        label: "Discard and skip",
        value: "discard",
      },
      {
        description: expect.stringContaining("Pin the scanned fingerprint"),
        label: "Pin this fingerprint",
        value: "pin",
      },
    ])
  })

  // R-0000202: after a scan has happened, discarding it must keep scaffolding
  // fail-closed instead of silently trusting the presented key.
  it("rejects when the operator discards the scanned fingerprint", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("discard")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /scanned host fingerprint for example.com was not pinned/v
    )
    expect(scanner).toHaveBeenCalledTimes(1)
    expect(select).toHaveBeenCalledTimes(2)
  })

  // R-0000122: the scanned material must be displayed in an isolated,
  // multi-line block so an operator can copy it cleanly for an out-of-band
  // comparison. The algorithm has to appear next to the fingerprint.
  it("renders algorithm and fingerprint on isolated lines before asking to pin", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan").mockResolvedValueOnce("pin")
    const scanner = vi.fn().mockResolvedValueOnce({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:scanned-fingerprint",
    })

    await promptForHostFingerprint("example.com", select, scanner)

    expect(console.log).toHaveBeenCalledTimes(1)
    const message = vi.mocked(console.log).mock.calls[0]?.[0]
    expect(message).toContain("Scanned SSH host key for example.com:22")
    expect(message).toContain("algorithm:")
    expect(message).toContain("ssh-ed25519")
    expect(message).toContain("fingerprint:")
    expect(message).toContain("SHA256:scanned-fingerprint")
    expect(message).toContain("out-of-band")
  })

  // R-0000202: a scan failure must surface as an explicit MITM-style warning
  // and abort instead of silently trusting the presented key.
  it("emits a MITM warning and rejects after a scan failure", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan")
    const scanner = vi.fn().mockRejectedValueOnce(new Error("network timeout"))

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /host-key scan for example.com failed \(network timeout\)/v
    )

    const errorMock = console.error as unknown as { mock: { calls: unknown[][] } }
    const warningCalls = errorMock.mock.calls.map((call) => String(call[0])).join("\n")
    expect(warningCalls).toContain("Warning: failed to scan SSH host key for example.com.")
    expect(warningCalls).toContain("network timeout")
    expect(warningCalls).toContain("man-in-the-middle")
    expect(warningCalls).toContain("Verify the host key out of band")

    expect(select).toHaveBeenCalledTimes(1)
  })

  it("escapes control bytes in host-key scan warnings", async () => {
    const escapeByte = String.fromCharCode(0x1b)
    const host = `example${escapeByte}.com`
    const select = vi.fn().mockResolvedValueOnce("scan")
    const scanner = vi.fn().mockRejectedValueOnce(new Error(`network${escapeByte}timeout`))

    await expect(promptForHostFingerprint(host, select, scanner)).rejects.toThrow(
      /host-key scan for example\\u\{001B\}\.com failed \(network\\u\{001B\}timeout\)/v
    )

    const warningCalls = vi
      .mocked(console.error)
      .mock.calls.map((call) => String(call[0]))
      .join("\n")
    expect(warningCalls).toContain("Warning: failed to scan SSH host key for example\\u{001B}.com.")
    expect(warningCalls).toContain("network\\u{001B}timeout")
    expect(warningCalls).not.toContain(escapeByte)
    expect(select).toHaveBeenCalledTimes(1)
  })

  it("rejects with an actionable error after a scan failure", async () => {
    const select = vi.fn().mockResolvedValueOnce("scan")
    const scanner = vi.fn().mockRejectedValueOnce(new Error("connect ETIMEDOUT"))

    await expect(promptForHostFingerprint("example.com", select, scanner)).rejects.toThrow(
      /Aborting scaffolding: host-key scan for example.com failed \(connect ETIMEDOUT\)/v
    )
    expect(select).toHaveBeenCalledTimes(1)
  })
})

describe("readHostFingerprintViaSsh2", () => {
  it("derives the OpenSSH fingerprint from the ssh2 hostVerifier key", async () => {
    const hostKey = Buffer.from(
      "0000000b7373682d6564323535313900000020e04a2a8d2c1b47d9c6b4d114e9d2a1ea4ad8eb49c1a14851771ab0ef0457f12",
      "hex"
    )
    const fakeClient = createFakeHostKeyClient((config, client) => {
      callHostVerifier(config, hostKey)
      setImmediate(() => {
        client.handlers.error(new Error("Host denied"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).resolves.toStrictEqual({
      algorithm: "ssh-ed25519",
      fingerprint: "SHA256:MYVLAwRUnY5x4jwQ1SPUJoYXVb/fB/L3kFjCi5WxfYA",
    })

    expect(fakeClient.connect).toHaveBeenCalledWith(
      expect.objectContaining({
        host: "example.com",
        port: 22,
        readyTimeout: 10_000,
        username: "paratix-hostkey-scan",
      })
    )
  })

  it("fails clearly when ssh2 cannot obtain a host key", async () => {
    const fakeClient = createFakeHostKeyClient((_config, client) => {
      setImmediate(() => {
        client.handlers.error(new Error("connect ECONNREFUSED"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow("Failed to read the host key from example.com:22: connect ECONNREFUSED")
  })

  it("rejects with a MITM warning when the presented key uses an unknown algorithm", async () => {
    // Wire-format buffer with algorithm "ssh-bogus" (length-prefixed ASCII).
    const algoName = "ssh-bogus"
    const algoBytes = Buffer.from(algoName, "ascii")
    const lengthPrefix = Buffer.alloc(4)
    lengthPrefix.writeUInt32BE(algoBytes.length, 0)
    const hostKey = Buffer.concat([lengthPrefix, algoBytes, Buffer.from("payload")])

    const verdicts: Array<boolean | undefined> = []

    const fakeClient = createFakeHostKeyClient((config, client) => {
      verdicts.push(callHostVerifier(config, hostKey))
      setImmediate(() => {
        client.handlers.error(new Error("Host denied"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-bogus"/v)

    expect(verdicts).toStrictEqual([false])
  })

  it("rejects with a MITM warning when the presented key buffer is too short", async () => {
    const truncatedKey = Buffer.from([0, 0])

    const fakeClient = createFakeHostKeyClient((config, client) => {
      callHostVerifier(config, truncatedKey)
      setImmediate(() => {
        client.handlers.close()
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow(/Invalid SSH host key buffer/v)
  })

  it("settles host key verifier errors raised from an asynchronous ssh2 callback", async () => {
    // Wire-format buffer with algorithm "ssh-bogus" (length-prefixed ASCII).
    const algoName = "ssh-bogus"
    const algoBytes = Buffer.from(algoName, "ascii")
    const lengthPrefix = Buffer.alloc(4)
    lengthPrefix.writeUInt32BE(algoBytes.length, 0)
    const hostKey = Buffer.concat([lengthPrefix, algoBytes, Buffer.from("payload")])

    const verdicts: Array<boolean | undefined> = []

    const fakeClient = createFakeHostKeyClient((config, client) => {
      setImmediate(() => {
        verdicts.push(callHostVerifier(config, hostKey))
        client.handlers.error(new Error("Host denied"))
      })
    })

    await expect(
      readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
      })
    ).rejects.toThrow(/unsupported SSH host key algorithm "ssh-bogus"/v)

    expect(verdicts).toStrictEqual([false])
  })

  // R-0000127: ssh2 cannot detect a TCP half-open state; if neither close
  // nor error fires, the Promise must still settle through the watchdog.
  it("rejects through the watchdog when ssh2 never fires close or error", async () => {
    vi.useFakeTimers()

    const fakeClient = createFakeHostKeyClient(() => {
      // Intentionally do not invoke any handler — simulate a half-open
      // socket where neither error nor close ever fire.
    })

    try {
      const promise = readHostFingerprintViaSsh2("example.com", {
        clientFactory: () => useFakeHostKeyClient(fakeClient),
        readyTimeoutMs: 5000,
      })

      // Attach a no-op rejection handler before advancing timers so the
      // watchdog can settle the promise without an unhandled-rejection
      // warning from Node, then advance timers and assert.
      promise.catch(() => {
        // Swallow the rejection until the assertion below observes it.
      })
      // Watchdog is armed at readyTimeoutMs * 2 = 10_000ms.
      await vi.advanceTimersByTimeAsync(10_001)
      await expect(promise).rejects.toThrow(/host key scan timed out after 10000ms/v)

      expect(fakeClient.removeAllListeners).toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  // R-0000127: when the close handler resolves first, the watchdog must be
  // cleared so it cannot keep the event loop alive or fire spuriously.
  it("clears the watchdog on a successful resolution", async () => {
    const hostKey = Buffer.from(
      "0000000b7373682d6564323535313900000020e04a2a8d2c1b47d9c6b4d114e9d2a1ea4ad8eb49c1a14851771ab0ef0457f12",
      "hex"
    )

    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout")

    try {
      const fakeClient = createFakeHostKeyClient((config, client) => {
        callHostVerifier(config, hostKey)
        setImmediate(() => {
          client.handlers.error(new Error("Host denied"))
        })
      })

      await expect(
        readHostFingerprintViaSsh2("example.com", {
          clientFactory: () => useFakeHostKeyClient(fakeClient),
        })
      ).resolves.toMatchObject({ algorithm: "ssh-ed25519" })

      expect(clearTimeoutSpy).toHaveBeenCalled()
    } finally {
      clearTimeoutSpy.mockRestore()
    }
  })
})

describe("writeProjectFiles", () => {
  beforeEach(() => {
    TEST_DIR = mkdtempSync(join(tmpdir(), "create-paratix-test-"))
  })

  afterEach(() => {
    rmSync(TEST_DIR, { force: true, recursive: true })
    TEST_DIR = ""
  })

  it("creates a package.json in the target directory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "package.json"))).toBe(true)
  })

  it("generated package.json contains an engines field with node >=24.0.0", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      engines: { node: ">=24.0.0" },
    })
  })

  it("generated package.json has type module", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({ type: "module" })
  })

  it("generated package.json contains the paratix dependency", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)
    const expectedRange = `^${readCreateParatixPackageVersion()}`

    expect(parsed).toMatchObject({
      dependencies: { paratix: expectedRange },
    })
  })

  it("derives the paratix dependency range from the create-paratix package version", () => {
    expect(deriveParatixDependencyRange()).toBe(`^${readCreateParatixPackageVersion()}`)
  })

  it("generated package.json includes TypeScript tooling so apply and lint scripts work immediately", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "package.json"), "utf8")
    const parsed: unknown = JSON.parse(raw)

    expect(parsed).toMatchObject({
      devDependencies: {
        "@types/node": expect.stringMatching(/^\^/v),
        eslint: expect.stringMatching(/^\^/v),
        "eslint-config-setup": expect.stringMatching(/^\^/v),
        prettier: expect.stringMatching(/^\^/v),
        tsx: expect.stringMatching(/^\^/v),
        typescript: expect.stringMatching(/^\^/v),
      },
      scripts: {
        apply: "paratix apply server.ts",
        "apply:dry": "paratix apply server.ts --dry-run",
        "apply:first-run": "paratix apply server.ts --first-run",
        "apply:first-run:dry": "paratix apply server.ts --dry-run --first-run",
        "format:check": "prettier --check .",
        "format:fix": "prettier --write .",
        lint: "eslint .",
      },
    })
  })

  it("derives package.json name correctly from a Windows-style absolute path", () => {
    const windowsPath = join(TEST_DIR, "windows", "C:\\tmp\\windows-project")
    writeProjectFiles(windowsPath)

    const raw = readFileSync(join(windowsPath, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe("windows-project")
  })

  it("derives package.json name correctly from a backslash-separated relative path", () => {
    const windowsRelativePath = join(TEST_DIR, "windows", "tmp\\nested\\mixed-project")
    writeProjectFiles(windowsRelativePath)

    const raw = readFileSync(join(windowsRelativePath, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe("mixed-project")
  })

  it("creates a server.ts file", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(true)
  })

  it("generated tsconfig.json uses the DX-oriented ESNext/Bundler defaults", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, "tsconfig.json"), "utf8")
    const parsed = JSON.parse(raw) as {
      compilerOptions: { module: string; moduleResolution: string; types: string[] }
      include: string[]
    }

    expect(parsed.compilerOptions).toMatchObject({
      module: "ESNext",
      moduleResolution: "Bundler",
      types: ["node"],
    })
    expect(parsed.include).toStrictEqual(["**/*.ts"])
  })

  it("writes a Prettier config matching the scaffold default", () => {
    writeProjectFiles(TEST_DIR)

    const raw = readFileSync(join(TEST_DIR, ".prettierrc"), "utf8")
    const parsed = JSON.parse(raw) as Record<string, boolean | number | string>

    expect(parsed).toStrictEqual({
      arrowParens: "always",
      bracketSpacing: true,
      printWidth: 100,
      semi: false,
      singleQuote: false,
      tabWidth: 2,
      trailingComma: "es5",
    })
  })

  it("writes a .prettierignore that excludes package-manager lockfiles", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, ".prettierignore"), "utf8")

    expect(content).toContain("pnpm-lock.yaml")
    expect(content).toContain("package-lock.json")
    expect(content).toContain("yarn.lock")
    expect(content).toContain("bun.lockb")
  })

  it("writes an eslint.config.ts using eslint-config-setup for node projects", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "eslint.config.ts"), "utf8")

    expect(content).toContain('import { getEslintConfig } from "eslint-config-setup"')
    expect(content).toContain("export default await getEslintConfig({ node: true })")
  })

  it("generated server.ts uses packages.upgrade and packages.installed (not apt.*)", () => {
    // Regression: SERVER_TEMPLATE previously used the deprecated apt module
    // (apt.upgrade / apt.installed). After Plan-0013 refactoring the correct
    // module is `package as packages` with packages.upgrade / packages.installed.
    // TypeScript cannot catch this because the template is a plain string.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("packages.upgrade(")
    expect(content).toContain('packages.installed("curl", "htop", "ufw")')
    expect(content).not.toContain("apt.upgrade(")
    expect(content).not.toContain("apt.installed(")
  })

  it("generated server.ts imports package as packages from paratix/modules", () => {
    // Regression: import must use `package as packages`, not the old `apt` import.
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain("package as packages")
    expect(content).toContain("net, package as packages")
    expect(content).not.toContain("import { apt")
  })

  it("generated server.ts uses the hardened admin mode by default", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "paratix";')
    expect(content).toContain(
      'const adminPublicKey = "ssh-ed25519 REPLACE_ME_WITH_YOUR_PUBLIC_KEY";'
    )
    expect(content).toContain('const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";')
    expect(content).toContain('host: "1.2.3.4"')
    expect(content).toContain("user: adminUser")
    expect(content).toContain("ssh.authorizedKeys(adminUser, adminPublicKey)")
    expect(content).toContain('PasswordAuthentication: "no"')
    expect(content).toContain('PermitRootLogin: "no"')
    expect(content).not.toContain('user: "root"')
    expect(content).not.toContain('PermitRootLogin: "prohibit-password"')
  })

  it("generated server.ts uses an explicitly provided admin username", () => {
    writeProjectFiles(TEST_DIR, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "deploy";')
    expect(content).toContain('host: "deploy.example.com"')
    expect(content).toContain("user: adminUser")
    expect(content).toContain('recipe("admin-access"')
    expect(content).not.toContain('user: "root"')
  })

  it("normalizes a padded programmatic admin username before rendering server.ts", () => {
    writeProjectFiles(TEST_DIR, {
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: " deploy " },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const adminUser = "deploy";')
    expect(content).not.toContain('const adminUser = " deploy ";')
  })

  it("rejects an invalid programmatic admin username before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        host: "deploy.example.com",
        initialUser: { kind: "admin", user: 'deploy";\nthrow new Error("owned")' },
      })
    }).toThrow(/Invalid initial user/v)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects programmatic admin mode with root as the username", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        host: "deploy.example.com",
        initialUser: { kind: "admin", user: "root" },
      })
    }).toThrow(/use a non-root lowercase Linux username for admin mode/v)

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("server template safely serializes admin usernames when called directly", () => {
    const initialAdminUser = 'deploy";\nthrow new Error("owned")'
    const content = createServerTemplate({
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: initialAdminUser },
    })

    expect(content).toContain(`const adminUser = ${JSON.stringify(initialAdminUser)};`)
    expect(content).not.toContain(`const adminUser = "${initialAdminUser}";`)
  })

  it("generated server.ts safely serializes quote characters in the host", () => {
    const host = 'dangerous"host.example'
    writeProjectFiles(TEST_DIR, {
      host,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`host: ${JSON.stringify(host)}`)
    expect(content).not.toContain(`host: "${host}"`)
  })

  it("generated server.ts safely serializes backslashes in the host", () => {
    const host = String.raw`example\host`
    writeProjectFiles(TEST_DIR, {
      host,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`host: ${JSON.stringify(host)}`)
  })

  it("generated server.ts safely serializes other string-literal escape sequences in the host", () => {
    const host = String.raw`example\${template}\path`
    writeProjectFiles(TEST_DIR, {
      host,
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`host: ${JSON.stringify(host)}`)
  })

  it("generated server.ts embeds a selected local public key directly", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      host: "deploy.example.com",
      initialUser: { kind: "admin", user: "deploy" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`const adminPublicKey = ${JSON.stringify(TEST_ADMIN_PUBLIC_KEY)};`)
    expect(content).not.toContain("REPLACE_ME_WITH_YOUR_PUBLIC_KEY")
  })

  it("generated server.ts also embeds a CLI-supplied public key directly", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain(`const adminPublicKey = ${JSON.stringify(TEST_ADMIN_PUBLIC_KEY)};`)
  })

  it("generated server.ts keeps first-run host-key checking fail-closed", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const strictHostKeyChecking = "yes";')
    expect(content).toContain('pass "paratix apply ... --first-run" for the bootstrap run')
    expect(content).toContain("pin expectedHostFingerprint/PublicKey or pre-populate known_hosts")
    expect(content).not.toContain('"accept-new"')
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).toContain(
      'expectedHostPublicKey: "ssh-ed25519 REPLACE_ME_WITH_YOUR_HOST_PUBLIC_KEY"'
    )
  })

  it("generated server.ts embeds a scanned expectedHostFingerprint and keeps strict host-key checking enabled", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      expectedHostFingerprint: TEST_HOST_FINGERPRINT,
      host: "deploy.example.com",
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const strictHostKeyChecking = "yes";')
    expect(content).toContain(`expectedHostFingerprint: ${JSON.stringify(TEST_HOST_FINGERPRINT)}`)
    expect(content).not.toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).not.toContain('"accept-new"')
  })

  it("rejects invalid programmatic hosts before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        host: "bad host",
        initialUser: { kind: "admin", user: "deploy" },
      })
    }).toThrow(
      'Error: Invalid host "bad host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects invalid programmatic admin public keys before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        adminPublicKey: "invalid-key",
        initialUser: { kind: "admin", user: "deploy" },
      })
    }).toThrow(
      'Error: Invalid value for "--admin-public-key" — provide a valid single-line OpenSSH public key.'
    )

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("rejects invalid programmatic expected host fingerprints before creating files", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, {
        expectedHostFingerprint: "SHA256:trusted-host-fingerprint",
        initialUser: { kind: "admin", user: "deploy" },
      })
    }).toThrow(
      'Error: Invalid expected host fingerprint "SHA256:trusted-host-fingerprint" — use an OpenSSH SHA256 fingerprint.'
    )

    expect(existsSync(join(TEST_DIR, "server.ts"))).toBe(false)
  })

  it("generated server.ts keeps the ~/.ssh privateKey default that Paratix expands at runtime", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('privateKey: "~/.ssh/id_ed25519"')
    expect(content).toContain('"~" is expanded by Paratix')
  })

  it("generated server.ts gates firewall and ssh ports behind FIRST_RUN", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";')
    expect(content).toContain("const sshPorts = FIRST_RUN ? [22] : [2222];")
    expect(content).toContain(
      "const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443];"
    )
    expect(content).toContain("ports: sshPorts")
    expect(content).toContain('ufw.rule("allow", firewallTcpPorts)')
    expect(content).toContain('(env) => env["FIRST_RUN"] !== true')
    expect(content).toContain('command.shell("ufw --force delete allow 22", {')
    expect(content).toContain("check: \"! ufw status | grep -Eq '^22[[:space:]]+ALLOW'\"")
  })

  it("generated server.ts keeps port 22 open during first run before removing it later", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firstRunPortsIndex = content.indexOf(
      "const firewallTcpPorts = FIRST_RUN ? [22, 2222, 80, 443] : [2222, 80, 443];"
    )
    const removeBootstrapRuleIndex = content.indexOf('name: "remove bootstrap ssh firewall rule"')

    expect(firstRunPortsIndex).toBeGreaterThanOrEqual(0)
    expect(removeBootstrapRuleIndex).toBeGreaterThanOrEqual(0)
    expect(firstRunPortsIndex).toBeLessThan(removeBootstrapRuleIndex)
    expect(content).toContain('when(\n        (env) => env["FIRST_RUN"] !== true,')
  })

  it("generated server.ts opens firewall port 2222 before applying sshd.port(2222)", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firewallIndex = content.indexOf('recipe("firewall"')
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening"')

    expect(firewallIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(firewallIndex).toBeLessThan(sshHardeningIndex)
  })

  it("generated server.ts supports an explicit root bootstrap transition mode", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      host: "203.0.113.10",
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('host: "203.0.113.10"')
    expect(content).toContain('user: FIRST_RUN ? "root" : adminUser')
    expect(content).toContain('const adminUser = "paratix";')
    expect(content).toContain('const FIRST_RUN = process.env["PARATIX_FIRST_RUN"] === "true";')
    expect(content).toContain("Transitional bootstrap mode:")
    expect(content).toContain('PasswordAuthentication: "no"')
    expect(content).toContain('PermitRootLogin: FIRST_RUN ? "prohibit-password" : "no"')
    expect(content).toContain('const strictHostKeyChecking = "yes";')
    expect(content).not.toContain('"accept-new"')
    expect(content).toContain(
      'expectedHostFingerprint: "SHA256:REPLACE_ME_WITH_YOUR_HOST_FINGERPRINT"'
    )
    expect(content).not.toContain("--bootstrap-root")
    expect(content).not.toContain('service.restart("sshd")')
  })

  it("rejects root bootstrap without an admin public key", () => {
    expect(() => {
      writeProjectFiles(TEST_DIR, { host: "203.0.113.10", initialUser: { kind: "root" } })
    }).toThrow(/Root bootstrap requires --admin-public-key or --admin-public-key-file/v)
  })

  it("generated server.ts does not scaffold a hardcoded sshd restart signal", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).not.toContain('service.restart("sshd")')
    expect(content).not.toContain('signals: [service.restart("sshd")]')
  })

  it("generated root-bootstrap server.ts switches to the admin user after FIRST_RUN", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('user: FIRST_RUN ? "root" : adminUser')
    expect(content).toContain('PermitRootLogin: FIRST_RUN ? "prohibit-password" : "no"')
    expect(content).not.toContain('user: "root"')
    expect(content).not.toContain('PermitRootLogin: "prohibit-password"')
  })

  it("generated root-bootstrap server.ts provisions passwordless sudo for the bootstrap admin user", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('recipe("bootstrap-admin-sudo"')
    expect(content).toContain("file.copy(")
    expect(content).toContain('"/etc/sudoers.d/90-paratix-admin-nopasswd"')
    expect(content).toContain('"./files/admin-nopasswd-sudoers"')
    expect(content).toContain('mode: "0440"')
    expect(content).toContain('owner: "root:root"')
    expect(content).toContain("NOPASSWD sudo")
  })

  it("generated root-bootstrap project writes the sudoers drop-in for the admin user", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const sudoersPath = join(TEST_DIR, "files", "admin-nopasswd-sudoers")

    expect(existsSync(sudoersPath)).toBe(true)
    expect(readFileSync(sudoersPath, "utf8")).toBe(createAdminNopasswdSudoersContent("paratix"))
  })

  it("generated direct-admin project does not add a bootstrap sudoers drop-in", () => {
    writeProjectFiles(TEST_DIR, { initialUser: { kind: "admin", user: "deploy" } })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).not.toContain('recipe("bootstrap-admin-sudo"')
    expect(existsSync(join(TEST_DIR, "files", "admin-nopasswd-sudoers"))).toBe(false)
  })

  it("generated server.ts exposes FIRST_RUN through env for template logic and operator visibility", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('const serverName = "my-server";')
    expect(content).toContain("name: serverName")
    expect(content).toContain("env: {")
    expect(content).toContain("FIRST_RUN,")
    expect(content).toContain("SERVER_NAME: serverName,")
    expect(content).toContain("SSH_PORT: 2222,")
    expect(content).toContain("hostname.set(serverName)")
  })

  it("generated server.ts adds /etc/hosts before setting the hostname", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const hostsIndex = content.indexOf('net.hosts("127.0.1.1", [serverName])')
    const hostnameIndex = content.indexOf("hostname.set(serverName)")

    expect(hostsIndex).toBeGreaterThanOrEqual(0)
    expect(hostnameIndex).toBeGreaterThanOrEqual(0)
    expect(hostsIndex).toBeLessThan(hostnameIndex)
  })

  it("generated root-bootstrap server.ts also opens firewall port 2222 before ssh-hardening-transition", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const firewallIndex = content.indexOf('recipe("firewall"')
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening-transition"')

    expect(firewallIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(firewallIndex).toBeLessThan(sshHardeningIndex)
  })

  it("generated server.ts includes the first-run stop after ssh hardening, kernel hardening and automatic security upgrades", () => {
    writeProjectFiles(TEST_DIR, {
      adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
      initialUser: { kind: "root" },
    })

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")
    const sshHardeningIndex = content.indexOf('recipe("ssh-hardening-transition"')
    const kernelHardeningIndex = content.indexOf('recipe("kernel-hardening"')
    const automaticUpgradesIndex = content.indexOf('recipe("automatic-security-upgrades"')
    const firstRunStopIndex = content.indexOf(
      'firstRun.stop("Bootstrap foundation complete; rerun without --first-run to continue.")'
    )

    expect(sshHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(kernelHardeningIndex).toBeGreaterThanOrEqual(0)
    expect(automaticUpgradesIndex).toBeGreaterThanOrEqual(0)
    expect(firstRunStopIndex).toBeGreaterThanOrEqual(0)
    expect(sshHardeningIndex).toBeLessThan(kernelHardeningIndex)
    expect(kernelHardeningIndex).toBeLessThan(automaticUpgradesIndex)
    expect(automaticUpgradesIndex).toBeLessThan(firstRunStopIndex)
    expect(content).toContain('import { firstRun, recipe, server, when } from "paratix";')
    expect(content).toContain("// Add application and user-facing services below this line.")
  })

  it("generated server.ts configures unattended-upgrades via scaffolded files", () => {
    writeProjectFiles(TEST_DIR)

    const content = readFileSync(join(TEST_DIR, "server.ts"), "utf8")

    expect(content).toContain('recipe("automatic-security-upgrades"')
    expect(content).toContain('packages.installed("unattended-upgrades")')
    expect(content).toContain('"/etc/apt/apt.conf.d/20auto-upgrades"')
    expect(content).toContain('"/etc/apt/apt.conf.d/50unattended-upgrades"')
  })

  it("generated project writes unattended-upgrades scaffold files", () => {
    writeProjectFiles(TEST_DIR)

    expect(readFileSync(join(TEST_DIR, "files", "20auto-upgrades"), "utf8")).toBe(
      AUTO_UPGRADES_20_TEMPLATE
    )
    expect(readFileSync(join(TEST_DIR, "files", "50unattended-upgrades"), "utf8")).toBe(
      UNATTENDED_UPGRADES_50_TEMPLATE
    )
  })

  it("creates a files subdirectory", () => {
    writeProjectFiles(TEST_DIR)

    expect(existsSync(join(TEST_DIR, "files"))).toBe(true)
  })
})

describe("scaffoldProject", () => {
  const projectName = "create-paratix-scaffold-test"
  const paddedProjectName = " create-paratix-trim-test "
  const trimmedProjectName = "create-paratix-trim-test"
  const invalidAdminKeyProjectName = "create-paratix-invalid-admin-key-test"
  const invalidFingerprintProjectName = "create-paratix-invalid-fingerprint-test"
  const invalidHostProjectName = "create-paratix-invalid-host-test"
  const missingKeyProjectName = "create-paratix-missing-root-key-test"
  let invalidAdminKeyProjectDirectory = ""
  let invalidFingerprintProjectDirectory = ""
  let invalidHostProjectDirectory = ""
  let missingKeyProjectDirectory = ""
  let originalCwd = ""
  let paddedProjectDirectory = ""
  let projectDirectory = ""
  let scaffoldRoot = ""
  let trimmedProjectDirectory = ""

  beforeEach(() => {
    originalCwd = process.cwd()
    scaffoldRoot = mkdtempSync(join(tmpdir(), "create-paratix-scaffold-"))
    const scaffoldCwd = join(scaffoldRoot, "cwd")
    mkdirSync(scaffoldCwd)
    process.chdir(scaffoldCwd)
    projectDirectory = resolve(projectName)
    paddedProjectDirectory = resolve(paddedProjectName)
    trimmedProjectDirectory = resolve(trimmedProjectName)
    invalidAdminKeyProjectDirectory = resolve(invalidAdminKeyProjectName)
    invalidFingerprintProjectDirectory = resolve(invalidFingerprintProjectName)
    invalidHostProjectDirectory = resolve(invalidHostProjectName)
    missingKeyProjectDirectory = resolve(missingKeyProjectName)
    vi.spyOn(console, "log").mockImplementation((...args) => {
      void args
    })
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
    process.exitCode = undefined
  })

  afterEach(() => {
    vi.restoreAllMocks()
    process.chdir(originalCwd)
    rmSync(scaffoldRoot, { force: true, recursive: true })
    process.exitCode = undefined
  })

  it("prints the success message when dependency installation succeeds", () => {
    const installer = vi.fn().mockReturnValue(true)

    const result = scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      {
        adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
        host: "example.com",
        initialUser: { kind: "root" },
        installer,
      }
    )

    expect(result).toBe(true)
    expect(installer).toHaveBeenCalledWith(projectDirectory, {
      command: "pnpm install",
      name: "pnpm",
    })
    expect(console.log).toHaveBeenCalledWith(`Creating Paratix project in ${projectDirectory}...`)
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining("Project created successfully!")
    )
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply"))
    expect(console.log).not.toHaveBeenCalledWith(
      expect.stringContaining("dependency installation failed")
    )
    expect(process.exitCode).toBeUndefined()
  })

  it("prints a partial-success message and keeps a non-zero exit code when dependency installation fails", () => {
    const installer = vi.fn().mockReturnValue(false)

    const result = scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      { host: "deploy.example.com", initialUser: { kind: "admin", user: "deploy" }, installer }
    )

    expect(result).toBe(false)
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining("Project files created, but dependency installation failed.")
    )
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:first-run"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("pnpm apply"))
    expect(console.log).not.toHaveBeenCalledWith(
      expect.stringContaining("Project created successfully!")
    )
    expect(process.exitCode).toBe(1)
  })

  it("prints npm completion commands with first-run bootstrap before regular apply", () => {
    const installer = vi.fn().mockReturnValue(true)

    scaffoldProject(
      projectName,
      { command: "npm install", name: "npm" },
      {
        host: "example.com",
        installer,
      }
    )

    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:first-run:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:first-run"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply:dry"))
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining("npm run apply"))
  })

  it("prints completion commands in bootstrap order", () => {
    const installer = vi.fn().mockReturnValue(true)

    scaffoldProject(
      projectName,
      { command: "pnpm install", name: "pnpm" },
      {
        host: "example.com",
        installer,
      }
    )

    const logMock = console.log as unknown as { mock: { calls: unknown[][] } }
    const completionMessage = logMock.mock.calls
      .map((call) => String(call[0]))
      .find((message) => message.includes("Project created successfully!"))

    expect(completionMessage).toBeDefined()
    const commandLines = completionMessage
      ?.split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("pnpm apply"))

    expect(commandLines).toStrictEqual([
      "pnpm apply:first-run:dry",
      "pnpm apply:first-run",
      "pnpm apply:dry",
      "pnpm apply",
    ])
  })

  it("rejects root bootstrap without an admin public key before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        missingKeyProjectName,
        { command: "pnpm install", name: "pnpm" },
        { host: "example.com", initialUser: { kind: "root" }, installer }
      )
    }).toThrow(/Root bootstrap requires --admin-public-key or --admin-public-key-file/v)

    expect(existsSync(missingKeyProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
    expect(console.log).not.toHaveBeenCalledWith(
      `Creating Paratix project in ${missingKeyProjectDirectory}...`
    )
  })

  it("rejects invalid programmatic hosts before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        invalidHostProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          host: "bad host",
          initialUser: { kind: "admin", user: "deploy" },
          installer,
        }
      )
    }).toThrow(
      'Error: Invalid host "bad host" — use a domain name, IPv4, or IPv6 address without spaces.'
    )

    expect(existsSync(invalidHostProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("rejects invalid programmatic admin public keys before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        invalidAdminKeyProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          adminPublicKey: "invalid-key",
          host: "example.com",
          initialUser: { kind: "admin", user: "deploy" },
          installer,
        }
      )
    }).toThrow(
      'Error: Invalid value for "--admin-public-key" — provide a valid single-line OpenSSH public key.'
    )

    expect(existsSync(invalidAdminKeyProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("rejects invalid programmatic expected host fingerprints before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        invalidFingerprintProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          expectedHostFingerprint: "SHA256:trusted-host-fingerprint",
          host: "example.com",
          initialUser: { kind: "admin", user: "deploy" },
          installer,
        }
      )
    }).toThrow(
      'Error: Invalid expected host fingerprint "SHA256:trusted-host-fingerprint" — use an OpenSSH SHA256 fingerprint.'
    )

    expect(existsSync(invalidFingerprintProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("rejects invalid programmatic initial users before creating the target directory", () => {
    const installer = vi.fn().mockReturnValue(true)

    expect(() => {
      scaffoldProject(
        missingKeyProjectName,
        { command: "pnpm install", name: "pnpm" },
        {
          host: "example.com",
          initialUser: { kind: "admin", user: "Deploy" },
          installer,
        }
      )
    }).toThrow(/Invalid initial user/v)

    expect(existsSync(missingKeyProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  // R-0000124 regression: scaffoldProject must fail closed when the target
  // directory already exists, instead of silently overwriting files inside it.
  // Previously the function used `existsSync(...) ? exit : mkdirSync(..., { recursive: true })`
  // which left a TOCTOU window — and `recursive: true` masked any pre-existing
  // directory created during that window. We now expect an atomic failure with
  // a clear error message and no overwrite of pre-existing files.
  it("fails with a clear message and does not overwrite files when the target directory already exists", async () => {
    const installer = vi.fn().mockReturnValue(true)
    mkdirSync(projectDirectory, { recursive: true })
    const sentinelPath = join(projectDirectory, "package.json")
    writeFileSync(sentinelPath, "PRE_EXISTING_CONTENT")

    await expectProcessExit(() => {
      scaffoldProject(
        projectName,
        { command: "pnpm install", name: "pnpm" },
        {
          adminPublicKey: TEST_ADMIN_PUBLIC_KEY,
          host: "example.com",
          initialUser: { kind: "root" },
          installer,
        }
      )
    })

    expect(console.error).toHaveBeenCalledWith(`Error: Directory "${projectName}" already exists.`)
    expect(installer).not.toHaveBeenCalled()
    expect(readFileSync(sentinelPath, "utf8")).toBe("PRE_EXISTING_CONTENT")
  })

  it("rejects invalid project names before creating directories", async () => {
    const installer = vi.fn().mockReturnValue(true)
    const invalidProjectDirectory = resolve("..", "create-paratix-invalid")

    await expectProcessExit(() => {
      scaffoldProject(
        "../create-paratix-invalid",
        { command: "pnpm install", name: "pnpm" },
        {
          host: "example.com",
          installer,
        }
      )
    })

    expect(console.error).toHaveBeenCalledWith(
      'Error: Invalid project name "../create-paratix-invalid" — use only lowercase letters, numbers, and hyphens.'
    )
    expect(existsSync(invalidProjectDirectory)).toBe(false)
    expect(installer).not.toHaveBeenCalled()
  })

  it("normalizes padded project names before creating the project directory and package name", () => {
    const installer = vi.fn().mockReturnValue(true)

    const result = scaffoldProject(
      paddedProjectName,
      { command: "pnpm install", name: "pnpm" },
      { host: "example.com", installer }
    )

    expect(result).toBe(true)
    expect(existsSync(trimmedProjectDirectory)).toBe(true)
    expect(existsSync(paddedProjectDirectory)).toBe(false)

    const raw = readFileSync(join(trimmedProjectDirectory, "package.json"), "utf8")
    const parsed = JSON.parse(raw) as { name: string }

    expect(parsed.name).toBe(trimmedProjectName)
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining(`cd ${trimmedProjectName}`))
  })
})

// R-0000056 regression: AGENTS.md forbids inline `cspell:ignore` directives.
// The two existing directives in `src/templates.ts` were lifted into the
// project root `cspell.json`. This guard prevents future regressions where
// new tokens get masked locally instead of being added to the shared
// dictionary.
describe("R-0000056: templates.ts must not contain inline cspell:ignore", () => {
  it("contains no `cspell:ignore` directives in src/templates.ts", () => {
    const templatesPath = resolve(__dirname, "..", "src", "templates.ts")
    const content = readFileSync(templatesPath, "utf8")
    expect(content).not.toMatch(/cspell:ignore/v)
  })
})
