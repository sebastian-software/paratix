import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import {
  CliExitError,
  handleCliExit,
  isDirectExecution,
  isValidExpectedHostFingerprint,
  isValidHost,
  isValidInitialUserName,
  isValidProjectName,
  normalizeHost,
  normalizeProjectName,
  parseCliArguments,
  parseInitialUserConfig,
  restoreInteractiveTerminal,
  validateExpectedHostFingerprint,
  validateHost,
} from "../src/index.js"
import {
  discoverLocalPublicKeys,
  isValidAdminPublicKey,
  readAdminPublicKeyFile,
  validateAdminPublicKey,
} from "../src/publicKeySelection.js"
import {
  createEcdsaNistp256PublicKey,
  createEd25519PublicKey,
  createGeneratedRsa2048PublicKey,
  createInvalidEcdsaNistp256PublicKey,
  createRsaModulus,
  createRsaPublicKey,
  createSecurityKeyEcdsaNistp256PublicKey,
  createWireString,
  expectProcessExit,
  setProcessTtyForTest,
  TEST_HOST_FINGERPRINT,
  throwExitError,
} from "./helpers.js"

let TEST_DIR = ""

describe("isValidProjectName", () => {
  // Verify the project name validation rules.

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
  afterEach(() => {
    vi.restoreAllMocks()
  })

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
    // R-0000726: `tmpdir()` already contains symlinks on macOS
    // (`/var/folders` → `/private/var/folders`), and the unconditional
    // realpath in `readAdminPublicKeyFile` now logs an ancestor-symlink
    // line for every path under such a directory. Canonicalise the test
    // root through realpathSync so the "regular file does not log"
    // assertions stay stable across platforms.
    TEST_DIR = realpathSync(mkdtempSync(join(tmpdir(), "create-paratix-test-")))
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

  // R-0000233: bidi formatting codepoints in the comment portion of a public
  // key would otherwise be embedded verbatim into server.ts, allowing an
  // attacker-supplied .pub file to visually rewrite the surrounding source.
  // Reject the entire key value when any unsafe codepoint appears anywhere.
  it("rejects public keys whose comment contains bidi formatting codepoints", () => {
    const bidiOverride = String.fromCodePoint(0x20_2e)
    const key = createEd25519PublicKey(`user${bidiOverride}@example`)
    expect(isValidAdminPublicKey(key)).toBe(false)
  })

  it("rejects public keys whose comment contains C0 control characters", () => {
    const controlByte = String.fromCharCode(0x07)
    const key = createEd25519PublicKey(`user${controlByte}example`)
    expect(isValidAdminPublicKey(key)).toBe(false)
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

  // R-0000185: even if a custom exitWithMessage stub does not actually
  // terminate execution (e.g. a test harness that swallows the thrown error
  // upstream), readAdminPublicKeyFile must never read from uninitialised
  // stat/value. The first failing exit call is responsible for stopping
  // execution; subsequent code paths must not crash with a TypeError.
  it("never reads uninitialised state when exitWithMessage returns instead of exiting", () => {
    const missingPath = join(TEST_DIR, "missing-stub-return.pub")
    const exitMessages: string[] = []
    const returningExit = ((message: string) => {
      exitMessages.push(message)
      // Intentionally return — simulates a misuse where the never-typed
      // contract is not honoured at runtime.
    }) as (message: string) => never

    expect(() => {
      readAdminPublicKeyFile(returningExit, missingPath)
    }).toThrow("Error: Failed to read admin public key file.")

    expect(exitMessages[0]).toBe("Error: Failed to read admin public key file.")
  })

  // R-0000186: legitimate operator setups symlink ~/.ssh/*.pub into a
  // password-manager vault. statSync follows the link so the file is still
  // accepted by readAdminPublicKeyFile / discoverLocalPublicKeys.
  it("accepts a public key file reached through a symbolic link", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const publicKey = createEd25519PublicKey("user@example")
    const targetFile = join(TEST_DIR, "real-admin.pub")
    const linkFile = join(TEST_DIR, "linked-admin.pub")
    writeFileSync(targetFile, `${publicKey}\n`)
    symlinkSync(targetFile, linkFile)

    expect(readAdminPublicKeyFile(throwExitError, linkFile)).toBe(publicKey)
  })

  // R-0000665: when --admin-public-key-file points at a symlink, the
  // operator-facing log line must name the realpath so a planted link in
  // a shared CI home cannot silently embed a different key into
  // server.ts.
  it("R-0000665: logs the resolved realpath when the admin public key file is a symlink", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const publicKey = createEd25519PublicKey("user@example")
    const targetFile = join(TEST_DIR, "vault-admin.pub")
    const linkFile = join(TEST_DIR, "linked-admin-log.pub")
    writeFileSync(targetFile, `${publicKey}\n`)
    symlinkSync(targetFile, linkFile)
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {
      // suppress log output during the test
    })
    try {
      expect(readAdminPublicKeyFile(throwExitError, linkFile)).toBe(publicKey)
      const logged = logSpy.mock.calls.flat().join(" ")
      expect(logged).toContain("Reading public key from")
      expect(logged).toContain("vault-admin.pub")
      expect(logged).toContain("(symlink target of")
    } finally {
      logSpy.mockRestore()
    }
  })

  // R-0000726: closes the R-0000665 gap for ancestor symlinks. The
  // leaf file is a regular `.pub`, but one of its parent directories is
  // a symlink. The previous implementation only consulted the leaf's
  // `lstat` and stayed silent in this case, so a planted directory link
  // like `~/.ssh -> /tmp/attacker-ssh` could swap in a different key
  // without the operator seeing the redirection in the prompt log.
  it("R-0000726: logs the resolved realpath when an ancestor directory is a symlink", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const publicKey = createEd25519PublicKey("user@example")
    const realDir = join(TEST_DIR, "real-ssh")
    const linkedDir = join(TEST_DIR, "linked-ssh")
    mkdirSync(realDir, { recursive: true })
    const targetFile = join(realDir, "admin.pub")
    writeFileSync(targetFile, `${publicKey}\n`)
    symlinkSync(realDir, linkedDir)
    const linkFile = join(linkedDir, "admin.pub")
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {
      // suppress log output during the test
    })
    try {
      expect(readAdminPublicKeyFile(throwExitError, linkFile)).toBe(publicKey)
      const logged = logSpy.mock.calls.flat().join(" ")
      expect(logged).toContain("Reading public key from")
      expect(logged).toContain("ancestor symlink")
    } finally {
      logSpy.mockRestore()
    }
  })

  // R-0000731: readAdminPublicKeyFile must read the file contents from
  // the already-resolved realpath, not from the original (possibly
  // re-pointed) symlink. Swap the symlink immediately after realpath
  // resolution and before stat/readFile to exercise the TOCTOU window.
  it("R-0000731: reads from the resolved realpath when the symlink target is swapped after realpath", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const originalKey = createEd25519PublicKey("user@original")
    const attackerKey = createEd25519PublicKey("attacker@example")
    const originalFile = join(TEST_DIR, "original-admin.pub")
    const attackerFile = join(TEST_DIR, "attacker-admin.pub")
    const linkFile = join(TEST_DIR, "linked-admin-toctou.pub")
    writeFileSync(originalFile, `${originalKey}\n`)
    writeFileSync(attackerFile, `${attackerKey}\n`)
    symlinkSync(originalFile, linkFile)
    const fileSystem = {
      lstatSync: vi.fn((path: string) => lstatSync(path)),
      readFileSync: vi.fn((path: string, encoding: "utf8") => readFileSync(path, encoding)),
      realpathSync: vi.fn((path: string) => {
        const materialisedPath = realpathSync(path)
        unlinkSync(linkFile)
        symlinkSync(attackerFile, linkFile)
        return materialisedPath
      }),
      statSync: vi.fn((path: string) => statSync(path)),
    }

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {
      // suppress log output during the test
    })
    try {
      expect(readAdminPublicKeyFile(throwExitError, linkFile, fileSystem)).toBe(originalKey)
      expect(realpathSync(linkFile)).toBe(attackerFile)
      expect(fileSystem.statSync).toHaveBeenCalledWith(originalFile)
      expect(fileSystem.readFileSync).toHaveBeenCalledWith(originalFile, "utf8")
    } finally {
      logSpy.mockRestore()
    }
  })

  it("R-0000665: does not log a symlink-target line for a regular admin public key file", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const publicKey = createEd25519PublicKey("user@example")
    const regularFile = join(TEST_DIR, "regular-admin.pub")
    writeFileSync(regularFile, `${publicKey}\n`)
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {
      // suppress log output during the test
    })
    try {
      expect(readAdminPublicKeyFile(throwExitError, regularFile)).toBe(publicKey)
      const logged = logSpy.mock.calls.flat().join(" ")
      expect(logged).not.toContain("Reading public key from")
    } finally {
      logSpy.mockRestore()
    }
  })

  // R-0000665: when an entry under ~/.ssh is a symlink, the operator-facing
  // label now reveals the realpath alongside the basename so a planted
  // link in a shared CI home cannot silently embed a key from an
  // attacker-controlled directory.
  it("R-0000665: discovers public keys reached through a symbolic link and surfaces the realpath", () => {
    mkdirSync(TEST_DIR, { recursive: true })
    const realDir = join(TEST_DIR, "real")
    const sshDir = join(TEST_DIR, "ssh")
    mkdirSync(realDir, { recursive: true })
    mkdirSync(sshDir, { recursive: true })

    const publicKey = createEd25519PublicKey("user@example")
    const targetFile = join(realDir, "id_ed25519.pub")
    const linkFile = join(sshDir, "id_ed25519.pub")
    writeFileSync(targetFile, `${publicKey}\n`)
    symlinkSync(targetFile, linkFile)

    const discovered = discoverLocalPublicKeys(sshDir)
    expect(discovered).toHaveLength(1)
    const [entry] = discovered as [(typeof discovered)[number]]
    expect(entry.key).toBe(publicKey)
    expect(entry.path).toBe(linkFile)
    expect(entry.label.startsWith("id_ed25519.pub -> ")).toBe(true)
    expect(entry.label).toContain("real/id_ed25519.pub")
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
  afterEach(() => {
    vi.restoreAllMocks()
  })

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
  afterEach(() => {
    vi.restoreAllMocks()
  })

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
  afterEach(() => {
    vi.restoreAllMocks()
  })

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

  // R-0000737: a 43-character base64 string that passes the regex can
  // still decode to a non-canonical 32-byte digest when its trailing
  // base64 character does not have the lower two bits zeroed. Decoding
  // and re-encoding asserts that the input is the canonical form of a
  // real 32-byte SHA-256 digest.
  it("rejects SHA256 fingerprints whose trailing base64 character is non-canonical", () => {
    // Derived from TEST_HOST_FINGERPRINT by flipping the final base64
    // character from `A` (000000) to `B` (000001). Both encode to a
    // 32-byte buffer, but the latter re-encodes back to `A` so the
    // roundtrip check exposes the non-canonical input.
    const nonCanonicalFingerprint = `${TEST_HOST_FINGERPRINT.slice(0, -1)}B`
    expect(isValidExpectedHostFingerprint(nonCanonicalFingerprint)).toBe(false)
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

// R-0000189: exitWithMessage must surface failures via a CliExitError so the
// CLI driver can run terminal cleanup before assigning process.exitCode.
describe("CliExitError + handleCliExit", () => {
  afterEach(() => {
    vi.restoreAllMocks()
    if ("exitCode" in process) {
      process.exitCode = 0
    }
  })

  it("throws a CliExitError instead of calling process.exit", () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    let caught: unknown
    try {
      validateHost(" bad host ")
    } catch (error) {
      caught = error
    }

    expect(caught).toBeInstanceOf(CliExitError)
    expect((caught as CliExitError).exitCode).toBe(1)
    expect((caught as CliExitError).cliMessage).toContain("Error: Invalid host")
    expect((caught as CliExitError).reported).toBe(true)
  })

  it("handleCliExit prints directly thrown CliExitError messages once", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    try {
      handleCliExit(new CliExitError("Error: direct prompt abort", 7))
      expect(process.exitCode).toBe(7)
      expect(errorSpy).toHaveBeenCalledTimes(1)
      expect(errorSpy).toHaveBeenCalledWith("Error: direct prompt abort")
    } finally {
      process.exitCode = 0
    }
  })

  it("handleCliExit does not duplicate messages already printed by exitWithMessage", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    try {
      try {
        validateHost(" bad host ")
      } catch (error) {
        handleCliExit(error)
      }

      expect(process.exitCode).toBe(1)
      expect(errorSpy).toHaveBeenCalledTimes(1)
      expect(errorSpy).toHaveBeenCalledWith(
        'Error: Invalid host " bad host " — use a domain name, IPv4, or IPv6 address without spaces.'
      )
    } finally {
      process.exitCode = 0
    }
  })

  it("handleCliExit assigns exitCode and runs terminal cleanup for CliExitError", () => {
    vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })
    const restoreTty = setProcessTtyForTest(true, true)
    const stdin = process.stdin as {
      setRawMode?: (mode: boolean) => NodeJS.ReadStream
    } & NodeJS.ReadStream
    const setRawModeCalls: boolean[] = []
    const previousSetRawMode = stdin.setRawMode
    stdin.setRawMode = (mode: boolean): NodeJS.ReadStream => {
      setRawModeCalls.push(mode)
      return stdin
    }
    const stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    try {
      handleCliExit(new CliExitError("boom", 7, { reported: true }))
      expect(process.exitCode).toBe(7)
      expect(stdoutWriteSpy).toHaveBeenCalledWith("\x1B[?25h")
      expect(setRawModeCalls).toContain(false)
    } finally {
      stdoutWriteSpy.mockRestore()
      stdin.setRawMode = previousSetRawMode
      restoreTty()
      process.exitCode = 0
    }
  })

  it("handleCliExit logs and assigns exitCode 1 for non-CliExitError values", () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation((...args) => {
      void args
    })

    try {
      handleCliExit(new Error("unexpected"))
      expect(process.exitCode).toBe(1)
      expect(errorSpy).toHaveBeenCalledWith("unexpected")
    } finally {
      process.exitCode = 0
    }
  })

  it("restoreInteractiveTerminal is a no-op when stdin/stdout are not TTYs", () => {
    const restoreTty = setProcessTtyForTest(false, false)
    const stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true)

    try {
      restoreInteractiveTerminal()
      expect(stdoutWriteSpy).not.toHaveBeenCalled()
    } finally {
      stdoutWriteSpy.mockRestore()
      restoreTty()
    }
  })
})
