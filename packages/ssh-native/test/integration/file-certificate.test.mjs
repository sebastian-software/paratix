// File user certificates: preflight before TCP, ECDSA/Ed25519 signing and
// RSA-SHA2 on CA-only sshd profiles, including an independent RSA CA.
import assert from "node:assert/strict"
import { once } from "node:events"
import { readFileSync } from "node:fs"
import { createServer } from "node:net"
import { describe } from "node:test"
import { setImmediate } from "node:timers/promises"

import { binding } from "../helpers/binding.mjs"
import { check, fixtures, target } from "./lib/context.mjs"
import { connectWithKeyFile, pinnedVerifier, run, targetOptions } from "./lib/remote.mjs"

const INVALID_CERTIFICATE = "certificate-invalid"

/** @param bytes caller's material */
function assertZeroed(bytes) {
  assert.ok(
    bytes.every((byte) => byte === 0),
    "the caller's buffer was zero-filled"
  )
}

/**
 * @param keyPath private key path
 * @param certificatePath OpenSSH public credential to send
 * @param port CA-only profile port
 * @returns the authenticated session
 */
function connectCertificate(keyPath, certificatePath, port) {
  const privateKey = readFileSync(keyPath)
  const certificate = readFileSync(certificatePath)
  const pending = binding.connect(
    targetOptions({ certificate, port, privateKey }),
    pinnedVerifier()
  )
  assertZeroed(privateKey)
  assertZeroed(certificate)
  return pending
}

/**
 * @param source a valid certificate buffer
 * @returns a copy with an invalid signature
 */
function corruptSignature(source) {
  const [algorithm, body] = source.toString().trim().split(/\s+/v)
  const blob = Buffer.from(body, "base64")
  blob[blob.length - 1] ^= 1
  return Buffer.from(`${algorithm} ${blob.toString("base64")}\n`)
}

describe("file user certificates", () => {
  for (const [kind, algorithm] of [
    ["ed25519", "ssh-ed25519-cert-v01@openssh.com"],
    ["p384", "ecdsa-sha2-nistp384-cert-v01@openssh.com"],
    ["p521", "ecdsa-sha2-nistp521-cert-v01@openssh.com"],
    ["rsa", "rsa-sha2-512-cert-v01@openssh.com"],
  ]) {
    check(`logs in with a ${kind} file certificate on a CA-only server`, async () => {
      const path = kind === "ed25519" ? fixtures().certKey : fixtures().fileCertKeys[kind]
      const port = target().ports.userCa
      // No bare-key fallback is possible on this sshd profile.
      await assert.rejects(connectWithKeyFile(path, { port }), { code: "AUTH_FAILED" })
      const session = await connectCertificate(path, `${path}-cert.pub`, port)
      try {
        assert.deepEqual(session.authInfo, {
          algorithm,
          attempts: 1,
          identityKind: "certificate",
          method: "publickey",
        })
        const result = await run(session, "id -un")
        assert.equal(result.stdout.trim(), target().user)
        if (kind !== "ed25519") {
          assert.notEqual(fixtures().filePrincipal, target().user)
        }
      } finally {
        await session.close()
      }
    })
  }

  check(
    "uses RSA-SHA2 with an RSA user key and RSA CA on a restricted certificate server",
    async () => {
      const path = fixtures().fileCertKeys.rsa
      const port = target().ports.rsaCa
      await assert.rejects(connectWithKeyFile(path, { port }), { code: "AUTH_FAILED" })
      const session = await connectCertificate(path, `${path}-cert.pub`, port)
      try {
        assert.match(
          session.authInfo.algorithm ?? "",
          /^rsa-sha2-(?:256|512)-cert-v01@openssh.com$/v
        )
        assert.equal(session.authInfo.identityKind, "certificate")
        const result = await run(session, "true")
        assert.equal(result.code, 0)
      } finally {
        await session.close()
      }
    }
  )

  check("rejects invalid local certificates before TCP with safe stable details", async () => {
    let connections = 0
    const listener = createServer((socket) => {
      connections += 1
      socket.destroy()
    })
    listener.listen(0, "127.0.0.1")
    await once(listener, "listening")
    const port = /** @type {import("node:net").AddressInfo} */ (listener.address()).port
    const fixture = fixtures()
    const keyPath = fixture.fileCertKeys.p384
    const valid = readFileSync(`${keyPath}-cert.pub`)
    const cases = [
      [INVALID_CERTIFICATE, Buffer.from("private-certificate-material")],
      [INVALID_CERTIFICATE, corruptSignature(valid)],
      [INVALID_CERTIFICATE, readFileSync(fixture.invalidCertificates.host)],
      ["certificate-key-mismatch", readFileSync(`${fixture.certKey}-cert.pub`)],
      ["certificate-expired", readFileSync(fixture.invalidCertificates.expired)],
      ["certificate-not-yet-valid", readFileSync(fixture.invalidCertificates.future)],
    ]
    try {
      for (const [detail, material] of cases) {
        const certificate = /** @type {Buffer} */ (material)
        const privateKey = readFileSync(keyPath)
        const original = certificate.toString()
        // eslint-disable-next-line no-await-in-loop -- test each independent preflight failure before the next connection
        await assert.rejects(
          binding.connect(
            { certificate, host: "127.0.0.1", port, privateKey, user: target().user },
            () => {
              assert.fail("local preflight must precede host-key verification")
            }
          ),
          (error) => {
            const nativeError = /** @type {import("../../index.js").NativeSshError} */ (error)
            assert.equal(nativeError.code, "AUTH_FAILED")
            assert.equal(nativeError.detail, detail)
            const strings = Object.getOwnPropertyNames(nativeError)
              .map((name) => nativeError[name])
              .filter((value) => typeof value === "string")
            for (const text of strings) {
              assert.ok(!text.includes(original))
              assert.ok(!text.includes("ssh-native-it-private-id"))
              assert.ok(!text.includes(fixture.filePrincipal))
            }
            return true
          }
        )
        assertZeroed(privateKey)
        assertZeroed(certificate)
      }
      await setImmediate()
      assert.equal(connections, 0)
    } finally {
      listener.close()
    }
  })

  check("retains private-key error codes during certificate preflight", async () => {
    for (const [keyPath, code] of [
      [fixtures().encryptedKey, "ENCRYPTED_KEY"],
      [fixtures().dsaOpensshKey, "UNSUPPORTED_KEY"],
    ]) {
      // An unreachable port distinguishes local preflight from connect errors.
      // eslint-disable-next-line no-await-in-loop -- verify the two independent key formats
      await assert.rejects(connectCertificate(keyPath, `${fixtures().certKey}-cert.pub`, 1), {
        code,
      })
    }
  })

  for (const name of ["untrusted", "wrongPrincipal"]) {
    check(`reports a generic server rejection for a ${name} certificate`, async () => {
      await assert.rejects(
        connectCertificate(
          fixtures().fileCertKeys.p384,
          fixtures().invalidCertificates[name],
          target().ports.userCa
        ),
        (error) => {
          const nativeError = /** @type {import("../../index.js").NativeSshError} */ (error)
          assert.equal(nativeError.code, "AUTH_FAILED")
          assert.equal(nativeError.detail, undefined)
          assert.match(nativeError.message, /server CA and principal configuration/v)
          assert.ok(!nativeError.message.includes("ssh-native-not-authorized"))
          return true
        }
      )
    })
  }
})
