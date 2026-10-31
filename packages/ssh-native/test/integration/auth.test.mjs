// Authentication against the real sshd: H1 (agent login with a user
// certificate on the TrustedUserCAKeys-only profile), ECDSA P-384/P-521
// from file and agent, password and keyboard-interactive (PAM, Docker
// only), and the key and login error codes without secrets in the error.
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { describe } from "node:test"

import { binding } from "../helpers/binding.mjs"
import { startAgent } from "./lib/agent.mjs"
import { check, fixtures, hardProof, target } from "./lib/context.mjs"
import {
  connectWithAgent,
  connectWithKeyFile,
  pinnedVerifier,
  run,
  targetOptions,
} from "./lib/remote.mjs"

/**
 * @param promise a connect() that must fail
 * @returns the rejection value
 */
async function failure(promise) {
  const session = await promise.catch((error) => ({ error }))
  if ("error" in session) return session.error
  session.destroy()
  assert.fail("connect() succeeded unexpectedly")
}

/**
 * Asserts that no string of the error (message, stack, detail and every
 * other own property) contains one of the secrets.
 *
 * @param error what connect() rejected with
 * @param secrets strings that must not appear
 */
function assertNoSecrets(error, secrets) {
  const texts = Object.getOwnPropertyNames(error)
    .map((name) => error[name])
    .filter((value) => typeof value === "string")
  assert.ok(texts.includes(error.message) && texts.includes(error.stack))
  for (const text of texts) {
    for (const secret of secrets) assert.ok(!text.includes(secret), `error leaks a secret: ${text}`)
  }
}

/**
 * @param keyPath a PEM or OpenSSH private key
 * @returns the header plus 24-character slices of its base64 body
 */
function keyMaterial(keyPath) {
  const lines = readFileSync(keyPath, "utf8").trim().split("\n")
  const body = lines.slice(1, -1).join("")
  const slices = body.match(/.{24}/gv) ?? []
  return ["PRIVATE KEY", ...slices]
}

describe("authentication", () => {
  hardProof(
    {
      id: "H1-agent-user-certificate",
      name: "agent login with a user certificate on a TrustedUserCAKeys-only sshd",
    },
    async (t) => {
      const { authorizedKeys, bareCertKey, certKey } = fixtures()
      const port = target().ports.userCa
      const [, certBlob] = readFileSync(`${certKey}.pub`, "utf8").split(" ")
      assert.ok(!readFileSync(authorizedKeys, "utf8").includes(certBlob), "key is not authorized")

      // Negative control: the same key without its certificate.
      const bare = await startAgent([bareCertKey])
      let bareError
      try {
        assert.equal(bare.added[bareCertKey], "added")
        assert.equal(bare.identities.length, 1, "the agent holds exactly the bare key")
        assert.equal(bare.identities[0].split(" ")[1], certBlob)
        bareError = await failure(connectWithAgent(bare.socket, { port }))
      } finally {
        await bare.stop()
      }
      assert.equal(bareError.code, "AUTH_FAILED")
      assert.ok(!String(bareError.detail ?? "").startsWith("agent-"), "refused by the server")

      const agent = await startAgent([certKey])
      try {
        assert.ok(agent.identities.some((line) => line.includes("-cert-v01@openssh.com")))
        const session = await connectWithAgent(agent.socket, { port })
        try {
          const { authInfo } = session
          t.diagnostic(`authInfo ${JSON.stringify(authInfo)}`)
          assert.equal(authInfo.method, "agent")
          assert.equal(authInfo.identityKind, "certificate")
          assert.equal(authInfo.algorithm, "ssh-ed25519-cert-v01@openssh.com")
          const whoami = await run(session, "id -un")
          assert.equal(whoami.code, 0)
          assert.equal(whoami.stdout.trim(), target().user)
        } finally {
          await session.close()
        }
      } finally {
        await agent.stop()
      }
    }
  )

  for (const [name, curve, algorithm] of [
    ["P-384", "p384", "ecdsa-sha2-nistp384"],
    ["P-521", "p521", "ecdsa-sha2-nistp521"],
  ]) {
    check(`logs in with an ECDSA ${name} key from a file`, async () => {
      const session = await connectWithKeyFile(fixtures().keys[curve])
      try {
        assert.deepEqual(session.authInfo, {
          algorithm,
          attempts: 1,
          identityKind: "key",
          method: "publickey",
        })
        const result = await run(session, "true")
        assert.equal(result.code, 0)
      } finally {
        await session.close()
      }
    })

    check(`logs in with an ECDSA ${name} key from the agent`, async () => {
      const keyPath = fixtures().keys[curve]
      const agent = await startAgent([keyPath])
      try {
        assert.equal(agent.added[keyPath], "added")
        const session = await connectWithAgent(agent.socket)
        try {
          assert.deepEqual(session.authInfo, {
            algorithm,
            attempts: 1,
            identityKind: "key",
            method: "agent",
          })
          const result = await run(session, "true")
          assert.equal(result.code, 0)
        } finally {
          await session.close()
        }
      } finally {
        await agent.stop()
      }
    })
  }

  check("rejects an encrypted key with ENCRYPTED_KEY, without the passphrase", async () => {
    const { encryptedKey, encryptedKeyPassphrase } = fixtures()
    const error = await failure(connectWithKeyFile(encryptedKey))
    assert.equal(error.code, "ENCRYPTED_KEY")
    assertNoSecrets(error, [encryptedKeyPassphrase, ...keyMaterial(encryptedKey)])
  })

  check("rejects a DSA key (PKCS#8) with UNSUPPORTED_KEY", async () => {
    const { dsaPkcs8Key } = fixtures()
    const error = await failure(connectWithKeyFile(dsaPkcs8Key))
    assert.equal(error.code, "UNSUPPORTED_KEY")
    assertNoSecrets(error, keyMaterial(dsaPkcs8Key))
  })

  check("rejects a DSA key (OpenSSH format) with UNSUPPORTED_KEY", async () => {
    const { dsaOpensshKey } = fixtures()
    const error = await failure(connectWithKeyFile(dsaOpensshKey))
    assertNoSecrets(error, keyMaterial(dsaOpensshKey))
    assert.equal(error.code, "UNSUPPORTED_KEY")
  })

  check("rejects an unauthorized key with AUTH_FAILED, without key material", async () => {
    const { unauthorizedKey } = fixtures()
    const error = await failure(connectWithKeyFile(unauthorizedKey))
    assert.equal(error.code, "AUTH_FAILED")
    assertNoSecrets(error, keyMaterial(unauthorizedKey))
  })

  check(
    "logs in with a password",
    async () => {
      const { password, ports } = target()
      const session = await binding.connect(
        targetOptions({ password: Buffer.from(String(password)), port: ports.password }),
        pinnedVerifier()
      )
      try {
        assert.equal(session.authInfo.method, "password")
        const result = await run(session, "true")
        assert.equal(result.code, 0)
      } finally {
        await session.close()
      }
    },
    { needs: ["sshd", "pam"] }
  )

  check(
    "logs in with keyboard-interactive",
    async () => {
      const { password, ports } = target()
      const session = await binding.connect(
        targetOptions({
          password: Buffer.from(String(password)),
          port: ports.keyboardInteractive,
        }),
        pinnedVerifier()
      )
      try {
        assert.equal(session.authInfo.method, "keyboard-interactive")
      } finally {
        await session.close()
      }
    },
    { needs: ["sshd", "pam"] }
  )

  check(
    "rejects a wrong password with AUTH_FAILED, without the password in the error",
    async () => {
      const wrong = `wrong-${target().password}`
      const error = await failure(
        binding.connect(targetOptions({ password: Buffer.from(wrong) }), pinnedVerifier())
      )
      assert.equal(error.code, "AUTH_FAILED")
      assertNoSecrets(error, [wrong, String(target().password)])
    },
    { needs: ["sshd", "pam"] }
  )
})
