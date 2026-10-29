import assert from "node:assert/strict"
import { once } from "node:events"
import { createServer } from "node:net"
import { finished } from "node:stream/promises"
import { after, before, describe, it } from "node:test"

import { binding, collect, connectWithKey, delay, trustServer } from "./helpers/binding.mjs"
import { clientKey, startServer, TEST_PASSWORD, TEST_USER } from "./helpers/server.mjs"

/**
 * @param buffer the caller's buffer
 * @returns whether every byte is zero
 */
const isZeroed = (buffer) => buffer.every((byte) => byte === 0)

/**
 * A verifier with an arbitrary (possibly non-boolean) verdict.
 *
 * @param verdict returns the verdict
 * @returns the verifier, typed loosely on purpose
 */
const verifier = (verdict) =>
  /** @type {import("./helpers/binding.mjs").HostVerifier} */ (/** @type {unknown} */ (verdict))

/** @returns a promise that never settles */
const never = () => new Promise(() => {})

/**
 * @param listener a listening server
 * @returns its port
 */
const portOf = (listener) => /** @type {import("node:net").AddressInfo} */ (listener.address()).port

/**
 * @param privateKey PEM key
 * @returns fresh secret buffers
 */
const secrets = (privateKey) => ({
  password: Buffer.from(TEST_PASSWORD),
  privateKey: Buffer.from(privateKey),
})

describe("connect", () => {
  const key = clientKey()
  const p384 = clientKey("ec", { namedCurve: "P-384" })
  const p521 = clientKey("ec", { namedCurve: "P-521" })
  const unknownKey = clientKey()
  let server

  before(async () => {
    server = await startServer({ keys: [key.publicKey, p384.publicKey, p521.publicKey] })
  })
  after(() => server.close())

  const target = () => ({ host: server.host, port: server.port, user: TEST_USER })

  it("scans the host key without logging in", async () => {
    const attempts = server.stats.authAttempts
    const info = await binding.scan({ host: server.host, port: server.port })
    assert.equal(info.kind, "key")
    assert.equal(info.algorithm, "ssh-rsa")
    assert.equal(info.keyBase64, server.hostKeyBase64)
    assert.match(info.fingerprintSha256, /^SHA256:/v)
    assert.equal(server.stats.authAttempts, attempts)
  })

  for (const { algorithm, name, pair } of [
    { algorithm: "ssh-ed25519", name: "ed25519", pair: key },
    { algorithm: "ecdsa-sha2-nistp384", name: "ECDSA P-384", pair: p384 },
    { algorithm: "ecdsa-sha2-nistp521", name: "ECDSA P-521", pair: p521 },
  ]) {
    it(`logs in with an ${name} key and runs a command`, async () => {
      const session = await connectWithKey(server, pair)
      try {
        assert.deepEqual(session.authInfo, {
          algorithm,
          attempts: 1,
          identityKind: "key",
          method: "publickey",
        })
        const channel = await session.exec("exit 7")
        const [stdout, stderr, exit] = await Promise.all([
          collect(channel.stdout),
          collect(channel.stderr),
          channel.exit,
        ])
        assert.equal(stdout.toString(), "out\n")
        assert.equal(stderr.toString(), "err\n")
        assert.deepEqual(exit, { code: 7, disconnected: false, signal: null })
      } finally {
        await session.close()
      }
    })
  }

  it("logs in with a password", async () => {
    const session = await binding.connect(
      { ...target(), password: Buffer.from(TEST_PASSWORD) },
      trustServer(server)
    )
    assert.equal(session.authInfo.method, "password")
    await session.close()
    assert.equal(session.closed, true)
  })

  it("rejects an unknown key with AUTH_FAILED", async () => {
    await assert.rejects(connectWithKey(server, unknownKey), { code: "AUTH_FAILED" })
  })

  describe("host key verdict", () => {
    it("accepts only true", async () => {
      const session = await connectWithKey(server, key, { verifyHost: () => true })
      await session.close()
      const asyncSession = await connectWithKey(server, key, { verifyHost: async () => true })
      await asyncSession.close()
    })

    for (const verdict of [false, undefined, 1, "yes", null, {}]) {
      it(`rejects the verdict ${JSON.stringify(verdict) ?? "undefined"} with HOST_KEY_REJECTED`, async () => {
        await assert.rejects(connectWithKey(server, key, { verifyHost: verifier(() => verdict) }), {
          code: "HOST_KEY_REJECTED",
        })
        const asyncVerifier = verifier(async () => verdict)
        await assert.rejects(connectWithKey(server, key, { verifyHost: asyncVerifier }), {
          code: "HOST_KEY_REJECTED",
        })
      })
    }

    for (const [name, thrown] of [
      ["an Error", new Error("known_hosts mismatch")],
      ["a non-Error value", { reason: "custom" }],
      ["a string", "plain string"],
    ]) {
      it(`passes ${name} thrown synchronously through as the same value`, async () => {
        const caught = await connectWithKey(server, key, {
          verifyHost: verifier(() => {
            throw thrown
          }),
        }).catch((error) => error)
        assert.equal(caught, thrown)
      })

      it(`passes ${name} rejected asynchronously through as the same value`, async () => {
        const caught = await connectWithKey(server, key, {
          verifyHost: verifier(() => Promise.reject(thrown)),
        }).catch((error) => error)
        assert.equal(caught, thrown)
      })
    }

    it("times out a verifier that never settles", async () => {
      const started = Date.now()
      await assert.rejects(
        connectWithKey(server, key, {
          readyTimeoutMs: 500,
          verifyHost: never,
        }),
        { code: "TIMEOUT" }
      )
      const elapsed = Date.now() - started
      assert.ok(elapsed >= 450 && elapsed < 1500, `rejected after ${elapsed} ms`)
    })
  })

  describe("abort", () => {
    it("rejects an already aborted signal with ABORTED without opening TCP", async () => {
      let connections = 0
      const listener = createServer((socket) => {
        connections += 1
        socket.destroy()
      })
      listener.listen(0, "127.0.0.1")
      await once(listener, "listening")
      try {
        await assert.rejects(
          binding.connect(
            {
              host: "127.0.0.1",
              password: Buffer.from("x"),
              port: portOf(listener),
              signal: AbortSignal.abort(),
              user: TEST_USER,
            },
            () => true
          ),
          { code: "ABORTED" }
        )
        await assert.rejects(
          binding.scan({
            host: "127.0.0.1",
            port: portOf(listener),
            signal: AbortSignal.abort(),
          }),
          { code: "ABORTED" }
        )
        await delay(50)
        assert.equal(connections, 0)
      } finally {
        listener.close()
      }
    })

    it("aborts while the verifier is pending", async () => {
      const controller = new AbortController()
      await assert.rejects(
        connectWithKey(server, key, {
          signal: controller.signal,
          verifyHost() {
            setTimeout(() => controller.abort(), 20)
            return never()
          },
        }),
        { code: "ABORTED" }
      )
    })
  })

  describe("zeroize", () => {
    it("zero-fills the caller's key on success", async () => {
      const { privateKey } = secrets(key.privateKey)
      const session = await binding.connect({ ...target(), privateKey }, trustServer(server))
      assert.ok(isZeroed(privateKey))
      await session.close()
    })

    it("zero-fills the caller's password on success", async () => {
      const { password } = secrets(key.privateKey)
      const session = await binding.connect({ ...target(), password }, trustServer(server))
      assert.ok(isZeroed(password))
      await session.close()
    })

    it("zero-fills the caller's password on auth failure", async () => {
      const password = Buffer.from("wrong password")
      await assert.rejects(binding.connect({ ...target(), password }, trustServer(server)), {
        code: "AUTH_FAILED",
      })
      assert.ok(isZeroed(password))
    })

    it("zero-fills the caller's key on host key rejection", async () => {
      const { privateKey } = secrets(key.privateKey)
      await assert.rejects(
        binding.connect({ ...target(), privateKey }, () => false),
        {
          code: "HOST_KEY_REJECTED",
        }
      )
      assert.ok(isZeroed(privateKey))
    })

    it("zero-fills both buffers on a validation error", async () => {
      const { password, privateKey } = secrets(key.privateKey)
      await assert.rejects(
        binding.connect({ ...target(), password, port: 0, privateKey }, trustServer(server)),
        TypeError
      )
      assert.ok(isZeroed(privateKey) && isZeroed(password))
    })

    it("zero-fills the caller's key on abort", async () => {
      const { privateKey } = secrets(key.privateKey)
      await assert.rejects(
        binding.connect(
          { ...target(), privateKey, signal: AbortSignal.abort() },
          trustServer(server)
        ),
        { code: "ABORTED" }
      )
      assert.ok(isZeroed(privateKey))
      const pending = secrets(key.privateKey).privateKey
      const controller = new AbortController()
      await assert.rejects(
        binding.connect({ ...target(), privateKey: pending, signal: controller.signal }, () => {
          controller.abort()
          return never()
        }),
        { code: "ABORTED" }
      )
      assert.ok(isZeroed(pending))
    })

    it("zero-fills the exec stdin option and stdin chunks", async () => {
      const session = await connectWithKey(server, key)
      try {
        const initial = Buffer.from("sudo-password\n")
        const chunk = Buffer.from("more stdin")
        const channel = await session.exec("echo-stdin", { stdin: initial })
        assert.ok(isZeroed(initial))
        channel.stdin.end(chunk)
        await finished(channel.stdin)
        assert.ok(isZeroed(chunk))
        const stdout = await collect(channel.stdout)
        assert.equal(stdout.toString(), "sudo-password\nmore stdin")
        const exit = await channel.exit
        assert.equal(exit.code, 0)

        const aborted = Buffer.from("secret")
        await assert.rejects(
          session.exec("echo-stdin", { signal: AbortSignal.abort(), stdin: aborted }),
          {
            code: "ABORTED",
          }
        )
        assert.ok(isZeroed(aborted))
      } finally {
        await session.close()
      }
    })

    it("zero-fills stdin chunks still queued when the channel is cancelled", async () => {
      const session = await connectWithKey(server, key)
      try {
        const channel = await session.exec("sleep")
        const chunks = [Buffer.from("first"), Buffer.from("queued"), Buffer.from("also queued")]
        for (const chunk of chunks) channel.stdin.write(chunk)
        channel.cancel()
        await assert.rejects(channel.exit, { code: "ABORTED" })
        for (const chunk of chunks) assert.ok(isZeroed(chunk), chunk.toString())
      } finally {
        await session.close()
      }
    })

    it("zero-fills stdin chunks written after the channel ended", async () => {
      const session = await connectWithKey(server, key)
      try {
        const channel = await session.exec("exit 0")
        channel.stdout.resume()
        await channel.exit
        const late = Buffer.from("written too late")
        channel.stdin.write(late, () => {})
        assert.ok(isZeroed(late))
        const ended = Buffer.from("after end")
        channel.stdin.end(ended)
        assert.ok(isZeroed(ended))
      } finally {
        await session.close()
      }
    })
  })
})
