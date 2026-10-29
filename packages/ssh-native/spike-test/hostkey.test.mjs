// THROWAWAY SPIKE (issue #254): host key proofs (H2, scan, host certificates).
import assert from "node:assert/strict"
import { createServer } from "node:net"
import { after, before } from "node:test"

import {
  native,
  pinnedVerifier,
  publicKeyBase64,
  readFixture,
  run,
  setupTarget,
} from "./lib/env.mjs"
import { proof } from "./lib/results.mjs"

let target
before(async () => {
  target = await setupTarget()
})
after(async () => {
  await target?.stop()
})

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function keyOptions(extra = {}) {
  return {
    host: target.host,
    port: target.port,
    user: target.user,
    privateKey: readFixture(target.fixtureDir, "key_ed25519_openssh"),
    ...extra,
  }
}

class KnownHostsMismatch extends Error {
  constructor(info) {
    super(`HOST KEY CHANGED for ${info.fingerprintSha256}`)
    this.name = "KnownHostsMismatch"
  }
}

proof(
  "H2-async-verifier",
  "hard",
  "async host key callback is awaited (real delay) before auth",
  async () => {
    const pinned = pinnedVerifier(target.fixtureDir)
    const events = []
    const started = Date.now()
    const session = await native.connect(keyOptions(), async (info) => {
      events.push(["verify-start", Date.now() - started])
      await sleep(750)
      const ok = await pinned(info)
      events.push(["verify-end", Date.now() - started, ok])
      return ok
    })
    const elapsed = Date.now() - started
    try {
      assert.ok(elapsed >= 750, `connect must wait for the verifier (took ${elapsed} ms)`)
      assert.equal((await run(session, "echo ok")).stdout, "ok\n")
      return { elapsedMs: elapsed, events }
    } finally {
      await session.close()
    }
  }
)

proof(
  "H2-verifier-error-identity",
  "hard",
  "error thrown in the verifier reaches the caller as the same object",
  async () => {
    const outcomes = {}

    const asyncError = new KnownHostsMismatch({ fingerprintSha256: "SHA256:x" })
    const rejected1 = await native
      .connect(keyOptions(), async () => {
        await sleep(300)
        throw asyncError
      })
      .then(
        () => null,
        (e) => e
      )
    assert.ok(rejected1 === asyncError, "async rejection must surface as the identical object")
    outcomes.asyncReject = { identical: rejected1 === asyncError, name: rejected1?.name }

    const syncError = new KnownHostsMismatch({ fingerprintSha256: "SHA256:y" })
    const rejected2 = await native
      .connect(keyOptions(), () => {
        throw syncError
      })
      .then(
        () => null,
        (e) => e
      )
    assert.ok(rejected2 === syncError, "synchronous throw must surface as the identical object")
    outcomes.syncThrow = { identical: rejected2 === syncError }

    const marker = Symbol("non-error")
    const rejected3 = await native
      .connect(keyOptions(), async () => {
        // eslint-disable-next-line no-throw-literal
        throw marker
      })
      .then(
        () => null,
        (e) => e
      )
    assert.ok(rejected3 === marker, "non-Error throw values keep identity too")
    outcomes.nonErrorValue = { identical: rejected3 === marker }

    const rejected4 = await native
      .connect(keyOptions(), async () => false)
      .then(
        () => null,
        (e) => e
      )
    assert.equal(
      rejected4?.code,
      "HOST_KEY_REJECTED",
      "a plain `false` gives a generic HOST_KEY_REJECTED"
    )
    outcomes.returnFalse = { code: rejected4.code, message: rejected4.message }
    return outcomes
  }
)

proof(
  "O-scan",
  "other",
  "scan(): handshake without auth returns the host key (ssh2 order → ed25519)",
  async () => {
    const info = await native.scan({ host: target.host, port: target.port, timeoutMs: 5000 })
    assert.equal(info.kind, "key")
    assert.equal(info.algorithm, "ssh-ed25519")
    assert.equal(info.keyBase64, publicKeyBase64(target.fixtureDir, "host_ed25519.pub"))
    assert.match(info.fingerprintSha256, /^SHA256:/)
    return info
  }
)

proof(
  "O-scan-half-open-timeout",
  "other",
  "scan() and connect() time out against a peer that never speaks",
  async () => {
    const sockets = []
    const silent = createServer((socket) => sockets.push(socket))
    await new Promise((r) => silent.listen(0, "127.0.0.1", r))
    const port = silent.address().port
    try {
      const t0 = Date.now()
      const scanError = await native.scan({ host: "127.0.0.1", port, timeoutMs: 1500 }).then(
        () => null,
        (e) => e
      )
      const scanMs = Date.now() - t0
      assert.equal(scanError?.code, "TIMEOUT")
      assert.ok(scanMs < 4000, `scan must honour its overall timeout (${scanMs} ms)`)
      const t1 = Date.now()
      const connectError = await native
        .connect(keyOptions({ host: "127.0.0.1", port, readyTimeoutMs: 1500 }), async () => true)
        .then(
          () => null,
          (e) => e
        )
      const connectMs = Date.now() - t1
      assert.equal(connectError?.code, "TIMEOUT")
      assert.ok(connectMs < 4000)
      return {
        scan: { code: scanError.code, ms: scanMs },
        connect: { code: connectError.code, ms: connectMs },
      }
    } finally {
      for (const s of sockets) s.destroy()
      silent.close()
    }
  }
)

proof(
  "O-host-certificate",
  "other",
  "host certificate reaches verifyHost as kind 'certificate' only when offered",
  async () => {
    const hostCa = publicKeyBase64(target.fixtureDir, "host_ca.pub")
    const seen = []
    const session = await native.connect(keyOptions({ hostCertificates: true }), async (info) => {
      seen.push(info)
      // Stand-in for an @cert-authority known_hosts line (work package E).
      return info.kind === "certificate" && info.caKeyBase64 === hostCa && info.certType === "host"
    })
    await session.close()
    const cert = seen[0]
    assert.equal(cert.kind, "certificate")
    assert.equal(cert.algorithm, "ssh-ed25519-cert-v01@openssh.com")
    assert.equal(cert.keyBase64, publicKeyBase64(target.fixtureDir, "host_ed25519.pub"))
    assert.ok(cert.principals.includes("localhost"))
    assert.equal(cert.caSignatureValid, true)

    const plainSeen = []
    const plain = await native.connect(
      keyOptions({ hostCertificates: false }),
      pinnedVerifier(target.fixtureDir, plainSeen)
    )
    await plain.close()
    assert.equal(plainSeen[0].kind, "key")
    const scanCert = await native.scan({
      host: target.host,
      port: target.port,
      timeoutMs: 5000,
      hostCertificates: true,
    })
    assert.equal(scanCert.kind, "certificate")
    return {
      withCertificates: cert,
      withoutCertificates: plainSeen[0],
      scanWithCertificates: scanCert.kind,
    }
  }
)
