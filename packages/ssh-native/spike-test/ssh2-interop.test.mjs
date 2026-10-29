// THROWAWAY SPIKE (issue #254): interop with the in-process ssh2 Server, plus
// binding-level checks (INTERNAL mapping, crypto backend, disconnect event).
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { join } from "node:path"

import { native, PACKAGE_DIR, run } from "./lib/env.mjs"
import { proof } from "./lib/results.mjs"
import { latestClient, startSsh2Server } from "./lib/ssh2-server.mjs"

proof(
  "O-ssh2-server-interop",
  "other",
  "scan + key auth (RSA PKCS#1) + exec against ssh2's Server",
  async () => {
    const server = await startSsh2Server()
    try {
      const info = await native.scan({ host: "127.0.0.1", port: server.port, timeoutMs: 5000 })
      assert.equal(info.algorithm, "ssh-rsa")
      assert.equal(info.keyBase64, server.hostKeyBase64)
      const key = Buffer.from(server.privateKey)
      const session = await native.connect(
        { host: "127.0.0.1", port: server.port, user: "root", privateKey: key },
        async (presented) => presented.keyBase64 === server.hostKeyBase64
      )
      try {
        const result = await run(session, "uname -a")
        assert.equal(result.code, 0)
        assert.equal(result.stdout, "ssh2-server ran: uname -a\n")
        return {
          scan: { algorithm: info.algorithm, fingerprint: info.fingerprintSha256 },
          authInfo: session.authInfo,
          exec: result,
        }
      } finally {
        await session.close()
      }
    } finally {
      await server.close()
    }
  }
)

proof(
  "O-disconnect-event",
  "other",
  "server-side disconnect emits 'disconnect' and later calls fail with DISCONNECTED",
  async () => {
    const server = await startSsh2Server()
    try {
      const session = await native.connect(
        {
          host: "127.0.0.1",
          port: server.port,
          user: "root",
          privateKey: Buffer.from(server.privateKey),
        },
        async () => true
      )
      const client = await latestClient(server)
      const disconnected = new Promise((resolve) => session.once("disconnect", resolve))
      client.end()
      const reason = await disconnected
      const error = await session.exec("true").then(
        () => null,
        (e) => e
      )
      assert.equal(error?.code, "DISCONNECTED")
      return { reason, followUpCode: error.code, closed: session.closed }
    } finally {
      await server.close()
    }
  }
)

proof(
  "O-panic-maps-to-internal",
  "other",
  "a Rust panic becomes INTERNAL, silently (no stderr)",
  async () => {
    const script = `
    const ssh = require(${JSON.stringify(join(PACKAGE_DIR, "index.js"))})
    ssh.internalPanicProbe().then(
      () => { console.log("resolved"); },
      (e) => { console.log(JSON.stringify({ code: e.code, message: e.message })) }
    )`
    const child = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 10_000 })
    assert.equal(child.status, 0)
    assert.equal(child.stderr, "")
    const outcome = JSON.parse(child.stdout.trim())
    assert.equal(outcome.code, "INTERNAL")
    return { outcome, stderr: child.stderr, cryptoBackend: native.cryptoBackend() }
  }
)
