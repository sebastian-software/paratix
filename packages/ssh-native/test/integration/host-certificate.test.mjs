// Native boundary proof: OpenSSH presents an Ed25519 leaf certified by an
// RSA CA. Authorization remains the callback's responsibility.
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { describe } from "node:test"

import { binding } from "../helpers/binding.mjs"
import { check, fixtures, target } from "./lib/context.mjs"
import { run, targetOptions } from "./lib/remote.mjs"

/** @returns fresh native connect options with file authentication */
function options() {
  return targetOptions({
    hostCertificates: true,
    privateKey: readFileSync(fixtures().keys.ed25519),
  })
}

describe("native host certificates", () => {
  check(
    "validates an RSA-signed Ed25519 host certificate and returns only the raw leaf",
    async () => {
      let calls = 0
      const session = await binding.connect(options(), (info) => {
        calls += 1
        assert.equal(info.kind, "certificate")
        assert.equal(info.keyAlgorithm, "ssh-ed25519")
        assert.equal(info.caAlgorithm, "ssh-rsa")
        assert.ok(info.keyBase64 === fixtures().hostKeyBase64, "certified leaf matches the raw key")
        assert.ok(info.caKeyBase64 === fixtures().hostCaBase64, "the selected CA matches")
        assert.equal(info.caSignatureValid, true)
        assert.equal(info.certType, "host")
        assert.ok(info.principals?.includes(target().host), "the requested host is a principal")
        assert.equal(info.certificateValidation?.valid, true)
        assert.equal(info.certificateValidation.reason, undefined)
        return true
      })
      try {
        assert.equal(calls, 1)
        const result = await run(session, "echo certificate-ok")
        assert.deepEqual([result.code, result.stdout], [0, "certificate-ok\n"])
      } finally {
        await session.close()
      }
    }
  )

  check("preserves certificate verifier error identity without a raw-key retry", async () => {
    const rejected = new Error("certificate authorization rejected")
    let calls = 0
    await assert.rejects(
      binding.connect(options(), (info) => {
        calls += 1
        assert.equal(info.kind, "certificate")
        throw rejected
      }),
      (error) => error === rejected
    )
    assert.equal(calls, 1)
  })

  check("scan still requests the raw key from the same certificate-capable server", async () => {
    const remote = target()
    const info = await binding.scan({ host: remote.host, port: remote.ports.main })
    assert.equal(info.kind, "key")
    assert.ok(info.keyBase64 === fixtures().hostKeyBase64)
    assert.equal(info.certificateValidation, undefined)
  })
})
