import assert from "node:assert/strict"
import { describe, it } from "node:test"

import { binding } from "./helpers/binding.mjs"

const target = { host: "127.0.0.1", port: 1, user: "unused" }
const isZeroed = (buffer) => buffer.every((byte) => byte === 0)

describe("certificate options", () => {
  /** @type {[string, Record<string, unknown>][]} */
  const cases = [
    ["a string certificate", { certificate: "invalid" }],
    ["a certificate without privateKey", { certificate: Buffer.from("certificate") }],
    [
      "an agent with an external certificate",
      {
        agent: "/unused-agent",
        certificate: Buffer.from("certificate"),
        privateKey: Buffer.from("key"),
      },
    ],
  ]
  for (const [name, options] of cases) {
    it(`rejects ${name} and zero-fills buffers`, async () => {
      const invalid = /** @type {import("../index.js").ConnectOptions} */ (
        /** @type {unknown} */ ({ ...target, ...options })
      )
      await assert.rejects(
        binding.connect(invalid, () => true),
        TypeError
      )
      for (const value of Object.values(options)) {
        if (Buffer.isBuffer(value)) assert.ok(isZeroed(value))
      }
    })
  }

  it("zero-fills a certificate and key on abort before native parsing", async () => {
    const privateKey = Buffer.from("key")
    const certificate = Buffer.from("certificate")
    await assert.rejects(
      binding.connect(
        { ...target, certificate, privateKey, signal: AbortSignal.abort() },
        () => true
      ),
      { code: "ABORTED" }
    )
    assert.ok(isZeroed(privateKey) && isZeroed(certificate))
  })
})
