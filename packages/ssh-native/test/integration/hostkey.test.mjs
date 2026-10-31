// H2 against the real sshd: an async verifier is awaited before login, and
// a value the verifier throws or rejects with reaches the caller of
// connect() as the identical object. The full verdict-value matrix (only
// `true` accepts) is a B1 unit test (test/connect.test.mjs, "host key verdict").
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { describe } from "node:test"
import { setTimeout as sleep } from "node:timers/promises"

import { binding } from "../helpers/binding.mjs"
import { fixtures, hardProof } from "./lib/context.mjs"
import { pinnedVerifier, run, targetOptions } from "./lib/remote.mjs"

const VERIFIER_DELAY_MS = 750

class KnownHostsMismatchError extends Error {
  /** @param fingerprint the presented fingerprint */
  constructor(fingerprint) {
    super(`host key changed: ${fingerprint}`)
    this.name = "KnownHostsMismatchError"
  }
}

/** @returns key-file login options for the main profile */
function keyOptions() {
  return targetOptions({ privateKey: readFileSync(fixtures().keys.ed25519) })
}

/**
 * @param verifyHost a verifier that throws or rejects
 * @returns what connect() rejected with
 */
async function rejection(verifyHost) {
  const outcome = await binding
    .connect(keyOptions(), /** @type {import("../../index.js").HostVerifier} */ (verifyHost))
    .then((session) => ({ session }))
    .catch((error) => ({ error }))
  if ("session" in outcome) {
    outcome.session.destroy()
    assert.fail("connect() succeeded unexpectedly")
  }
  return outcome.error
}

describe("host key verification", () => {
  hardProof(
    { id: "H2-async-verifier", name: "connect() waits for an async verifier" },
    async (t) => {
      const pinned = pinnedVerifier()
      const started = Date.now()
      /** @type {number[]} */
      const marks = []
      const session = await binding.connect(keyOptions(), async (info) => {
        marks.push(Date.now() - started)
        await sleep(VERIFIER_DELAY_MS)
        marks.push(Date.now() - started)
        return pinned(info)
      })
      const elapsed = Date.now() - started
      try {
        t.diagnostic(`verify start ${marks[0]} ms, end ${marks[1]} ms, connected ${elapsed} ms`)
        assert.equal(marks.length, 2)
        assert.ok(elapsed >= VERIFIER_DELAY_MS, `connect() took only ${elapsed} ms`)
        const result = await run(session, "echo ok")
        assert.deepEqual([result.code, result.stdout], [0, "ok\n"])
      } finally {
        await session.close()
      }
    }
  )

  hardProof(
    {
      id: "H2-verifier-error-identity",
      name: "a thrown or rejected verifier value reaches the caller as the same object",
    },
    async () => {
      const asyncError = new KnownHostsMismatchError("SHA256:async")
      const asyncRejected = await rejection(async () => {
        await sleep(300)
        throw asyncError
      })
      assert.strictEqual(asyncRejected, asyncError, "async rejection")

      const syncError = new KnownHostsMismatchError("SHA256:sync")
      const syncThrown = await rejection(() => {
        throw syncError
      })
      assert.strictEqual(syncThrown, syncError, "synchronous throw")

      const marker = Symbol("not an Error")
      const nonError = await rejection(async () => {
        throw marker
      })
      assert.strictEqual(nonError, marker, "non-Error value")

      const plain = { reason: "plain object" }
      const plainThrown = await rejection(() => {
        throw plain
      })
      assert.strictEqual(plainThrown, plain, "plain object")
    }
  )
})
