// THROWAWAY SPIKE (issue #254): exec proofs (H3) and channel rejection.
import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { after, before } from "node:test"

import { connectWithKey, readAll, run, setupTarget } from "./lib/env.mjs"
import { proof } from "./lib/results.mjs"

let target
before(async () => {
  target = await setupTarget()
})
after(async () => {
  await target?.stop()
})

proof(
  "H3-exec-streams-and-exit",
  "hard",
  "exec with stdout, stderr, stdin and exit code",
  async () => {
    const session = await connectWithKey(target)
    try {
      const basic = await run(session, "cat; echo err >&2; exit 3", "hello from stdin")
      assert.equal(basic.stdout, "hello from stdin")
      assert.equal(basic.stderr, "err\n")
      assert.equal(basic.code, 3)
      assert.equal(basic.signal, null)

      // Signal case: the remote shell kills itself; sshd reports exit-signal.
      const signalled = await run(session, "kill -TERM $$")
      assert.equal(signalled.signal, "TERM")
      assert.equal(signalled.code, null)

      // Streaming: the first line arrives before the command finishes.
      const channel = await session.exec("echo first; sleep 1; echo second")
      channel.stdin.end()
      const t0 = Date.now()
      const firstChunkAt = await new Promise((resolve) =>
        channel.stdout.once("data", () => resolve(Date.now() - t0))
      )
      const rest = readAll(channel.stdout)
      const exit = await channel.done
      const doneAt = Date.now() - t0
      await rest
      assert.ok(
        firstChunkAt < doneAt - 500,
        `stdout must stream (first ${firstChunkAt} ms, done ${doneAt} ms)`
      )

      // Larger stdin through the channel window: 8 MiB into sha256sum.
      const payload = randomBytes(8 * 1024 * 1024)
      const big = await run(session, "sha256sum", payload)
      const expected = createHash("sha256").update(payload).digest("hex")
      assert.equal(big.stdout.split(" ")[0], expected)

      return {
        basic: { code: basic.code, stdout: basic.stdout, stderr: basic.stderr },
        signal: { code: signalled.code, signal: signalled.signal },
        streaming: { firstChunkMs: firstChunkAt, doneMs: doneAt, exit },
        stdin8MiB: { sha256Match: true },
      }
    } finally {
      await session.close()
    }
  }
)

proof(
  "O-channel-open-failed",
  "other",
  "server refuses a session channel (MaxSessions 1) → CHANNEL_OPEN_FAILED",
  async () => {
    const session = await connectWithKey(target, "key_ed25519_openssh", {
      port: target.maxSessionsPort,
    })
    try {
      const first = await session.exec("sleep 3")
      first.stdin.end()
      const error = await session.exec("echo second").then(
        () => null,
        (e) => e
      )
      assert.equal(error?.code, "CHANNEL_OPEN_FAILED")
      const firstExit = await first.done
      // The connection stays usable after the refusal. sshd frees the session
      // slot only after it processed our CHANNEL_CLOSE, so allow a short retry.
      let third
      let attempts = 0
      while (!third && attempts < 20) {
        attempts += 1
        try {
          third = await run(session, "echo third")
        } catch (retryError) {
          if (retryError.code !== "CHANNEL_OPEN_FAILED") throw retryError
          await new Promise((r) => setTimeout(r, 100))
        }
      }
      assert.equal(third?.stdout, "third\n")
      return {
        code: error.code,
        detail: error.detail,
        message: error.message,
        firstExit,
        reuseAttempts: attempts,
      }
    } finally {
      await session.close()
    }
  }
)
