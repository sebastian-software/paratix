import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { after, before, describe, it } from "node:test"
import { fileURLToPath } from "node:url"

import { INDEX_PATH } from "./helpers/binding.mjs"
import { startServer } from "./helpers/server.mjs"

const CHILD = fileURLToPath(new URL("children/verifier-child.mjs", import.meta.url))
const READY_TIMEOUT_MS = 1000

/**
 * Runs the child; records when each stdout line arrived and when it exited.
 *
 * @param mode verifier behaviour
 * @param port server port
 * @returns exit code, signal, stderr and the timestamped stdout lines
 */
function runChild(mode, port) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CHILD, mode], {
      env: {
        ...process.env,
        READY_TIMEOUT_MS: String(READY_TIMEOUT_MS),
        SERVER_PORT: String(port),
        SSH_NATIVE_INDEX: INDEX_PATH,
      },
      stdio: ["ignore", "pipe", "pipe"],
    })
    /** @type {{ line: string, at: number }[]} */
    const lines = []
    let stderr = ""
    let buffered = ""
    child.stdout.on("data", (data) => {
      buffered += data
      const parts = buffered.split("\n")
      buffered = parts.pop() ?? ""
      for (const line of parts) lines.push({ at: Date.now(), line })
    })
    child.stderr.on("data", (data) => {
      stderr += data
    })
    const killer = setTimeout(() => child.kill("SIGKILL"), 15_000)
    child.on("exit", (code, signal) => {
      clearTimeout(killer)
      resolve({ code, exitedAt: Date.now(), lines, signal, stderr })
    })
  })
}

describe("verifier abort (child process)", () => {
  let server

  before(async () => {
    server = await startServer()
  })
  after(() => server.close())

  it("rejects a never-settling verifier with TIMEOUT and lets the process exit", async () => {
    const result = await runChild("never", server.port)
    assert.equal(result.stderr, "")
    assert.equal(result.signal, null)
    assert.equal(result.code, 0)
    assert.equal(result.lines.length, 1)
    const outcome = JSON.parse(result.lines[0].line)
    assert.equal(outcome.outcome, "rejected")
    assert.equal(outcome.code, "TIMEOUT")
    assert.ok(
      Math.abs(outcome.elapsedMs - READY_TIMEOUT_MS) <= 500,
      `rejected after ${outcome.elapsedMs} ms`
    )
    const exitDelay = result.exitedAt - result.lines[0].at
    assert.ok(exitDelay < 2000, `process exited ${exitDelay} ms after the rejection`)
  })

  it("discards a verdict that arrives after the timeout", async () => {
    const attempts = server.stats.authAttempts
    const result = await runChild("late", server.port)
    assert.equal(result.stderr, "", "no unhandledRejection")
    assert.equal(result.code, 0)
    const lines = result.lines.map((entry) => entry.line)
    assert.equal(lines.length, 2)
    assert.deepEqual(
      { ...JSON.parse(lines[0]), elapsedMs: undefined },
      { code: "TIMEOUT", elapsedMs: undefined, outcome: "rejected" }
    )
    assert.equal(lines[1], "LATE-SETTLED")
    assert.equal(server.stats.authAttempts, attempts, "no call into the ended session")
  })
})
