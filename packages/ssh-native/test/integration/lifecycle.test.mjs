// H5 against the real sshd, in child processes (test/helpers/lifecycle-child.mjs):
// destroy() + process.exit(0) during a running command and while output
// streams, destroy() releasing the event loop, close() then a natural exit,
// and an idle connection keeping the process alive. Every run must end with
// exit code 0, no signal and an empty stderr.
import assert from "node:assert/strict"
import { describe } from "node:test"

import { childEnvironment, exitWithin, startChild } from "../helpers/lifecycle.mjs"
import { fixtures, hardProof, sleepCommand, target } from "./lib/context.mjs"
import { connectWithKeyFile, run } from "./lib/remote.mjs"

const SLEEP_RUNS = 5
// 50 runs, as in the evidence of ADR 0008.
const STREAMING_RUNS = 50
const EXIT_WAIT_MS = 5000
const IDLE_MS = 5000

/**
 * @param [extra] COMMAND and STREAM_BYTES
 * @returns the child environment for the main profile
 */
function environment(extra = {}) {
  const { host, ports, user } = target()
  const connection = {
    host,
    hostKeyBase64: fixtures().hostKeyBase64,
    keyPath: fixtures().keys.ed25519,
    port: ports.main,
    user,
  }
  return childEnvironment(connection, extra)
}

/**
 * Asserts a clean exit within EXIT_WAIT_MS.
 *
 * @param handle the started child
 * @param label run label for messages
 * @returns ms from the marker to the exit
 */
async function assertCleanExit(handle, label) {
  const exit = await exitWithin(handle, EXIT_WAIT_MS)
  if (exit === null) handle.kill()
  assert.ok(exit, `${label}: the child must exit on its own`)
  assert.equal(handle.stderr(), "", `${label}: empty stderr`)
  assert.equal(exit.signal, null, `${label}: no signal`)
  assert.equal(exit.code, 0, `${label}: exit code`)
  return exit.at - handle.markerAt
}

describe("lifecycle (child processes)", () => {
  hardProof(
    {
      id: "H5-destroy-before-process-exit",
      name: "destroy() + process.exit(0) during a running command",
    },
    async (t) => {
      const command = sleepCommand(30)
      const latencies = []
      for (let index = 0; index < SLEEP_RUNS; index += 1) {
        // eslint-disable-next-line no-await-in-loop -- one child process at a time
        const handle = await startChild(
          "destroy-exit",
          environment({ SSH_NATIVE_CHILD_COMMAND: command }),
          "READY"
        )
        // eslint-disable-next-line no-await-in-loop -- one child process at a time
        latencies.push(await assertCleanExit(handle, `run ${index}`))
      }
      // Informational: exec runs without a PTY, so the remote sleeps survive
      // the dropped connection (README, "Known limitations"); remove them.
      const session = await connectWithKeyFile(fixtures().keys.ed25519)
      try {
        const pattern = `^${command.replace(".", "\\.")}$`
        const leftovers = await run(session, `pgrep -f '${pattern}' | wc -l; pkill -f '${pattern}'`)
        t.diagnostic(
          `exit latencies ${latencies.join(", ")} ms; remote sleeps left: ${leftovers.stdout.trim()}`
        )
      } finally {
        await session.close()
      }
    }
  )

  hardProof(
    {
      id: "H5-destroy-before-exit-while-streaming",
      name: "destroy() + process.exit(0) while stdout streams into a listener",
    },
    async (t) => {
      const latencies = []
      let maxBytes = 0
      for (let index = 0; index < STREAMING_RUNS; index += 1) {
        // eslint-disable-next-line no-await-in-loop -- one child process at a time
        const handle = await startChild(
          "destroy-exit-streaming",
          environment({
            SSH_NATIVE_CHILD_COMMAND: "yes ssh-native-streaming-line",
            SSH_NATIVE_CHILD_STREAM_BYTES: String(1024 * 1024),
          }),
          "READY"
        )
        // eslint-disable-next-line no-await-in-loop -- one child process at a time
        latencies.push(await assertCleanExit(handle, `run ${index}`))
        maxBytes = Math.max(maxBytes, Number(handle.fields[0]))
      }
      latencies.sort((left, right) => left - right)
      t.diagnostic(
        `${STREAMING_RUNS} runs, exit latency max ${latencies.at(-1)} ms, up to ${maxBytes} bytes received`
      )
    }
  )

  hardProof(
    { id: "H5-destroy-releases-event-loop", name: "after destroy() the process ends on its own" },
    async () => {
      const handle = await startChild(
        "destroy-natural",
        environment({ SSH_NATIVE_CHILD_COMMAND: sleepCommand(30) }),
        "DESTROYED"
      )
      await assertCleanExit(handle, "destroy-natural")
    }
  )

  hardProof(
    { id: "H5-close-then-natural-exit", name: "after close() the process ends on its own" },
    async () => {
      const handle = await startChild(
        "close",
        environment({ SSH_NATIVE_CHILD_COMMAND: "echo ok" }),
        "CLOSED"
      )
      await assertCleanExit(handle, "close")
    }
  )

  hardProof(
    {
      id: "H5-idle-connection-keeps-process-alive",
      name: "an idle open connection keeps the process alive for 5 s",
    },
    async () => {
      const handle = await startChild("idle", environment(), "IDLE")
      const exit = await exitWithin(handle, IDLE_MS)
      handle.kill()
      await handle.exit
      assert.equal(exit, null, "the process must still run after 5 s")
      assert.equal(handle.stderr(), "")
    }
  )
})
