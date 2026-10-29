// THROWAWAY SPIKE (issue #254): lifecycle proofs (H5) in child processes.
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { dirname, join } from "node:path"
import { after, before } from "node:test"
import { fileURLToPath } from "node:url"

import { connectWithKey, run, setupTarget } from "./lib/env.mjs"
import { proof } from "./lib/results.mjs"

const CHILD = join(dirname(fileURLToPath(import.meta.url)), "children", "lifecycle-child.mjs")
const ABORT_PATTERN = /abort|panic|fatal|terminate called|core dumped|assertion|segmentation/i

let target
before(async () => {
  target = await setupTarget()
})
after(async () => {
  await target?.stop()
})

/**
 * Spawns the child; resolves once `marker` was printed, with a handle that
 * reports exit code/signal and timing.
 */
async function startChild(mode, marker, extraEnv = {}) {
  const child = spawn(process.execPath, [CHILD, mode], {
    env: {
      ...process.env,
      SPIKE_CHILD_HOST: target.host,
      SPIKE_CHILD_PORT: String(target.port),
      SPIKE_CHILD_USER: target.user,
      SPIKE_CHILD_KEY: join(target.fixtureDir, "key_ed25519_openssh"),
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  })
  let stdout = ""
  let stderr = ""
  child.stderr.on("data", (d) => {
    stderr += d
  })
  const exit = new Promise((resolve) => {
    child.once("exit", (code, signal) => resolve({ code, signal, at: Date.now() }))
  })
  const markerAt = await new Promise((resolve, reject) => {
    child.stdout.on("data", (d) => {
      stdout += d
      const line = stdout.split("\n").find((l) => l.startsWith(`${marker} `))
      if (line) resolve(Number(line.split(" ")[1]))
    })
    exit.then((e) =>
      reject(new Error(`child exited before ${marker}: ${JSON.stringify(e)} ${stderr}`))
    )
    setTimeout(() => reject(new Error(`child never printed ${marker}: ${stderr}`)), 20_000)
  })
  return {
    child,
    markerAt,
    exit,
    get stderr() {
      return stderr
    },
  }
}

async function exitWithin(handle, ms) {
  return await Promise.race([handle.exit, new Promise((r) => setTimeout(() => r(null), ms))])
}

proof(
  "H5-destroy-before-process-exit",
  "hard",
  "destroy() + process.exit(0) during a running exec ends cleanly",
  async () => {
    const marker = `${(61 + Math.random()).toFixed(6)}`
    const runs = []
    for (let i = 0; i < 5; i += 1) {
      const handle = await startChild("destroy-exit", "READY", {
        SPIKE_CHILD_COMMAND: `sleep ${marker}`,
      })
      const exit = await exitWithin(handle, 5000)
      assert.ok(exit, "child must exit")
      assert.equal(exit.code, 0, `exit code (stderr: ${handle.stderr})`)
      assert.equal(exit.signal, null)
      assert.ok(!ABORT_PATTERN.test(handle.stderr), `no abort output: ${handle.stderr}`)
      assert.equal(handle.stderr, "")
      runs.push({
        code: exit.code,
        signal: exit.signal,
        exitAfterMs: exit.at - handle.markerAt,
        stderrBytes: handle.stderr.length,
      })
    }
    // Informational: what happened to the remote command after the hard stop.
    const session = await connectWithKey(target)
    let remoteLeftovers
    try {
      remoteLeftovers = (
        await run(
          session,
          `ps -eo args | grep -c '^sleep ${marker}$'; pkill -f '^sleep ${marker}$' || true`
        )
      ).stdout.trim()
    } finally {
      await session.close()
    }
    return {
      runs,
      remoteSleepProcessesStillRunning: Number(remoteLeftovers.split("\n")[0]),
      note: "informational: exec runs without a PTY, so sshd does not signal the command when the connection drops",
    }
  }
)

proof(
  "H5-destroy-releases-event-loop",
  "hard",
  "destroy() without process.exit lets the process end on its own",
  async () => {
    const handle = await startChild("destroy-natural", "DESTROYED")
    const exit = await exitWithin(handle, 5000)
    assert.ok(exit, "process must exit by itself after destroy()")
    assert.equal(exit.code, 0)
    assert.equal(handle.stderr, "")
    return { code: exit.code, exitAfterMs: exit.at - handle.markerAt }
  }
)

proof(
  "H5-close-then-natural-exit",
  "hard",
  "after close() the process exits on its own",
  async () => {
    const handle = await startChild("close", "CLOSED")
    const exit = await exitWithin(handle, 5000)
    assert.ok(exit, "process must exit by itself after close()")
    assert.equal(exit.code, 0)
    assert.equal(handle.stderr, "")
    const ssh2Handle = await startChild("ssh2-close", "CLOSED")
    const ssh2Exit = await exitWithin(ssh2Handle, 5000)
    return {
      native: { code: exit.code, exitAfterMs: exit.at - handle.markerAt },
      ssh2Parity: ssh2Exit
        ? { code: ssh2Exit.code, exitAfterMs: ssh2Exit.at - ssh2Handle.markerAt }
        : "did not exit",
    }
  }
)

proof(
  "H5-idle-connection-keeps-process-alive",
  "hard",
  "an idle open connection keeps the process alive (ssh2 parity)",
  async () => {
    const observe = async (mode) => {
      const handle = await startChild(mode, "IDLE")
      const exit = await exitWithin(handle, 5000)
      const alive = exit === null
      handle.child.kill("SIGKILL")
      await handle.exit
      return { aliveAfter5s: alive, stderr: handle.stderr }
    }
    const nativeIdle = await observe("idle")
    const ssh2Idle = await observe("ssh2-idle")
    assert.equal(
      nativeIdle.aliveAfter5s,
      true,
      "native idle connection must keep the process alive"
    )
    assert.equal(ssh2Idle.aliveAfter5s, true, "ssh2 reference behaviour")
    return { native: nativeIdle, ssh2: ssh2Idle }
  }
)
