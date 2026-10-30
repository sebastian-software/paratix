// Exec against the real sshd: H3 (streams, exit code, raw signal name,
// streaming, 8 MiB stdin), the ordering of decision 3 on a lost connection,
// ABORTED through cancel() or an AbortSignal during exec, and ABORTED
// through an AbortSignal during connect() (after TCP is up, inside the SSH
// handshake, and while the host-key verifier is pending). cancel() exists
// only on exec channels; connect() is aborted only through its AbortSignal.
//
// An already aborted signal rejecting with ABORTED without opening TCP is
// proven by the B1 unit test "rejects an already aborted signal with
// ABORTED without opening TCP" (test/connect.test.mjs), which counts the
// TCP connections of a listener; it is not repeated here.
import assert from "node:assert/strict"
import { randomBytes } from "node:crypto"
import { readFileSync } from "node:fs"
import { createConnection, createServer } from "node:net"
import { after, before, describe } from "node:test"

import { binding, collect, within } from "../helpers/binding.mjs"
import { sha256 } from "../helpers/server.mjs"
import { check, descriptor, fixtures, hardProof, sleepCommand, target } from "./lib/context.mjs"
import {
  connectWithKeyFile,
  pinnedVerifier,
  run,
  SHA256_STDIN,
  targetOptions,
} from "./lib/remote.mjs"

const STDIN_SIZE = 8 * 1024 * 1024
const READY_MARKER = "ssh-native-ready"

/** @returns a promise that never settles */
const never = () => new Promise(() => {})

/**
 * A TCP relay to the target's main port that forwards the client freely but
 * of the server only its first chunk (the banner, possibly with KEXINIT) and
 * then holds every further server byte. A client connected through it has
 * its TCP connection up and is stuck inside the SSH handshake, before the
 * host-key verifier can run.
 *
 * @param onGreeting runs once the server's first chunk reached the client
 * @returns the relay port, how many greetings it forwarded, and `close()`
 */
async function stallingRelay(onGreeting) {
  const { host, ports } = target()
  /** @type {Set<import("node:net").Socket>} */
  const sockets = new Set()
  const state = { greetings: 0 }
  const server = createServer((client) => {
    const upstream = createConnection({ host, port: ports.main })
    for (const socket of [client, upstream]) {
      sockets.add(socket)
      socket.on("error", () => {})
    }
    client.pipe(upstream)
    upstream.once("data", (chunk) => {
      upstream.pause()
      client.write(chunk, () => {
        state.greetings += 1
        onGreeting()
      })
    })
  })
  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(undefined))
  })
  const { port } = /** @type {import("node:net").AddressInfo} */ (server.address())
  const close = () =>
    new Promise((resolve) => {
      for (const socket of sockets) socket.destroy()
      server.close(() => resolve(undefined))
    })
  return { close, port, state }
}

describe("exec", () => {
  /** @type {import("../../index.js").Session | undefined} */
  let session

  before(async () => {
    if (descriptor.unavailable === null) session = await connectWithKeyFile(fixtures().keys.ed25519)
  })
  after(() => session?.close())

  /** @returns the shared session */
  const shared = () => /** @type {import("../../index.js").Session} */ (session)

  hardProof(
    {
      id: "H3-exec-streams-and-exit",
      name: "stdout, stderr, stdin, exit code, signal and streaming",
    },
    async (t) => {
      const basic = await run(shared(), "cat; echo err >&2; exit 3", "hello from stdin")
      assert.deepEqual(basic, {
        code: 3,
        disconnected: false,
        signal: null,
        stderr: "err\n",
        stdout: "hello from stdin",
      })

      const signalled = await run(shared(), "kill -TERM $$")
      assert.deepEqual([signalled.code, signalled.signal], [null, "TERM"])

      const channel = await shared().exec("echo first; sleep 1; echo second")
      channel.stdin.end()
      const started = Date.now()
      const first = await new Promise((resolve) => {
        channel.stdout.once("data", () => resolve(Date.now() - started))
      })
      const rest = collect(channel.stdout)
      const exit = await channel.exit
      const done = Date.now() - started
      await rest
      t.diagnostic(`streaming: first chunk after ${first} ms, exit after ${done} ms`)
      assert.equal(exit.code, 0)
      assert.ok(Number(first) < done - 500, `stdout streams (first ${first} ms, done ${done} ms)`)

      const payload = randomBytes(STDIN_SIZE)
      // Hash first: the binding zero-fills every Buffer written to stdin.
      const expected = sha256(payload)
      const summed = await run(shared(), SHA256_STDIN, payload)
      assert.equal(summed.code, 0, summed.stderr)
      assert.equal(summed.stdout.split(" ")[0], expected)
    }
  )

  check("reports the disconnect before a non-zero exit when the connection drops", async () => {
    const victim = await connectWithKeyFile(fixtures().keys.ed25519)
    try {
      /** @type {[string, unknown][]} */
      const order = []
      victim.onDisconnect((event) => order.push(["disconnect", event]))
      // $PPID is the sshd process of this connection; killing it drops the
      // TCP connection without CHANNEL_CLOSE. The command first prints a
      // marker and blocks on stdin, so the kill cannot race exec() resolving
      // or the listeners below being attached.
      const channel = await victim.exec(
        `echo ${READY_MARKER}; read _; kill -KILL $PPID; ${sleepCommand(5)}`
      )
      const exited = channel.exit.then((exit) => {
        order.push(["exit", exit])
        return exit
      })
      channel.stderr.resume()
      await within(
        new Promise((resolve) => {
          let seen = ""
          channel.stdout.on("data", (chunk) => {
            seen += String(chunk)
            if (seen.includes(`${READY_MARKER}\n`)) resolve(undefined)
          })
        }),
        15_000,
        "the ready marker before the connection is dropped"
      )
      // Compare the length rather than deepEqual(order, []): the assertion
      // signature would narrow `order` to never[] for the checks below.
      assert.equal(order.length, 0, "nothing ends before the command is released")
      channel.stdin.end("go\n")
      const exit = await within(exited, 15_000, "exit after the connection dropped")
      assert.deepEqual(
        order.map(([event]) => event),
        ["disconnect", "exit"]
      )
      assert.notEqual(/** @type {{ reason: string }} */ (order[0][1]).reason, "local")
      assert.deepEqual(exit, { code: null, disconnected: true, signal: null })
      assert.equal(victim.closed, true)
    } finally {
      victim.destroy()
    }
  })

  check("cancel() ends a running command with ABORTED", async () => {
    const channel = await shared().exec(sleepCommand(30))
    channel.stdout.resume()
    channel.cancel()
    await assert.rejects(within(channel.exit, 5000, "exit after cancel()"), { code: "ABORTED" })
    const still = await run(shared(), "echo still")
    assert.equal(still.stdout, "still\n", "the connection stays usable")
  })

  check("an AbortSignal ends a running command with ABORTED", async () => {
    const controller = new AbortController()
    const channel = await shared().exec(sleepCommand(30), { signal: controller.signal })
    channel.stdout.resume()
    setTimeout(() => controller.abort(), 100)
    await assert.rejects(within(channel.exit, 5000, "exit after abort"), { code: "ABORTED" })
    const still = await run(shared(), "echo still")
    assert.equal(still.stdout, "still\n", "the connection stays usable")
  })

  check("an AbortSignal during connect() rejects with ABORTED (verifier pending)", async () => {
    const controller = new AbortController()
    const options = targetOptions({
      privateKey: readFileSync(fixtures().keys.ed25519),
      signal: controller.signal,
    })
    const pending = binding.connect(options, () => {
      setTimeout(() => controller.abort(), 50)
      return never()
    })
    await assert.rejects(within(pending, 5000, "connect() after abort"), { code: "ABORTED" })
  })

  check(
    "an AbortSignal after TCP is up, inside the SSH handshake, rejects connect() with ABORTED",
    async () => {
      const controller = new AbortController()
      const relay = await stallingRelay(() => controller.abort())
      let verifierCalls = 0
      const verify = pinnedVerifier()
      try {
        const options = targetOptions({
          port: relay.port,
          privateKey: readFileSync(fixtures().keys.ed25519),
          signal: controller.signal,
        })
        const pending = binding.connect(options, (info) => {
          verifierCalls += 1
          return verify(info)
        })
        await assert.rejects(within(pending, 5000, "connect() after abort"), { code: "ABORTED" })
        assert.equal(relay.state.greetings, 1, "the abort came after the server greeting over TCP")
        assert.equal(verifierCalls, 0, "the abort came before host-key verification")
      } finally {
        await relay.close()
      }
    }
  )
})
