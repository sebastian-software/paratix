import assert from "node:assert/strict"
import { once } from "node:events"
import { after, before, describe, it } from "node:test"

import { collect, connectWithKey, delay, within } from "./helpers/binding.mjs"
import { clientKey, payload, sha256, startServer } from "./helpers/server.mjs"

describe("exec", () => {
  const key = clientKey()
  let server

  before(async () => {
    server = await startServer({ keys: [key.publicKey] })
  })
  after(() => server.close())

  async function withSession(run) {
    const session = await connectWithKey(server, key)
    try {
      return await run(session)
    } finally {
      session.destroy()
    }
  }

  it("streams stdin through and reports the exit code", () =>
    withSession(async (session) => {
      const channel = await session.exec("echo-stdin", { stdin: Buffer.from("initial ") })
      channel.stdin.write(Buffer.from("chunk "))
      channel.stdin.end("tail")
      const stdout = await collect(channel.stdout)
      assert.equal(stdout.toString(), "initial chunk tail")
      assert.deepEqual(await channel.exit, { code: 0, disconnected: false, signal: null })
    }))

  it("reports the raw signal name", () =>
    withSession(async (session) => {
      const channel = await session.exec("signal TERM")
      channel.stdout.resume()
      assert.deepEqual(await channel.exit, { code: null, disconnected: false, signal: "TERM" })
    }))

  it("delivers all stdout and stderr data before the exit", () =>
    withSession(async (session) => {
      const size = 4 * 1024 * 1024
      const channel = await session.exec(`stdout-flood ${size}`)
      let received = 0
      let exitSeenEarly = false
      channel.stdout.on("data", (chunk) => {
        received += chunk.length
      })
      channel.exit.then(() => {
        exitSeenEarly = received < size
      })
      await channel.exit
      await delay(0)
      assert.equal(exitSeenEarly, false)
      assert.equal(received, size)
    }))

  it("rejects writes to stdin after the channel ended, without crashing", () =>
    withSession(async (session) => {
      const channel = await session.exec("exit 0")
      channel.stdout.resume()
      await channel.exit
      const error = await new Promise((resolve) => {
        channel.stdin.write(Buffer.from("too late"), resolve)
      })
      assert.equal(error?.code, "ERR_STREAM_DESTROYED")
    }))

  it("cancel() ends the channel with ABORTED", () =>
    withSession(async (session) => {
      const channel = await session.exec("sleep")
      channel.cancel()
      await assert.rejects(channel.exit, { code: "ABORTED" })
      assert.ok(channel.stdout.destroyed)
      // The connection stays usable.
      const next = await session.exec("exit 3")
      next.stdout.resume()
      const exit = await next.exit
      assert.equal(exit.code, 3)
    }))

  it("an AbortSignal ends a running channel with ABORTED", () =>
    withSession(async (session) => {
      const controller = new AbortController()
      const channel = await session.exec("sleep", { signal: controller.signal })
      setTimeout(() => controller.abort(), 20)
      await assert.rejects(channel.exit, { code: "ABORTED" })
    }))

  it("reports the disconnect before the exit of a channel lost with the connection", async () => {
    const session = await connectWithKey(server, key)
    const order = []
    session.onDisconnect((event) => order.push(["disconnect", event]))
    const channel = await session.exec("drop")
    channel.stdout.resume()
    const exit = await channel.exit
    order.push(["exit", exit])
    assert.deepEqual(order, [
      ["disconnect", { code: "DISCONNECTED", reason: "error" }],
      ["exit", { code: null, disconnected: true, signal: null }],
    ])
    assert.equal(session.closed, true)
    await assert.rejects(session.exec("exit 0"), { code: "DISCONNECTED" })
  })

  it("notifies onDisconnect exactly once and late subscribers asynchronously", async () => {
    const session = await connectWithKey(server, key)
    const events = []
    const unsubscribed = []
    session.onDisconnect((event) => events.push(event))
    const unsubscribe = session.onDisconnect((event) => unsubscribed.push(event))
    unsubscribe()
    await session.close()
    session.destroy()
    assert.deepEqual(events, [{ reason: "local" }])
    assert.deepEqual(unsubscribed, [])
    /** @type {unknown} */
    let late = null
    session.onDisconnect((event) => {
      late = event
    })
    assert.equal(late, null, "late subscribers are not called synchronously")
    await delay(10)
    assert.deepEqual(late, { reason: "local" })
  })

  it("destroy() ends open channels with a disconnected exit", async () => {
    const session = await connectWithKey(server, key)
    const channel = await session.exec("sleep")
    const order = []
    session.onDisconnect(() => order.push("disconnect"))
    channel.exit.then(() => order.push("exit"))
    session.destroy()
    assert.deepEqual(await channel.exit, { code: null, disconnected: true, signal: null })
    assert.deepEqual(order, ["disconnect", "exit"])
  })

  it("delivers 8 MiB of unread stderr, stdout and then the exit", () =>
    withSession(async (session) => {
      const size = 8 * 1024 * 1024
      const channel = await session.exec(`stderr-flood ${size}`)
      const stdout = await collect(channel.stdout)
      assert.equal(stdout.toString(), "stdout-before\nstdout-after\n")
      assert.deepEqual(await channel.exit, { code: 0, disconnected: false, signal: null })
      assert.equal(channel.stderr.readableLength, size, "all stderr data arrived unread")
      assert.equal(sha256(await collect(channel.stderr)), sha256(payload(size)))
    }))

  it("close() ends the channel with a regular exit and keeps the session usable", () =>
    withSession(async (session) => {
      const silent = await session.exec("sleep")
      silent.stdout.resume()
      await silent.close()
      const exit = await within(silent.exit, 2000, "exit after close()")
      assert.deepEqual(exit, { code: null, disconnected: false, signal: null })

      const reported = await session.exec("status 4")
      const [line] = await once(reported.stdout, "data")
      assert.equal(line.toString(), "status sent\n")
      reported.stdout.resume()
      // Let the exit status arrive before closing.
      await delay(50)
      await reported.close()
      const reportedExit = await within(reported.exit, 2000, "exit after close()")
      assert.deepEqual(reportedExit, { code: 4, disconnected: false, signal: null })

      assert.equal(session.closed, false)
      const next = await session.exec("exit 0")
      next.stdout.resume()
      const nextExit = await next.exit
      assert.equal(nextExit.code, 0)
    }))

  it("reports a disconnected exit when the connection drops while stdout is paused", async () => {
    const session = await connectWithKey(server, key)
    try {
      // 2 MiB: more than JS takes while paused, little enough that russh's
      // session loop is not blocked and notices the dropped connection.
      const channel = await session.exec(`flood-then-drop ${2 * 1024 * 1024}`)
      channel.stdout.pause()
      const exit = await within(channel.exit, 5000, "exit after the connection dropped")
      assert.deepEqual(exit, { code: null, disconnected: true, signal: null })
      assert.equal(session.closed, true)
    } finally {
      session.destroy()
    }
  })

  it("does not notify a late subscriber that unsubscribed right away", async () => {
    const session = await connectWithKey(server, key)
    await session.close()
    let notified = false
    const unsubscribe = session.onDisconnect(() => {
      notified = true
    })
    unsubscribe()
    await delay(20)
    assert.equal(notified, false)
  })
})
