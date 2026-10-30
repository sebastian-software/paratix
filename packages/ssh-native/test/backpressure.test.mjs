import assert from "node:assert/strict"
import { once } from "node:events"
import { Writable } from "node:stream"
import { pipeline } from "node:stream/promises"
import { after, before, describe, it } from "node:test"

import { connectWithKey, delay, within } from "./helpers/binding.mjs"
import { clientKey, payload, sha256, startServer } from "./helpers/server.mjs"

// Mirrors of the crate's flow-control constants (src/exec.rs, src/connect.rs);
// `cargo test` asserts the same values on the Rust side.
const STDOUT_QUEUE_LIMIT = 1_048_576
const WINDOW_SIZE = 2_097_152
const MAXIMUM_PACKET_SIZE = 32_768
const CHANNEL_BUFFER_SIZE = 100
// highWaterMark of the exec stdout Readable (lib/exec.js).
const HIGH_WATER_MARK = 64 * 1024

const FLOOD_SIZE = 64 * 1024 * 1024
const SERVER_BOUND =
  STDOUT_QUEUE_LIMIT + HIGH_WATER_MARK + CHANNEL_BUFFER_SIZE * MAXIMUM_PACKET_SIZE + WINDOW_SIZE
const JS_BOUND = STDOUT_QUEUE_LIMIT + HIGH_WATER_MARK

/**
 * Takes one chunk and pauses the stream synchronously in the same `data`
 * event, so no data is emitted without a listener.
 *
 * @param readable a fresh stdout stream
 * @returns the chunk that arrived before the pause
 */
function firstChunkThenPause(readable) {
  const { promise, resolve } = Promise.withResolvers()
  readable.once("data", (chunk) => {
    readable.pause()
    resolve(chunk)
  })
  return promise
}

/**
 * @typedef {object} Flood
 * @property {import("../index.js").ExecChannel} channel the flooding channel
 * @property {Buffer[]} chunks stdout chunks read so far
 * @property {() => number} sent stdout bytes the server sent since the start
 */

/**
 * Asserts that the paused flood stalled within the bounds.
 *
 * @param flood the paused flood
 */
async function assertStalled(flood) {
  const { channel, chunks, sent } = flood
  const consumed = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  await delay(1000)
  const atOneSecond = sent()
  await delay(500)
  const atOneAndAHalf = sent()
  assert.equal(atOneAndAHalf, atOneSecond, "the server stopped sending while stdout is paused")
  assert.ok(
    atOneAndAHalf - consumed <= SERVER_BOUND,
    `server sent ${atOneAndAHalf - consumed} unread bytes, bound ${SERVER_BOUND}`
  )
  assert.ok(atOneAndAHalf < FLOOD_SIZE / 4, "the flood is far from complete")
  assert.ok(
    channel.stdout.readableLength <= JS_BOUND,
    `JS buffered ${channel.stdout.readableLength} bytes, bound ${JS_BOUND}`
  )
}

describe("stdout backpressure", () => {
  const key = clientKey()
  let server

  before(async () => {
    server = await startServer({ keys: [key.publicKey] })
  })
  after(() => server.close())

  /**
   * Starts a 64 MiB stdout flood and pauses the reader at its first chunk.
   *
   * @param session an open session
   * @param [options] exec options
   * @returns the channel, the chunks read so far and a server counter
   */
  async function pausedFlood(session, options) {
    const sentBefore = server.stats.stdoutSent
    const channel = await session.exec(`stdout-flood ${FLOOD_SIZE}`, options)
    const first = await firstChunkThenPause(channel.stdout)
    return { channel, chunks: [first], sent: () => server.stats.stdoutSent - sentBefore }
  }

  it("stalls a paused reader within the bound and delivers everything after resuming", async () => {
    const session = await connectWithKey(server, key)
    try {
      const flood = await pausedFlood(session)
      await assertStalled(flood)
      const { channel, chunks } = flood
      let receivedAtExit = -1
      channel.stdout.on("data", (chunk) => chunks.push(chunk))
      channel.exit.then(() => {
        receivedAtExit = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
      })
      channel.stdout.resume()
      await once(channel.stdout, "end")
      const data = Buffer.concat(chunks)
      assert.equal(data.length, FLOOD_SIZE)
      assert.equal(sha256(data), sha256(payload(FLOOD_SIZE)))
      assert.deepEqual(await channel.exit, { code: 0, disconnected: false, signal: null })
      assert.equal(receivedAtExit, FLOOD_SIZE, "the exit follows all stdout data")
    } finally {
      session.destroy()
    }
  })

  it("destroy() works while stdout is paused", async () => {
    const session = await connectWithKey(server, key)
    try {
      const flood = await pausedFlood(session)
      await assertStalled(flood)
      const started = Date.now()
      session.destroy()
      const exit = await flood.channel.exit
      assert.deepEqual(exit, { code: null, disconnected: true, signal: null })
      assert.ok(Date.now() - started < 500)
      assert.equal(session.closed, true)
    } finally {
      // Idempotent; releases the connection if an assertion failed first.
      session.destroy()
    }
  })

  it("an AbortSignal works while stdout is paused and unblocks the connection", async () => {
    const session = await connectWithKey(server, key)
    try {
      const controller = new AbortController()
      const flood = await pausedFlood(session, { signal: controller.signal })
      await assertStalled(flood)
      controller.abort()
      await assert.rejects(flood.channel.exit, { code: "ABORTED" })
      const next = await session.exec("exit 5")
      next.stdout.resume()
      const exit = await next.exit
      assert.equal(exit.code, 5)
    } finally {
      session.destroy()
    }
  })

  /**
   * Runs `stopReading` on a stalled flood and checks that the channel still
   * ends and the connection stays usable.
   *
   * @param stopReading ends the consumer of stdout
   */
  async function abandonStdout(stopReading) {
    const session = await connectWithKey(server, key)
    try {
      const flood = await pausedFlood(session)
      await assertStalled(flood)
      await stopReading(flood.channel.stdout)
      const exit = await within(flood.channel.exit, 10_000, "exit after stdout was abandoned")
      assert.deepEqual(exit, { code: 0, disconnected: false, signal: null })
      const next = await session.exec("exit 6")
      next.stdout.resume()
      const nextExit = await next.exit
      assert.equal(nextExit.code, 6)
    } finally {
      session.destroy()
    }
  }

  it("stdout.destroy() while stalled releases the connection", () =>
    abandonStdout(async (stdout) => {
      stdout.destroy()
    }))

  it("leaving a for-await loop early while stalled releases the connection", () =>
    abandonStdout(async (stdout) => {
      // What `for await (...) { break }` does: take one chunk, then return.
      const iterator = stdout[Symbol.asyncIterator]()
      const first = await iterator.next()
      assert.ok(first.value.length > 0)
      await iterator.return?.()
    }))

  it("a failed pipeline while stalled releases the connection", () =>
    abandonStdout(async (stdout) => {
      const failing = new Writable({
        write(_chunk, _encoding, callback) {
          callback(new Error("disk full"))
        },
      })
      await assert.rejects(pipeline(stdout, failing), /disk full/v)
    }))

  it("close() during a stall settles in time and ends the channel as disconnected", async () => {
    const session = await connectWithKey(server, key)
    try {
      const flood = await pausedFlood(session)
      await assertStalled(flood)
      // Fill russh's handle queue too: the server never reads this stdin.
      flood.channel.stdin.write(Buffer.alloc(1024 * 1024, 1))
      const started = Date.now()
      await within(session.close(), 7000, "close() during a stall")
      assert.ok(Date.now() - started < 6500, `close() took ${Date.now() - started} ms`)
      const exit = await within(flood.channel.exit, 2000, "exit after close()")
      assert.deepEqual(exit, { code: null, disconnected: true, signal: null })
      assert.equal(session.closed, true)
    } finally {
      session.destroy()
    }
  })
})
