// THROWAWAY SPIKE (issue #254): SFTP write proofs (H4).
import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { once } from "node:events"
import { finished } from "node:stream/promises"
import { after, before } from "node:test"

import { connectWithKey, native, run, setupTarget } from "./lib/env.mjs"
import { proof } from "./lib/results.mjs"
import { startSsh2Server } from "./lib/ssh2-server.mjs"

let target
before(async () => {
  target = await setupTarget()
})
after(async () => {
  await target?.stop()
})

const MiB = 1024 * 1024

/** Writes `data` respecting backpressure and returns observations. */
async function pump(stream, data, chunkSize, progress = {}) {
  const stats = { writeReturnedFalse: 0, drainEvents: 0, maxWritableLength: 0, produced: 0 }
  Object.assign(progress, stats)
  stream.on("drain", () => {
    stats.drainEvents += 1
  })
  while (stats.produced < data.length) {
    const chunk = data.subarray(stats.produced, stats.produced + chunkSize)
    stats.produced += chunk.length
    const ok = stream.write(chunk)
    stats.maxWritableLength = Math.max(stats.maxWritableLength, stream.writableLength)
    Object.assign(progress, stats, { writableLength: stream.writableLength })
    if (!ok) {
      stats.writeReturnedFalse += 1
      await once(stream, "drain")
    }
  }
  stream.end()
  await finished(stream)
  return { ...stats, bytesWritten: stream.bytesWritten }
}

proof(
  "H4-sftp-mode-0600-and-backpressure",
  "hard",
  "SFTP write: mode 0600, backpressure, 32 MiB content intact",
  async () => {
    const session = await connectWithKey(target)
    try {
      const dir = (await run(session, "mktemp -d")).stdout.trim()
      const existing = `${dir}/existing.bin`
      const fresh = `${dir}/fresh.bin`
      // Pre-existing 0644 file: proves mode is applied to existing files too (fchmod).
      assert.equal(
        (
          await run(session, `umask 022; echo old > ${existing}; stat -c %a ${existing}`)
        ).stdout.trim(),
        "644"
      )

      const data = randomBytes(32 * MiB)
      const expected = createHash("sha256").update(data).digest("hex")
      const t0 = Date.now()
      const writer = await session.sftpWrite(existing, { mode: 0o600, highWaterMark: 256 * 1024 })
      const stats = await pump(writer, data, 64 * 1024)
      const ms = Date.now() - t0

      const small = await session.sftpWrite(fresh, { mode: 0o600 })
      small.end(Buffer.from("fresh"))
      await finished(small)

      const check = await run(
        session,
        `stat -c '%a %s' ${existing} ${fresh}; sha256sum ${existing}; rm -rf ${dir}`
      )
      const [existingStat, freshStat, sum] = check.stdout.trim().split("\n")
      assert.equal(existingStat, `600 ${32 * MiB}`)
      assert.equal(freshStat, "600 5")
      assert.equal(sum.split(" ")[0], expected)
      assert.ok(stats.writeReturnedFalse > 0, "write() must return false at least once")
      assert.ok(stats.drainEvents > 0, "drain must fire")
      assert.ok(stats.maxWritableLength <= 256 * 1024 + 64 * 1024, "JS-side buffer stays bounded")
      return {
        ...stats,
        sizeBytes: 32 * MiB,
        durationMs: ms,
        mibPerSecond: Number(((32 * 1000) / ms).toFixed(1)),
        modes: { existing: existingStat, fresh: freshStat },
        sha256Match: true,
      }
    } finally {
      await session.close()
    }
  }
)

proof(
  "H4-sftp-bounded-in-flight",
  "hard",
  "SFTP write stalls with bounded in-flight data when the server stops acknowledging",
  async () => {
    const server = await startSsh2Server()
    const session = await native.connect(
      {
        host: "127.0.0.1",
        port: server.port,
        user: "spike",
        privateKey: Buffer.from(server.privateKey),
      },
      async (info) => info.keyBase64 === server.hostKeyBase64
    )
    try {
      const data = randomBytes(32 * MiB)
      const writer = await session.sftpWrite("/stall.bin", { mode: 0o600 })
      server.state.sftp.stalled = true
      const progress = {}
      const pumping = pump(writer, data, 64 * 1024, progress)
      await new Promise((r) => setTimeout(r, 1500))
      const sftp = server.state.sftp
      const acceptedByNative = progress.produced - progress.writableLength
      const snapshot = {
        producedByJs: progress.produced,
        acceptedByNative,
        serverReceived: sftp.received,
        outstandingWrites: sftp.outstanding,
      }
      assert.ok(
        progress.produced < data.length,
        "the producer must be blocked while the server stalls"
      )
      assert.ok(
        acceptedByNative <= 4 * MiB,
        `in-flight data must stay bounded (${acceptedByNative} bytes)`
      )
      sftp.stalled = false
      server.releaseHeld()
      const stats = await pumping
      assert.equal(sftp.received, data.length)
      return {
        duringStall: snapshot,
        maxOutstandingSftpWrites: sftp.maxOutstanding,
        modesSeenByServer: sftp.modes.map((m) => m.toString(8)),
        after: stats,
      }
    } finally {
      await session.close()
      await server.close()
    }
  }
)
